import { createServer } from 'node:http';
import { readFile, mkdir, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { randomUUID, randomInt, createHmac } from 'node:crypto';
import { extname, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { sendMail } from './mailer.mjs';
import { openDatabase, getSetting, setSetting, createPublicUserId } from './db.mjs';
import { loadConfig } from './config.mjs';
import { hashPassword, verifyPassword, createSession, cookieOptions, csrfCookieOptions, parseCookies, isSameOrigin, sealValue, unsealValue } from './security.mjs';
import { cleanText, deviceCategory, hashToken, normalizeEmail, passwordLooksCompromised, randomToken, safeAlias, validateAdDestination, validateDestination, validateEmail, validatePassword, calculateEarning, nextStepPosition, publicStepState, safeEqualHex } from './domain.mjs';

const ROOT = resolve(fileURLToPath(new URL('..', import.meta.url)));
const PUBLIC = resolve(ROOT, 'public');
const MIME = { '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.svg': 'image/svg+xml', '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.webp': 'image/webp', '.ico': 'image/x-icon' };
const RESERVED = new Set(['api', 's', 'r', 'admin', 'login', 'register', 'logout', 'assets', 'favicon.ico']);

function json(res, status, body, headers = {}) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...headers });
  res.end(JSON.stringify(body));
}

function error(res, status, message, details) {
  json(res, status, { error: { message, ...(details ? { details } : {}) } });
}

function applyCors(req, res, config) {
  const origin = String(req.headers.origin || '');
  if (!origin) { req.allowedCorsOrigin = true; return true; }
  let allowed = false;
  try {
    const candidate = new URL(origin);
    const configured = [config.appUrl, ...(config.corsOrigins || [])].map(value => { try { return new URL(value).origin; } catch { return ''; } });
    const requestOrigin = req.headers.host ? `${req.socket?.encrypted ? 'https:' : 'http:'}//${req.headers.host}` : '';
    allowed = candidate.protocol !== 'null:' && (candidate.origin === requestOrigin || configured.includes(candidate.origin));
  } catch {}
  req.allowedCorsOrigin = allowed;
  if (allowed) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Methods', 'GET, HEAD, POST, PATCH, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-CSRF-Token');
    res.setHeader('Vary', 'Origin');
  }
  return allowed;
}

function htmlSafeCookie(value) { return encodeURIComponent(value); }

function setCookies(res, cookies) {
  const current = res.getHeader('Set-Cookie');
  res.setHeader('Set-Cookie', [...(Array.isArray(current) ? current : current ? [current] : []), ...cookies]);
}

async function readBody(req, max = 1024 * 1024) {
  let body = '';
  for await (const chunk of req) {
    body += chunk;
    if (Buffer.byteLength(body) > max) throw Object.assign(new Error('Request body is too large'), { status: 413 });
  }
  req.rawBody = body;
  if (!body) return {};
  const type = String(req.headers['content-type'] ?? '').split(';')[0].trim();
  if (type !== 'application/json') throw Object.assign(new Error('Content-Type must be application/json'), { status: 415 });
  try { return JSON.parse(body); } catch { throw Object.assign(new Error('Request body must be valid JSON'), { status: 400 }); }
}

function makeRateLimiter({ limit = 20, windowMs = 60000 } = {}) {
  const buckets = new Map();
  return (key) => {
    const now = Date.now();
    const item = buckets.get(key);
    if (!item || item.until <= now) {
      buckets.set(key, { count: 1, until: now + windowMs });
      return true;
    }
    item.count++;
    if (buckets.size > 10000) for (const [k, v] of buckets) if (v.until <= now) buckets.delete(k);
    return item.count <= limit;
  };
}

function ipKey(req) {
  // Do not persist or log the address; it is used only for short-lived throttling.
  return String(req.socket.remoteAddress ?? 'local').replace(/^::ffff:/, '');
}

function referrerDomain(req) {
  try { return req.headers.referer ? new URL(req.headers.referer).hostname.slice(0, 255) : ''; } catch { return ''; }
}

function countryCodeFromRequest(req) {
  const raw=req.headers['cf-ipcountry']||req.headers['x-vercel-ip-country']||req.headers['cloudfront-viewer-country']||req.headers['x-country-code']||'';
  const code=String(raw).trim().toUpperCase();
  return /^[A-Z]{2}$/.test(code)&&!['XX','T1'].includes(code)?code:'Unknown';
}

function audit(db, actorId, action, resourceType, resourceId = '', reason = '', metadata = {}) {
  db.prepare(`INSERT INTO audit_logs(id,actor_id,action,resource_type,resource_id,reason,metadata)
    VALUES (?,?,?,?,?,?,?)`).run(randomUUID(), actorId, action, resourceType, String(resourceId), String(reason), JSON.stringify(metadata));
}

function notify(db, userId, title, message) {
  db.prepare('INSERT INTO notifications(id,user_id,title,message) VALUES (?,?,?,?)').run(randomUUID(), userId, title, message);
}

function userPublic(user) {
  return { id: user.id, publicId: user.public_id || '', email: user.email, displayName: user.display_name, avatarUrl: user.avatar_url || '', role: user.role, status: user.status, createdAt: user.created_at };
}

function publicArticleAuthor(article) {
  let socialLinks = {};
  try { socialLinks = JSON.parse(article.author_social_links || '{}'); } catch {}
  return { displayName: article.author_display_name || 'Mylink creator', avatarUrl: article.author_avatar_url || '', socialLinks };
}

function activeUser(db, req, config) {
  const cookies = parseCookies(req.headers.cookie);
  const token = cookies.sid;
  if (!token) return null;
  const session = db.prepare(`SELECT s.*,u.* FROM user_sessions s JOIN users u ON u.id=s.user_id
    WHERE s.token_hash=? AND julianday(s.expires_at)>julianday('now')`).get(hashToken(token));
  if (!session) return null;
  db.prepare("UPDATE user_sessions SET last_seen_at=datetime('now') WHERE token_hash=?").run(hashToken(token));
  return { ...session, csrf: session.csrf_token };
}

function requireAuth(db, req, res, config) {
  const user = activeUser(db, req, config);
  if (!user) { error(res, 401, 'Please sign in to continue.'); return null; }
  if (user.status !== 'active') { error(res, 403, `This account is ${user.status.replaceAll('_', ' ')}.`); return null; }
  return user;
}

function requireAdmin(db, req, res, config) {
  const user = requireAuth(db, req, res, config);
  if (!user) return null;
  if (!['admin', 'super_admin'].includes(user.role)) { error(res, 403, 'Administrator access is required.'); return null; }
  return user;
}

function requireCsrf(req, user, res) {
  if (!isSameOrigin(req, req.appUrl)) { error(res, 403, 'Cross-origin requests are not allowed.'); return false; }
  const token = req.headers['x-csrf-token'];
  if (!user || !token || token !== user.csrf) { error(res, 403, 'Your session token is missing or expired. Refresh and try again.'); return false; }
  return true;
}

function moneySummary(db, userId) {
  const balance = db.prepare(`SELECT COALESCE(SUM(amount_paise),0) AS amount FROM earning_ledger
    WHERE user_id=? AND status IN ('approved','paid')`).get(userId).amount;
  const reserved = db.prepare(`SELECT COALESCE(SUM(amount_paise),0) AS amount FROM withdrawal_requests
    WHERE user_id=? AND status IN ('requested','under_review','approved','processing')`).get(userId).amount;
  const pending = db.prepare("SELECT COALESCE(SUM(amount_paise),0) AS amount FROM earning_ledger WHERE user_id=? AND status IN ('pending','estimated','on_hold') AND amount_paise>0").get(userId).amount;
  const approved = db.prepare("SELECT COALESCE(SUM(amount_paise),0) AS amount FROM earning_ledger WHERE user_id=? AND status IN ('approved','paid') AND amount_paise>0").get(userId).amount;
  const paid = Math.abs(db.prepare("SELECT COALESCE(SUM(amount_paise),0) AS amount FROM earning_ledger WHERE user_id=? AND type='payout'").get(userId).amount);
  return { balancePaise: balance, reservedPaise: reserved, withdrawablePaise: Math.max(0, balance - reserved), pendingPaise: pending, approvedPaise: approved, paidPaise: paid };
}

function linkStats(db, linkId) {
  return db.prepare(`SELECT
    SUM(CASE WHEN event_type='visit' THEN 1 ELSE 0 END) AS raw_visits,
    COUNT(DISTINCT unlock_session_id) AS unique_visitors,
    SUM(CASE WHEN event_type='visit' AND eligible_status='eligible' THEN 1 ELSE 0 END) AS eligible_clicks,
    SUM(CASE WHEN event_type='visit' AND eligible_status IN ('ineligible','rejected') THEN 1 ELSE 0 END) AS invalid_clicks,
    SUM(CASE WHEN event_type='unlock_completed' THEN 1 ELSE 0 END) AS unlock_completions,
    SUM(CASE WHEN event_type='redirect_success' THEN 1 ELSE 0 END) AS successful_redirects
    FROM click_events WHERE short_link_id=?`).get(linkId);
}

function analyticsOverview(db, ownerId = null, dateStart = null, dateEnd = null) {
  const params = [];
  let where = '1=1';
  if (ownerId) { where += ' AND ce.owner_id=?'; params.push(ownerId); }
  if (dateStart) { where += ' AND ce.created_at>=?'; params.push(dateStart); }
  if (dateEnd) { where += ' AND ce.created_at<?'; params.push(dateEnd); }
  const totals = db.prepare(`SELECT SUM(CASE WHEN ce.event_type='visit' THEN 1 ELSE 0 END) AS rawVisits, COUNT(DISTINCT CASE WHEN ce.event_type='visit' THEN ce.unlock_session_id END) AS uniqueVisitors,
    SUM(CASE WHEN ce.event_type='visit' AND ce.eligible_status='eligible' THEN 1 ELSE 0 END) AS eligibleClicks,
    SUM(CASE WHEN ce.event_type='visit' AND ce.eligible_status IN ('ineligible','rejected') THEN 1 ELSE 0 END) AS invalidTraffic,
    SUM(CASE WHEN ce.event_type='unlock_completed' THEN 1 ELSE 0 END) AS unlockCompletions,
    SUM(CASE WHEN ce.event_type='redirect_success' THEN 1 ELSE 0 END) AS redirects
    FROM click_events ce WHERE ${where}`).get(...params);
  const daily = db.prepare(`SELECT date(ce.created_at) AS day, SUM(CASE WHEN ce.event_type='visit' THEN 1 ELSE 0 END) AS visits,
    SUM(CASE WHEN ce.eligible_status='eligible' THEN 1 ELSE 0 END) AS eligible,
    SUM(CASE WHEN ce.event_type='unlock_completed' THEN 1 ELSE 0 END) AS unlocks
    FROM click_events ce WHERE ${where} GROUP BY date(ce.created_at) ORDER BY day`).all(...params);
  const devices = db.prepare(`SELECT ce.device_category AS category, COUNT(*) AS count FROM click_events ce
    WHERE ${where} AND ce.event_type='visit' GROUP BY ce.device_category ORDER BY count DESC`).all(...params);
  const refs = db.prepare(`SELECT COALESCE(NULLIF(ce.referrer_domain,''),'Direct') AS source, COUNT(*) AS count FROM click_events ce
    WHERE ${where} AND ce.event_type='visit' GROUP BY source ORDER BY count DESC LIMIT 10`).all(...params);
  const topLinks = db.prepare(`SELECT l.id,l.title,l.code,SUM(CASE WHEN ce.event_type='visit' THEN 1 ELSE 0 END) AS visits,
    SUM(CASE WHEN ce.event_type='visit' AND ce.eligible_status='eligible' THEN 1 ELSE 0 END) AS eligible
    FROM short_links l LEFT JOIN click_events ce ON ce.short_link_id=l.id
    ${ownerId ? 'WHERE l.owner_id=?' : ''} GROUP BY l.id ORDER BY visits DESC LIMIT 8`).all(...(ownerId ? [ownerId] : []));
  return { totals: Object.fromEntries(Object.entries(totals).map(([k, v]) => [k, Number(v ?? 0)])), daily, devices, referrers: refs, topLinks };
}

function dashboardPerformingCreations(db, ownerId) {
  const links = db.prepare(`SELECT l.id,l.code,l.title,l.campaign,l.description,l.status,l.created_at,
      COALESCE(SUM(CASE WHEN ce.event_type='visit' THEN 1 ELSE 0 END),0) AS visits
    FROM short_links l LEFT JOIN click_events ce ON ce.short_link_id=l.id
    WHERE l.owner_id=? AND l.status<>'deleted'
      AND lower(COALESCE(l.campaign,'')) NOT LIKE '%mylink post%'
      AND lower(COALESCE(l.description,'')) NOT LIKE '%shared post link%'
    GROUP BY l.id ORDER BY visits DESC,l.created_at DESC LIMIT 40`).all(ownerId).map(item => {
      const isFile = /telegram file link/i.test(String(item.campaign || '')) || /file shared through telegram storage/i.test(String(item.description || ''));
      return { id: item.id, type: isFile ? 'file' : 'link', title: item.title || item.code, path: `/s/${encodeURIComponent(item.code)}`, visits: Number(item.visits || 0), createdAt: item.created_at };
    });
  const posts = db.prepare(`SELECT id,slug,title,status,view_count AS visits,created_at FROM articles WHERE user_id=?
    ORDER BY view_count DESC,created_at DESC LIMIT 40`).all(ownerId).map(item => ({ id: item.id, type: 'post', title: item.title || item.slug, path: `/post/${encodeURIComponent(item.slug)}`, visits: Number(item.visits || 0), createdAt: item.created_at }));
  const trees = db.prepare(`SELECT id,slug,title,status,view_count AS visits,created_at FROM link_trees WHERE user_id=?
    ORDER BY view_count DESC,created_at DESC LIMIT 40`).all(ownerId).map(item => ({ id: item.id, type: 'tree', title: item.title || item.slug, path: `/tree/${encodeURIComponent(item.slug)}`, visits: Number(item.visits || 0), createdAt: item.created_at }));
  return [...links, ...posts, ...trees].sort((a,b) => b.visits - a.visits || String(b.createdAt).localeCompare(String(a.createdAt))).slice(0,8);
}

function dashboardCreationCounts(db, ownerId) {
  const fileExpression = "(lower(COALESCE(campaign,'')) LIKE '%telegram file link%' OR lower(COALESCE(description,'')) LIKE '%file shared through telegram storage%')";
  const postExpression = "(lower(COALESCE(campaign,'')) LIKE '%mylink post%' OR lower(COALESCE(description,'')) LIKE '%shared post link%')";
  const links = db.prepare(`SELECT COUNT(*) AS total,
      SUM(CASE WHEN ${fileExpression} THEN 1 ELSE 0 END) AS files,
      SUM(CASE WHEN NOT ${fileExpression} AND ${postExpression} THEN 1 ELSE 0 END) AS postLinks
    FROM short_links WHERE owner_id=? AND status<>'deleted'`).get(ownerId);
  return {
    links: Math.max(0, Number(links.total || 0) - Number(links.files || 0) - Number(links.postLinks || 0)),
    files: Number(links.files || 0),
    trees: Number(db.prepare("SELECT COUNT(*) AS n FROM link_trees WHERE user_id=? AND status<>'deleted'").get(ownerId).n || 0),
    posts: Number(db.prepare("SELECT COUNT(*) AS n FROM articles WHERE user_id=? AND status<>'deleted'").get(ownerId).n || 0),
  };
}

function pageDate(value) {
  if (!value) return null;
  const d = new Date(value);
  if (Number.isNaN(d.valueOf())) return null;
  return d.toISOString().slice(0, 10);
}

function renderAdScriptFrame(res, db, position, slot = null, contentType = '') {
  let availableScripts;
  if (['posts','trees','files'].includes(contentType)) {
    const rows=db.prepare('SELECT slot,script_html,enabled FROM content_ad_scripts WHERE content_type=? ORDER BY slot').all(contentType);
    availableScripts=['',''];
    for(const row of rows)if(row.enabled&&row.script_html)availableScripts[Number(row.slot)-1]=row.script_html;
  } else {
    const step = db.prepare('SELECT ad_script_one,ad_script_two,ad_script_one_enabled,ad_script_two_enabled FROM unlock_step_settings WHERE position=? AND enabled=1').get(position);
    if (!step) return error(res, 404, 'Ad scripts are turned off or not configured for this step.');
    availableScripts=[step.ad_script_one_enabled?step.ad_script_one:'',step.ad_script_two_enabled?step.ad_script_two:''];
  }
  const scripts = slot ? [availableScripts[Number(slot)-1]||''] : availableScripts;
  if (!scripts.some(Boolean)) return error(res, 404, 'Ad scripts are turned off or not configured for this section.');
  const slots = scripts.filter(Boolean).map((script,index)=>`<section class="ad-slot ad-slot-${slot||index+1}">${script}</section>`).join('');
  const html = `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><style>html,body{margin:0;min-height:100%;width:100%;background:transparent}body{box-sizing:border-box;display:flex;align-items:center;justify-content:center;padding:0;font-family:Arial,sans-serif}.ad-stack{display:flex;flex-direction:column;align-items:center;justify-content:center;gap:0;width:max-content;max-width:100%}.ad-slot{display:flex;align-items:center;justify-content:center;max-width:100%;min-width:0;overflow:visible}.ad-slot iframe{max-width:100%}</style></head><body><main class="ad-stack">${slots}</main><script>(function(){const send=()=>{const root=document.querySelector('.ad-stack');if(!root)return;const r=root.getBoundingClientRect();parent.postMessage({type:'step-ad-size',width:Math.ceil(Math.max(r.width,root.scrollWidth)),height:Math.ceil(Math.max(r.height,root.scrollHeight))},'*')};new ResizeObserver(send).observe(document.documentElement);addEventListener('load',send);setInterval(send,500);send()})()</script></body></html>`;
  res.removeHeader('X-Frame-Options');
  res.setHeader('X-Frame-Options','SAMEORIGIN');
  res.setHeader('Referrer-Policy','no-referrer');
  res.setHeader('Content-Security-Policy',"default-src https: http: data: blob:; script-src https: http: 'unsafe-inline' 'unsafe-eval'; style-src https: http: 'unsafe-inline'; img-src https: http: data: blob:; frame-src https: http: data: blob:; connect-src https: http: wss:; font-src https: http: data:; media-src https: http: data: blob:; object-src 'none'; base-uri 'none'; form-action https: http:; frame-ancestors 'self'; sandbox allow-scripts allow-forms allow-popups");
  res.writeHead(200,{'Content-Type':'text/html; charset=utf-8','Cache-Control':'no-store'});
  res.end(html);
}

function configuredBannerAds(db, adsEnabled, contentType = 'links') {
  if (!adsEnabled) return {position:1,slots:[]};
  if (['posts','trees','files'].includes(contentType)) {
    const rows=db.prepare('SELECT slot,script_html,enabled FROM content_ad_scripts WHERE content_type=? ORDER BY slot').all(contentType);
    return {position:1,slots:rows.filter(row=>row.enabled&&row.script_html).map(row=>Number(row.slot))};
  }
  const steps = db.prepare('SELECT position,ad_script_one,ad_script_two,ad_script_one_enabled,ad_script_two_enabled FROM unlock_step_settings WHERE enabled=1 ORDER BY display_order,position').all();
  for (const step of steps) {
    const slots=[...(step.ad_script_one_enabled&&step.ad_script_one?[1]:[]),...(step.ad_script_two_enabled&&step.ad_script_two?[2]:[])];
    if(slots.length)return {position:Number(step.position),slots};
  }
  return {position:1,slots:[]};
}

export function createApp(options = {}) {
  const config = options.config ?? loadConfig(options.env ?? {});
  const db = options.db ?? openDatabase(config.databasePath);
  const loginLimit = makeRateLimiter({ limit: 10, windowMs: 15 * 60 * 1000 });
  const generalLimit = makeRateLimiter({ limit: 60, windowMs: 60 * 1000 });
  const linkLimit = makeRateLimiter({ limit: 30, windowMs: 60 * 60 * 1000 });
  const unlockLimit = makeRateLimiter({ limit: 30, windowMs: 60 * 1000 });
  const articleUnlockLimit = makeRateLimiter({ limit: 8, windowMs: 10 * 60 * 1000 });
  const router = async (req, res) => {
    const url = new URL(req.url, config.appUrl);
    const path = decodeURIComponent(url.pathname);
    const method = req.method ?? 'GET';
    req.appUrl = config.appUrl;
    const corsAllowed = applyCors(req, res, config);
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    const connectOrigins = [...new Set([config.appUrl, ...(config.corsOrigins || [])].map(value => { try { return new URL(value).origin; } catch { return ''; } }).filter(Boolean))].join(' ');
    res.setHeader('Content-Security-Policy', `default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' https: data:; connect-src 'self' ${connectOrigins}; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'`);

    if (path.startsWith('/api/') && method === 'OPTIONS') {
      if (!corsAllowed) return error(res, 403, 'This origin is not allowed.');
      res.writeHead(204, { 'Cache-Control': 'no-store' });
      return res.end();
    }

    if (path.startsWith('/api/')) {
      if (!generalLimit(`${ipKey(req)}:${path.split('/').slice(0, 4).join('/')}`)) return error(res, 429, 'Too many requests. Please try again shortly.');
      try { return await api(req, res, url, config, db, { loginLimit, linkLimit, unlockLimit, articleUnlockLimit }); }
      catch (e) {
        if (res.headersSent) return res.end();
        if (e.status) return error(res, e.status, e.message);
        console.error('Request failed:', e?.message ?? 'unknown error');
        return error(res, 500, 'Something went wrong. Please try again.');
      }
    }

    if (method !== 'GET' && method !== 'HEAD') return error(res, 405, 'Method not allowed.');
    if (path.startsWith('/r/')) return redeemRedirect(req, res, path.slice(3), db);
    const adFrameMatch=path.match(/^\/ad-frame\/([1-5])(?:\/([12]))?\/?$/);
    if(adFrameMatch&&method==='GET')return renderAdScriptFrame(res,db,Number(adFrameMatch[1]),adFrameMatch[2]?Number(adFrameMatch[2]):null);
    const contentAdFrameMatch=path.match(/^\/content-ad-frame\/(posts|trees|files)\/([12])\/?$/);
    if(contentAdFrameMatch&&method==='GET')return renderAdScriptFrame(res,db,1,Number(contentAdFrameMatch[2]),contentAdFrameMatch[1]);
    const staticPath = path.startsWith('/assets/')||path.startsWith('/uploads/') ? path.slice(1) : path === '/favicon.ico' ? 'favicon.svg' : 'index.html';
    const absolute = resolve(PUBLIC, staticPath);
    if (!absolute.startsWith(`${PUBLIC}${sep}`) && absolute !== resolve(PUBLIC, 'index.html')) return error(res, 404, 'Not found.');
    if (!existsSync(absolute)) return error(res, 404, 'Not found.');
    try {
      const data = await readFile(absolute);
      res.writeHead(200, { 'Content-Type': MIME[extname(absolute)] ?? 'application/octet-stream', 'Cache-Control': absolute.endsWith('index.html') ? 'no-cache' : 'public, max-age=3600' });
      return res.end(data);
    } catch { return error(res, 404, 'Not found.'); }
  };
  return { handler: router, db, config };
}

function redeemRedirect(req, res, token, db) {
  if (!token || token.length > 160) { res.writeHead(404); return res.end('Not found'); }
  const row = db.prepare(`SELECT us.id,us.status,l.destination_url,l.status AS link_status,l.expires_at
    FROM unlock_sessions us JOIN short_links l ON l.id=us.short_link_id WHERE us.redirect_token_hash=?`).get(hashToken(token));
  if (!row || row.status !== 'completed' || row.link_status !== 'active' || row.expires_at && Date.parse(row.expires_at) <= Date.now()) {
    res.writeHead(410, { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' });
    return res.end('This unlock link has expired. Start again from the short URL.');
  }
  const update = db.prepare(`UPDATE unlock_sessions SET status='redeemed',redirect_token_hash=NULL,redeemed_at=datetime('now')
    WHERE id=? AND status='completed' AND redirect_token_hash=?`).run(row.id, hashToken(token));
  if (!update.changes) { res.writeHead(410); return res.end('This redirect has already been used.'); }
  db.prepare(`INSERT INTO click_events(id,short_link_id,owner_id,unlock_session_id,event_type,device_category,referrer_domain,is_bot,eligible_status)
    SELECT ?,v.short_link_id,v.owner_id,?, 'redirect_success',v.device_category,v.referrer_domain,v.is_bot,v.eligible_status
    FROM click_events v WHERE v.unlock_session_id=? AND v.event_type='visit'`).run(randomUUID(), row.id, row.id);
  res.writeHead(302, { Location: row.destination_url, 'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer' });
  return res.end();
}

function normalizeTreeInput(body){
  const slug=String(body.slug||'').trim().toLowerCase();const title=cleanText(body.title,80);const bio=cleanText(body.bio,300);const avatarUrl=String(body.avatarUrl||'').trim();
  if(!/^[a-z0-9][a-z0-9-]{1,38}[a-z0-9]$/.test(slug))return{error:'Use a 3–40 character slug with lowercase letters, numbers, and hyphens.'};
  if(!title)return{error:'Enter a title for your link tree.'};
  const avatar=avatarUrl?validateDestination(avatarUrl):'';if(avatarUrl&&!avatar)return{error:'Enter a valid HTTPS or HTTP photo URL.'};
  const socialInput=body.socials&&typeof body.socials==='object'&&!Array.isArray(body.socials)?body.socials:{};const socials={};
  for(const key of ['instagram','youtube','tiktok','facebook','x','whatsapp','telegram','website']){const value=String(socialInput[key]||'').trim();const safe=value?validateDestination(value):'';if(value&&!safe)return{error:`Enter a valid URL for ${key}.`};socials[key]=safe;}
  const rowsInput=Array.isArray(body.rows)?body.rows:[];if(rowsInput.length>24)return{error:'A link tree can have up to 24 rows.'};const rows=[];
  for(const row of rowsInput){const type=row?.type==='photo'?'photo':'link';const rowTitle=cleanText(row?.title,80);const target=validateDestination(row?.url);const imageUrl=String(row?.imageUrl||'').trim();const safeImage=imageUrl?validateDestination(imageUrl):'';const actions=['arrow','watch','play','signup','learn-more','shop-now','register','apply-now','custom'];const action=actions.includes(row?.action)?row.action:'arrow';const customAction=cleanText(row?.customAction,24);const columnInput=Number(row?.columns);const columns=Number.isFinite(columnInput)?Math.round(Math.min(3,Math.max(1,columnInput))):1;if(!rowTitle||!target)return{error:'Each row needs a title and a valid destination URL.'};if(type==='photo'&&!imageUrl)return{error:'Add a photo URL for each photo row.'};if(imageUrl&&!safeImage)return{error:'Enter a valid photo URL for each photo row.'};rows.push({type,title:rowTitle,url:target,imageUrl:safeImage,action,customAction,columns});}
  const themes=['glass','liquid','white','dark','neon','forest','ocean','sunset','rose','aurora','custom'];const themeInput=body.theme&&typeof body.theme==='object'?body.theme:{};const themeName=themes.includes(themeInput.name)?themeInput.name:'glass';const validColor=value=>/^#[0-9a-fA-F]{6}$/.test(String(value||''));const rawBgImage=String(themeInput.backgroundImage||'').trim();const backgroundImage=rawBgImage?validateDestination(rawBgImage):'';if(rawBgImage&&!backgroundImage)return{error:'Enter a valid HTTP or HTTPS background image URL.'};const bounded=(name,fallback,min,max)=>{const value=Number(themeInput[name]);return Number.isFinite(value)?Math.round(Math.min(max,Math.max(min,value))):fallback;};const theme={name:themeName,background:validColor(themeInput.background)?themeInput.background:'#edf3f0',surface:validColor(themeInput.surface)?themeInput.surface:'#ffffff',accent:validColor(themeInput.accent)?themeInput.accent:'#167347',text:validColor(themeInput.text)?themeInput.text:'#17251e',backgroundImage,backgroundOpacity:bounded('backgroundOpacity',100,0,100),surfaceOpacity:bounded('surfaceOpacity',78,0,100),borderColor:validColor(themeInput.borderColor)?themeInput.borderColor:'#ffffff',borderOpacity:bounded('borderOpacity',72,0,100),borderWidth:bounded('borderWidth',1,0,12),radius:bounded('radius',29,0,64),blur:bounded('blur',22,0,40),shadowColor:validColor(themeInput.shadowColor)?themeInput.shadowColor:'#12231a',shadowOpacity:bounded('shadowOpacity',12,0,100),shadowX:bounded('shadowX',0,-60,60),shadowY:bounded('shadowY',20,-60,60),shadowBlur:bounded('shadowBlur',45,0,100),shadowSpread:bounded('shadowSpread',0,-30,40),backgroundImageOpacity:bounded('backgroundImageOpacity',45,0,100),backgroundPositionX:bounded('backgroundPositionX',50,0,100),backgroundPositionY:bounded('backgroundPositionY',50,0,100),outerPadding:bounded('outerPadding',24,0,64),innerPadding:bounded('innerPadding',30,0,60),containerTopPadding:bounded('containerTopPadding',30,0,120),avatarBorderColor:validColor(themeInput.avatarBorderColor)?themeInput.avatarBorderColor:'#ffffff',avatarBorderOpacity:bounded('avatarBorderOpacity',85,0,100),avatarBorderWidth:bounded('avatarBorderWidth',2,0,12),avatarWidth:bounded('avatarWidth',94,48,180),avatarHeight:bounded('avatarHeight',94,48,180),avatarRadius:bounded('avatarRadius',50,0,50),rowColumns:bounded('rowColumns',1,1,3),buttonPadding:bounded('buttonPadding',14,0,40),buttonHeight:bounded('buttonHeight',52,36,140),buttonGap:bounded('buttonGap',11,0,36),buttonRadius:bounded('buttonRadius',15,0,32),ctaBackgroundType:['transparent','glass','custom'].includes(themeInput.ctaBackgroundType)?themeInput.ctaBackgroundType:'glass',ctaBackgroundColor:validColor(themeInput.ctaBackgroundColor)?themeInput.ctaBackgroundColor:'#167347',ctaTextColor:validColor(themeInput.ctaTextColor)?themeInput.ctaTextColor:'#ffffff',ctaRadius:bounded('ctaRadius',18,0,32),ctaHeight:bounded('ctaHeight',32,20,64),showVisits:body.showVisits!==false};
  const passwordEnabled=body.passwordEnabled===true||body.passwordEnabled==='on';const password=String(body.password||'');if(passwordEnabled&&password&&!/^\d{6}$/.test(password))return{error:'Tree passwords must contain exactly 6 digits.'};
  return{value:{slug,title,bio,avatarUrl:avatar,socials,rows,theme,adsEnabled:body.adsEnabled===true||body.adsEnabled==='on'},passwordEnabled,password};
}

async function api(req, res, url, config, db, limits) {
  const path = decodeURIComponent(url.pathname.replace(/^\/api\/v1/, '') || '/');
  const method = req.method ?? 'GET';
  const cookies = parseCookies(req.headers.cookie);
  const user = activeUser(db, req, config);
  const body = ['POST', 'PATCH', 'PUT', 'DELETE'].includes(method) ? await readBody(req,['/profile/trees/upload','/profile/avatar'].includes(path)?3*1024*1024:1024*1024) : {};
  const csrf = (u = user) => requireCsrf(req, u, res);
  const auth = () => requireAuth(db, req, res, config);
  const admin = () => requireAdmin(db, req, res, config);
  const id = () => randomUUID();

  if (method === 'GET' && path === '/health') return json(res, 200, { ok: true, service: 'verdant-links' });
  if (method === 'GET' && path === '/public/settings') return json(res, 200, {
    siteName: getSetting(db, 'site_name', 'Verdant Links'),
    unlockEnabled: getSetting(db, 'unlock_enabled', '1') === '1',
    referralsEnabled: getSetting(db, 'referrals_enabled', '0') === '1',
    currency: getSetting(db, 'currency', config.currency),
    minimumWithdrawalPaise: Number(getSetting(db, 'minimum_withdrawal_paise', String(config.minWithdrawalPaise))),
  });
  if (method === 'GET' && path === '/public/blogs') {
    const items = db.prepare(`SELECT id,slug,title,excerpt,cover_image,status,view_count,created_at,updated_at,published_at
      FROM blog_posts WHERE status='published' ORDER BY COALESCE(published_at,created_at) DESC LIMIT 100`).all();
    return json(res, 200, { items });
  }
  const publicBlogMatch = path.match(/^\/public\/blogs\/([a-z0-9-]{3,80})$/);
  if (method === 'GET' && publicBlogMatch) {
    const blog = db.prepare(`SELECT id,slug,title,excerpt,cover_image,content_html,view_count,created_at,updated_at,published_at
      FROM blog_posts WHERE slug=? AND status='published'`).get(publicBlogMatch[1]);
    if (!blog) return error(res, 404, 'This blog post could not be found.');
    db.prepare('UPDATE blog_posts SET view_count=view_count+1 WHERE id=?').run(blog.id);
    return json(res, 200, { blog: { ...blog, view_count: Number(blog.view_count || 0) + 1 } });
  }
  const creationViewMatch=path.match(/^\/public\/(posts|trees)\/([a-z0-9-]{3,80})\/view$/);
  if(creationViewMatch&&method==='POST'){const type=creationViewMatch[1]==='posts'?'post':'tree';const slug=creationViewMatch[2];const entity=type==='post'?db.prepare("SELECT id FROM articles WHERE slug=? AND status='published'").get(slug):db.prepare("SELECT id FROM link_trees WHERE slug=? AND status='active'").get(slug);if(!entity)return error(res,404,'This page could not be found.');const viewId=String(body.viewId||'');const seconds=Number(body.activeSeconds);if(!/^[a-f0-9-]{30,40}$/i.test(viewId)||!Number.isInteger(seconds)||seconds<0||seconds>14400)return error(res,400,'Invalid view tracking data.');const ua=String(req.headers['user-agent']||'');const browser=/Edg\//.test(ua)?'Edge':/Firefox\//.test(ua)?'Firefox':/Chrome\//.test(ua)?'Chrome':/Safari\//.test(ua)?'Safari':'Other';const country=countryCodeFromRequest(req);db.prepare(`INSERT INTO creation_view_events(entity_type,entity_id,view_id,active_seconds,country,device,browser) VALUES(?,?,?,?,?,?,?) ON CONFLICT(entity_type,entity_id,view_id) DO UPDATE SET active_seconds=MAX(active_seconds,excluded.active_seconds)`).run(type,entity.id,viewId,seconds,country,deviceCategory(ua),browser);return json(res,200,{ok:true});}
  const creationStatsMatch=path.match(/^\/profile\/creations\/(posts|trees)\/([^/]+)\/stats$/);
  if(creationStatsMatch&&method==='GET'){const me=auth();if(!me)return;const type=creationStatsMatch[1]==='posts'?'post':'tree';const entity=type==='post'?db.prepare('SELECT id,title,slug,view_count FROM articles WHERE id=? AND user_id=?').get(creationStatsMatch[2],me.id):db.prepare('SELECT id,title,slug,view_count FROM link_trees WHERE id=? AND user_id=?').get(creationStatsMatch[2],me.id);if(!entity)return error(res,404,'Creation not found.');const events=db.prepare('SELECT COUNT(*) AS tracked_views,COALESCE(ROUND(AVG(active_seconds)),0) AS avg_seconds FROM creation_view_events WHERE entity_type=? AND entity_id=?').get(type,entity.id);const breakdown=field=>db.prepare(`SELECT ${field} AS label,COUNT(*) AS count FROM creation_view_events WHERE entity_type=? AND entity_id=? GROUP BY ${field} ORDER BY count DESC LIMIT 8`).all(type,entity.id);let earnings=0,clicks=0;if(type==='post'){const destination=`${config.appUrl}/post/${entity.slug}`;earnings=db.prepare("SELECT COALESCE(SUM(el.amount_paise),0) AS amount FROM earning_ledger el JOIN short_links l ON l.id=el.link_id WHERE l.owner_id=? AND l.destination_url=? AND el.status IN ('pending','estimated','approved','paid')").get(me.id,destination).amount;clicks=db.prepare("SELECT COALESCE(SUM(visit_count),0) AS n FROM short_links WHERE owner_id=? AND destination_url=?").get(me.id,destination).n;}return json(res,200,{entity,stats:{views:Number(entity.view_count||0),trackedViews:Number(events.tracked_views||0),averageStaySeconds:Number(events.avg_seconds||0),earnings:Number(earnings||0),shortLinkVisits:Number(clicks||0)},devices:breakdown('device'),countries:breakdown('country'),browsers:breakdown('browser')});}
  const publicArticleMatch=path.match(/^\/public\/posts\/([a-z0-9-]{3,80})$/);
  const publicArticleUnlockMatch=path.match(/^\/public\/posts\/([a-z0-9-]{3,80})\/unlock$/);
  if(method==='POST'&&publicArticleUnlockMatch){
    if(!isSameOrigin(req,config.appUrl))return error(res,403,'Cross-origin requests are not allowed.');
    const slug=publicArticleUnlockMatch[1];
    if(!limits.articleUnlockLimit(`post-unlock:${ipKey(req)}:${slug}`))return error(res,429,'Too many password attempts. Please wait before trying again.');
    const article=db.prepare("SELECT a.id,a.slug,a.title,a.excerpt,a.cover_image,a.content_html,a.password_hash,a.ads_enabled,a.view_count,a.created_at,u.display_name AS author_display_name,u.avatar_url AS author_avatar_url,c.social_links AS author_social_links FROM articles a JOIN users u ON u.id=a.user_id LEFT JOIN user_profile_channels c ON c.user_id=u.id WHERE a.slug=? AND a.status='published'").get(slug);
    if(!article)return error(res,404,'This article could not be found.');
    if(!article.password_hash)return error(res,409,'This post does not require a password. Reload the page to continue.');
    const password=String(body.password||'');
    if(!/^\d{6}$/.test(password)||!await verifyPassword(password,article.password_hash))return error(res,401,'That 6-digit password is incorrect. Please try again.');
    db.prepare('UPDATE articles SET view_count=view_count+1 WHERE id=?').run(article.id);
    const adsEnabled=Boolean(article.ads_enabled);const adConfig=configuredBannerAds(db,adsEnabled,'posts');return json(res,200,{article:{id:article.id,slug:article.slug,title:article.title,excerpt:article.excerpt,cover_image:article.cover_image,content_html:article.content_html,adsEnabled,adScriptType:'posts',adScriptStep:adConfig.position,adScriptSlots:adConfig.slots,hasPassword:true,viewCount:Number(article.view_count)+1,created_at:article.created_at,author:publicArticleAuthor(article)}});
  }
  if(method==='GET'&&publicArticleMatch){
    const article=db.prepare("SELECT a.id,a.slug,a.title,a.excerpt,a.cover_image,a.content_html,a.password_hash,a.ads_enabled,a.view_count,a.created_at,u.display_name AS author_display_name,u.avatar_url AS author_avatar_url,c.social_links AS author_social_links FROM articles a JOIN users u ON u.id=a.user_id LEFT JOIN user_profile_channels c ON c.user_id=u.id WHERE a.slug=? AND a.status='published'").get(publicArticleMatch[1]);
    if(!article)return error(res,404,'This article could not be found.');
    if(article.password_hash)return json(res,200,{article:{slug:article.slug,hasPassword:true}});
    db.prepare('UPDATE articles SET view_count=view_count+1 WHERE id=?').run(article.id);
    const adsEnabled=Boolean(article.ads_enabled);const adConfig=configuredBannerAds(db,adsEnabled,'posts');return json(res,200,{article:{id:article.id,slug:article.slug,title:article.title,excerpt:article.excerpt,cover_image:article.cover_image,content_html:article.content_html,adsEnabled,adScriptType:'posts',adScriptStep:adConfig.position,adScriptSlots:adConfig.slots,hasPassword:false,viewCount:Number(article.view_count)+1,created_at:article.created_at,author:publicArticleAuthor(article)}});
  }
  const publicTreeMatch=path.match(/^\/public\/trees\/([a-z0-9-]{3,40})$/);
  const publicTreeUnlockMatch=path.match(/^\/public\/trees\/([a-z0-9-]{3,40})\/unlock$/);
  if(method==='POST'&&publicTreeUnlockMatch){
    if(!isSameOrigin(req,config.appUrl))return error(res,403,'Cross-origin requests are not allowed.');
    const slug=publicTreeUnlockMatch[1];if(!limits.articleUnlockLimit(`tree-unlock:${ipKey(req)}:${slug}`))return error(res,429,'Too many password attempts. Please wait before trying again.');
    const tree=db.prepare(`SELECT t.*,u.display_name FROM link_trees t JOIN users u ON u.id=t.user_id WHERE t.slug=? AND t.status='active'`).get(slug);
    if(!tree)return error(res,404,'This link tree could not be found.');if(!tree.password_hash)return error(res,409,'This tree does not require a password. Reload the page to continue.');
    const password=String(body.password||'');if(!/^\d{6}$/.test(password)||!await verifyPassword(password,tree.password_hash))return error(res,401,'That 6-digit password is incorrect. Please try again.');
    db.prepare('UPDATE link_trees SET view_count=view_count+1 WHERE id=?').run(tree.id);let socials={},rows=[],theme={};try{socials=JSON.parse(tree.socials_json);}catch{}try{rows=JSON.parse(tree.rows_json);}catch{}try{theme=JSON.parse(tree.theme_json);}catch{}
    const adsEnabled=Boolean(tree.ads_enabled);const adConfig=configuredBannerAds(db,adsEnabled,'trees');return json(res,200,{tree:{id:tree.id,slug:tree.slug,title:tree.title,bio:tree.bio,avatarUrl:tree.avatar_url,socials,rows,theme,adsEnabled,adScriptType:'trees',adScriptStep:adConfig.position,adScriptSlots:adConfig.slots,treeBackgroundDirectLink:getSetting(db,'tree_background_direct_link',''),hasPassword:true,viewCount:Number(tree.view_count)+1,createdAt:tree.created_at,updatedAt:tree.updated_at,creator:tree.display_name}});
  }
  if(method==='GET'&&publicTreeMatch){
    const tree=db.prepare(`SELECT t.*,u.display_name FROM link_trees t JOIN users u ON u.id=t.user_id WHERE t.slug=? AND t.status='active'`).get(publicTreeMatch[1]);
    if(!tree)return error(res,404,'This link tree could not be found.');
    if(tree.password_hash)return json(res,200,{tree:{slug:tree.slug,title:tree.title,treeBackgroundDirectLink:getSetting(db,'tree_background_direct_link',''),hasPassword:true}});
    db.prepare('UPDATE link_trees SET view_count=view_count+1 WHERE id=?').run(tree.id);
    let socials={},rows=[],theme={};try{socials=JSON.parse(tree.socials_json);}catch{}try{rows=JSON.parse(tree.rows_json);}catch{}try{theme=JSON.parse(tree.theme_json);}catch{}
    const adsEnabled=Boolean(tree.ads_enabled);const adConfig=configuredBannerAds(db,adsEnabled,'trees');return json(res,200,{tree:{id:tree.id,slug:tree.slug,title:tree.title,bio:tree.bio,avatarUrl:tree.avatar_url,socials,rows,theme,adsEnabled,adScriptType:'trees',adScriptStep:adConfig.position,adScriptSlots:adConfig.slots,treeBackgroundDirectLink:getSetting(db,'tree_background_direct_link',''),hasPassword:false,viewCount:Number(tree.view_count)+1,createdAt:tree.created_at,updatedAt:tree.updated_at,creator:tree.display_name}});
  }

  if (method === 'POST' && path === '/auth/register') {
    if (!isSameOrigin(req, config.appUrl)) return error(res, 403, 'Cross-origin requests are not allowed.');
    if (!limits.loginLimit(`register:${ipKey(req)}`)) return error(res, 429, 'Too many registration attempts. Try again later.');
    const email = normalizeEmail(body.email);
    const name = cleanText(body.displayName, 80);
    if (!validateEmail(email) || !name) return error(res, 400, 'Enter a valid email and display name.');
    if (!validatePassword(body.password) || passwordLooksCompromised(body.password)) return error(res, 400, 'Use a password with at least 10 characters, an uppercase letter, a lowercase letter, and a number.');
    if (db.prepare('SELECT id FROM users WHERE email=?').get(email)) return error(res, 409, 'An account with this email already exists.');
    const userId = id();
    const passwordHash = await hashPassword(body.password);
    const publicId = createPublicUserId(db);
    const refCode = randomToken(7).slice(0, 10).toUpperCase();
    const referrer = getSetting(db, 'referrals_enabled', '0') === '1' && body.referralCode ? db.prepare('SELECT id FROM users WHERE referral_code=? AND status=\'active\'').get(cleanText(body.referralCode, 32)) : null;
    db.prepare(`INSERT INTO users(id,email,password_hash,display_name,public_id,status,referral_code,referred_by)
      VALUES (?,?,?,?,?,?,?,?)`).run(userId, email, passwordHash, name, publicId, 'pending_verification', refCode, referrer?.id ?? null);
    const token = randomToken();
    db.prepare(`INSERT INTO auth_tokens(token_hash,user_id,purpose,expires_at)
      VALUES (?,?, 'verify_email', datetime('now','+24 hours'))`).run(hashToken(token), userId);
    const verificationUrl = `${config.appUrl}/verify?token=${encodeURIComponent(token)}`;
    if (config.smtpUrl) {
      try { await sendMail(config,email,'Verify your Verdant Links account',`Open this link to verify your email address:\n\n${verificationUrl}\n\nThis link expires in 24 hours.`); }
      catch (e) { db.prepare('DELETE FROM users WHERE id=?').run(userId); console.error('Verification email delivery failed:',e.message); return error(res,503,'Could not send a verification email. Please try again later.'); }
    } else if (config.nodeEnv !== 'production') console.info(`Development email verification link: ${verificationUrl}`);
    if (referrer) db.prepare('INSERT OR IGNORE INTO referral_events(id,referrer_id,referred_user_id) VALUES (?,?,?)').run(id(), referrer.id, userId);
    return json(res, 201, { message: 'Account created. Check your email for a verification link before signing in.' });
  }

  if (method === 'POST' && path === '/auth/verify-email') {
    if (!isSameOrigin(req, config.appUrl)) return error(res, 403, 'Cross-origin requests are not allowed.');
    const token = cleanText(body.token, 200);
    const record = db.prepare(`SELECT t.*,u.status FROM auth_tokens t JOIN users u ON u.id=t.user_id
      WHERE t.token_hash=? AND t.purpose='verify_email' AND t.consumed_at IS NULL AND t.expires_at>datetime('now')`).get(hashToken(token));
    if (!record) return error(res, 400, 'This verification link is invalid or has expired.');
    db.exec('BEGIN IMMEDIATE');
    try {
      db.prepare("UPDATE auth_tokens SET consumed_at=datetime('now') WHERE token_hash=?").run(hashToken(token));
      db.prepare("UPDATE users SET status='active',verified_at=datetime('now') WHERE id=? AND status='pending_verification'").run(record.user_id);
      db.prepare("UPDATE referral_events SET status='eligible' WHERE referred_user_id=? AND status='pending'").run(record.user_id);
      notify(db, record.user_id, 'Account verified', 'Your email is verified and your account is active.');
      db.exec('COMMIT');
    } catch (e) { db.exec('ROLLBACK'); throw e; }
    return json(res, 200, { message: 'Email verified. You can now sign in.' });
  }

  if (method === 'POST' && path === '/auth/login') {
    if (!isSameOrigin(req, config.appUrl)) return error(res, 403, 'Cross-origin requests are not allowed.');
    if (!limits.loginLimit(`login:${ipKey(req)}:${normalizeEmail(body.email)}`)) return error(res, 429, 'Too many sign-in attempts. Try again later.');
    const account = db.prepare('SELECT * FROM users WHERE email=?').get(normalizeEmail(body.email));
    const ok = account && await verifyPassword(String(body.password ?? ''), account.password_hash);
    if (!ok) return error(res, 401, 'Email or password is incorrect.');
    if (account.status !== 'active') return error(res, 403, account.status === 'pending_verification' ? 'Verify your email before signing in.' : `This account is ${account.status.replaceAll('_', ' ')}.`);
    const session = createSession(db, account.id, config.sessionTtlHours);
    if(['admin','super_admin'].includes(account.role))audit(db,account.id,'admin_login','admin_session',account.id,'Administrator signed in',{email:account.email,role:account.role});
    setCookies(res, [`sid=${htmlSafeCookie(session.token)}; ${cookieOptions({ secure: config.nodeEnv === 'production' })}; Expires=${new Date(session.expires).toUTCString()}`, `csrf=${htmlSafeCookie(session.csrf)}; ${csrfCookieOptions({ secure: config.nodeEnv === 'production' })}; Expires=${new Date(session.expires).toUTCString()}`]);
    return json(res, 200, { user: userPublic(account), csrfToken: session.csrf });
  }

  if (method === 'POST' && path === '/auth/logout') {
    if (user && !csrf()) return;
    if(user&&['admin','super_admin'].includes(user.role))audit(db,user.id,'admin_logout','admin_session',user.id,'Administrator signed out',{email:user.email,role:user.role});
    if (cookies.sid) db.prepare('DELETE FROM user_sessions WHERE token_hash=?').run(hashToken(cookies.sid));
    setCookies(res, [`sid=; ${cookieOptions({ secure: config.nodeEnv === 'production' })}; Max-Age=0`, `csrf=; ${csrfCookieOptions({ secure: config.nodeEnv === 'production' })}; Max-Age=0`]);
    return json(res, 200, { ok: true });
  }

  if (method === 'GET' && path === '/auth/me') {
    if (!user) return json(res, 200, { user: null });
    return json(res, 200, { user: userPublic(user), csrfToken: user.csrf });
  }

  if (method === 'POST' && path === '/auth/forgot-password') {
    if (!isSameOrigin(req, config.appUrl)) return error(res, 403, 'Cross-origin requests are not allowed.');
    if (!limits.loginLimit(`forgot:${ipKey(req)}`)) return error(res, 429, 'Too many requests. Try again later.');
    const account = db.prepare("SELECT id FROM users WHERE email=? AND status='active'").get(normalizeEmail(body.email));
    if (account) {
      const token = randomToken();
      db.prepare(`INSERT INTO auth_tokens(token_hash,user_id,purpose,expires_at) VALUES (?,?, 'reset_password',datetime('now','+1 hour'))`).run(hashToken(token), account.id);
      const resetUrl=`${config.appUrl}/reset?token=${encodeURIComponent(token)}`;
      if(config.smtpUrl){
        try{await sendMail(config,normalizeEmail(body.email),'Reset your Verdant Links password',`Open this link to choose a new password:\n\n${resetUrl}\n\nThis link expires in one hour. If you did not request this, ignore the message.`);}
        catch(e){db.prepare('DELETE FROM auth_tokens WHERE token_hash=?').run(hashToken(token));console.error('Password reset email delivery failed:',e.message);}
      } else if (config.nodeEnv !== 'production') console.info(`Development password reset link: ${resetUrl}`);
    }
    return json(res, 200, { message: 'If an active account exists for that email, password reset instructions have been sent.' });
  }

  if (method === 'POST' && path === '/auth/reset-password') {
    if (!isSameOrigin(req, config.appUrl)) return error(res, 403, 'Cross-origin requests are not allowed.');
    if (!validatePassword(body.password) || passwordLooksCompromised(body.password)) return error(res, 400, 'Use a stronger password with at least 10 characters, mixed case, and a number.');
    const token = cleanText(body.token, 200);
    const record = db.prepare(`SELECT user_id FROM auth_tokens WHERE token_hash=? AND purpose='reset_password'
      AND consumed_at IS NULL AND expires_at>datetime('now')`).get(hashToken(token));
    if (!record) return error(res, 400, 'This reset link is invalid or has expired.');
    db.exec('BEGIN IMMEDIATE');
    try {
      db.prepare('UPDATE users SET password_hash=? WHERE id=?').run(await hashPassword(body.password), record.user_id);
      db.prepare("UPDATE auth_tokens SET consumed_at=datetime('now') WHERE user_id=? AND purpose='reset_password' AND consumed_at IS NULL").run(record.user_id);
      db.prepare('DELETE FROM user_sessions WHERE user_id=?').run(record.user_id);
      db.exec('COMMIT');
    } catch (e) { db.exec('ROLLBACK'); throw e; }
    return json(res, 200, { message: 'Password updated. Sign in with your new password.' });
  }

  if (method === 'POST' && path === '/auth/change-password') {
    const me = auth(); if (!me || !csrf(me)) return;
    if (!validatePassword(body.newPassword) || passwordLooksCompromised(body.newPassword)) return error(res, 400, 'Use a stronger password with at least 10 characters, mixed case, and a number.');
    if (!await verifyPassword(String(body.currentPassword ?? ''), me.password_hash)) return error(res, 400, 'Current password is incorrect.');
    db.prepare('UPDATE users SET password_hash=? WHERE id=?').run(await hashPassword(body.newPassword), me.id);
    db.prepare('DELETE FROM user_sessions WHERE user_id=? AND token_hash<>?').run(me.id, hashToken(cookies.sid));
    audit(db, me.id, 'password_changed', 'user', me.id);
    return json(res, 200, { message: 'Password updated. Other sessions have been signed out.' });
  }

  if (path === '/links' && method === 'POST') {
    const me = auth(); if (!me || !csrf(me)) return;
    if (!limits.linkLimit(`create-link:${me.id}`)) return error(res, 429, 'Link creation limit reached. Try again later.');
    if (me.role === 'user' && getSetting(db, 'unlock_enabled', '1') !== '1') return error(res, 403, 'Short-link creation is temporarily unavailable.');
    const destination = validateDestination(body.destinationUrl);
    if (!destination) return error(res, 400, 'Enter a valid HTTP or HTTPS destination URL.');
    const suppliedAlias = safeAlias(body.alias);
    if (suppliedAlias === undefined) return error(res, 400, 'Aliases must be 3–32 characters using letters, numbers, hyphens, or underscores.');
    const code = suppliedAlias ?? randomToken(7).replace(/[-_]/g, '').slice(0, 9);
    if (RESERVED.has(code.toLowerCase())) return error(res, 400, 'That alias is reserved.');
    if (db.prepare('SELECT id FROM short_links WHERE code=?').get(code)) return error(res, 409, 'That alias is already in use.');
    const expiration = body.expiresAt ? new Date(body.expiresAt) : null;
    if (expiration && (!Number.isFinite(expiration.valueOf()) || expiration <= new Date())) return error(res, 400, 'Expiration must be a future date.');
    const maxVisits = body.maxVisits ? Number(body.maxVisits) : null;
    if (maxVisits !== null && (!Number.isInteger(maxVisits) || maxVisits < 1 || maxVisits > 10000000)) return error(res, 400, 'Maximum visits must be a positive whole number.');
    const perIpLimit = body.perIpLimit ? Number(body.perIpLimit) : null;
    if (perIpLimit !== null && (!Number.isInteger(perIpLimit) || perIpLimit < 1 || perIpLimit > 10000000)) return error(res, 400, 'Per-IP view limit must be a positive whole number.');
    const linkPassword = String(body.password ?? '');
    if (linkPassword && (linkPassword.length !== 6)) return error(res, 400, 'Link passwords must be exactly 6 characters.');
    const passwordHash = linkPassword ? await hashPassword(linkPassword) : null;
    const linkId = id();
    db.prepare(`INSERT INTO short_links(id,owner_id,code,title,destination_url,campaign,description,password_hash,expires_at,max_visits,per_ip_limit)
      VALUES (?,?,?,?,?,?,?,?,?,?,?)`).run(linkId, me.id, code, cleanText(body.title, 120), destination, cleanText(body.campaign, 100), cleanText(body.description, 500), passwordHash, expiration?.toISOString() ?? null, maxVisits, perIpLimit);
    notify(db, me.id, 'Short link created', `Your short link /s/${code} is ready.`);
    audit(db, me.id, 'link_created', 'short_link', linkId);
    const created = db.prepare('SELECT id,owner_id,code,title,destination_url,campaign,description,expires_at,max_visits,visit_count,status,created_at,updated_at FROM short_links WHERE id=?').get(linkId);
    return json(res, 201, { link: { ...created, shortUrl: `${config.appUrl}/s/${code}`, stats: linkStats(db, linkId) } });
  }

  if (path === '/links' && method === 'GET') {
    const me = auth(); if (!me) return;
    const limit = Math.min(100, Math.max(1, Number(url.searchParams.get('limit') ?? 25)));
    const offset = Math.max(0, Number(url.searchParams.get('offset') ?? 0));
    const search = cleanText(url.searchParams.get('q'), 120);
    const rows = db.prepare(`SELECT l.id,l.owner_id,l.code,l.title,l.destination_url,l.campaign,l.description,l.expires_at,l.max_visits,l.visit_count,l.status,l.created_at,l.updated_at,
      (l.password_hash IS NOT NULL) AS has_password,
      SUM(CASE WHEN ce.event_type='visit' THEN 1 ELSE 0 END) AS raw_visits,
      COUNT(DISTINCT ce.unlock_session_id) AS unique_visitors,
      SUM(CASE WHEN ce.eligible_status='eligible' THEN 1 ELSE 0 END) AS eligible_clicks,
      COALESCE((SELECT SUM(el.amount_paise) FROM earning_ledger el WHERE el.link_id=l.id AND el.status IN ('pending','estimated','approved','paid')),0) AS earnings_paise
      FROM short_links l LEFT JOIN click_events ce ON ce.short_link_id=l.id
      WHERE l.owner_id=? AND l.status<>'deleted' AND (l.code LIKE ? OR l.title LIKE ? OR l.destination_url LIKE ?)
      GROUP BY l.id ORDER BY l.created_at DESC LIMIT ? OFFSET ?`).all(me.id, `%${search}%`, `%${search}%`, `%${search}%`, limit, offset);
    const total = db.prepare("SELECT COUNT(*) AS n FROM short_links WHERE owner_id=? AND status<>'deleted' AND (code LIKE ? OR title LIKE ? OR destination_url LIKE ?)").get(me.id, `%${search}%`, `%${search}%`, `%${search}%`).n;
    return json(res, 200, { items: rows.map(({password_hash,...row}) => ({ ...row, shortUrl: `${config.appUrl}/s/${row.code}` })), total, limit, offset });
  }

  const linkMatch = path.match(/^\/links\/([^/]+)$/);
  if (linkMatch && method === 'GET') {
    const me = auth(); if (!me) return;
    const row = db.prepare('SELECT id,owner_id,code,title,destination_url,campaign,description,expires_at,max_visits,visit_count,status,created_at,updated_at,(password_hash IS NOT NULL) AS has_password FROM short_links WHERE id=? AND owner_id=? AND status<>\'deleted\'').get(linkMatch[1], me.id);
    if (!row) return error(res, 404, 'Link not found.');
    return json(res, 200, { link: { ...row, shortUrl: `${config.appUrl}/s/${row.code}`, stats: linkStats(db, row.id) } });
  }
  if (linkMatch && method === 'PATCH') {
    const me = auth(); if (!me || !csrf(me)) return;
    const row = db.prepare('SELECT * FROM short_links WHERE id=? AND owner_id=? AND status<>\'deleted\'').get(linkMatch[1], me.id);
    if (!row) return error(res, 404, 'Link not found.');
    if (body.status !== undefined && !['active','paused'].includes(row.status)) return error(res, 403, 'This link status can only be changed by an administrator after review.');
    if (body.destinationUrl !== undefined && !validateDestination(body.destinationUrl)) return error(res, 400, 'Enter a valid HTTP or HTTPS destination URL.');
    const status = body.status === undefined ? row.status : body.status;
    if (!['active','paused','disabled'].includes(status)) return error(res, 400, 'Invalid link status.');
    const title = body.title === undefined ? row.title : cleanText(body.title, 120);
    const destination = body.destinationUrl === undefined ? row.destination_url : validateDestination(body.destinationUrl);
    const alias = body.alias === undefined || !String(body.alias).trim() ? row.code : safeAlias(body.alias);
    if (!alias) return error(res, 400, 'Aliases must be 3–32 characters using letters, numbers, hyphens, or underscores.');
    if (RESERVED.has(alias.toLowerCase())) return error(res, 400, 'That alias is reserved.');
    if (alias !== row.code && db.prepare('SELECT id FROM short_links WHERE code=?').get(alias)) return error(res, 409, 'That alias is already in use.');
    const campaign = body.campaign === undefined ? row.campaign : cleanText(body.campaign, 100);
    const description = body.description === undefined ? row.description : cleanText(body.description, 500);
    let expiresAt = row.expires_at;
    if (body.expiresAt !== undefined) {
      if (!body.expiresAt) expiresAt = null;
      else { const parsed = new Date(body.expiresAt); if (!Number.isFinite(parsed.valueOf()) || parsed <= new Date()) return error(res, 400, 'Expiration must be a future date.'); expiresAt = parsed.toISOString(); }
    }
    let maxVisits = row.max_visits;
    if (body.maxVisits !== undefined) { maxVisits = body.maxVisits === '' || body.maxVisits === null ? null : Number(body.maxVisits); if (maxVisits !== null && (!Number.isInteger(maxVisits) || maxVisits < 1 || maxVisits > 10000000)) return error(res, 400, 'Maximum visits must be a positive whole number.'); }
    let passwordHash = row.password_hash;
    if (body.clearPassword) passwordHash = null;
    else if (body.password) { if (String(body.password).length !== 6) return error(res, 400, 'Link passwords must be exactly 6 characters.'); passwordHash = await hashPassword(String(body.password)); }
    db.prepare(`UPDATE short_links SET code=?,title=?,destination_url=?,campaign=?,description=?,expires_at=?,max_visits=?,password_hash=?,status=?,updated_at=datetime('now') WHERE id=?`)
      .run(alias,title,destination,campaign,description,expiresAt,maxVisits,passwordHash,status,row.id);
    audit(db, me.id, 'link_updated', 'short_link', row.id);
    return json(res, 200, { ok: true });
  }
  if (linkMatch && method === 'DELETE') {
    const me = auth(); if (!me || !csrf(me)) return;
    const row = db.prepare("SELECT id FROM short_links WHERE id=? AND owner_id=? AND status<>'deleted'").get(linkMatch[1], me.id);
    if (!row) return error(res, 404, 'Link not found.');
    db.prepare("UPDATE short_links SET status='deleted',updated_at=datetime('now') WHERE id=?").run(row.id);
    audit(db, me.id, 'link_deleted', 'short_link', row.id);
    return json(res, 200, { ok: true });
  }

  if (method === 'GET' && path === '/analytics/overview') {
    const me = auth(); if (!me) return;
    const from = pageDate(url.searchParams.get('from'));
    const to = pageDate(url.searchParams.get('to'));
    const earnings = moneySummary(db, me.id);
    const analytics = analyticsOverview(db, me.id, from, to ? new Date(Date.parse(`${to}T00:00:00Z`) + 86400000).toISOString() : null);
    const earningsDaily=db.prepare(`SELECT date(created_at) AS day,COALESCE(SUM(amount_paise),0) AS amountPaise FROM earning_ledger WHERE user_id=? AND type='earning' AND status IN ('pending','estimated','on_hold','approved','paid') AND amount_paise>0 AND (? IS NULL OR date(created_at)>=?) AND (? IS NULL OR date(created_at)<=?) GROUP BY date(created_at) ORDER BY day`).all(me.id,from||null,from||null,to||null,to||null).map(row=>({day:row.day,amountPaise:Number(row.amountPaise||0)}));
    const countriesByCode=new Map();
    const countryRows=db.prepare(`SELECT country_code AS code,COUNT(*) AS visits FROM click_events WHERE owner_id=? AND event_type='visit' AND country_code<>'Unknown' AND (? IS NULL OR date(created_at)>=?) AND (? IS NULL OR date(created_at)<=?) GROUP BY country_code UNION ALL SELECT e.country AS code,COUNT(*) AS visits FROM creation_view_events e JOIN articles a ON e.entity_type='post' AND a.id=e.entity_id WHERE a.user_id=? AND e.country NOT IN ('Unknown','XX','T1','') AND (? IS NULL OR date(e.created_at)>=?) AND (? IS NULL OR date(e.created_at)<=?) GROUP BY e.country UNION ALL SELECT e.country AS code,COUNT(*) AS visits FROM creation_view_events e JOIN link_trees t ON e.entity_type='tree' AND t.id=e.entity_id WHERE t.user_id=? AND e.country NOT IN ('Unknown','XX','T1','') AND (? IS NULL OR date(e.created_at)>=?) AND (? IS NULL OR date(e.created_at)<=?) GROUP BY e.country`).all(me.id,from||null,from||null,to||null,to||null,me.id,from||null,from||null,to||null,to||null,me.id,from||null,from||null,to||null,to||null);
    for(const row of countryRows){const code=String(row.code||'').toUpperCase();if(/^[A-Z]{2}$/.test(code)&&!['XX','T1'].includes(code))countriesByCode.set(code,(countriesByCode.get(code)||0)+Number(row.visits||0));}
    const countries=[...countriesByCode].map(([code,visits])=>({code,visits})).sort((a,b)=>b.visits-a.visits).slice(0,10);
    const today = new Date(); const todayStart = new Date(Date.UTC(today.getUTCFullYear(), today.getUTCMonth(), today.getUTCDate())).toISOString();
    const monthStart = new Date(Date.UTC(today.getUTCFullYear(), today.getUTCMonth(), 1)).toISOString();
    const todayEarn = db.prepare("SELECT COALESCE(SUM(amount_paise),0) AS amount FROM earning_ledger WHERE user_id=? AND created_at>=? AND amount_paise>0").get(me.id, todayStart).amount;
    const monthEarn = db.prepare("SELECT COALESCE(SUM(amount_paise),0) AS amount FROM earning_ledger WHERE user_id=? AND created_at>=? AND amount_paise>0").get(me.id, monthStart).amount;
    return json(res, 200, { ...analytics, earningsDaily, countries, linkCount: db.prepare("SELECT COUNT(*) AS n FROM short_links WHERE owner_id=? AND status<>'deleted'").get(me.id).n, creationCounts: dashboardCreationCounts(db, me.id), earnings: { ...earnings, todayPaise: todayEarn, monthPaise: monthEarn }, performingCreations: dashboardPerformingCreations(db, me.id) });
  }

  if (method === 'GET' && path === '/analytics/export.csv') {
    const me = auth(); if (!me) return;
    const from=pageDate(url.searchParams.get('from'));const to=pageDate(url.searchParams.get('to'));
    const rows=db.prepare(`SELECT ce.created_at,l.code,l.title,ce.event_type,ce.device_category,ce.country_code,ce.referrer_domain,ce.eligible_status FROM click_events ce JOIN short_links l ON l.id=ce.short_link_id WHERE ce.owner_id=? AND (? IS NULL OR date(ce.created_at)>=?) AND (? IS NULL OR date(ce.created_at)<=?) ORDER BY ce.created_at DESC LIMIT 50000`).all(me.id,from||null,from||null,to||null,to||null);
    const csv = ['timestamp,short_code,title,event,device,country,referrer,eligible_status', ...rows.map(r => [r.created_at,r.code,r.title,r.event_type,r.device_category,r.country_code,r.referrer_domain,r.eligible_status].map(csvCell).join(','))].join('\r\n');
    res.writeHead(200, { 'Content-Type': 'text/csv; charset=utf-8', 'Content-Disposition': 'attachment; filename="link-analytics.csv"', 'Cache-Control': 'no-store' });
    return res.end(csv);
  }

  const linkAnalyticsMatch = path.match(/^\/analytics\/links\/([^/]+)$/);
  if (method === 'GET' && linkAnalyticsMatch) {
    const me = auth(); if (!me) return;
    const link = db.prepare('SELECT id,code,title,destination_url FROM short_links WHERE id=? AND owner_id=?').get(linkAnalyticsMatch[1], me.id);
    if (!link) return error(res, 404, 'Link not found.');
    const devices = db.prepare(`SELECT device_category AS category,COUNT(*) AS count FROM click_events WHERE short_link_id=? AND event_type='visit' GROUP BY device_category ORDER BY count DESC`).all(link.id);
    const referrers = db.prepare(`SELECT COALESCE(NULLIF(referrer_domain,''),'Direct') AS source,COUNT(*) AS count FROM click_events WHERE short_link_id=? AND event_type='visit' GROUP BY source ORDER BY count DESC LIMIT 8`).all(link.id);
    return json(res, 200, { link, stats: linkStats(db, link.id), devices, referrers, funnel: db.prepare(`SELECT position,
      SUM(CASE WHEN event_type='activated' THEN 1 ELSE 0 END) AS activated,
      SUM(CASE WHEN event_type='acknowledged' THEN 1 ELSE 0 END) AS completed,
      SUM(CASE WHEN event_type='provider_verified' THEN 1 ELSE 0 END) AS providerVerified
      FROM unlock_step_events e JOIN unlock_sessions s ON s.id=e.unlock_session_id WHERE s.short_link_id=? GROUP BY position ORDER BY position`).all(link.id) });
  }

  if (method === 'GET' && path === '/earnings/summary') {
    const me = auth(); if (!me) return;
    const total = moneySummary(db, me.id);
    const rows = db.prepare(`SELECT status,COALESCE(SUM(amount_paise),0) AS amount,COUNT(*) AS count
      FROM earning_ledger WHERE user_id=? GROUP BY status`).all(me.id);
    return json(res, 200, { ...total, byStatus: rows, currency: getSetting(db, 'currency', config.currency), ratePaisePerThousand: Number(getSetting(db, 'earning_rate_paise_per_1000', '0')) });
  }

  if (method === 'GET' && path === '/earnings/transactions') {
    const me = auth(); if (!me) return;
    const limit = Math.min(100, Math.max(1, Number(url.searchParams.get('limit') ?? 25)));
    const offset = Math.max(0, Number(url.searchParams.get('offset') ?? 0));
    const rows = db.prepare(`SELECT el.*,l.code,l.title FROM earning_ledger el LEFT JOIN short_links l ON l.id=el.link_id
      WHERE el.user_id=? ORDER BY el.created_at DESC LIMIT ? OFFSET ?`).all(me.id, limit, offset);
    const count = db.prepare('SELECT COUNT(*) AS n FROM earning_ledger WHERE user_id=?').get(me.id).n;
    return json(res, 200, { items: rows, total: count, limit, offset });
  }

  if (method === 'GET' && path === '/withdrawals') {
    const me = auth(); if (!me) return;
    const rows = db.prepare('SELECT id,amount_paise,currency,status,payout_method,reference,reason,created_at,updated_at FROM withdrawal_requests WHERE user_id=? ORDER BY created_at DESC LIMIT 100').all(me.id);
    return json(res, 200, { items: rows, balance: moneySummary(db, me.id), minimumPaise: Number(getSetting(db, 'minimum_withdrawal_paise', String(config.minWithdrawalPaise))) });
  }

  if (method === 'POST' && path === '/withdrawals') {
    const me = auth(); if (!me || !csrf(me)) return;
    const amount = Number(body.amountPaise);
    const methodName = cleanText(body.payoutMethod, 40);
    const details = cleanText(body.payoutDetails, 250);
    const minimum = Number(getSetting(db, 'minimum_withdrawal_paise', String(config.minWithdrawalPaise)));
    if (!Number.isSafeInteger(amount) || amount < minimum) return error(res, 400, `Withdrawal minimum is ${minimum} cents.`);
    if (!['USDT','UPI','PayPal','Binance','Bank transfer'].includes(methodName) || details.length < 5) return error(res, 400, 'Choose a payout method and enter valid payout details. Do not include passwords, PINs, or OTPs.');
    db.exec('BEGIN IMMEDIATE');
    try {
      const balance = moneySummary(db, me.id);
      if (amount > balance.withdrawablePaise) { db.exec('ROLLBACK'); return error(res, 400, 'The requested amount exceeds your withdrawable balance.'); }
      const withdrawalId = id();
      db.prepare(`INSERT INTO withdrawal_requests(id,user_id,amount_paise,currency,payout_method,payout_details_cipher)
        VALUES (?,?,?,?,?,?)`).run(withdrawalId, me.id, amount, getSetting(db, 'currency', config.currency), methodName, sealValue(details, config.encryptionKey));
      notify(db, me.id, 'Withdrawal requested', 'Your request has been submitted for review.');
      audit(db, me.id, 'withdrawal_requested', 'withdrawal', withdrawalId, '', { amountPaise: amount });
      db.exec('COMMIT');
      return json(res, 201, { id: withdrawalId, status: 'requested', amountPaise: amount });
    } catch (e) { db.exec('ROLLBACK'); throw e; }
  }

  if (method === 'GET' && path === '/referrals') {
    const me = auth(); if (!me) return;
    const rows = db.prepare(`SELECT re.status,re.reward_paise,re.created_at,u.email,
      COALESCE((SELECT SUM(el.amount_paise) FROM earning_ledger el WHERE el.user_id=u.id AND el.type='earning' AND el.status IN ('approved','paid')
        AND strftime('%Y-%m',el.created_at)=strftime('%Y-%m','now')),0) AS monthly_revenue_paise
      FROM referral_events re JOIN users u ON u.id=re.referred_user_id WHERE re.referrer_id=? ORDER BY re.created_at DESC`).all(me.id)
      .map(row=>{const monthlyRevenuePaise=Number(row.monthly_revenue_paise||0);return {...row,monthly_revenue_paise:monthlyRevenuePaise,qualified_this_month:monthlyRevenuePaise>2000?1:0,estimated_share_paise:monthlyRevenuePaise>2000?Math.floor(monthlyRevenuePaise*0.1):0};});
    const code = db.prepare('SELECT referral_code FROM users WHERE id=?').get(me.id).referral_code;
    const stats={total:rows.length,verified:rows.filter(row=>row.status==='eligible').length,qualifiedThisMonth:rows.filter(row=>row.qualified_this_month).length,estimatedSharePaise:rows.reduce((sum,row)=>sum+row.estimated_share_paise,0)};
    return json(res, 200, { enabled: getSetting(db, 'referrals_enabled', '0') === '1', code, link: `${config.appUrl}/register?ref=${encodeURIComponent(code)}`, thresholdPaise:2000, sharePercent:10, stats, referrals: rows });
  }

  if (method === 'GET' && path === '/notifications') {
    const me = auth(); if (!me) return;
    const rows = db.prepare('SELECT * FROM notifications WHERE user_id=? ORDER BY created_at DESC LIMIT 100').all(me.id);
    return json(res, 200, { items: rows, unread: rows.filter(n => !n.read_at).length });
  }
  if (method === 'POST' && path === '/notifications/read-all') {
    const me = auth(); if (!me || !csrf(me)) return;
    db.prepare("UPDATE notifications SET read_at=COALESCE(read_at,datetime('now')) WHERE user_id=?").run(me.id);
    return json(res, 200, { ok: true });
  }
  const notificationMatch = path.match(/^\/notifications\/([^/]+)\/read$/);
  if (notificationMatch && method === 'POST') {
    const me = auth(); if (!me || !csrf(me)) return;
    const changed = db.prepare("UPDATE notifications SET read_at=datetime('now') WHERE id=? AND user_id=?").run(notificationMatch[1], me.id);
    if (!changed.changes) return error(res, 404, 'Notification not found.');
    return json(res, 200, { ok: true });
  }

  if (path === '/support/tickets' && method === 'GET') {
    const me = auth(); if (!me) return;
    return json(res, 200, { items: db.prepare('SELECT * FROM support_tickets WHERE user_id=? ORDER BY updated_at DESC').all(me.id) });
  }
  if (path === '/support/tickets' && method === 'POST') {
    const me = auth(); if (!me || !csrf(me)) return;
    const subject = cleanText(body.subject, 120);
    const message = cleanText(body.message, 3000);
    if (subject.length < 4 || message.length < 10) return error(res, 400, 'Enter a subject and a message with at least 10 characters.');
    const ticketId = id();
    db.prepare('INSERT INTO support_tickets(id,user_id,subject,category) VALUES (?,?,?,?)').run(ticketId, me.id, subject, cleanText(body.category, 40) || 'general');
    db.prepare('INSERT INTO support_messages(id,ticket_id,author_id,message) VALUES (?,?,?,?)').run(id(), ticketId, me.id, message);
    return json(res, 201, { id: ticketId });
  }
  const ticketMatch = path.match(/^\/support\/tickets\/([^/]+)$/);
  if (ticketMatch && method === 'GET') {
    const me = auth(); if (!me) return;
    const ticket = db.prepare('SELECT * FROM support_tickets WHERE id=? AND user_id=?').get(ticketMatch[1], me.id);
    if (!ticket) return error(res, 404, 'Support ticket not found.');
    const messages = db.prepare(`SELECT m.id,m.author_id,m.message,m.created_at,u.display_name,u.role FROM support_messages m
      JOIN users u ON u.id=m.author_id WHERE m.ticket_id=? ORDER BY m.created_at`).all(ticket.id);
    return json(res, 200, { ticket, messages });
  }
  if (ticketMatch && method === 'POST') {
    const me = auth(); if (!me || !csrf(me)) return;
    const ticket = db.prepare('SELECT * FROM support_tickets WHERE id=? AND user_id=?').get(ticketMatch[1], me.id);
    if (!ticket) return error(res, 404, 'Support ticket not found.');
    const message = cleanText(body.message, 3000);
    if (message.length < 2) return error(res, 400, 'Enter a message.');
    db.prepare('INSERT INTO support_messages(id,ticket_id,author_id,message) VALUES (?,?,?,?)').run(id(), ticket.id, me.id, message);
    db.prepare("UPDATE support_tickets SET status='open',updated_at=datetime('now') WHERE id=?").run(ticket.id);
    return json(res, 201, { ok: true });
  }

  if (path === '/profile' && method === 'GET') {
    const me = auth(); if (!me) return;
    const profile = db.prepare('SELECT id,public_id,email,display_name,avatar_url,role,status,referral_code,payout_method,payout_details_cipher,created_at,verified_at FROM users WHERE id=?').get(me.id);
    const length = profile.payout_details_cipher ? unsealValue(profile.payout_details_cipher, config.encryptionKey).length : 0;
    return json(res, 200, { ...userPublic(profile), referralCode: profile.referral_code, verifiedAt: profile.verified_at, payout: { method: profile.payout_method, masked: length ? `••••${'•'.repeat(Math.min(length, 8))}` : '' } });
  }
  if (path === '/profile' && method === 'PATCH') {
    const me = auth(); if (!me || !csrf(me)) return;
    const displayName = cleanText(body.displayName, 80);
    if (displayName.length < 2) return error(res, 400, 'Your name must contain at least 2 characters.');
    db.prepare('UPDATE users SET display_name=? WHERE id=?').run(displayName, me.id);
    const user = db.prepare('SELECT * FROM users WHERE id=?').get(me.id);
    return json(res, 200, { ok: true, user: userPublic(user) });
  }
  if (path === '/profile/avatar' && method === 'POST') {
    const me = auth(); if (!me || !csrf(me)) return;
    const match = String(body.dataUrl || '').match(/^data:image\/(png|jpeg|webp);base64,([A-Za-z0-9+/]+={0,2})$/);
    if (!match) return error(res, 400, 'Choose a PNG, JPG, or WebP profile photo.');
    const [, kind, encoded] = match;
    const bytes = Buffer.from(encoded, 'base64');
    if (!bytes.length || bytes.length > 2 * 1024 * 1024) return error(res, 413, 'Profile photos must be 2 MB or smaller.');
    const isPng = kind === 'png' && bytes.subarray(0, 8).equals(Buffer.from([137,80,78,71,13,10,26,10]));
    const isJpeg = kind === 'jpeg' && bytes[0] === 255 && bytes[1] === 216 && bytes[2] === 255;
    const isWebp = kind === 'webp' && bytes.toString('ascii', 0, 4) === 'RIFF' && bytes.toString('ascii', 8, 12) === 'WEBP';
    if (!isPng && !isJpeg && !isWebp) return error(res, 400, 'The selected file does not match its image type.');
    const extension = kind === 'jpeg' ? 'jpg' : kind;
    const fileName = `${randomUUID()}.${extension}`;
    const directory = resolve(PUBLIC, 'uploads', 'avatars');
    await mkdir(directory, { recursive: true });
    await writeFile(resolve(directory, fileName), bytes, { flag: 'wx' });
    const avatarUrl = `/uploads/avatars/${fileName}`;
    db.prepare('UPDATE users SET avatar_url=? WHERE id=?').run(avatarUrl, me.id);
    const user = db.prepare('SELECT * FROM users WHERE id=?').get(me.id);
    return json(res, 201, { ok: true, avatarUrl, user: userPublic(user) });
  }
  if (path === '/profile/channels' && method === 'GET') {
    const me = auth(); if (!me) return;
    const row = db.prepare('SELECT social_links,traffic_source FROM user_profile_channels WHERE user_id=?').get(me.id);
    let socialLinks = {};
    try { socialLinks = JSON.parse(row?.social_links || '{}'); } catch {}
    return json(res, 200, { socialLinks, trafficSource: row?.traffic_source || '' });
  }
  const articleStatusMatch=path.match(/^\/profile\/posts\/([^/]+)\/status$/);
  if(articleStatusMatch&&method==='PATCH'){const me=auth();if(!me||!csrf(me))return;const status=body.status==='draft'?'draft':body.status==='published'?'published':'';if(!status)return error(res,400,'Choose draft or published status.');const result=db.prepare('UPDATE articles SET status=?,updated_at=datetime(\'now\') WHERE id=? AND user_id=?').run(status,articleStatusMatch[1],me.id);if(!result.changes)return error(res,404,'Article not found.');return json(res,200,{ok:true,status});}
  const treeStatusMatch=path.match(/^\/profile\/trees\/([^/]+)\/status$/);
  if(treeStatusMatch&&method==='PATCH'){const me=auth();if(!me||!csrf(me))return;const status=body.status==='paused'?'paused':body.status==='active'?'active':'';if(!status)return error(res,400,'Choose active or paused status.');const result=db.prepare('UPDATE link_trees SET status=? WHERE id=? AND user_id=?').run(status,treeStatusMatch[1],me.id);if(!result.changes)return error(res,404,'Link tree not found.');return json(res,200,{ok:true,status});}
  const profileTreeDeleteMatch=path.match(/^\/profile\/trees\/([^/]+)$/);
  if(profileTreeDeleteMatch&&method==='DELETE'){const me=auth();if(!me||!csrf(me))return;const result=db.prepare("UPDATE link_trees SET status='deleted',updated_at=datetime('now') WHERE id=? AND user_id=? AND status<>'deleted'").run(profileTreeDeleteMatch[1],me.id);if(!result.changes)return error(res,404,'Link tree not found.');return json(res,200,{ok:true});}
  const articleMatch=path.match(/^\/profile\/posts\/([^/]+)$/);
  if(articleMatch&&method==='GET'){const me=auth();if(!me)return;const article=db.prepare('SELECT id,slug,title,excerpt,cover_image,content_html,status,view_count,created_at,updated_at,ads_enabled,(password_hash IS NOT NULL) AS has_password FROM articles WHERE id=? AND user_id=?').get(articleMatch[1],me.id);if(!article)return error(res,404,'Article not found.');return json(res,200,{article});}
  if(articleMatch&&method==='PATCH'){
    const me=auth();if(!me||!csrf(me))return;
    const old=db.prepare('SELECT id,password_hash,ads_enabled FROM articles WHERE id=? AND user_id=?').get(articleMatch[1],me.id);if(!old)return error(res,404,'Article not found.');
    const title=cleanText(body.title,160),excerpt=cleanText(body.excerpt,500),slug=String(body.slug||'').trim().toLowerCase(),cover=String(body.coverImage||'').trim(),raw=String(body.contentHtml||'');
    if(title.length<3||! /^[a-z0-9][a-z0-9-]{1,78}[a-z0-9]$/.test(slug)||raw.length<1||raw.length>200000)return error(res,400,'Add a title, valid slug, and article content.');
    if(db.prepare('SELECT id FROM articles WHERE slug=? AND id<>?').get(slug,old.id))return error(res,409,'This post slug is already taken.');
    const protectPost=body.postPasswordEnabled===true||body.postPasswordEnabled==='on';const postPassword=String(body.postPassword||'');let passwordHash=protectPost?old.password_hash:null;
    if(protectPost&&postPassword){if(!/^\d{6}$/.test(postPassword))return error(res,400,'Post passwords must contain exactly 6 digits.');passwordHash=await hashPassword(postPassword);}
    if(protectPost&&!passwordHash)return error(res,400,'Enter a 6-digit password to protect this post.');
    const adsEnabled=body.adsEnabled===true||body.adsEnabled==='on';const html=sanitizeArticleHtml(raw);db.prepare("UPDATE articles SET slug=?,title=?,excerpt=?,cover_image=?,content_html=?,password_hash=?,ads_enabled=?,updated_at=datetime('now') WHERE id=?").run(slug,title,excerpt,cover,html,passwordHash,adsEnabled?1:0,old.id);
    return json(res,200,{ok:true,article:{id:old.id,slug,title,excerpt,coverImage:cover,hasPassword:Boolean(passwordHash),adsEnabled,publicUrl:`${config.appUrl}/post/${slug}`}});
  }
  if(path==='/profile/posts'&&method==='GET'){const me=auth();if(!me)return;const items=db.prepare('SELECT id,slug,title,excerpt,cover_image,status,view_count,created_at,updated_at,ads_enabled,(password_hash IS NOT NULL) AS has_password FROM articles WHERE user_id=? ORDER BY created_at DESC').all(me.id);return json(res,200,{items});}
  if(path==='/profile/posts'&&method==='POST'){
    const me=auth();if(!me||!csrf(me))return;
    const title=cleanText(body.title,160),excerpt=cleanText(body.excerpt,500),slug=String(body.slug||'').trim().toLowerCase(),cover=String(body.coverImage||'').trim(),raw=String(body.contentHtml||'');
    if(title.length<3||! /^[a-z0-9][a-z0-9-]{1,78}[a-z0-9]$/.test(slug)||raw.length<1||raw.length>200000)return error(res,400,'Add a title, valid 3–80 character slug, and article content.');
    if(cover){try{const u=new URL(cover);if(!['http:','https:'].includes(u.protocol))throw 0;}catch{return error(res,400,'Cover image must be an HTTP or HTTPS URL.');}}
    if(db.prepare('SELECT id FROM articles WHERE slug=?').get(slug))return error(res,409,'This post slug is already taken.');
    const protectPost=body.postPasswordEnabled===true||body.postPasswordEnabled==='on';const postPassword=String(body.postPassword||'');
    if(protectPost&&!/^\d{6}$/.test(postPassword))return error(res,400,'Enter a 6-digit password to protect this post.');
    const html=sanitizeArticleHtml(raw);if(!html.trim())return error(res,400,'Write some article content first.');
    const postId=id(),passwordHash=protectPost?await hashPassword(postPassword):null,adsEnabled=body.adsEnabled===true||body.adsEnabled==='on';
    db.prepare('INSERT INTO articles(id,user_id,slug,title,excerpt,cover_image,content_html,password_hash,ads_enabled) VALUES(?,?,?,?,?,?,?,?,?)').run(postId,me.id,slug,title,excerpt,cover,html,passwordHash,adsEnabled?1:0);
    return json(res,201,{post:{id:postId,slug,title,excerpt,coverImage:cover,hasPassword:protectPost,adsEnabled,publicUrl:`${config.appUrl}/post/${slug}`}});
  }
  if(path==='/profile/trees'&&method==='GET'){
    const me=auth();if(!me)return;
    const items=db.prepare(`SELECT id,slug,title,bio,avatar_url,socials_json,rows_json,theme_json,password_hash,ads_enabled,view_count,status,created_at,updated_at FROM link_trees WHERE user_id=? AND status<>'deleted' ORDER BY created_at DESC`).all(me.id).map(tree=>{let socials={},rows=[],theme={};try{socials=JSON.parse(tree.socials_json);}catch{}try{rows=JSON.parse(tree.rows_json);}catch{}try{theme=JSON.parse(tree.theme_json);}catch{}return{id:tree.id,slug:tree.slug,title:tree.title,bio:tree.bio,avatarUrl:tree.avatar_url,socials,rows,theme,adsEnabled:Boolean(tree.ads_enabled),hasPassword:Boolean(tree.password_hash),viewCount:Number(tree.view_count),status:tree.status||'active',createdAt:tree.created_at,updatedAt:tree.updated_at};});
    return json(res,200,{items});
  }
  if(path==='/profile/trees/upload'&&method==='POST'){
    const me=auth();if(!me||!csrf(me))return;
    const match=String(body.dataUrl||'').match(/^data:image\/(png|jpeg|webp);base64,([A-Za-z0-9+/]+={0,2})$/);
    if(!match)return error(res,400,'Choose a PNG, JPG, or WebP image to upload.');
    const [,kind,encoded]=match;const bytes=Buffer.from(encoded,'base64');if(!bytes.length||bytes.length>2*1024*1024)return error(res,413,'Images must be 2 MB or smaller.');
    const isPng=kind==='png'&&bytes.subarray(0,8).equals(Buffer.from([137,80,78,71,13,10,26,10]));
    const isJpeg=kind==='jpeg'&&bytes[0]===255&&bytes[1]===216&&bytes[2]===255;
    const isWebp=kind==='webp'&&bytes.toString('ascii',0,4)==='RIFF'&&bytes.toString('ascii',8,12)==='WEBP';
    if(!isPng&&!isJpeg&&!isWebp)return error(res,400,'The selected file does not match its image type.');
    const extension=kind==='jpeg'?'jpg':kind;const fileName=`${randomUUID()}.${extension}`;const directory=resolve(PUBLIC,'uploads','trees');await mkdir(directory,{recursive:true});await writeFile(resolve(directory,fileName),bytes,{flag:'wx'});
    return json(res,201,{url:`/uploads/trees/${fileName}`});
  }
  if(path==='/profile/trees'&&method==='POST'){
    const me=auth();if(!me||!csrf(me))return;
    const parsed=normalizeTreeInput(body);if(parsed.error)return error(res,400,parsed.error);const tree=parsed.value;if(parsed.passwordEnabled&&!/^\d{6}$/.test(parsed.password))return error(res,400,'Enter exactly 6 digits to protect this tree.');const passwordHash=parsed.passwordEnabled?await hashPassword(parsed.password):null;
    if(db.prepare('SELECT id FROM link_trees WHERE slug=?').get(tree.slug))return error(res,409,'That tree URL is already in use. Choose another slug.');
    const treeId=id();db.prepare(`INSERT INTO link_trees(id,user_id,slug,title,bio,avatar_url,socials_json,rows_json,theme_json,password_hash,ads_enabled) VALUES (?,?,?,?,?,?,?,?,?,?,?)`).run(treeId,me.id,tree.slug,tree.title,tree.bio,tree.avatarUrl,JSON.stringify(tree.socials),JSON.stringify(tree.rows),JSON.stringify(tree.theme),passwordHash,tree.adsEnabled?1:0);
    return json(res,201,{tree:{id:treeId,...tree,hasPassword:Boolean(passwordHash),viewCount:0,publicUrl:`${config.appUrl}/tree/${tree.slug}`}});
  }
  const profileTreeMatch=path.match(/^\/profile\/trees\/([^/]+)$/);
  if(profileTreeMatch&&method==='PATCH'){
    const me=auth();if(!me||!csrf(me))return;const existing=db.prepare('SELECT id,password_hash FROM link_trees WHERE id=? AND user_id=?').get(profileTreeMatch[1],me.id);if(!existing)return error(res,404,'Link tree not found.');
    const parsed=normalizeTreeInput(body);if(parsed.error)return error(res,400,parsed.error);const tree=parsed.value;let passwordHash=parsed.passwordEnabled?existing.password_hash:null;if(parsed.passwordEnabled&&parsed.password){if(!/^\d{6}$/.test(parsed.password))return error(res,400,'Tree passwords must contain exactly 6 digits.');passwordHash=await hashPassword(parsed.password);}if(parsed.passwordEnabled&&!passwordHash)return error(res,400,'Enter a 6-digit password to protect this tree.');const slugOwner=db.prepare('SELECT id FROM link_trees WHERE slug=? AND id<>?').get(tree.slug,existing.id);if(slugOwner)return error(res,409,'That tree URL is already in use. Choose another slug.');
    db.prepare(`UPDATE link_trees SET slug=?,title=?,bio=?,avatar_url=?,socials_json=?,rows_json=?,theme_json=?,password_hash=?,ads_enabled=?,updated_at=datetime('now') WHERE id=? AND user_id=?`).run(tree.slug,tree.title,tree.bio,tree.avatarUrl,JSON.stringify(tree.socials),JSON.stringify(tree.rows),JSON.stringify(tree.theme),passwordHash,tree.adsEnabled?1:0,existing.id,me.id);
    const viewCount=Number(db.prepare('SELECT view_count FROM link_trees WHERE id=?').get(existing.id).view_count);return json(res,200,{tree:{id:existing.id,...tree,hasPassword:Boolean(passwordHash),viewCount,publicUrl:`${config.appUrl}/tree/${tree.slug}`}});
  }
  if (path === '/profile/channels' && method === 'PUT') {
    const me = auth(); if (!me || !csrf(me)) return;
    const platforms = ['telegram','whatsapp','youtube','facebook','instagram','snapchat','tiktok','x','website'];
    const input = body.socialLinks && typeof body.socialLinks === 'object' && !Array.isArray(body.socialLinks) ? body.socialLinks : {};
    const socialLinks = {};
    for (const platform of platforms) {
      const value = cleanText(input[platform], 300);
      if (value && !/^@[A-Za-z0-9_.]{2,64}$/.test(value)) {
        try { const url = new URL(value); if (!['http:','https:'].includes(url.protocol)) throw new Error(); }
        catch { return error(res, 400, `Enter a valid URL or @handle for ${platform}.`); }
      }
      socialLinks[platform] = value;
    }
    const trafficSource = cleanText(body.trafficSource, 40);
    const allowedSources = ['social_media','youtube','telegram','whatsapp','website_blog','search_engine','paid_ads','referral','other'];
    if (trafficSource && !allowedSources.includes(trafficSource)) return error(res, 400, 'Choose a listed traffic source.');
    db.prepare(`INSERT INTO user_profile_channels(user_id,social_links,traffic_source,updated_at) VALUES (?,?,?,datetime('now'))
      ON CONFLICT(user_id) DO UPDATE SET social_links=excluded.social_links,traffic_source=excluded.traffic_source,updated_at=datetime('now')`)
      .run(me.id, JSON.stringify(socialLinks), trafficSource);
    return json(res, 200, { ok: true });
  }
  if (path === '/profile/payout' && method === 'PATCH') {
    const me = auth(); if (!me || !csrf(me)) return;
    const methodName = cleanText(body.payoutMethod, 40);
    const details = cleanText(body.payoutDetails, 250);
    if (!['USDT','UPI','PayPal','Binance','Bank transfer'].includes(methodName) || details.length < 5) return error(res, 400, 'Choose a payout method and provide valid details.');
    db.prepare('UPDATE users SET payout_method=?,payout_details_cipher=? WHERE id=?').run(methodName, sealValue(details, config.encryptionKey), me.id);
    return json(res, 200, { ok: true });
  }
  if (path === '/profile/telegram/bots' && method === 'GET') {
    const me = auth(); if (!me) return;
    const items = db.prepare('SELECT id,bot_name,bot_id,bot_api_key_cipher,storage_channel_id,created_at,updated_at FROM user_telegram_bots WHERE user_id=? ORDER BY created_at,id').all(me.id).map(bot => {
      let botApiKey = '';
      try { botApiKey = unsealValue(bot.bot_api_key_cipher, config.encryptionKey); } catch { return { id:bot.id,botName:bot.bot_name,botId:bot.bot_id,botApiKey:'',storageChannelId:bot.storage_channel_id,createdAt:bot.created_at,updatedAt:bot.updated_at }; }
      return { id:bot.id,botName:bot.bot_name,botId:bot.bot_id,botApiKey,storageChannelId:bot.storage_channel_id,createdAt:bot.created_at,updatedAt:bot.updated_at };
    });
    return json(res, 200, { items, limit:10 });
  }
  if (path === '/profile/telegram/bots' && method === 'POST') {
    const me = auth(); if (!me || !csrf(me)) return;
    const botKeyId = cleanText(body.id, 80);
    const botName = cleanText(body.botName, 64);
    const botId = String(body.botId ?? '').trim();
    const botApiKey = String(body.botApiKey ?? '').trim();
    const storageChannelId = String(body.storageChannelId ?? '').trim();
    if (!botName) return error(res, 400, 'Enter a name for this bot.');
    if (!/^\d{5,15}$/.test(botId)) return error(res, 400, 'Enter a valid numeric Telegram Bot ID.');
    if (botApiKey && !/^\d{6,15}:[A-Za-z0-9_-]{20,}$/.test(botApiKey)) return error(res, 400, 'Enter a valid Telegram bot token from BotFather.');
    if (storageChannelId && !/^(?:-100\d{6,20}|@[A-Za-z0-9_]{5,32})$/.test(storageChannelId)) return error(res, 400, 'Enter a valid Telegram channel ID or @channel username.');
    const existing = botKeyId ? db.prepare('SELECT * FROM user_telegram_bots WHERE id=? AND user_id=?').get(botKeyId,me.id) : null;
    if (botKeyId && !existing) return error(res, 404, 'Telegram bot not found.');
    if (!existing && db.prepare('SELECT COUNT(*) AS count FROM user_telegram_bots WHERE user_id=?').get(me.id).count >= 10) return error(res, 400, 'You can add up to 10 Telegram bots.');
    if (!existing && !botApiKey) return error(res, 400, 'Enter the Telegram Bot API key for this bot.');
    const cipher = botApiKey ? sealValue(botApiKey, config.encryptionKey) : existing.bot_api_key_cipher;
    const savedId = existing?.id || id();
    if (existing) {
      db.prepare(`UPDATE user_telegram_bots SET bot_name=?,bot_id=?,bot_api_key_cipher=?,storage_channel_id=?,updated_at=datetime('now') WHERE id=? AND user_id=?`)
        .run(botName,botId,cipher,storageChannelId,savedId,me.id);
    } else {
      db.prepare(`INSERT INTO user_telegram_bots(id,user_id,bot_name,bot_id,bot_api_key_cipher,storage_channel_id) VALUES (?,?,?,?,?,?)`)
        .run(savedId,me.id,botName,botId,cipher,storageChannelId);
    }
    return json(res, 200, { ok:true,id:savedId,botName,botId,storageChannelId });
  }
  const telegramBotMatch = path.match(/^\/profile\/telegram\/bots\/([^/]+)$/);
  if (telegramBotMatch && method === 'DELETE') {
    const me = auth(); if (!me || !csrf(me)) return;
    const removed = db.prepare('DELETE FROM user_telegram_bots WHERE id=? AND user_id=?').run(telegramBotMatch[1],me.id);
    if (!removed.changes) return error(res, 404, 'Telegram bot not found.');
    return json(res, 200, { ok:true });
  }
  if (path === '/profile/telegram' && method === 'GET') {
    const me = auth(); if (!me) return;
    const firstBot = db.prepare('SELECT * FROM user_telegram_bots WHERE user_id=? ORDER BY created_at,id LIMIT 1').get(me.id);
    if (firstBot) {
      let botApiKey='';try{botApiKey=unsealValue(firstBot.bot_api_key_cipher,config.encryptionKey);}catch{}
      return json(res,200,{botApiKey,botName:firstBot.bot_name,botId:firstBot.bot_id,storageChannelId:firstBot.storage_channel_id});
    }
    const settings = db.prepare('SELECT bot_api_key_cipher,bot_name,bot_id,storage_channel_id FROM user_telegram_settings WHERE user_id=?').get(me.id);
    let botApiKey = '';
    if (settings?.bot_api_key_cipher) {
      try { botApiKey = unsealValue(settings.bot_api_key_cipher, config.encryptionKey); } catch { return error(res, 500, 'Could not read the saved Telegram bot key.'); }
    }
    return json(res, 200, { botApiKey, botName: settings?.bot_name || '', botId: settings?.bot_id || '', storageChannelId: settings?.storage_channel_id || '' });
  }
  if (path === '/profile/telegram' && method === 'PUT') {
    const me = auth(); if (!me || !csrf(me)) return;
    const botApiKey = String(body.botApiKey ?? '').trim();
    const botName = cleanText(body.botName, 64);
    const botId = String(body.botId ?? '').trim();
    const storageChannelId = String(body.storageChannelId ?? '').trim();
    if (botApiKey && !/^\d{6,15}:[A-Za-z0-9_-]{20,}$/.test(botApiKey)) return error(res, 400, 'Enter a valid Telegram bot token from BotFather.');
    if (String(body.botName ?? '').trim().length > 64) return error(res, 400, 'Bot name must be 64 characters or fewer.');
    if (botId && !/^\d{5,15}$/.test(botId)) return error(res, 400, 'Enter a valid numeric Telegram Bot ID.');
    if (storageChannelId && !/^(?:-100\d{6,20}|@[A-Za-z0-9_]{5,32})$/.test(storageChannelId)) return error(res, 400, 'Enter a valid Telegram channel ID or @channel username.');
    const existing = db.prepare('SELECT bot_api_key_cipher FROM user_telegram_settings WHERE user_id=?').get(me.id);
    const cipher = body.clearBotApiKey ? '' : (botApiKey ? sealValue(botApiKey, config.encryptionKey) : (existing?.bot_api_key_cipher || ''));
    db.prepare(`INSERT INTO user_telegram_settings(user_id,bot_api_key_cipher,bot_name,bot_id,storage_channel_id,updated_at) VALUES (?,?,?,?,?,datetime('now'))
      ON CONFLICT(user_id) DO UPDATE SET bot_api_key_cipher=excluded.bot_api_key_cipher,bot_name=excluded.bot_name,bot_id=excluded.bot_id,storage_channel_id=excluded.storage_channel_id,updated_at=datetime('now')`)
      .run(me.id, cipher, botName, botId, storageChannelId);
    return json(res, 200, { ok: true, botApiKeySaved: Boolean(cipher), botName, botId, storageChannelId });
  }

  if (path === '/unlock/sessions' && method === 'POST') {
    if (!isSameOrigin(req, config.appUrl)) return error(res, 403, 'Cross-origin requests are not allowed.');
    const code = cleanText(body.code, 40);
    if (!limits.unlockLimit(`unlock:${ipKey(req)}:${code}`)) return error(res, 429, 'Too many unlock attempts. Try again shortly.');
    if (getSetting(db, 'unlock_enabled', '1') !== '1') return error(res, 503, 'The unlock system is temporarily unavailable.');
    const link = db.prepare("SELECT * FROM short_links WHERE code=? AND status='active'").get(code);
    if (!link) return error(res, 404, 'This short link is not available.');
    if (link.expires_at && Date.parse(link.expires_at) <= Date.now()) {
      db.prepare("UPDATE short_links SET status='expired' WHERE id=?").run(link.id);
      return error(res, 410, 'This short link has expired.');
    }
    const unlockCookie = cookies.unlock_sid;
    const previous = unlockCookie && db.prepare(`SELECT us.*,l.id AS link_id FROM unlock_sessions us JOIN short_links l ON l.id=us.short_link_id
      WHERE us.token_hash=? AND us.short_link_id=? AND julianday(us.expires_at)>julianday('now') AND us.status IN ('in_progress','completed')`)
      .get(hashToken(unlockCookie), link.id);
    if (link.password_hash && !previous && !await verifyPassword(String(body.password ?? ''),link.password_hash)) return error(res, 401, 'This link is password-protected. Enter the password to continue.');
    if (!previous && link.max_visits && link.visit_count >= link.max_visits) return error(res, 410, 'This short link has reached its visit limit.');
    const visitorIpHash = createHmac('sha256', config.sessionSecret).update(ipKey(req)).digest('hex');
    if (!previous && link.per_ip_limit) { const ipVisit = db.prepare('SELECT visit_count FROM link_ip_visits WHERE short_link_id=? AND ip_hash=?').get(link.id, visitorIpHash); if ((ipVisit?.visit_count ?? 0) >= link.per_ip_limit) return error(res, 410, 'This link has reached its view limit for your IP address.'); }
    let session = previous;
    if (!session) {
      const steps = db.prepare('SELECT * FROM unlock_step_settings WHERE enabled=1 ORDER BY display_order').all();
      const current = nextStepPosition(steps, []);
      const token = randomToken();
      const sessionId = id();
      const expires = new Date(Date.now() + Number(getSetting(db, 'unlock_ttl_minutes', String(config.unlockTtlMinutes))) * 60000).toISOString();
      const category = deviceCategory(req.headers['user-agent'] ?? '');
      const bot = category === 'bot' ? 1 : 0;
      db.exec('BEGIN IMMEDIATE');
      try {
        // Re-check visit cap under the write lock.
        const currentLink = db.prepare('SELECT visit_count,max_visits FROM short_links WHERE id=? AND status=\'active\'').get(link.id);
        if (!currentLink || currentLink.max_visits && currentLink.visit_count >= currentLink.max_visits) { db.exec('ROLLBACK'); return error(res, 410, 'This short link has reached its visit limit.'); }
        db.prepare(`INSERT INTO unlock_sessions(id,token_hash,short_link_id,current_step,expires_at,risk_flags)
          VALUES (?,?,?,?,?,?)`).run(sessionId, hashToken(token), link.id, current ?? 6, expires, bot ? 'bot_user_agent' : '');
        db.prepare(`INSERT INTO click_events(id,short_link_id,owner_id,unlock_session_id,event_type,device_category,country_code,referrer_domain,is_bot,eligible_status)
          VALUES (?,?,?,?,?,?,?,?,?,?)`).run(id(), link.id, link.owner_id, sessionId, 'visit', category, countryCodeFromRequest(req), referrerDomain(req), bot, bot ? 'ineligible' : 'pending');
        db.prepare('UPDATE short_links SET visit_count=visit_count+1 WHERE id=?').run(link.id);
        if (link.per_ip_limit) db.prepare('INSERT INTO link_ip_visits(short_link_id,ip_hash,visit_count) VALUES (?,?,1) ON CONFLICT(short_link_id,ip_hash) DO UPDATE SET visit_count=visit_count+1').run(link.id, visitorIpHash);
        db.exec('COMMIT');
      } catch (e) { db.exec('ROLLBACK'); throw e; }
      session = db.prepare('SELECT * FROM unlock_sessions WHERE id=?').get(sessionId);
      setCookies(res, [`unlock_sid=${htmlSafeCookie(token)}; ${cookieOptions({ secure: config.nodeEnv === 'production', path: '/api/v1/unlock' })}; Expires=${new Date(expires).toUTCString()}`]);
    }
    return json(res, 200, unlockPayload(db, session, link));
  }

  const unlockRoute = path.match(/^\/unlock\/sessions\/([^/]+)$/);
  if (unlockRoute && method === 'GET') {
    const code = unlockRoute[1];
    const session = findUnlockSession(db, cookies.unlock_sid, code);
    if (!session) return error(res, 404, 'Unlock session not found. Start from the short URL.');
    const link = db.prepare('SELECT id,code,title,status,expires_at,campaign,description FROM short_links WHERE id=?').get(session.short_link_id);
    if (session.expires_at <= new Date().toISOString()) return error(res, 410, 'This unlock session has expired. Start again from the short URL.');
    return json(res, 200, unlockPayload(db, session, link));
  }

  const demoDwellRoute = path.match(/^\/unlock\/demo-dwell\/(start|ping|status|restart)$/);
  if (demoDwellRoute && (method === 'GET' && demoDwellRoute[1] === 'status' || method === 'POST' && demoDwellRoute[1] !== 'status')) {
    if (method === 'POST' && !isSameOrigin(req, config.appUrl)) return error(res, 403, 'Cross-origin requests are not allowed.');
    const token = cookies.unlock_sid;
    const eventId = cleanText(method === 'GET' ? url.searchParams.get('event_id') : body.eventId, 80);
    const row = token && db.prepare(`SELECT e.id,e.position,e.unlock_session_id,us.status,st.destination_url,st.ad_script_one,st.ad_script_two,st.ad_script_one_enabled,st.ad_script_two_enabled
      FROM unlock_step_events e JOIN unlock_sessions us ON us.id=e.unlock_session_id
      JOIN unlock_step_settings st ON st.position=e.position
      WHERE e.id=? AND e.event_type='activated' AND us.token_hash=? AND us.status='in_progress'`).get(eventId, hashToken(token));
    const hasActiveScripts=Boolean((row?.ad_script_one_enabled&&row.ad_script_one)||(row?.ad_script_two_enabled&&row.ad_script_two));
    if (!row || (!/^https?:\/\//i.test(row.destination_url) && !hasActiveScripts)) return error(res, 404, 'No ad destination or enabled scripts are configured for this step.');
    const now = Date.now();
    if (demoDwellRoute[1] === 'start') {
      db.prepare(`INSERT INTO demo_dwell_sessions(event_id,unlock_session_id,position,active_seconds,last_ping_at_ms)
        VALUES (?,?,?,0,?) ON CONFLICT(event_id) DO UPDATE SET last_ping_at_ms=excluded.last_ping_at_ms`)
        .run(row.id,row.unlock_session_id,row.position,now);
    } else if (demoDwellRoute[1] === 'restart') {
      db.prepare(`INSERT INTO demo_dwell_sessions(event_id,unlock_session_id,position,active_seconds,last_ping_at_ms,completed_at)
        VALUES (?,?,?,0,?,NULL) ON CONFLICT(event_id) DO UPDATE SET active_seconds=0,last_ping_at_ms=excluded.last_ping_at_ms,completed_at=NULL`)
        .run(row.id,row.unlock_session_id,row.position,now);
    } else if (demoDwellRoute[1] === 'ping') {
      const progress = db.prepare('SELECT active_seconds,last_ping_at_ms FROM demo_dwell_sessions WHERE event_id=? AND unlock_session_id=?').get(row.id,row.unlock_session_id);
      if (!progress) return error(res, 409, 'Open the demo partner page first.');
      const elapsedMs = now - Number(progress.last_ping_at_ms);
      if (elapsedMs >= 750) {
        const seconds = Math.min(10,Number(progress.active_seconds) + Math.min(1.5,elapsedMs/1000));
        db.prepare(`UPDATE demo_dwell_sessions SET active_seconds=?,last_ping_at_ms=?,
          completed_at=CASE WHEN ? >= 10 THEN COALESCE(completed_at,datetime('now')) ELSE completed_at END
          WHERE event_id=? AND unlock_session_id=?`).run(seconds,now,seconds,row.id,row.unlock_session_id);
      }
    }
    const progress = db.prepare('SELECT active_seconds FROM demo_dwell_sessions WHERE event_id=? AND unlock_session_id=?').get(row.id,row.unlock_session_id);
    return json(res,200,{seconds:Math.min(10,Number(progress?.active_seconds||0)),requiredSeconds:10,complete:Number(progress?.active_seconds||0)>=10});
  }

  const activateMatch = path.match(/^\/unlock\/sessions\/([^/]+)\/steps\/(\d+)\/activate$/);
  if (activateMatch && method === 'POST') {
    if (!isSameOrigin(req, config.appUrl)) return error(res, 403, 'Cross-origin requests are not allowed.');
    const session = findUnlockSession(db, cookies.unlock_sid, activateMatch[1]);
    if (!session || session.expires_at <= new Date().toISOString() || session.status !== 'in_progress') return error(res, 410, 'This unlock session has expired or is complete.');
    const position = Number(activateMatch[2]);
    const settings = db.prepare('SELECT * FROM unlock_step_settings WHERE position=? AND enabled=1').get(position);
    const enabled = db.prepare('SELECT * FROM unlock_step_settings WHERE enabled=1 ORDER BY display_order').all();
    const existingCompleted = db.prepare("SELECT position FROM unlock_step_events WHERE unlock_session_id=? AND event_type='acknowledged'").all(session.id).map(x => x.position);
    const next = nextStepPosition(enabled, existingCompleted);
    if (!settings || position !== next) return error(res, 409, 'Complete the current step before opening another.');
    const hasAdScripts=Boolean((settings.ad_script_one_enabled&&settings.ad_script_one)||(settings.ad_script_two_enabled&&settings.ad_script_two));
    if ((!settings.destination_url || /^demo:\/\//i.test(settings.destination_url)) && !hasAdScripts) return error(res, 409, `Configure a direct ad URL or ad scripts for step ${position} in Admin first.`);
    let event = db.prepare("SELECT * FROM unlock_step_events WHERE unlock_session_id=? AND position=? AND event_type='activated'").get(session.id, position);
    if (!event) {
      event = { id: id() };
      db.prepare(`INSERT INTO unlock_step_events(id,unlock_session_id,position,event_type,integration_id)
        VALUES (?,?,?,'activated',?)`).run(event.id, session.id, position, settings.integration_id || null);
    }
    let destinationUrl = settings.destination_url && !/^demo:\/\//i.test(settings.destination_url) ? settings.destination_url.replaceAll('{event_id}', encodeURIComponent(event.id)).replaceAll('{callback_url}', encodeURIComponent(`${config.appUrl}/api/v1/integrations/callback`)) : '';
    const now = Date.now();
    db.prepare(`INSERT INTO demo_dwell_sessions(event_id,unlock_session_id,position,active_seconds,last_ping_at_ms)
      VALUES (?,?,?,0,?) ON CONFLICT(event_id) DO NOTHING`).run(event.id,session.id,position,now);
    const stepStatus = db.prepare("SELECT 1 FROM unlock_step_events WHERE unlock_session_id=? AND position=? AND event_type='provider_verified'").get(session.id, position) ? 'verified' : settings.policy === 'provider_callback' ? 'awaiting_provider' : 'clickthrough_only';
    return json(res, 200, { eventId: event.id, destinationUrl, hasAdScripts, policy: settings.policy, status: stepStatus, message: stepStatus === 'clickthrough_only' ? 'This records a click-through action only. It does not confirm an ad impression, view, conversion, or payable event.' : 'Waiting for the configured provider’s signed verification callback.' });
  }

  const completeMatch = path.match(/^\/unlock\/sessions\/([^/]+)\/steps\/(\d+)\/complete$/);
  if (completeMatch && method === 'POST') {
    if (!isSameOrigin(req, config.appUrl)) return error(res, 403, 'Cross-origin requests are not allowed.');
    const session = findUnlockSession(db, cookies.unlock_sid, completeMatch[1]);
    if (!session || session.expires_at <= new Date().toISOString() || session.status !== 'in_progress') return error(res, 410, 'This unlock session has expired or is complete.');
    const position = Number(completeMatch[2]);
    const settings = db.prepare('SELECT * FROM unlock_step_settings WHERE position=? AND enabled=1').get(position);
    const enabled = db.prepare('SELECT * FROM unlock_step_settings WHERE enabled=1 ORDER BY display_order').all();
    const completed = db.prepare("SELECT position FROM unlock_step_events WHERE unlock_session_id=? AND event_type='acknowledged'").all(session.id).map(x => x.position);
    if (!settings || nextStepPosition(enabled, completed) !== position) return error(res, 409, 'Complete the current step before continuing.');
    const activation = db.prepare("SELECT id FROM unlock_step_events WHERE unlock_session_id=? AND position=? AND event_type='activated'").get(session.id, position);
    if (!activation) return error(res, 409, 'Open this step first.');
    if (/^https?:\/\//i.test(settings.destination_url) || (settings.ad_script_one_enabled&&settings.ad_script_one)||(settings.ad_script_two_enabled&&settings.ad_script_two)) {
      const dwell = db.prepare('SELECT active_seconds FROM demo_dwell_sessions WHERE event_id=? AND unlock_session_id=?').get(activation.id,session.id);
      if (Number(dwell?.active_seconds||0) < 10) return error(res,409,'Keep the ad open for the full 10 seconds before continuing.');
    }
    if (settings.policy === 'provider_callback' && !db.prepare("SELECT id FROM unlock_step_events WHERE unlock_session_id=? AND position=? AND event_type='provider_verified'").get(session.id, position)) return error(res, 409, 'The provider has not verified this step yet.');
    db.prepare(`INSERT OR IGNORE INTO unlock_step_events(id,unlock_session_id,position,event_type,integration_id)
      VALUES (?,?,?,'acknowledged',?)`).run(id(), session.id, position, settings.integration_id || null);
    const doneNow = [...completed, position];
    const next = nextStepPosition(enabled, doneNow);
    if (next === null) {
      db.prepare("UPDATE unlock_sessions SET status='completed',current_step=6,completed_at=datetime('now') WHERE id=?").run(session.id);
      db.prepare(`INSERT INTO click_events(id,short_link_id,owner_id,unlock_session_id,event_type,device_category,referrer_domain,is_bot,eligible_status)
        SELECT ?,l.id,l.owner_id,?,'unlock_completed',v.device_category,v.referrer_domain,v.is_bot,v.eligible_status FROM short_links l JOIN click_events v ON v.short_link_id=l.id AND v.unlock_session_id=? AND v.event_type='visit' WHERE l.id=?`)
        .run(id(), session.id, session.id, session.short_link_id);
    } else {
      db.prepare('UPDATE unlock_sessions SET current_step=? WHERE id=?').run(next, session.id);
    }
    return json(res, 200, unlockPayload(db, db.prepare('SELECT * FROM unlock_sessions WHERE id=?').get(session.id), db.prepare('SELECT * FROM short_links WHERE id=?').get(session.short_link_id)));
  }

  const redeemMatch = path.match(/^\/unlock\/sessions\/([^/]+)\/redeem$/);
  if (redeemMatch && method === 'POST') {
    if (!isSameOrigin(req, config.appUrl)) return error(res, 403, 'Cross-origin requests are not allowed.');
    const session = findUnlockSession(db, cookies.unlock_sid, redeemMatch[1]);
    if (!session || session.expires_at <= new Date().toISOString() || session.status !== 'completed') return error(res, 409, 'Complete all required steps before unlocking the destination.');
    const enabled = db.prepare('SELECT * FROM unlock_step_settings WHERE enabled=1').all();
    const acknowledged = db.prepare("SELECT position FROM unlock_step_events WHERE unlock_session_id=? AND event_type='acknowledged'").all(session.id).map(x => x.position);
    if (nextStepPosition(enabled, acknowledged) !== null) return error(res, 409, 'Complete all required steps before unlocking the destination.');
    const ticket = randomToken();
    const event = db.prepare("SELECT * FROM click_events WHERE unlock_session_id=? AND event_type='visit'").get(session.id);
    const callbackVerified = Boolean(session.callback_verified) && !event?.is_bot;
    db.exec('BEGIN IMMEDIATE');
    try {
      const changed = db.prepare("UPDATE unlock_sessions SET redirect_token_hash=? WHERE id=? AND status='completed' AND redirect_token_hash IS NULL").run(hashToken(ticket), session.id);
      if (!changed.changes) { db.exec('ROLLBACK'); return error(res, 409, 'This unlock session has already been redeemed.'); }
      if (event) {
        db.prepare("UPDATE click_events SET eligible_status=? WHERE id=?").run(callbackVerified ? 'eligible' : event.is_bot ? 'ineligible' : 'ineligible', event.id);
        if (callbackVerified) {
          const rate = Number(getSetting(db, 'earning_rate_paise_per_1000', '0'));
          const amount = calculateEarning(rate, 1);
          if (amount > 0) {
            const earningId = id();
            db.prepare(`INSERT OR IGNORE INTO earning_ledger(id,user_id,link_id,source_event_id,type,status,amount_paise,rate_paise_per_1000,eligible_event_count,currency,reason)
              VALUES (?,?,?,?,'earning','pending',?,?,1,?,'Provider-verified eligible event; pending review')`)
              .run(earningId, db.prepare('SELECT owner_id FROM short_links WHERE id=?').get(session.short_link_id).owner_id, session.short_link_id, event.id, amount, rate, getSetting(db, 'currency', config.currency));
          }
        }
      }
      db.exec('COMMIT');
    } catch (e) { db.exec('ROLLBACK'); throw e; }
    return json(res, 200, { redirectPath: `/r/${ticket}` });
  }

  if (method === 'POST' && path === '/integrations/callback') {
    if (!config.callbackSecret) return error(res, 503, 'Provider callback verification is not configured.');
    const raw = req.rawBody ?? '';
    const signature = String(req.headers['x-provider-signature'] ?? '').replace(/^sha256=/, '');
    const expected = createHmac('sha256', config.callbackSecret).update(raw).digest('hex');
    if (!safeEqualHex(signature, expected)) return error(res, 401, 'Invalid provider signature.');
    const eventId = cleanText(body.eventId, 100);
    const providerEventId = cleanText(body.providerEventId, 160);
    if (!eventId || !providerEventId || typeof body.eligible !== 'boolean') return error(res, 400, 'Callback requires eventId, providerEventId, and boolean eligible.');
    const event = db.prepare(`SELECT e.*,s.id AS session_id,s.short_link_id,s.status AS session_status,st.policy,st.integration_id,st.enabled,
      i.callback_enabled,i.enabled AS integration_enabled FROM unlock_step_events e JOIN unlock_sessions s ON s.id=e.unlock_session_id
      JOIN unlock_step_settings st ON st.position=e.position LEFT JOIN ad_integrations i ON i.id=e.integration_id
      WHERE e.id=? AND e.event_type='activated'`).get(eventId);
    if (!event || !event.enabled || event.policy !== 'provider_callback' || !event.integration_id || !event.callback_enabled || !event.integration_enabled) return error(res, 403, 'This callback does not match an enabled provider-verified step.');
    if (db.prepare('SELECT provider_event_id FROM callback_receipts WHERE provider_event_id=?').get(providerEventId)) return json(res, 200, { ok: true, duplicate: true });
    db.exec('BEGIN IMMEDIATE');
    try {
      db.prepare('INSERT INTO callback_receipts(provider_event_id,event_id) VALUES (?,?)').run(providerEventId, eventId);
      if (body.eligible) {
        db.prepare(`INSERT OR IGNORE INTO unlock_step_events(id,unlock_session_id,position,event_type,integration_id,provider_event_id)
          VALUES (?,?,?,'provider_verified',?,?)`).run(id(), event.session_id, event.position, event.integration_id, providerEventId);
        db.prepare('UPDATE unlock_sessions SET callback_verified=1 WHERE id=?').run(event.session_id);
      } else {
        db.prepare(`INSERT OR IGNORE INTO unlock_step_events(id,unlock_session_id,position,event_type,integration_id,provider_event_id)
          VALUES (?,?,?,'failed',?,?)`).run(id(), event.session_id, event.position, event.integration_id, providerEventId);
      }
      db.exec('COMMIT');
    } catch (e) { db.exec('ROLLBACK'); throw e; }
    return json(res, 200, { ok: true, verified: body.eligible });
  }

  if (method === 'GET' && path === '/admin/blogs') {
    const me = admin(); if (!me) return;
    const q = cleanText(url.searchParams.get('q'), 120);
    const status = cleanText(url.searchParams.get('status'), 20);
    const filterStatus = ['draft','published'].includes(status) ? status : '';
    const items = db.prepare(`SELECT b.id,b.slug,b.title,b.excerpt,b.cover_image,b.status,b.view_count,b.created_at,b.updated_at,b.published_at,
      u.display_name AS author_name
      FROM blog_posts b JOIN users u ON u.id=b.created_by
      WHERE (b.title LIKE ? OR b.slug LIKE ? OR b.excerpt LIKE ?) AND (?='' OR b.status=?)
      ORDER BY b.updated_at DESC LIMIT 200`).all(`%${q}%`,`%${q}%`,`%${q}%`,filterStatus,filterStatus);
    const stats = db.prepare(`SELECT COUNT(*) AS total,
      SUM(CASE WHEN status='published' THEN 1 ELSE 0 END) AS published,
      SUM(CASE WHEN status='draft' THEN 1 ELSE 0 END) AS drafts,
      COALESCE(SUM(view_count),0) AS views FROM blog_posts`).get();
    return json(res, 200, { items, stats });
  }
  const adminBlogStatusMatch = path.match(/^\/admin\/blogs\/([^/]+)\/status$/);
  if (adminBlogStatusMatch && method === 'PATCH') {
    const me = admin(); if (!me || !csrf(me)) return;
    const status = String(body.status || '');
    if (!['draft','published'].includes(status)) return error(res, 400, 'Choose draft or published status.');
    const blog = db.prepare('SELECT id,status FROM blog_posts WHERE id=?').get(adminBlogStatusMatch[1]);
    if (!blog) return error(res, 404, 'Blog post not found.');
    db.prepare(`UPDATE blog_posts SET status=?,published_at=CASE WHEN ?='published' THEN COALESCE(published_at,datetime('now')) ELSE NULL END,
      updated_at=datetime('now') WHERE id=?`).run(status,status,blog.id);
    audit(db, me.id, 'blog_status_changed', 'blog_post', blog.id, '', { from: blog.status, to: status });
    return json(res, 200, { ok: true, status });
  }
  const adminBlogMatch = path.match(/^\/admin\/blogs\/([^/]+)$/);
  if (method === 'GET' && adminBlogMatch) {
    const me = admin(); if (!me) return;
    const blog = db.prepare(`SELECT id,slug,title,excerpt,cover_image,content_html,status,view_count,created_at,updated_at,published_at
      FROM blog_posts WHERE id=?`).get(adminBlogMatch[1]);
    if (!blog) return error(res, 404, 'Blog post not found.');
    return json(res, 200, { blog });
  }
  if (method === 'POST' && path === '/admin/blogs') {
    const me = admin(); if (!me || !csrf(me)) return;
    const parsed = normalizeBlogInput(body);
    if (parsed.error) return error(res, 400, parsed.error);
    const { slug,title,excerpt,coverImage,contentHtml,status } = parsed.value;
    if (db.prepare('SELECT 1 FROM blog_posts WHERE slug=?').get(slug)) return error(res, 409, 'That blog URL is already in use. Choose a different slug.');
    const blogId = id();
    db.prepare(`INSERT INTO blog_posts(id,slug,title,excerpt,cover_image,content_html,status,created_by,published_at)
      VALUES(?,?,?,?,?,?,?,?,CASE WHEN ?='published' THEN datetime('now') ELSE NULL END)`)
      .run(blogId,slug,title,excerpt,coverImage,contentHtml,status,me.id,status);
    audit(db, me.id, 'blog_created', 'blog_post', blogId, '', { slug,status });
    const blog = db.prepare('SELECT id,slug,title,excerpt,cover_image,content_html,status,view_count,created_at,updated_at,published_at FROM blog_posts WHERE id=?').get(blogId);
    return json(res, 201, { blog, publicUrl: status === 'published' ? `${config.appUrl}/blog/${slug}` : '' });
  }
  if (adminBlogMatch && method === 'PATCH') {
    const me = admin(); if (!me || !csrf(me)) return;
    const current = db.prepare('SELECT id,status,slug FROM blog_posts WHERE id=?').get(adminBlogMatch[1]);
    if (!current) return error(res, 404, 'Blog post not found.');
    const parsed = normalizeBlogInput(body);
    if (parsed.error) return error(res, 400, parsed.error);
    const { slug,title,excerpt,coverImage,contentHtml,status } = parsed.value;
    if (db.prepare('SELECT 1 FROM blog_posts WHERE slug=? AND id<>?').get(slug,current.id)) return error(res, 409, 'That blog URL is already in use. Choose a different slug.');
    db.prepare(`UPDATE blog_posts SET slug=?,title=?,excerpt=?,cover_image=?,content_html=?,status=?,
      published_at=CASE WHEN ?='published' THEN COALESCE(published_at,datetime('now')) ELSE NULL END,updated_at=datetime('now') WHERE id=?`)
      .run(slug,title,excerpt,coverImage,contentHtml,status,status,current.id);
    audit(db, me.id, 'blog_updated', 'blog_post', current.id, '', { slug,status });
    const blog = db.prepare('SELECT id,slug,title,excerpt,cover_image,content_html,status,view_count,created_at,updated_at,published_at FROM blog_posts WHERE id=?').get(current.id);
    return json(res, 200, { blog, publicUrl: status === 'published' ? `${config.appUrl}/blog/${slug}` : '' });
  }

  if (method === 'GET' && path === '/admin/dashboard') {
    const me = admin(); if (!me) return;
    const analytics = analyticsOverview(db);
    const users = db.prepare(`SELECT COUNT(*) AS total,SUM(CASE WHEN status='active' THEN 1 ELSE 0 END) AS active,
      SUM(CASE WHEN verified_at IS NOT NULL THEN 1 ELSE 0 END) AS verified,
      SUM(CASE WHEN status='pending_verification' THEN 1 ELSE 0 END) AS pendingVerification,
      SUM(CASE WHEN date(created_at)=date('now') THEN 1 ELSE 0 END) AS newToday,
      SUM(CASE WHEN date(created_at)>=date('now','start of month') THEN 1 ELSE 0 END) AS newThisMonth FROM users`).get();
    const fileLinkExpr = "(lower(COALESCE(campaign,'')) LIKE '%telegram file link%' OR lower(COALESCE(description,'')) LIKE '%file shared through telegram storage%')";
    const postLinkExpr = "(lower(COALESCE(campaign,'')) LIKE '%mylink post%' OR lower(COALESCE(description,'')) LIKE '%shared post link%')";
    const creations = db.prepare(`SELECT
      SUM(CASE WHEN NOT ${fileLinkExpr} AND NOT ${postLinkExpr} THEN 1 ELSE 0 END) AS links,
      SUM(CASE WHEN ${fileLinkExpr} THEN 1 ELSE 0 END) AS files,
      SUM(CASE WHEN NOT ${fileLinkExpr} AND NOT ${postLinkExpr} AND status='active' THEN 1 ELSE 0 END) AS activeLinks,
      SUM(CASE WHEN ${fileLinkExpr} AND status='active' THEN 1 ELSE 0 END) AS activeFiles,
      SUM(CASE WHEN status='flagged' THEN 1 ELSE 0 END) AS flaggedLinks
      FROM short_links WHERE status<>'deleted'`).get();
    creations.trees = db.prepare(`SELECT COUNT(*) AS total,SUM(CASE WHEN status='active' THEN 1 ELSE 0 END) AS active,
      SUM(CASE WHEN status='paused' THEN 1 ELSE 0 END) AS paused FROM link_trees`).get();
    creations.posts = db.prepare(`SELECT COUNT(*) AS total,SUM(CASE WHEN status='published' THEN 1 ELSE 0 END) AS published,
      SUM(CASE WHEN status='draft' THEN 1 ELSE 0 END) AS drafts FROM articles`).get();
    for (const key of ['links','files','activeLinks','activeFiles','flaggedLinks']) creations[key] = Number(creations[key] || 0);
    creations.trees = Object.fromEntries(Object.entries(creations.trees).map(([key,value])=>[key,Number(value||0)]));
    creations.posts = Object.fromEntries(Object.entries(creations.posts).map(([key,value])=>[key,Number(value||0)]));
    creations.total = creations.links + creations.files + creations.trees.total + creations.posts.total;
    const dateWindow = db.prepare(`SELECT date('now') AS today,date('now','-13 days') AS start`).get();
    const traffic14Days = analyticsOverview(db,null,`${dateWindow.start} 00:00:00`);
    const trafficToday = analyticsOverview(db,null,`${dateWindow.today} 00:00:00`);
    const earnings = db.prepare(`SELECT COALESCE(SUM(CASE WHEN status IN ('pending','estimated') THEN amount_paise ELSE 0 END),0) AS pending,
      COALESCE(SUM(CASE WHEN status='approved' THEN amount_paise ELSE 0 END),0) AS approved,
      COALESCE(SUM(CASE WHEN status='on_hold' THEN amount_paise ELSE 0 END),0) AS onHold,
      COALESCE(SUM(CASE WHEN type='payout' THEN -amount_paise ELSE 0 END),0) AS paid,
      SUM(CASE WHEN status IN ('pending','estimated','on_hold') THEN 1 ELSE 0 END) AS reviewCount FROM earning_ledger`).get();
    const withdrawals = db.prepare(`SELECT COUNT(*) AS pendingCount,COALESCE(SUM(amount_paise),0) AS pendingPaise,
      SUM(CASE WHEN status='requested' THEN 1 ELSE 0 END) AS requestedCount,
      SUM(CASE WHEN status IN ('under_review','approved','processing') THEN 1 ELSE 0 END) AS inProgressCount FROM withdrawal_requests
      WHERE status IN ('requested','under_review','approved','processing')`).get();
    const operations = {
      supportOpen: Number(db.prepare("SELECT COUNT(*) AS n FROM support_tickets WHERE status IN ('open','in_progress')").get().n || 0),
      draftPosts: Number(creations.posts.drafts),
      flaggedLinks: Number(creations.flaggedLinks),
    };
    const funnel = db.prepare(`SELECT e.position,SUM(CASE WHEN e.event_type='activated' THEN 1 ELSE 0 END) AS activated,
      SUM(CASE WHEN e.event_type='acknowledged' THEN 1 ELSE 0 END) AS completed,
      SUM(CASE WHEN e.event_type='provider_verified' THEN 1 ELSE 0 END) AS verified
      FROM unlock_step_events e GROUP BY e.position ORDER BY e.position`).all();
    const performingLinks = db.prepare(`SELECT l.id,l.code,l.title,l.status,
      SUM(CASE WHEN ce.event_type='visit' THEN 1 ELSE 0 END) AS visits,l.created_at,
      CASE WHEN ${fileLinkExpr} THEN 'file' ELSE 'link' END AS type
      FROM short_links l LEFT JOIN click_events ce ON ce.short_link_id=l.id
      WHERE l.status<>'deleted' AND NOT ${postLinkExpr}
      GROUP BY l.id ORDER BY visits DESC,l.created_at DESC LIMIT 30`).all().map(item=>({
        id:item.id,type:item.type,title:item.title||item.code,path:`/s/${encodeURIComponent(item.code)}`,
        status:item.status,visits:Number(item.visits||0),createdAt:item.created_at,
      }));
    const performingPosts = db.prepare(`SELECT id,slug,title,status,view_count AS visits,created_at FROM articles
      ORDER BY view_count DESC,created_at DESC LIMIT 20`).all().map(item=>({
        id:item.id,type:'post',title:item.title||item.slug,path:`/post/${encodeURIComponent(item.slug)}`,
        status:item.status,visits:Number(item.visits||0),createdAt:item.created_at,
      }));
    const performingTrees = db.prepare(`SELECT id,slug,title,status,view_count AS visits,created_at FROM link_trees
      ORDER BY view_count DESC,created_at DESC LIMIT 20`).all().map(item=>({
        id:item.id,type:'tree',title:item.title||item.slug,path:`/tree/${encodeURIComponent(item.slug)}`,
        status:item.status,visits:Number(item.visits||0),createdAt:item.created_at,
      }));
    const performingCreations=[...performingLinks,...performingPosts,...performingTrees]
      .sort((a,b)=>b.visits-a.visits||String(b.createdAt).localeCompare(String(a.createdAt))).slice(0,8);
    return json(res, 200, { users, creations, analytics, traffic14Days, trafficToday, earnings, withdrawals, operations, funnel, performingCreations, generatedAt:new Date().toISOString() });
  }

  if (method === 'GET' && path === '/admin/users') {
    const me = admin(); if (!me) return;
    const q = cleanText(url.searchParams.get('q'), 120);
    const status = cleanText(url.searchParams.get('status'), 30);
    const allowedStatuses=['active','pending_verification','suspended','banned','closed'];
    if(status&&!allowedStatuses.includes(status))return error(res,400,'Choose a valid account status.');
    const limit = Math.min(50, Math.max(1, Number(url.searchParams.get('limit') ?? 20)));
    const page = Math.max(1, Number(url.searchParams.get('page') ?? 1));
    const offset = (page-1)*limit, like=`%${q}%`;
    const total=Number(db.prepare(`SELECT COUNT(*) AS total FROM users u
      WHERE (?='' OR u.email LIKE ? OR u.display_name LIKE ? OR u.id LIKE ? OR COALESCE(u.public_id,'') LIKE ?)
      AND (?='' OR u.status=?)`).get(q,like,like,like,like,status,status).total);
    const summary=db.prepare(`SELECT COUNT(*) AS total,
      SUM(CASE WHEN status='active' THEN 1 ELSE 0 END) AS active,
      SUM(CASE WHEN status='pending_verification' THEN 1 ELSE 0 END) AS pending,
      SUM(CASE WHEN status IN ('suspended','banned') THEN 1 ELSE 0 END) AS restricted,
      SUM(CASE WHEN status='closed' THEN 1 ELSE 0 END) AS closed
      FROM users`).get();
    const rows = db.prepare(`SELECT u.id,u.public_id,u.email,u.display_name,u.role,u.status,u.created_at,u.verified_at,
      (SELECT COUNT(*) FROM short_links l WHERE l.owner_id=u.id AND l.status<>'deleted'
        AND lower(COALESCE(l.campaign,'')) NOT LIKE '%telegram file link%'
        AND lower(COALESCE(l.description,'')) NOT LIKE '%file shared through telegram storage%'
        AND lower(COALESCE(l.campaign,'')) NOT LIKE '%mylink post%'
        AND lower(COALESCE(l.description,'')) NOT LIKE '%shared post link%') AS link_count,
      (SELECT COUNT(*) FROM short_links l WHERE l.owner_id=u.id AND l.status<>'deleted'
        AND (lower(COALESCE(l.campaign,'')) LIKE '%telegram file link%' OR lower(COALESCE(l.description,'')) LIKE '%file shared through telegram storage%')) AS file_count,
      (SELECT COUNT(*) FROM link_trees t WHERE t.user_id=u.id) AS tree_count,
      (SELECT COUNT(*) FROM articles a WHERE a.user_id=u.id) AS post_count,
      (SELECT COUNT(*) FROM click_events ce WHERE ce.owner_id=u.id AND ce.event_type='visit') AS raw_visits,
      (SELECT COALESCE(SUM(amount_paise),0) FROM earning_ledger el WHERE el.user_id=u.id AND el.status IN ('pending','estimated','approved','paid','on_hold')) AS earnings_paise,
      (SELECT COALESCE(SUM(amount_paise),0) FROM earning_ledger el WHERE el.user_id=u.id AND el.status IN ('approved','paid')) AS balance_paise,
      (SELECT COALESCE(SUM(amount_paise),0) FROM withdrawal_requests wr WHERE wr.user_id=u.id AND wr.status IN ('requested','under_review','approved','processing')) AS reserved_paise
      FROM users u WHERE (?='' OR u.email LIKE ? OR u.display_name LIKE ? OR u.id LIKE ? OR COALESCE(u.public_id,'') LIKE ?)
      AND (?='' OR u.status=?) ORDER BY u.created_at DESC,u.id LIMIT ? OFFSET ?`).all(q,like,like,like,like,status,status,limit,offset);
    return json(res, 200, { items:rows.map(row=>({...row,creation_count:Number(row.link_count||0)+Number(row.file_count||0)+Number(row.tree_count||0)+Number(row.post_count||0)})), total, page, pageSize:limit, pages:Math.max(1,Math.ceil(total/limit)), summary });
  }
  const adminUserMatch = path.match(/^\/admin\/users\/([^/]+)\/status$/);
  if (adminUserMatch && method === 'PATCH') {
    const me = admin(); if (!me || !csrf(me)) return;
    const status = body.status;
    const reason = cleanText(body.reason, 500);
    if (!['active','suspended','banned','closed'].includes(status) || reason.length < 5) return error(res, 400, 'Choose an account status and provide a reason of at least 5 characters.');
    const target = db.prepare('SELECT id,email,status FROM users WHERE id=?').get(adminUserMatch[1]);
    if (!target) return error(res, 404, 'User not found.');
    if (target.id === me.id && status !== 'active') return error(res, 400, 'You cannot suspend your own administrator account.');
    if (target.email.endsWith('@deleted.invalid') && status === 'active') return error(res, 409, 'A deleted and anonymized account cannot be reactivated.');
    db.prepare('UPDATE users SET status=? WHERE id=?').run(status, target.id);
    if (status !== 'active') db.prepare('DELETE FROM user_sessions WHERE user_id=?').run(target.id);
    notify(db, target.id, 'Account status updated', `Your account is now ${status.replaceAll('_', ' ')}. Contact support if you need help.`);
    audit(db, me.id, 'user_status_changed', 'user', target.id, reason, { from: target.status, to: status });
    return json(res, 200, { ok: true });
  }
  const adminUserPasswordMatch=path.match(/^\/admin\/users\/([^/]+)\/password$/);
  if(adminUserPasswordMatch&&method==='PATCH'){
    const me=admin();if(!me||!csrf(me))return;
    const target=db.prepare('SELECT id,email,role,status FROM users WHERE id=?').get(adminUserPasswordMatch[1]);
    const password=String(body.password||''),reason=cleanText(body.reason,500);
    if(!target)return error(res,404,'User not found.');
    if(target.role!=='user')return error(res,403,'Administrator passwords must be changed from their own account settings.');
    if(target.status==='closed')return error(res,409,'This account is closed. Reopen it before resetting its password.');
    if(!validatePassword(password)||passwordLooksCompromised(password))return error(res,400,'Use 10–128 characters with uppercase, lowercase, and a number; avoid common passwords.');
    if(reason.length<5)return error(res,400,'Provide a reason of at least 5 characters.');
    db.exec('BEGIN IMMEDIATE');
    try{
      db.prepare('UPDATE users SET password_hash=? WHERE id=?').run(await hashPassword(password),target.id);
      db.prepare('DELETE FROM user_sessions WHERE user_id=?').run(target.id);
      db.prepare("DELETE FROM auth_tokens WHERE user_id=? AND purpose='reset_password'").run(target.id);
      notify(db,target.id,'Password updated by support','An administrator reset your account password. If you did not expect this, contact support.');
      audit(db,me.id,'user_password_reset','user',target.id,reason,{email:target.email});
      db.exec('COMMIT');
    }catch(e){db.exec('ROLLBACK');throw e;}
    return json(res,200,{ok:true});
  }
  const adminUserDeleteMatch=path.match(/^\/admin\/users\/([^/]+)\/delete$/);
  if(adminUserDeleteMatch&&method==='POST'){
    const me=admin();if(!me||!csrf(me))return;
    const target=db.prepare('SELECT id,email,role,status FROM users WHERE id=?').get(adminUserDeleteMatch[1]);
    const reason=cleanText(body.reason,500),confirmEmail=normalizeEmail(body.confirmEmail);
    if(!target)return error(res,404,'User not found.');
    if(target.id===me.id||target.role!=='user')return error(res,403,'You cannot delete your own account or another administrator.');
    if(confirmEmail!==normalizeEmail(target.email)||reason.length<5)return error(res,400,'Confirm the account email and provide a reason of at least 5 characters.');
    db.exec('BEGIN IMMEDIATE');
    try{
      db.prepare("UPDATE users SET email=?,display_name='Deleted account',public_id=NULL,avatar_url='',status='closed',referral_code=NULL,referred_by=NULL,payout_method=NULL,payout_details_cipher=NULL WHERE id=?").run(`deleted+${target.id}@deleted.invalid`,target.id);
      db.prepare('DELETE FROM user_sessions WHERE user_id=?').run(target.id);
      db.prepare('DELETE FROM auth_tokens WHERE user_id=?').run(target.id);
      db.prepare('DELETE FROM user_telegram_settings WHERE user_id=?').run(target.id);
      db.prepare('DELETE FROM user_telegram_bots WHERE user_id=?').run(target.id);
      db.prepare('DELETE FROM user_profile_channels WHERE user_id=?').run(target.id);
      db.prepare("UPDATE short_links SET status='disabled',updated_at=datetime('now') WHERE owner_id=? AND status<>'deleted'").run(target.id);
      db.prepare("UPDATE link_trees SET status='paused',updated_at=datetime('now') WHERE user_id=?").run(target.id);
      db.prepare("UPDATE articles SET status='draft',updated_at=datetime('now') WHERE user_id=?").run(target.id);
      db.prepare("UPDATE withdrawal_requests SET status='cancelled',payout_details_cipher='',reason='Account closed' WHERE user_id=? AND status IN ('requested','under_review','approved','processing')").run(target.id);
      db.prepare("UPDATE withdrawal_requests SET payout_details_cipher='' WHERE user_id=?").run(target.id);
      db.prepare("UPDATE notifications SET read_at=COALESCE(read_at,datetime('now')) WHERE user_id=?").run(target.id);
      audit(db,me.id,'user_deleted_anonymized','user',target.id,reason,{emailAnonymized:true,previousStatus:target.status,financialHistoryRetained:true});
      db.exec('COMMIT');
    }catch(e){db.exec('ROLLBACK');throw e;}
    return json(res,200,{ok:true,anonymized:true});
  }

  if (method === 'GET' && path === '/admin/creations') {
    const me=admin();if(!me)return;
    const type=cleanText(url.searchParams.get('type')||'links',20);
    if(!['links','files','trees','posts'].includes(type))return error(res,400,'Choose links, files, trees, or posts.');
    const q=cleanText(url.searchParams.get('q'),120),status=cleanText(url.searchParams.get('status'),30);
    const page=Math.max(1,Number(url.searchParams.get('page')||1)),limit=Math.min(50,Math.max(1,Number(url.searchParams.get('limit')||20))),offset=(page-1)*limit;
    const fileExpr="(lower(COALESCE(l.campaign,'')) LIKE '%telegram file link%' OR lower(COALESCE(l.description,'')) LIKE '%file shared through telegram storage%')";
    const postLinkExpr="(lower(COALESCE(l.campaign,'')) LIKE '%mylink post%' OR lower(COALESCE(l.description,'')) LIKE '%shared post link%')";
    const shortTypeWhere=type==='files'?fileExpr:`NOT ${fileExpr} AND NOT ${postLinkExpr}`;
    const allowedStatus={links:['active','paused','disabled','flagged','expired'],files:['active','paused','disabled','flagged','expired'],trees:['active','paused'],posts:['draft','published']}[type];
    if(status&&!allowedStatus.includes(status))return error(res,400,'That status is not available for this creation type.');
    let total=0,items=[];
    if(type==='links'||type==='files'){
      const where=[`l.status<>'deleted'`,shortTypeWhere],params=[];
      if(status){where.push('l.status=?');params.push(status);}
      if(q){where.push(`(l.title LIKE ? OR l.code LIKE ? OR l.destination_url LIKE ? OR u.email LIKE ? OR u.display_name LIKE ?)`);params.push(...Array(5).fill(`%${q}%`));}
      const clause=where.join(' AND ');
      total=Number(db.prepare(`SELECT COUNT(*) AS total FROM short_links l JOIN users u ON u.id=l.owner_id WHERE ${clause}`).get(...params).total||0);
      items=db.prepare(`SELECT l.id,l.owner_id,l.code,l.title,l.destination_url,l.campaign,l.description,l.status,l.created_at,l.expires_at,
        u.display_name AS owner_name,u.email AS owner_email,u.status AS owner_status,u.role AS owner_role,
        (SELECT COUNT(*) FROM click_events ce WHERE ce.short_link_id=l.id AND ce.event_type='visit') AS visits
        FROM short_links l JOIN users u ON u.id=l.owner_id WHERE ${clause}
        ORDER BY l.created_at DESC,l.id LIMIT ? OFFSET ?`).all(...params,limit,offset).map(row=>({
          id:row.id,type,title:row.title||row.code,slug:row.code,path:`/s/${encodeURIComponent(row.code)}`,destination_url:row.destination_url,
          status:row.status,visits:Number(row.visits||0),created_at:row.created_at,expires_at:row.expires_at,
          owner_id:row.owner_id,owner_name:row.owner_name,owner_email:row.owner_email,owner_status:row.owner_status,owner_role:row.owner_role,
        }));
    } else {
      const table=type==='trees'?'link_trees':'articles',ownerColumn=type==='trees'?'user_id':'user_id';
      const titleColumn='title',slugColumn='slug',viewColumn=type==='trees'?'view_count':'view_count';
      const where=[],params=[];
      if(status){where.push('c.status=?');params.push(status);}
      if(q){where.push(`(c.title LIKE ? OR c.slug LIKE ? OR u.email LIKE ? OR u.display_name LIKE ?)`);params.push(...Array(4).fill(`%${q}%`));}
      const clause=where.length?`WHERE ${where.join(' AND ')}`:'';
      total=Number(db.prepare(`SELECT COUNT(*) AS total FROM ${table} c JOIN users u ON u.id=c.${ownerColumn} ${clause}`).get(...params).total||0);
      items=db.prepare(`SELECT c.id,c.${ownerColumn} AS owner_id,c.${slugColumn} AS slug,c.${titleColumn} AS title,c.status,c.created_at,c.${viewColumn} AS visits,
        u.display_name AS owner_name,u.email AS owner_email,u.status AS owner_status,u.role AS owner_role
        FROM ${table} c JOIN users u ON u.id=c.${ownerColumn} ${clause}
        ORDER BY c.created_at DESC,c.id LIMIT ? OFFSET ?`).all(...params,limit,offset).map(row=>({
          id:row.id,type,title:row.title||row.slug,slug:row.slug,path:`/${type==='trees'?'tree':'post'}/${encodeURIComponent(row.slug)}`,
          status:row.status,visits:Number(row.visits||0),created_at:row.created_at,
          owner_id:row.owner_id,owner_name:row.owner_name,owner_email:row.owner_email,owner_status:row.owner_status,owner_role:row.owner_role,
        }));
    }
    const linkCounts=db.prepare(`SELECT
      SUM(CASE WHEN NOT ${fileExpr} AND NOT ${postLinkExpr} THEN 1 ELSE 0 END) AS links,
      SUM(CASE WHEN ${fileExpr} THEN 1 ELSE 0 END) AS files
      FROM short_links l WHERE l.status<>'deleted'`).get();
    const typeCounts={
      links:Number(linkCounts.links||0),files:Number(linkCounts.files||0),
      trees:Number(db.prepare('SELECT COUNT(*) AS n FROM link_trees').get().n||0),
      posts:Number(db.prepare('SELECT COUNT(*) AS n FROM articles').get().n||0),
    };
    return json(res,200,{type,items,total,page,pageSize:limit,pages:Math.max(1,Math.ceil(total/limit)),typeCounts});
  }

  const adminCreationStatusMatch=path.match(/^\/admin\/creations\/(links|files|trees|posts)\/([^/]+)\/status$/);
  if(adminCreationStatusMatch&&method==='PATCH'){
    const me=admin();if(!me||!csrf(me))return;
    const [,type,creationId]=adminCreationStatusMatch,status=cleanText(body.status,30),reason=cleanText(body.reason,500);
    if(reason.length<5)return error(res,400,'Provide a review reason with at least 5 characters.');
    const statuses={links:['active','paused','disabled','flagged'],files:['active','paused','disabled','flagged'],trees:['active','paused'],posts:['draft','published']}[type];
    if(!statuses.includes(status))return error(res,400,'That status is not available for this creation type.');
    let row,resourceType;
    if(type==='links'||type==='files'){
      row=db.prepare('SELECT id,owner_id,title,code,status,campaign,description FROM short_links WHERE id=? AND status<>\'deleted\'').get(creationId);
      if(row){const isFile=/telegram file link/i.test(String(row.campaign||''))||/file shared through telegram storage/i.test(String(row.description||''));if((type==='files')!==isFile)row=null;}
      if(row){db.prepare("UPDATE short_links SET status=?,updated_at=datetime('now') WHERE id=?").run(status,row.id);resourceType='short_link';}
    }else if(type==='trees'){
      row=db.prepare('SELECT id,user_id AS owner_id,title,slug,status FROM link_trees WHERE id=?').get(creationId);
      if(row){db.prepare("UPDATE link_trees SET status=?,updated_at=datetime('now') WHERE id=?").run(status,row.id);resourceType='link_tree';}
    }else{
      row=db.prepare('SELECT id,user_id AS owner_id,title,slug,status FROM articles WHERE id=?').get(creationId);
      if(row){db.prepare("UPDATE articles SET status=?,updated_at=datetime('now') WHERE id=?").run(status,row.id);resourceType='article';}
    }
    if(!row)return error(res,404,'Creation not found.');
    const label=type==='trees'?'tree':type==='posts'?'post':type==='files'?'file':'link';
    notify(db,row.owner_id,'Creation status updated',`Your ${label} “${row.title||row.code||row.slug}” is now ${status.replaceAll('_',' ')}. ${reason}`);
    audit(db,me.id,'creation_status_changed',resourceType,row.id,reason,{type,from:row.status,to:status});
    return json(res,200,{ok:true,status});
  }

  const adminCreationMatch=path.match(/^\/admin\/creations\/(links|files|trees|posts)\/([^/]+)$/);
  if(adminCreationMatch&&method==='DELETE'){
    const me=admin();if(!me||!csrf(me))return;
    const [,type,creationId]=adminCreationMatch,reason=cleanText(body.reason,500);
    if(reason.length<5)return error(res,400,'Provide a deletion reason with at least 5 characters.');
    let row,resourceType;
    if(type==='links'||type==='files'){
      row=db.prepare('SELECT id,owner_id,title,code,status,campaign,description FROM short_links WHERE id=? AND status<>\'deleted\'').get(creationId);
      if(row){const isFile=/telegram file link/i.test(String(row.campaign||''))||/file shared through telegram storage/i.test(String(row.description||''));if((type==='files')!==isFile)row=null;}
      if(row){db.prepare("UPDATE short_links SET status='deleted',updated_at=datetime('now') WHERE id=?").run(row.id);resourceType='short_link';}
    }else if(type==='trees'){
      row=db.prepare('SELECT id,user_id AS owner_id,title,slug FROM link_trees WHERE id=?').get(creationId);
      if(row){db.prepare("DELETE FROM creation_view_events WHERE entity_type='tree' AND entity_id=?").run(row.id);db.prepare('DELETE FROM link_trees WHERE id=?').run(row.id);resourceType='link_tree';}
    }else{
      row=db.prepare('SELECT id,user_id AS owner_id,title,slug FROM articles WHERE id=?').get(creationId);
      if(row){db.prepare("DELETE FROM creation_view_events WHERE entity_type='post' AND entity_id=?").run(row.id);db.prepare('DELETE FROM articles WHERE id=?').run(row.id);resourceType='article';}
    }
    if(!row)return error(res,404,'Creation not found.');
    const label=type==='trees'?'tree':type==='posts'?'post':type==='files'?'file':'link';
    notify(db,row.owner_id,'Creation removed',`Your ${label} “${row.title||row.code||row.slug}” was removed after review. ${reason}`);
    audit(db,me.id,'creation_deleted',resourceType,row.id,reason,{type});
    return json(res,200,{ok:true});
  }

  if (method === 'GET' && path === '/admin/links') {
    const me = admin(); if (!me) return;
    const q = cleanText(url.searchParams.get('q'), 120);
    const limit = Math.min(100, Math.max(1, Number(url.searchParams.get('limit') ?? 50)));
    const rows = db.prepare(`SELECT l.id,l.code,l.title,l.status,l.created_at,l.expires_at,u.email AS owner_email,
      (SELECT COUNT(*) FROM click_events ce WHERE ce.short_link_id=l.id AND ce.event_type='visit') AS visits
      FROM short_links l JOIN users u ON u.id=l.owner_id WHERE l.status<>'deleted' AND (l.code LIKE ? OR l.title LIKE ? OR l.destination_url LIKE ? OR u.email LIKE ?)
      ORDER BY l.created_at DESC LIMIT ?`).all(`%${q}%`,`%${q}%`,`%${q}%`,`%${q}%`,limit);
    return json(res, 200, { items: rows });
  }
  const adminLinkMatch = path.match(/^\/admin\/links\/([^/]+)$/);
  if (adminLinkMatch && method === 'PATCH') {
    const me = admin(); if (!me || !csrf(me)) return;
    const status = body.status;
    const reason = cleanText(body.reason, 500);
    if (!['active','paused','disabled','flagged'].includes(status) || reason.length < 5) return error(res, 400, 'Choose a link status and provide a review reason.');
    const row = db.prepare('SELECT id,owner_id,status FROM short_links WHERE id=?').get(adminLinkMatch[1]);
    if (!row) return error(res, 404, 'Link not found.');
    db.prepare("UPDATE short_links SET status=?,updated_at=datetime('now') WHERE id=?").run(status, row.id);
    if (status !== 'active') notify(db, row.owner_id, 'Link status updated', `Your link is now ${status}. ${reason}`);
    audit(db, me.id, 'link_status_changed', 'short_link', row.id, reason, { from: row.status, to: status });
    return json(res, 200, { ok: true });
  }

  if (method === 'GET' && path === '/admin/settings') {
    const me = admin(); if (!me) return;
    return json(res, 200, {
      siteName: getSetting(db, 'site_name', 'Verdant Links'),
      unlockEnabled: getSetting(db, 'unlock_enabled', '1') === '1',
      referralsEnabled: getSetting(db, 'referrals_enabled', '0') === '1',
      minimumWithdrawalPaise: Number(getSetting(db, 'minimum_withdrawal_paise', String(config.minWithdrawalPaise))),
      earningRatePaisePerThousand: Number(getSetting(db, 'earning_rate_paise_per_1000', '0')),
      currency: getSetting(db, 'currency', config.currency),
      unlockTtlMinutes: Number(getSetting(db, 'unlock_ttl_minutes', String(config.unlockTtlMinutes))),
      unlockPreviousTabUrl: getSetting(db, 'unlock_previous_tab_url', ''),
      treeBackgroundDirectLink: getSetting(db, 'tree_background_direct_link', ''),
      callbackConfigured: Boolean(config.callbackSecret),
      steps: db.prepare('SELECT * FROM unlock_step_settings ORDER BY display_order').all(),
      integrations: db.prepare('SELECT * FROM ad_integrations ORDER BY created_at DESC').all(),
    });
  }
  if (method === 'PATCH' && path === '/admin/settings') {
    const me = admin(); if (!me || !csrf(me)) return;
    const siteName = cleanText(body.siteName, 80);
    const rate = Number(body.earningRatePaisePerThousand);
    const min = Number(body.minimumWithdrawalPaise);
    const ttl = Number(body.unlockTtlMinutes);
    if (siteName.length < 2 || !Number.isSafeInteger(rate) || rate < 0 || rate > 100000000 || !Number.isSafeInteger(min) || min < 1 || !Number.isInteger(ttl) || ttl < 5 || ttl > 1440) return error(res, 400, 'Settings contain invalid values.');
    db.exec('BEGIN IMMEDIATE');
    try {
      setSetting(db, 'site_name', siteName, me.id);
      setSetting(db, 'unlock_enabled', body.unlockEnabled ? '1' : '0', me.id);
      setSetting(db, 'referrals_enabled', body.referralsEnabled ? '1' : '0', me.id);
      setSetting(db, 'earning_rate_paise_per_1000', String(rate), me.id);
      setSetting(db, 'minimum_withdrawal_paise', String(min), me.id);
      setSetting(db, 'currency', config.currency, me.id);
      setSetting(db, 'unlock_ttl_minutes', String(ttl), me.id);
      db.prepare('INSERT INTO earning_rates(id,user_share_paise_per_1000,currency,created_by) VALUES (?,?,?,?)').run(id(), rate, config.currency, me.id);
      audit(db, me.id, 'settings_updated', 'settings', 'general', cleanText(body.reason, 500) || 'Administrator settings update');
      db.exec('COMMIT');
    } catch (e) { db.exec('ROLLBACK'); throw e; }
    return json(res, 200, { ok: true });
  }
  if (method === 'GET' && path === '/admin/ads-scripts') {
    const me=admin();if(!me)return;
    const steps=db.prepare('SELECT position,title,ad_script_one,ad_script_two,ad_script_one_enabled,ad_script_two_enabled FROM unlock_step_settings ORDER BY position').all();
    const contentRows=db.prepare('SELECT content_type,slot,script_html,enabled FROM content_ad_scripts ORDER BY content_type,slot').all();
    const contentScripts={posts:[],trees:[],files:[]};for(const row of contentRows)contentScripts[row.content_type].push({slot:Number(row.slot),script:row.script_html,enabled:Boolean(row.enabled)});
    return json(res,200,{steps:steps.map(step=>({position:step.position,title:step.title,scriptOne:step.ad_script_one,scriptTwo:step.ad_script_two,scriptOneEnabled:Boolean(step.ad_script_one_enabled),scriptTwoEnabled:Boolean(step.ad_script_two_enabled)})),contentScripts});
  }
  if (method === 'PATCH' && path === '/admin/ads-scripts') {
    const me=admin();if(!me||!csrf(me))return;
    const isStepUpdate=Array.isArray(body.steps);const isContentUpdate=['posts','trees','files'].includes(body.contentType)&&Array.isArray(body.scripts);
    if(isStepUpdate===isContentUpdate)return error(res,400,'Choose one ad section to update.');
    if(isStepUpdate){if(body.steps.length!==5)return error(res,400,'Provide two ad scripts for all five steps.');const positions=new Set();for(const step of body.steps){const position=Number(step.position);const one=step.scriptOne??'';const two=step.scriptTwo??'';if(!Number.isInteger(position)||position<1||position>5||positions.has(position)||typeof one!=='string'||typeof two!=='string'||typeof step.scriptOneEnabled!=='boolean'||typeof step.scriptTwoEnabled!=='boolean'||one.length>50000||two.length>50000)return error(res,400,'Provide a script on/off setting and two text scripts under 50,000 characters each for every step.');positions.add(position);}}
    else{if(body.scripts.length!==2)return error(res,400,'Each content section needs exactly two ad scripts.');const slots=new Set();for(const script of body.scripts){const slot=Number(script.slot);if(!Number.isInteger(slot)||slot<1||slot>2||slots.has(slot)||typeof script.script!=='string'||script.script.length>50000||typeof script.enabled!=='boolean')return error(res,400,'Each ad script needs a slot, HTML text under 50,000 characters, and its own on/off setting.');slots.add(slot);}}
    db.exec('BEGIN IMMEDIATE');
    try{if(isStepUpdate){for(const step of body.steps)db.prepare("UPDATE unlock_step_settings SET ad_script_one=?,ad_script_two=?,ad_script_one_enabled=?,ad_script_two_enabled=?,updated_at=datetime('now') WHERE position=?").run(step.scriptOne??'',step.scriptTwo??'',step.scriptOneEnabled?1:0,step.scriptTwoEnabled?1:0,Number(step.position));audit(db,me.id,'ad_scripts_updated','unlock_settings','global','Independent link-step ad scripts and toggles updated');}else{const update=db.prepare("UPDATE content_ad_scripts SET script_html=?,enabled=?,updated_by=?,updated_at=datetime('now') WHERE content_type=? AND slot=?");for(const script of body.scripts)update.run(script.script,script.enabled?1:0,me.id,body.contentType,Number(script.slot));audit(db,me.id,'content_ad_scripts_updated','content_ad_scripts',body.contentType,`${body.contentType} ad scripts updated`,{slots:body.scripts.length});}db.exec('COMMIT');}
    catch(e){db.exec('ROLLBACK');throw e;}
    return json(res,200,{ok:true});
  }
  if (method === 'PATCH' && path === '/admin/unlock-steps') {
    const me = admin(); if (!me || !csrf(me)) return;
    if (!Array.isArray(body.steps) || body.steps.length !== 5) return error(res, 400, 'Provide exactly five step configurations.');
    if (body.steps.filter(step => step.enabled).length < 1) return error(res, 400, 'At least one unlock step must remain enabled.');
    const unlockPreviousTabUrl = validateAdDestination(body.unlockPreviousTabUrl ?? getSetting(db, 'unlock_previous_tab_url', ''));
    if (unlockPreviousTabUrl === null) return error(res, 400, 'Unlock button previous-tab URL must be a valid http or https URL.');
    const treeBackgroundDirectLink = validateAdDestination(body.treeBackgroundDirectLink ?? getSetting(db, 'tree_background_direct_link', ''));
    if (treeBackgroundDirectLink === null) return error(res, 400, 'Link tree background Direct Link must be a valid http or https URL.');
    const positions = new Set();
    for (const step of body.steps) {
      const position = Number(step.position);
      const destination = validateAdDestination(step.destinationUrl ?? '');
      const nextTabDestination = validateAdDestination(step.nextTabUrl ?? step.destinationUrl ?? '');
      const policy = step.policy;
      if (!Number.isInteger(position) || position < 1 || position > 5 || positions.has(position) || !cleanText(step.title, 80) || !cleanText(step.buttonLabel, 80) || !cleanText(step.instruction, 240) || destination === null || nextTabDestination === null || !['clickthrough','provider_callback'].includes(policy)) return error(res, 400, 'One or more step settings are invalid.');
      positions.add(position);
      if (policy === 'provider_callback') {
        if (!config.callbackSecret) return error(res, 400, 'Set AD_CALLBACK_SECRET before enabling provider callback verification.');
        const integration = db.prepare('SELECT * FROM ad_integrations WHERE id=? AND enabled=1 AND callback_enabled=1').get(step.integrationId);
        if (!integration) return error(res, 400, `Step ${position} needs an enabled callback integration.`);
      }
    }
    db.exec('BEGIN IMMEDIATE');
    try {
      for (const step of body.steps) {
        const position = Number(step.position);
        db.prepare(`UPDATE unlock_step_settings SET title=?,button_label=?,instruction=?,destination_url=?,next_tab_url=?,enabled=?,display_order=?,policy=?,retry_limit=?,timeout_seconds=?,integration_id=?,updated_at=datetime('now') WHERE position=?`)
          .run(cleanText(step.title, 80), cleanText(step.buttonLabel, 80), cleanText(step.instruction, 240), validateAdDestination(step.destinationUrl ?? ''), validateAdDestination(step.nextTabUrl ?? step.destinationUrl ?? ''), step.enabled ? 1 : 0, Number(step.displayOrder) || position, step.policy, Math.min(10, Math.max(1, Number(step.retryLimit) || 3)), Math.min(3600, Math.max(0, Number(step.timeoutSeconds) || 0)), step.integrationId || null, position);
      }
      setSetting(db, 'unlock_previous_tab_url', unlockPreviousTabUrl, me.id);
      setSetting(db, 'tree_background_direct_link', treeBackgroundDirectLink, me.id);
      audit(db, me.id, 'unlock_steps_updated', 'unlock_settings', 'global', cleanText(body.reason, 500) || 'Step configuration updated');
      db.exec('COMMIT');
    } catch (e) { db.exec('ROLLBACK'); throw e; }
    return json(res, 200, { ok: true });
  }
  if (method === 'GET' && path === '/admin/integrations') {
    const me = admin(); if (!me) return;
    return json(res, 200, { items: db.prepare('SELECT * FROM ad_integrations ORDER BY created_at DESC').all(), callbackConfigured: Boolean(config.callbackSecret) });
  }
  if (method === 'POST' && path === '/admin/integrations') {
    const me = admin(); if (!me || !csrf(me)) return;
    const name = cleanText(body.name, 80);
    const provider = cleanText(body.provider, 80);
    if (name.length < 2 || provider.length < 2) return error(res, 400, 'Enter an integration name and provider.');
    if (body.callbackEnabled && !config.callbackSecret) return error(res, 400, 'Set AD_CALLBACK_SECRET in the server environment before enabling callbacks.');
    const integrationId = id();
    db.prepare('INSERT INTO ad_integrations(id,name,provider,callback_enabled,enabled,created_by) VALUES (?,?,?,?,1,?)').run(integrationId, name, provider, body.callbackEnabled ? 1 : 0, me.id);
    audit(db, me.id, 'ad_integration_created', 'ad_integration', integrationId, '', { provider });
    return json(res, 201, { id: integrationId });
  }

  if (method === 'GET' && path === '/admin/withdrawals') {
    const me = admin(); if (!me) return;
    const status = cleanText(url.searchParams.get('status'), 30),q=cleanText(url.searchParams.get('q'),120);
    const statuses=['requested','under_review','approved','processing','paid','rejected','cancelled'];
    if(status&&!statuses.includes(status))return error(res,400,'Choose a valid withdrawal status.');
    const limit=Math.min(50,Math.max(1,Number(url.searchParams.get('limit')||20))),page=Math.max(1,Number(url.searchParams.get('page')||1)),offset=(page-1)*limit,like=`%${q}%`;
    const total=Number(db.prepare(`SELECT COUNT(*) AS total FROM withdrawal_requests w JOIN users u ON u.id=w.user_id
      WHERE (?='' OR w.status=?) AND (?='' OR u.email LIKE ? OR u.display_name LIKE ? OR w.payout_method LIKE ? OR w.reference LIKE ?)`)
      .get(status,status,q,like,like,like,like).total);
    const summary=db.prepare(`SELECT COUNT(*) AS total,
      SUM(CASE WHEN status IN ('requested','under_review') THEN 1 ELSE 0 END) AS needsReview,
      SUM(CASE WHEN status IN ('requested','under_review','approved','processing') THEN amount_paise ELSE 0 END) AS openAmount,
      SUM(CASE WHEN status='paid' THEN amount_paise ELSE 0 END) AS paidAmount
      FROM withdrawal_requests`).get();
    const rows = db.prepare(`SELECT w.id,w.user_id,w.amount_paise,w.currency,w.status,w.payout_method,w.reference,w.reason,w.created_at,w.updated_at,w.reviewed_at,
      u.email,u.display_name FROM withdrawal_requests w JOIN users u ON u.id=w.user_id
      WHERE (?='' OR w.status=?) AND (?='' OR u.email LIKE ? OR u.display_name LIKE ? OR w.payout_method LIKE ? OR w.reference LIKE ?)
      ORDER BY CASE WHEN w.status IN ('requested','under_review') THEN 0 WHEN w.status IN ('approved','processing') THEN 1 ELSE 2 END,w.created_at DESC
      LIMIT ? OFFSET ?`).all(status,status,q,like,like,like,like,limit,offset);
    return json(res, 200, { items:rows,total,page,pageSize:limit,pages:Math.max(1,Math.ceil(total/limit)),summary });
  }
  const adminWithdrawalMatch = path.match(/^\/admin\/withdrawals\/([^/]+)\/(approve|reject|hold|cancel|processing|paid|payout-details)$/);
  if (adminWithdrawalMatch && (method === 'POST' || method === 'GET' && adminWithdrawalMatch[2] === 'payout-details')) {
    const me = admin(); if (!me || method === 'POST' && !csrf(me)) return;
    const [, withdrawalId, action] = adminWithdrawalMatch;
    const row = db.prepare('SELECT * FROM withdrawal_requests WHERE id=?').get(withdrawalId);
    if (!row) return error(res, 404, 'Withdrawal request not found.');
    if (action === 'payout-details' && method === 'GET') {
      audit(db, me.id, 'payout_details_revealed', 'withdrawal', row.id, 'Manual payout review');
      return json(res, 200, { method: row.payout_method, details: unsealValue(row.payout_details_cipher, config.encryptionKey) });
    }
    const reason = cleanText(body.reason, 500);
    if (reason.length < 5) return error(res, 400, 'Provide a review note of at least 5 characters.');
    const transitions = { approve: ['requested','under_review'], reject: ['requested','under_review','approved','processing'], hold: ['requested','under_review','approved'], cancel: ['requested','under_review','approved'], processing: ['approved'], paid: ['approved','processing'] };
    if (!transitions[action].includes(row.status)) return error(res, 409, `Cannot ${action} a request in ${row.status} status.`);
    db.exec('BEGIN IMMEDIATE');
    try {
      let nextStatus = action === 'approve' ? 'approved' : action === 'reject' ? 'rejected' : action === 'hold' ? 'under_review' : action === 'cancel' ? 'cancelled' : action === 'processing' ? 'processing' : 'paid';
      const reference = action === 'paid' ? cleanText(body.reference, 120) : row.reference;
      if (action === 'paid' && !reference) { db.exec('ROLLBACK'); return error(res, 400, 'Enter the confirmed payout reference before marking this request paid.'); }
      db.prepare(`UPDATE withdrawal_requests SET status=?,reason=?,reference=?,reviewed_by=?,reviewed_at=datetime('now'),updated_at=datetime('now') WHERE id=?`)
        .run(nextStatus, reason || row.reason, reference, me.id, row.id);
      if (action === 'paid') {
        db.prepare(`INSERT INTO earning_ledger(id,user_id,source_event_id,type,status,amount_paise,currency,reason,created_by)
          VALUES (?,?,?,'payout','paid',?,?,?,?)`).run(id(), row.user_id, `withdrawal:${row.id}`, -row.amount_paise, row.currency, `Manual payout ${reference}`, me.id);
      }
      notify(db, row.user_id, `Withdrawal ${nextStatus}`, action === 'reject' || action === 'cancel' ? `Your request was ${nextStatus}: ${reason}` : `Your request is now ${nextStatus}. Note: ${reason}`);
      audit(db, me.id, `withdrawal_${action}`, 'withdrawal', row.id, reason, { from: row.status, to: nextStatus, reference: action === 'paid' ? reference : undefined });
      db.exec('COMMIT');
    } catch (e) { db.exec('ROLLBACK'); throw e; }
    return json(res, 200, { ok: true, status: action === 'approve' ? 'approved' : action === 'reject' ? 'rejected' : action === 'hold' ? 'under_review' : action === 'cancel' ? 'cancelled' : action === 'processing' ? 'processing' : 'paid' });
  }

  if (method === 'GET' && path === '/admin/earnings') {
    const me = admin(); if (!me) return;
    const status = cleanText(url.searchParams.get('status'), 30);
    const rows = db.prepare(`SELECT el.*,u.email,l.code FROM earning_ledger el JOIN users u ON u.id=el.user_id LEFT JOIN short_links l ON l.id=el.link_id
      WHERE (?='' OR el.status=?) ORDER BY el.created_at DESC LIMIT 500`).all(status,status);
    return json(res, 200, { items: rows });
  }
  const earningMatch = path.match(/^\/admin\/earnings\/([^/]+)\/(approve|reject|hold)$/);
  if (earningMatch && method === 'POST') {
    const me = admin(); if (!me || !csrf(me)) return;
    const row = db.prepare("SELECT * FROM earning_ledger WHERE id=? AND type='earning'").get(earningMatch[1]);
    if (!row) return error(res, 404, 'Earning record not found.');
    const action = earningMatch[2]; const reason = cleanText(body.reason, 500);
    if (action !== 'approve' && reason.length < 5) return error(res, 400, 'Provide a reason for this change.');
    if (row.status !== 'pending' && row.status !== 'estimated' && !(action === 'hold' && row.status === 'on_hold')) return error(res, 409, `This earning is already ${row.status}.`);
    const status = action === 'approve' ? 'approved' : action === 'reject' ? 'rejected' : 'on_hold';
    db.prepare('UPDATE earning_ledger SET status=?,reason=? WHERE id=?').run(status, reason || row.reason, row.id);
    notify(db, row.user_id, `Earning ${status}`, `An earning record was marked ${status}. ${reason}`);
    audit(db, me.id, `earning_${action}`, 'earning', row.id, reason);
    return json(res, 200, { ok: true });
  }
  if (method === 'POST' && path === '/admin/earnings/adjustments') {
    const me = admin(); if (!me || !csrf(me)) return;
    const userId = cleanText(body.userId, 80); const amount = Number(body.amountPaise); const reason = cleanText(body.reason, 500);
    if (!Number.isSafeInteger(amount) || amount === 0 || Math.abs(amount) > 100000000 || reason.length < 5 || !db.prepare('SELECT id FROM users WHERE id=?').get(userId)) return error(res, 400, 'Provide a valid user, non-zero amount, and documented reason.');
    const ledgerId = id();
    db.prepare(`INSERT INTO earning_ledger(id,user_id,type,status,amount_paise,currency,reason,created_by)
      VALUES (?,?,'adjustment','approved',?,?,?,?)`).run(ledgerId,userId,amount,getSetting(db,'currency',config.currency),reason,me.id);
    notify(db, userId, 'Balance adjustment', `An administrator recorded an adjustment: ${reason}`);
    audit(db, me.id, 'balance_adjusted', 'user', userId, reason, { amountPaise: amount, ledgerId });
    return json(res, 201, { id: ledgerId });
  }

  if (method === 'GET' && path === '/admin/audit-logs') {
    const me = admin(); if (!me) return;
    const q=cleanText(url.searchParams.get('q'),120),action=cleanText(url.searchParams.get('action'),100),resource=cleanText(url.searchParams.get('resource'),50);
    const page=Math.max(1,Number(url.searchParams.get('page')||1)),limit=Math.min(100,Math.max(1,Number(url.searchParams.get('limit')||25))),offset=(page-1)*limit,like=`%${q}%`;
    const where=`(?='' OR a.action=? ) AND (?='' OR a.resource_type=?) AND (?='' OR a.action LIKE ? OR a.resource_type LIKE ? OR a.resource_id LIKE ? OR a.reason LIKE ? OR a.metadata LIKE ? OR COALESCE(u.email,'') LIKE ?)`;
    const total=Number(db.prepare(`SELECT COUNT(*) AS total FROM audit_logs a LEFT JOIN users u ON u.id=a.actor_id WHERE ${where}`)
      .get(action,action,resource,resource,q,like,like,like,like,like,like).total);
    const rows=db.prepare(`SELECT a.*,u.email AS actor_email FROM audit_logs a LEFT JOIN users u ON u.id=a.actor_id WHERE ${where}
      ORDER BY a.created_at DESC,a.id DESC LIMIT ? OFFSET ?`).all(action,action,resource,resource,q,like,like,like,like,like,like,limit,offset);
    const summary=db.prepare(`SELECT COUNT(*) AS total,
      SUM(CASE WHEN created_at>=datetime('now','-1 day') THEN 1 ELSE 0 END) AS lastDay,
      COUNT(DISTINCT actor_id) AS actors,
      SUM(CASE WHEN action LIKE '%delete%' OR action LIKE '%reject%' OR action LIKE '%suspend%' OR action LIKE '%password%' OR action LIKE '%balance%' OR action LIKE '%earning%' OR action LIKE '%withdrawal%' OR action LIKE '%support%' THEN 1 ELSE 0 END) AS sensitive
      FROM audit_logs`).get();
    const actions=db.prepare('SELECT action,COUNT(*) AS count FROM audit_logs GROUP BY action ORDER BY action').all();
    const resources=db.prepare('SELECT resource_type,COUNT(*) AS count FROM audit_logs GROUP BY resource_type ORDER BY resource_type').all();
    return json(res,200,{items:rows,total,page,pageSize:limit,pages:Math.max(1,Math.ceil(total/limit)),summary,actions,resources});
  }
  if (method === 'GET' && path === '/admin/unlock-sessions') {
    const me = admin(); if (!me) return;
    const rows = db.prepare(`SELECT us.id,us.status,us.current_step,us.callback_verified,us.risk_flags,us.expires_at,us.created_at,
      l.code,l.title,u.email AS owner_email,
      (SELECT COUNT(*) FROM unlock_step_events e WHERE e.unlock_session_id=us.id AND e.event_type='acknowledged') AS completed_steps
      FROM unlock_sessions us JOIN short_links l ON l.id=us.short_link_id JOIN users u ON u.id=l.owner_id
      ORDER BY us.created_at DESC LIMIT 500`).all();
    return json(res, 200, { items: rows });
  }
  if(method==='GET'&&path==='/admin/reports/creations'){
    const me=admin();if(!me)return;
    const fileExpr="(lower(COALESCE(l.campaign,'')) LIKE '%telegram file link%' OR lower(COALESCE(l.description,'')) LIKE '%file shared through telegram storage%')";
    const postExpr="(lower(COALESCE(l.campaign,'')) LIKE '%mylink post%' OR lower(COALESCE(l.description,'')) LIKE '%shared post link%')";
    const linkSummary=where=>db.prepare(`SELECT COUNT(*) AS total,SUM(CASE WHEN l.status='active' THEN 1 ELSE 0 END) AS active,
      COALESCE(SUM((SELECT COUNT(*) FROM click_events ce WHERE ce.short_link_id=l.id AND ce.event_type='visit')),0) AS visits,
      COALESCE(SUM((SELECT COUNT(*) FROM click_events ce WHERE ce.short_link_id=l.id AND ce.event_type='visit' AND ce.eligible_status='eligible')),0) AS eligible,
      COALESCE(SUM((SELECT COALESCE(SUM(el.amount_paise),0) FROM earning_ledger el WHERE el.link_id=l.id AND el.status IN ('pending','estimated','approved','paid'))),0) AS earnings
      FROM short_links l WHERE l.status<>'deleted' AND ${where}`).get();
    const contentSummary=type=>db.prepare(`SELECT COUNT(*) AS total,SUM(CASE WHEN status IN ('published','active') THEN 1 ELSE 0 END) AS active,
      SUM(CASE WHEN status IN ('draft','paused') THEN 1 ELSE 0 END) AS inactive,COALESCE(SUM(view_count),0) AS visits,
      COALESCE(SUM((SELECT COUNT(*) FROM creation_view_events e WHERE e.entity_type=? AND e.entity_id=c.id)),0) AS trackedViews,
      COALESCE(ROUND(AVG((SELECT AVG(e.active_seconds) FROM creation_view_events e WHERE e.entity_type=? AND e.entity_id=c.id)),0),0) AS averageStaySeconds
      FROM ${type==='posts'?'articles':'link_trees'} c`).get(type==='posts'?'post':'tree',type==='posts'?'post':'tree');
    return json(res,200,{reports:{links:linkSummary(`NOT ${fileExpr} AND NOT ${postExpr}`),files:linkSummary(fileExpr),trees:contentSummary('trees'),posts:contentSummary('posts')}});
  }
  const creationReportCsv=path==='/admin/reports/creations.csv'&&method==='GET';
  if(creationReportCsv){
    const me=admin();if(!me)return;const type=cleanText(url.searchParams.get('type'),20);
    if(!['links','files','trees','posts'].includes(type))return error(res,400,'Choose links, files, trees, or posts.');
    const fileExpr="(lower(COALESCE(l.campaign,'')) LIKE '%telegram file link%' OR lower(COALESCE(l.description,'')) LIKE '%file shared through telegram storage%')";
    const postExpr="(lower(COALESCE(l.campaign,'')) LIKE '%mylink post%' OR lower(COALESCE(l.description,'')) LIKE '%shared post link%')";
    let rows,columns;
    if(type==='links'||type==='files'){
      const where=type==='files'?fileExpr:`NOT ${fileExpr} AND NOT ${postExpr}`;
      columns=['created_at','owner_name','owner_email','title','short_code','status','destination','visits','unique_visitors','eligible_visits','earnings_cents','currency'];
      rows=db.prepare(`SELECT l.created_at,u.display_name AS owner_name,u.email AS owner_email,l.title,l.code AS short_code,l.status,l.destination_url AS destination,
        (SELECT COUNT(*) FROM click_events ce WHERE ce.short_link_id=l.id AND ce.event_type='visit') AS visits,
        (SELECT COUNT(DISTINCT ce.unlock_session_id) FROM click_events ce WHERE ce.short_link_id=l.id AND ce.event_type='visit') AS unique_visitors,
        (SELECT COUNT(*) FROM click_events ce WHERE ce.short_link_id=l.id AND ce.event_type='visit' AND ce.eligible_status='eligible') AS eligible_visits,
        (SELECT COALESCE(SUM(el.amount_paise),0) FROM earning_ledger el WHERE el.link_id=l.id AND el.status IN ('pending','estimated','approved','paid')) AS earnings_cents,
        COALESCE((SELECT el.currency FROM earning_ledger el WHERE el.link_id=l.id ORDER BY el.created_at DESC LIMIT 1),'USD') AS currency
        FROM short_links l JOIN users u ON u.id=l.owner_id WHERE l.status<>'deleted' AND ${where} ORDER BY l.created_at DESC LIMIT 100000`).all();
    }else{
      const kind=type==='posts'?'post':'tree',table=type==='posts'?'articles':'link_trees',slugType=type==='posts'?'post':'tree';
      columns=['created_at','owner_name','owner_email','title','slug','status','page_views','tracked_views','average_stay_seconds','device_breakdown','country_breakdown','browser_breakdown'];
      rows=db.prepare(`SELECT c.created_at,u.display_name AS owner_name,u.email AS owner_email,c.title,c.slug,c.status,c.view_count AS page_views,
        (SELECT COUNT(*) FROM creation_view_events e WHERE e.entity_type=? AND e.entity_id=c.id) AS tracked_views,
        COALESCE((SELECT ROUND(AVG(e.active_seconds),0) FROM creation_view_events e WHERE e.entity_type=? AND e.entity_id=c.id),0) AS average_stay_seconds,
        COALESCE((SELECT GROUP_CONCAT(device||':'||n, '; ') FROM (SELECT device,COUNT(*) AS n FROM creation_view_events WHERE entity_type=? AND entity_id=c.id GROUP BY device ORDER BY n DESC LIMIT 8)),'') AS device_breakdown,
        COALESCE((SELECT GROUP_CONCAT(country||':'||n, '; ') FROM (SELECT country,COUNT(*) AS n FROM creation_view_events WHERE entity_type=? AND entity_id=c.id GROUP BY country ORDER BY n DESC LIMIT 8)),'') AS country_breakdown,
        COALESCE((SELECT GROUP_CONCAT(browser||':'||n, '; ') FROM (SELECT browser,COUNT(*) AS n FROM creation_view_events WHERE entity_type=? AND entity_id=c.id GROUP BY browser ORDER BY n DESC LIMIT 8)),'') AS browser_breakdown
        FROM ${table} c JOIN users u ON u.id=c.user_id ORDER BY c.created_at DESC LIMIT 100000`).all(kind,kind,kind,kind,kind);
    }
    const csv=[columns.join(','),...rows.map(row=>columns.map(column=>csvCell(row[column])).join(','))].join('\r\n');
    audit(db,me.id,'report_exported','report',type,`Exported ${type} creation report`,{type,rowCount:rows.length,format:'csv'});
    res.writeHead(200,{'Content-Type':'text/csv; charset=utf-8','Content-Disposition':`attachment; filename="${type}-report.csv"`,'Cache-Control':'no-store'});return res.end(csv);
  }
  if (method === 'GET' && (path === '/admin/reports/traffic.csv' || path === '/admin/reports/earnings.csv')) {
    const me = admin(); if (!me) return;
    const traffic = path.endsWith('traffic.csv');
    const rows = traffic
      ? db.prepare(`SELECT ce.created_at,ce.event_type,ce.device_category,ce.referrer_domain,ce.eligible_status,l.code,u.email
        FROM click_events ce JOIN short_links l ON l.id=ce.short_link_id JOIN users u ON u.id=ce.owner_id ORDER BY ce.created_at DESC LIMIT 100000`).all()
      : db.prepare(`SELECT el.created_at,u.email,el.type,el.status,el.amount_paise,el.rate_paise_per_1000,el.eligible_event_count,el.currency,el.reason
        FROM earning_ledger el JOIN users u ON u.id=el.user_id ORDER BY el.created_at DESC LIMIT 100000`).all();
    const columns = traffic ? ['created_at','code','email','event_type','device_category','referrer_domain','eligible_status']
      : ['created_at','email','type','status','amount_paise','rate_paise_per_1000','eligible_event_count','currency','reason'];
    const csv=[columns.join(','),...rows.map(row=>columns.map(column=>csvCell(row[column])).join(','))].join('\r\n');
    audit(db,me.id,'report_exported','report',traffic?'traffic':'earnings',`Exported ${traffic?'traffic':'earnings'} report`,{rowCount:rows.length,format:'csv'});
    res.writeHead(200,{ 'Content-Type':'text/csv; charset=utf-8','Content-Disposition':`attachment; filename="${traffic?'traffic-report':'earnings-ledger'}.csv"`,'Cache-Control':'no-store' });
    return res.end(csv);
  }
  if (path === '/admin/support/tickets' && method === 'GET') {
    const me = admin(); if (!me) return;
    const status = cleanText(url.searchParams.get('status'), 30),q=cleanText(url.searchParams.get('q'),120),statuses=['open','in_progress','resolved','closed'];
    if(status&&!statuses.includes(status))return error(res,400,'Choose a valid ticket status.');
    const limit=Math.min(50,Math.max(1,Number(url.searchParams.get('limit')||20))),page=Math.max(1,Number(url.searchParams.get('page')||1)),offset=(page-1)*limit,like=`%${q}%`;
    const total=Number(db.prepare(`SELECT COUNT(*) AS total FROM support_tickets t JOIN users u ON u.id=t.user_id
      WHERE (?='' OR t.status=?) AND (?='' OR t.subject LIKE ? OR u.email LIKE ? OR u.display_name LIKE ? OR t.category LIKE ?)`)
      .get(status,status,q,like,like,like,like).total);
    const summary=db.prepare(`SELECT COUNT(*) AS total,SUM(CASE WHEN status='open' THEN 1 ELSE 0 END) AS open,
      SUM(CASE WHEN status='in_progress' THEN 1 ELSE 0 END) AS inProgress,
      SUM(CASE WHEN status IN ('open','in_progress') THEN 1 ELSE 0 END) AS needingReply FROM support_tickets`).get();
    const items=db.prepare(`SELECT t.*,u.email,u.display_name,(SELECT COUNT(*) FROM support_messages m WHERE m.ticket_id=t.id) AS message_count
      FROM support_tickets t JOIN users u ON u.id=t.user_id
      WHERE (?='' OR t.status=?) AND (?='' OR t.subject LIKE ? OR u.email LIKE ? OR u.display_name LIKE ? OR t.category LIKE ?)
      ORDER BY CASE WHEN t.status='open' THEN 0 WHEN t.status='in_progress' THEN 1 ELSE 2 END,t.updated_at DESC
      LIMIT ? OFFSET ?`).all(status,status,q,like,like,like,like,limit,offset);
    return json(res,200,{items,total,page,pageSize:limit,pages:Math.max(1,Math.ceil(total/limit)),summary});
  }
  const adminTicketMatch = path.match(/^\/admin\/support\/tickets\/([^/]+)$/);
  if (adminTicketMatch && method === 'GET') {
    const me = admin(); if (!me) return;
    const ticket = db.prepare('SELECT t.*,u.email,u.display_name FROM support_tickets t JOIN users u ON u.id=t.user_id WHERE t.id=?').get(adminTicketMatch[1]);
    if (!ticket) return error(res, 404, 'Support ticket not found.');
    audit(db,me.id,'support_ticket_reviewed','support_ticket',ticket.id,'Opened support conversation',{status:ticket.status,category:ticket.category,userId:ticket.user_id});
    return json(res, 200, { ticket, messages: db.prepare('SELECT m.*,u.display_name,u.role FROM support_messages m JOIN users u ON u.id=m.author_id WHERE m.ticket_id=? ORDER BY m.created_at').all(ticket.id) });
  }
  if (adminTicketMatch && method === 'POST') {
    const me = admin(); if (!me || !csrf(me)) return;
    const ticket = db.prepare('SELECT * FROM support_tickets WHERE id=?').get(adminTicketMatch[1]);
    if (!ticket) return error(res, 404, 'Support ticket not found.');
    const message = cleanText(body.message, 3000);
    if (message.length < 2) return error(res, 400, 'Enter a reply.');
    db.prepare('INSERT INTO support_messages(id,ticket_id,author_id,message) VALUES (?,?,?,?)').run(id(),ticket.id,me.id,message);
    const status = ['open','in_progress','resolved','closed'].includes(body.status) ? body.status : 'in_progress';
    db.prepare('UPDATE support_tickets SET status=?,assigned_to=?,updated_at=datetime(\'now\') WHERE id=?').run(status, me.id, ticket.id);
    audit(db,me.id,'support_ticket_replied','support_ticket',ticket.id,'Administrator replied to support ticket',{from:ticket.status,to:status,replyLength:message.length,userId:ticket.user_id});
    notify(db, ticket.user_id, 'Support replied', `There is a new reply to your ticket: ${ticket.subject}`);
    return json(res, 201, { ok: true });
  }

  const publicShort = path.match(/^\/unlock\/sessions$/);
  if (publicShort) return error(res, 404, 'Unlock session not found.');
  return error(res, 404, 'API route not found.');
}

function findUnlockSession(db, token, code) {
  if (!token) return null;
  return db.prepare(`SELECT us.* FROM unlock_sessions us JOIN short_links l ON l.id=us.short_link_id
    WHERE us.token_hash=? AND l.code=? AND julianday(us.expires_at)>julianday('now')`).get(hashToken(token), code);
}

function unlockPayload(db, session, link) {
  const steps = db.prepare('SELECT * FROM unlock_step_settings WHERE enabled=1 ORDER BY display_order').all();
  const completed = db.prepare("SELECT position FROM unlock_step_events WHERE unlock_session_id=? AND event_type='acknowledged'").all(session.id).map(row => row.position);
  const state = publicStepState(steps, completed, nextStepPosition(steps, completed));
  const providerEvents = db.prepare("SELECT position,event_type FROM unlock_step_events WHERE unlock_session_id=? AND event_type IN ('provider_verified','failed')").all(session.id);
  const activatedPositions = db.prepare("SELECT position FROM unlock_step_events WHERE unlock_session_id=? AND event_type='activated'").all(session.id).map(row => row.position);
  const demoDwell = db.prepare('SELECT position,active_seconds FROM demo_dwell_sessions WHERE unlock_session_id=?').all(session.id);
  const dwellByPosition = new Map(demoDwell.map(row=>[Number(row.position),Math.min(10,Number(row.active_seconds||0))]));
  const settingByPosition = new Map(steps.map(setting=>[Number(setting.position),setting]));
  const enrichedSteps = state.steps.map(step=>{const setting=settingByPosition.get(Number(step.position));const scriptOneEnabled=Boolean(setting?.ad_script_one_enabled),scriptTwoEnabled=Boolean(setting?.ad_script_two_enabled);return { ...step, adLink:Boolean(setting&&/^https?:\/\//i.test(setting.destination_url)), hasAdScripts:Boolean((scriptOneEnabled&&setting?.ad_script_one)||(scriptTwoEnabled&&setting?.ad_script_two)), adScriptSlots:[...(scriptOneEnabled&&setting?.ad_script_one?[1]:[]),...(scriptTwoEnabled&&setting?.ad_script_two?[2]:[])], nextTabUrl:setting?.next_tab_url||'', demoSeconds:dwellByPosition.get(Number(step.position))||0 };});
  const isFile=/telegram file link/i.test(String(link.campaign||''))||/file shared through telegram storage/i.test(String(link.description||''));
  const configuredFileSlots=isFile?db.prepare("SELECT slot FROM content_ad_scripts WHERE content_type='files' AND enabled=1 AND script_html<>'' ORDER BY slot").all().map(row=>Number(row.slot)):[];
  const fileAdSlots=configuredFileSlots.length?[configuredFileSlots[randomInt(configuredFileSlots.length)]]:[];
  return { sessionId: link.code, status: session.status, expiresAt: session.expires_at, link: { title: link.title || 'Your link is ready', isFile }, fileAdSlots, unlockPreviousTabUrl:getSetting(db,'unlock_previous_tab_url',''), ...state, steps:enrichedSteps, providerEvents, activatedPositions };
}

function normalizeBlogInput(body){
  const title=cleanText(body.title,160);
  const slug=String(body.slug||'').trim().toLowerCase();
  const excerpt=cleanText(body.excerpt,500);
  const coverRaw=String(body.coverImage||'').trim();
  const coverImage=coverRaw?validateDestination(coverRaw):'';
  const contentHtml=sanitizeArticleHtml(body.contentHtml||'');
  const contentText=contentHtml.replace(/<[^>]*>/g,' ').replace(/&nbsp;|&#160;/gi,' ').trim();
  const status=String(body.status||'draft');
  if(title.length<3)return{error:'Enter a blog title with at least 3 characters.'};
  if(!/^[a-z0-9][a-z0-9-]{1,78}[a-z0-9]$/.test(slug))return{error:'Use a 3–80 character slug with lowercase letters, numbers, and hyphens.'};
  if(coverRaw&&!coverImage)return{error:'Enter a valid HTTP or HTTPS cover image URL.'};
  if(!contentText&&!/<img\b/i.test(contentHtml))return{error:'Add some content to the blog before saving.'};
  if(!['draft','published'].includes(status))return{error:'Choose draft or published status.'};
  return{value:{title,slug,excerpt,coverImage,contentHtml,status}};
}
function sanitizeArticleHtml(value){return String(value).replace(/<(script|style|iframe|object|form|svg)[^>]*>[\s\S]*?<\/\1\s*>/gi,'').replace(/\s+on[a-z]+\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+)/gi,'').replace(/\s+(href|src)\s*=\s*(["'])(javascript:|data:text\/html)[\s\S]*?\2/gi,'').replace(/<(?!\/?(?:p|br|h[1-6]|strong|b|em|i|u|s|blockquote|ul|ol|li|a|img|table|thead|tbody|tr|th|td|hr|div|span)\b)[^>]*>/gi,'');}

function csvCell(value) { return `"${String(value ?? '').replaceAll('"','""')}"`; }

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const { handler, config } = createApp();
  const server = createServer(handler);
  server.listen(config.port, config.host, () => console.info(`Verdant Links listening on ${config.appUrl}`));
}
