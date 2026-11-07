import { createCipheriv, createDecipheriv, createHash, pbkdf2, randomBytes, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';
import { hashToken } from './domain.mjs';

const pbkdf2Async = promisify(pbkdf2);

export async function hashPassword(password) {
  const salt = randomBytes(16);
  const derived = await pbkdf2Async(password, salt, 310000, 32, 'sha256');
  return `pbkdf2$310000$${salt.toString('base64url')}$${Buffer.from(derived).toString('base64url')}`;
}

export async function verifyPassword(password, encoded) {
  const [algorithm, iterationsText, saltText, keyText] = String(encoded).split('$');
  if (algorithm !== 'pbkdf2' || !saltText || !keyText) return false;
  const iterations = Number(iterationsText);
  if (!Number.isInteger(iterations) || iterations < 100000 || iterations > 1000000) return false;
  const expected = Buffer.from(keyText, 'base64url');
  const actual = Buffer.from(await pbkdf2Async(password, Buffer.from(saltText, 'base64url'), iterations, expected.length, 'sha256'));
  return expected.length === actual.length && timingSafeEqual(expected, actual);
}

export function encryptionKey(secret) {
  return createHash('sha256').update(String(secret)).digest();
}

export function sealValue(value, secret) {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', encryptionKey(secret), iv);
  const encrypted = Buffer.concat([cipher.update(String(value), 'utf8'), cipher.final()]);
  return [iv, cipher.getAuthTag(), encrypted].map(part => part.toString('base64url')).join('.');
}

export function unsealValue(value, secret) {
  const [ivText, tagText, encryptedText] = String(value).split('.');
  if (!ivText || !tagText || !encryptedText) throw new Error('Invalid encrypted value');
  const decipher = createDecipheriv('aes-256-gcm', encryptionKey(secret), Buffer.from(ivText, 'base64url'));
  decipher.setAuthTag(Buffer.from(tagText, 'base64url'));
  return Buffer.concat([decipher.update(Buffer.from(encryptedText, 'base64url')), decipher.final()]).toString('utf8');
}

export function createSession(db, userId, ttlHours = 168) {
  const token = randomBytes(32).toString('base64url');
  const csrf = randomBytes(24).toString('base64url');
  const expires = new Date(Date.now() + ttlHours * 3600000).toISOString();
  db.prepare('INSERT INTO user_sessions(token_hash,user_id,csrf_token,expires_at) VALUES (?,?,?,?)').run(hashToken(token), userId, csrf, expires);
  return { token, csrf, expires };
}

export function cookieOptions({ secure = false, path = '/' } = {}) {
  return `Path=${path}; HttpOnly; SameSite=Strict${secure ? '; Secure' : ''}`;
}

export function csrfCookieOptions({ secure = false } = {}) {
  return `Path=/; SameSite=Strict${secure ? '; Secure' : ''}`;
}

export function parseCookies(header = '') {
  const result = {};
  for (const part of header.split(';')) {
    const index = part.indexOf('=');
    if (index < 0) continue;
    const key = part.slice(0, index).trim();
    try { result[key] = decodeURIComponent(part.slice(index + 1).trim()); } catch {}
  }
  return result;
}

export function isSameOrigin(req, appUrl) {
  const origin = req.headers.origin;
  if (!origin) return true;
  try {
    const originUrl = new URL(origin);
    if (originUrl.protocol !== 'http:' && originUrl.protocol !== 'https:') return false;
    if (req.allowedCorsOrigin === true) return true;

    // Validate against the host the browser actually opened. APP_URL is a
    // configured/public URL and can lag behind when a local Wi-Fi IP changes.
    const requestHost = req.headers.host;
    if (requestHost) {
      const requestProtocol = req.socket?.encrypted ? 'https:' : 'http:';
      return originUrl.protocol === requestProtocol && originUrl.host.toLowerCase() === requestHost.toLowerCase();
    }

    // Keep compatibility for internal callers that do not carry HTTP headers.
    return originUrl.origin === new URL(appUrl).origin;
  } catch { return false; }
}
