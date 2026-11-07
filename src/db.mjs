import { mkdirSync } from 'node:fs';
import { randomInt } from 'node:crypto';
import { dirname, resolve } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { DEFAULT_STEPS } from './domain.mjs';

const schema = `
PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;
PRAGMA busy_timeout = 5000;
CREATE TABLE IF NOT EXISTS schema_migrations (
  version INTEGER PRIMARY KEY,
  applied_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL COLLATE NOCASE UNIQUE,
  password_hash TEXT NOT NULL,
  display_name TEXT NOT NULL,
  public_id TEXT,
  avatar_url TEXT NOT NULL DEFAULT '',
  role TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('user','admin','super_admin')),
  status TEXT NOT NULL DEFAULT 'pending_verification' CHECK(status IN ('pending_verification','active','suspended','banned','closed')),
  referral_code TEXT UNIQUE,
  referred_by TEXT REFERENCES users(id),
  payout_method TEXT,
  payout_details_cipher TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  verified_at TEXT
);
CREATE INDEX IF NOT EXISTS users_status_created ON users(status, created_at);
CREATE TABLE IF NOT EXISTS user_sessions (
  token_hash TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  csrf_token TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  last_seen_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS user_telegram_settings (
  user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  bot_api_key_cipher TEXT NOT NULL DEFAULT '',
  whitelist_ids TEXT NOT NULL DEFAULT '[]',
  bot_name TEXT NOT NULL DEFAULT '',
  bot_id TEXT NOT NULL DEFAULT '',
  storage_channel_id TEXT NOT NULL DEFAULT '',
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS user_telegram_bots (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  bot_name TEXT NOT NULL,
  bot_id TEXT NOT NULL,
  bot_api_key_cipher TEXT NOT NULL,
  storage_channel_id TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS user_telegram_bots_user_created ON user_telegram_bots(user_id,created_at);
CREATE TABLE IF NOT EXISTS user_profile_channels (
  user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  social_links TEXT NOT NULL DEFAULT '{}',
  traffic_source TEXT NOT NULL DEFAULT '',
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS user_sessions_user ON user_sessions(user_id);
CREATE TABLE IF NOT EXISTS link_trees (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  slug TEXT NOT NULL UNIQUE,
  title TEXT NOT NULL,
  bio TEXT NOT NULL DEFAULT '',
  avatar_url TEXT NOT NULL DEFAULT '',
  socials_json TEXT NOT NULL DEFAULT '{}',
  rows_json TEXT NOT NULL DEFAULT '[]',
  theme_json TEXT NOT NULL DEFAULT '{}',
  password_hash TEXT,
  ads_enabled INTEGER NOT NULL DEFAULT 0 CHECK(ads_enabled IN (0,1)),
  view_count INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','paused')),
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS link_trees_user_created ON link_trees(user_id,created_at DESC);
CREATE TABLE IF NOT EXISTS articles (id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, slug TEXT NOT NULL UNIQUE, title TEXT NOT NULL, excerpt TEXT NOT NULL DEFAULT '', cover_image TEXT NOT NULL DEFAULT '', content_html TEXT NOT NULL, password_hash TEXT, ads_enabled INTEGER NOT NULL DEFAULT 0 CHECK(ads_enabled IN (0,1)), status TEXT NOT NULL DEFAULT 'published' CHECK(status IN ('draft','published')), view_count INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL DEFAULT (datetime('now')), updated_at TEXT NOT NULL DEFAULT (datetime('now')));
CREATE INDEX IF NOT EXISTS articles_user_created ON articles(user_id,created_at DESC);
CREATE TABLE IF NOT EXISTS blog_posts (
  id TEXT PRIMARY KEY,
  slug TEXT NOT NULL UNIQUE,
  title TEXT NOT NULL,
  excerpt TEXT NOT NULL DEFAULT '',
  cover_image TEXT NOT NULL DEFAULT '',
  content_html TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'draft' CHECK(status IN ('draft','published')),
  view_count INTEGER NOT NULL DEFAULT 0,
  created_by TEXT NOT NULL REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  published_at TEXT
);
CREATE INDEX IF NOT EXISTS blog_posts_status_published ON blog_posts(status,published_at DESC);
CREATE TABLE IF NOT EXISTS content_ad_scripts (
  content_type TEXT NOT NULL CHECK(content_type IN ('posts','trees','files')),
  slot INTEGER NOT NULL CHECK(slot IN (1,2)),
  script_html TEXT NOT NULL DEFAULT '',
  enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)),
  updated_by TEXT REFERENCES users(id),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY(content_type,slot)
);
CREATE TABLE IF NOT EXISTS creation_view_events (entity_type TEXT NOT NULL CHECK(entity_type IN ('post','tree')), entity_id TEXT NOT NULL, view_id TEXT NOT NULL, active_seconds INTEGER NOT NULL DEFAULT 0, country TEXT NOT NULL DEFAULT 'Unknown', device TEXT NOT NULL DEFAULT 'Unknown', browser TEXT NOT NULL DEFAULT 'Unknown', created_at TEXT NOT NULL DEFAULT (datetime('now')), PRIMARY KEY(entity_type,entity_id,view_id));
CREATE INDEX IF NOT EXISTS creation_view_entity ON creation_view_events(entity_type,entity_id,created_at DESC);
CREATE TABLE IF NOT EXISTS auth_tokens (
  token_hash TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  purpose TEXT NOT NULL CHECK(purpose IN ('verify_email','reset_password')),
  expires_at TEXT NOT NULL,
  consumed_at TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS auth_tokens_user ON auth_tokens(user_id, purpose);
CREATE TABLE IF NOT EXISTS short_links (
  id TEXT PRIMARY KEY,
  owner_id TEXT NOT NULL REFERENCES users(id),
  code TEXT NOT NULL UNIQUE,
  title TEXT NOT NULL DEFAULT '',
  destination_url TEXT NOT NULL,
  campaign TEXT NOT NULL DEFAULT '',
  description TEXT NOT NULL DEFAULT '',
  password_hash TEXT,
  expires_at TEXT,
  max_visits INTEGER,
  visit_count INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','paused','disabled','flagged','expired','deleted')),
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS short_links_owner_created ON short_links(owner_id, created_at DESC);
CREATE INDEX IF NOT EXISTS short_links_status_expiry ON short_links(status, expires_at);
CREATE TABLE IF NOT EXISTS unlock_step_settings (
  position INTEGER PRIMARY KEY CHECK(position BETWEEN 1 AND 5),
  title TEXT NOT NULL,
  button_label TEXT NOT NULL,
  instruction TEXT NOT NULL,
  destination_url TEXT NOT NULL DEFAULT '',
  next_tab_url TEXT NOT NULL DEFAULT '',
  ad_script_one TEXT NOT NULL DEFAULT '',
  ad_script_two TEXT NOT NULL DEFAULT '',
  ad_scripts_enabled INTEGER NOT NULL DEFAULT 1 CHECK(ad_scripts_enabled IN (0,1)),
  ad_script_one_enabled INTEGER NOT NULL DEFAULT 1 CHECK(ad_script_one_enabled IN (0,1)),
  ad_script_two_enabled INTEGER NOT NULL DEFAULT 1 CHECK(ad_script_two_enabled IN (0,1)),
  enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)),
  display_order INTEGER NOT NULL,
  policy TEXT NOT NULL DEFAULT 'clickthrough' CHECK(policy IN ('clickthrough','provider_callback')),
  retry_limit INTEGER NOT NULL DEFAULT 3,
  timeout_seconds INTEGER NOT NULL DEFAULT 0,
  integration_id TEXT,
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS ad_integrations (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  provider TEXT NOT NULL DEFAULT 'custom',
  callback_enabled INTEGER NOT NULL DEFAULT 0 CHECK(callback_enabled IN (0,1)),
  enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)),
  created_by TEXT REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS app_settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_by TEXT REFERENCES users(id),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS unlock_sessions (
  id TEXT PRIMARY KEY,
  token_hash TEXT NOT NULL UNIQUE,
  short_link_id TEXT NOT NULL REFERENCES short_links(id),
  status TEXT NOT NULL DEFAULT 'in_progress' CHECK(status IN ('in_progress','completed','expired','redeemed')),
  current_step INTEGER NOT NULL DEFAULT 1,
  callback_verified INTEGER NOT NULL DEFAULT 0 CHECK(callback_verified IN (0,1)),
  risk_flags TEXT NOT NULL DEFAULT '',
  redirect_token_hash TEXT UNIQUE,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  completed_at TEXT,
  redeemed_at TEXT
);
CREATE INDEX IF NOT EXISTS unlock_sessions_link_created ON unlock_sessions(short_link_id, created_at DESC);
CREATE TABLE IF NOT EXISTS click_events (
  id TEXT PRIMARY KEY,
  short_link_id TEXT NOT NULL REFERENCES short_links(id),
  owner_id TEXT NOT NULL REFERENCES users(id),
  unlock_session_id TEXT REFERENCES unlock_sessions(id),
  event_type TEXT NOT NULL,
  device_category TEXT NOT NULL DEFAULT 'unknown',
  country_code TEXT NOT NULL DEFAULT 'Unknown',
  referrer_domain TEXT NOT NULL DEFAULT '',
  is_bot INTEGER NOT NULL DEFAULT 0 CHECK(is_bot IN (0,1)),
  eligible_status TEXT NOT NULL DEFAULT 'ineligible' CHECK(eligible_status IN ('pending','eligible','ineligible','rejected')),
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS click_events_link_time ON click_events(short_link_id, created_at DESC);
CREATE INDEX IF NOT EXISTS click_events_owner_time ON click_events(owner_id, created_at DESC);
CREATE INDEX IF NOT EXISTS click_events_eligibility ON click_events(eligible_status, created_at);
CREATE TABLE IF NOT EXISTS unlock_step_events (
  id TEXT PRIMARY KEY,
  unlock_session_id TEXT NOT NULL REFERENCES unlock_sessions(id),
  position INTEGER NOT NULL,
  event_type TEXT NOT NULL CHECK(event_type IN ('activated','acknowledged','provider_verified','failed')),
  integration_id TEXT REFERENCES ad_integrations(id),
  provider_event_id TEXT UNIQUE,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE(unlock_session_id, position, event_type)
);
CREATE INDEX IF NOT EXISTS step_events_session ON unlock_step_events(unlock_session_id, position);
CREATE TABLE IF NOT EXISTS demo_dwell_sessions (
  event_id TEXT PRIMARY KEY REFERENCES unlock_step_events(id) ON DELETE CASCADE,
  unlock_session_id TEXT NOT NULL REFERENCES unlock_sessions(id) ON DELETE CASCADE,
  position INTEGER NOT NULL CHECK(position BETWEEN 1 AND 5),
  active_seconds REAL NOT NULL DEFAULT 0 CHECK(active_seconds >= 0),
  last_ping_at_ms INTEGER NOT NULL,
  completed_at TEXT
);
CREATE INDEX IF NOT EXISTS demo_dwell_session_position ON demo_dwell_sessions(unlock_session_id, position);
CREATE TABLE IF NOT EXISTS earning_rates (
  id TEXT PRIMARY KEY,
  user_share_paise_per_1000 INTEGER NOT NULL CHECK(user_share_paise_per_1000 >= 0),
  currency TEXT NOT NULL DEFAULT 'USD',
  effective_from TEXT NOT NULL DEFAULT (datetime('now')),
  created_by TEXT REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS earning_rates_effective ON earning_rates(effective_from DESC);
CREATE TABLE IF NOT EXISTS earning_ledger (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  link_id TEXT REFERENCES short_links(id),
  source_event_id TEXT UNIQUE,
  type TEXT NOT NULL CHECK(type IN ('earning','adjustment','payout','reversal')),
  status TEXT NOT NULL CHECK(status IN ('pending','estimated','approved','rejected','on_hold','paid','reversed')),
  amount_paise INTEGER NOT NULL,
  rate_paise_per_1000 INTEGER NOT NULL DEFAULT 0,
  eligible_event_count INTEGER NOT NULL DEFAULT 0,
  currency TEXT NOT NULL DEFAULT 'USD',
  reason TEXT NOT NULL DEFAULT '',
  created_by TEXT REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS earning_ledger_user_time ON earning_ledger(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS earning_ledger_status ON earning_ledger(status, created_at);
CREATE TABLE IF NOT EXISTS withdrawal_requests (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  amount_paise INTEGER NOT NULL CHECK(amount_paise > 0),
  currency TEXT NOT NULL DEFAULT 'USD',
  status TEXT NOT NULL DEFAULT 'requested' CHECK(status IN ('requested','under_review','approved','processing','paid','rejected','cancelled')),
  payout_method TEXT NOT NULL,
  payout_details_cipher TEXT NOT NULL,
  reference TEXT NOT NULL DEFAULT '',
  reason TEXT NOT NULL DEFAULT '',
  reviewed_by TEXT REFERENCES users(id),
  reviewed_at TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS withdrawals_user_time ON withdrawal_requests(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS withdrawals_status_time ON withdrawal_requests(status, created_at DESC);
CREATE TABLE IF NOT EXISTS referral_events (
  id TEXT PRIMARY KEY,
  referrer_id TEXT NOT NULL REFERENCES users(id),
  referred_user_id TEXT NOT NULL UNIQUE REFERENCES users(id),
  status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','eligible','rejected')),
  reward_paise INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS notifications (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  title TEXT NOT NULL,
  message TEXT NOT NULL,
  read_at TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS notifications_user_time ON notifications(user_id, created_at DESC);
CREATE TABLE IF NOT EXISTS support_tickets (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  subject TEXT NOT NULL,
  category TEXT NOT NULL DEFAULT 'general',
  status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open','in_progress','resolved','closed')),
  assigned_to TEXT REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS tickets_user_time ON support_tickets(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS tickets_status_time ON support_tickets(status, updated_at DESC);
CREATE TABLE IF NOT EXISTS support_messages (
  id TEXT PRIMARY KEY,
  ticket_id TEXT NOT NULL REFERENCES support_tickets(id) ON DELETE CASCADE,
  author_id TEXT NOT NULL REFERENCES users(id),
  message TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS audit_logs (
  id TEXT PRIMARY KEY,
  actor_id TEXT REFERENCES users(id),
  action TEXT NOT NULL,
  resource_type TEXT NOT NULL,
  resource_id TEXT NOT NULL DEFAULT '',
  reason TEXT NOT NULL DEFAULT '',
  metadata TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS audit_logs_time ON audit_logs(created_at DESC);
CREATE TABLE IF NOT EXISTS callback_receipts (
  provider_event_id TEXT PRIMARY KEY,
  event_id TEXT NOT NULL REFERENCES unlock_step_events(id),
  received_at TEXT NOT NULL DEFAULT (datetime('now'))
);
`;

export function openDatabase(databasePath = './data/verdant.sqlite') {
  const path = resolve(databasePath);
  mkdirSync(dirname(path), { recursive: true });
  const db = new DatabaseSync(path);
  db.exec(schema);
  const contentAdsSql=db.prepare("SELECT sql FROM sqlite_master WHERE type='table' AND name='content_ad_scripts'").get()?.sql||'';
  if(!contentAdsSql.includes("'files'")){
    db.exec('BEGIN IMMEDIATE');
    try{
      db.exec("ALTER TABLE content_ad_scripts RENAME TO content_ad_scripts_old; CREATE TABLE content_ad_scripts (content_type TEXT NOT NULL CHECK(content_type IN ('posts','trees','files')),slot INTEGER NOT NULL CHECK(slot IN (1,2)),script_html TEXT NOT NULL DEFAULT '',enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)),updated_by TEXT REFERENCES users(id),updated_at TEXT NOT NULL DEFAULT (datetime('now')),PRIMARY KEY(content_type,slot)); INSERT INTO content_ad_scripts(content_type,slot,script_html,enabled,updated_by,updated_at) SELECT content_type,slot,script_html,enabled,updated_by,updated_at FROM content_ad_scripts_old; DROP TABLE content_ad_scripts_old;");
      db.exec('COMMIT');
    }catch(error){db.exec('ROLLBACK');throw error;}
  }
  const clickEventColumns = new Set(db.prepare('PRAGMA table_info(click_events)').all().map(column => column.name));
  if (!clickEventColumns.has('country_code')) db.exec("ALTER TABLE click_events ADD COLUMN country_code TEXT NOT NULL DEFAULT 'Unknown'");
  db.prepare('INSERT OR IGNORE INTO schema_migrations(version) VALUES (12)').run();
  const userColumns = new Set(db.prepare('PRAGMA table_info(users)').all().map(column => column.name));
  if (!userColumns.has('public_id')) db.exec('ALTER TABLE users ADD COLUMN public_id TEXT');
  if (!userColumns.has('avatar_url')) db.exec("ALTER TABLE users ADD COLUMN avatar_url TEXT NOT NULL DEFAULT ''");
  const assignedPublicIds = new Set(db.prepare('SELECT public_id FROM users WHERE public_id IS NOT NULL').all().map(row => row.public_id));
  const missingPublicIds = db.prepare("SELECT id FROM users WHERE public_id IS NULL OR public_id='' ").all();
  const updatePublicId = db.prepare('UPDATE users SET public_id=? WHERE id=?');
  for (const user of missingPublicIds) {
    let publicId = '';
    for (let attempt = 0; attempt < 100; attempt++) {
      const candidate = String(randomInt(10000000, 100000000));
      if (!assignedPublicIds.has(candidate)) { publicId = candidate; assignedPublicIds.add(candidate); break; }
    }
    if (!publicId) throw new Error('Could not assign a unique 8-digit user ID.');
    updatePublicId.run(publicId, user.id);
  }
  db.exec('CREATE UNIQUE INDEX IF NOT EXISTS users_public_id_unique ON users(public_id)');
  db.prepare('INSERT OR IGNORE INTO schema_migrations(version) VALUES (8)').run();
  db.prepare('INSERT OR IGNORE INTO schema_migrations(version) VALUES (9)').run();
  db.prepare('INSERT OR IGNORE INTO schema_migrations(version) VALUES (10)').run();
  db.prepare('INSERT OR IGNORE INTO schema_migrations(version) VALUES (11)').run();
  const articleColumns = new Set(db.prepare('PRAGMA table_info(articles)').all().map(column => column.name));
  if (!articleColumns.has('password_hash')) db.exec('ALTER TABLE articles ADD COLUMN password_hash TEXT');
  if (!articleColumns.has('ads_enabled')) db.exec('ALTER TABLE articles ADD COLUMN ads_enabled INTEGER NOT NULL DEFAULT 0 CHECK(ads_enabled IN (0,1))');
  db.prepare('INSERT OR IGNORE INTO schema_migrations(version) VALUES (7)').run();
  const linkColumns = new Set(db.prepare('PRAGMA table_info(short_links)').all().map(column => column.name));
  if (!linkColumns.has('per_ip_limit')) db.exec('ALTER TABLE short_links ADD COLUMN per_ip_limit INTEGER');
  db.exec(`CREATE TABLE IF NOT EXISTS link_ip_visits (short_link_id TEXT NOT NULL REFERENCES short_links(id) ON DELETE CASCADE, ip_hash TEXT NOT NULL, visit_count INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(short_link_id,ip_hash))`);
  const treeColumns = new Set(db.prepare('PRAGMA table_info(link_trees)').all().map(column => column.name));
  if (!treeColumns.has('status')) db.exec("ALTER TABLE link_trees ADD COLUMN status TEXT NOT NULL DEFAULT 'active'");
  if (!treeColumns.has('password_hash')) db.exec('ALTER TABLE link_trees ADD COLUMN password_hash TEXT');
  if (!treeColumns.has('ads_enabled')) db.exec('ALTER TABLE link_trees ADD COLUMN ads_enabled INTEGER NOT NULL DEFAULT 0 CHECK(ads_enabled IN (0,1))');
  const telegramColumns = new Set(db.prepare('PRAGMA table_info(user_telegram_settings)').all().map(column => column.name));
  if (!telegramColumns.has('bot_name')) db.exec("ALTER TABLE user_telegram_settings ADD COLUMN bot_name TEXT NOT NULL DEFAULT ''");
  if (!telegramColumns.has('bot_id')) db.exec("ALTER TABLE user_telegram_settings ADD COLUMN bot_id TEXT NOT NULL DEFAULT ''");
  if (!telegramColumns.has('storage_channel_id')) db.exec("ALTER TABLE user_telegram_settings ADD COLUMN storage_channel_id TEXT NOT NULL DEFAULT ''");
  const oldTelegramSettings = db.prepare(`SELECT user_id,bot_api_key_cipher,bot_name,bot_id,storage_channel_id FROM user_telegram_settings
    WHERE bot_api_key_cipher<>'' OR bot_name<>'' OR bot_id<>'' OR storage_channel_id<>''`).all();
  const migrateTelegramBot = db.prepare(`INSERT OR IGNORE INTO user_telegram_bots(id,user_id,bot_name,bot_id,bot_api_key_cipher,storage_channel_id)
    VALUES (?,?,?,?,?,?)`);
  for (const bot of oldTelegramSettings) migrateTelegramBot.run(`legacy-${bot.user_id}`,bot.user_id,bot.bot_name||'Telegram bot',bot.bot_id||'',bot.bot_api_key_cipher,bot.storage_channel_id||'');
  const stepColumns = new Set(db.prepare('PRAGMA table_info(unlock_step_settings)').all().map(column => column.name));
  if (!stepColumns.has('next_tab_url')) {
    db.exec("ALTER TABLE unlock_step_settings ADD COLUMN next_tab_url TEXT NOT NULL DEFAULT ''");
    db.exec("UPDATE unlock_step_settings SET next_tab_url=destination_url WHERE next_tab_url=''");
  }
  if (!stepColumns.has('ad_script_one')) db.exec("ALTER TABLE unlock_step_settings ADD COLUMN ad_script_one TEXT NOT NULL DEFAULT ''");
  if (!stepColumns.has('ad_script_two')) db.exec("ALTER TABLE unlock_step_settings ADD COLUMN ad_script_two TEXT NOT NULL DEFAULT ''");
  if (!stepColumns.has('ad_scripts_enabled')) db.exec("ALTER TABLE unlock_step_settings ADD COLUMN ad_scripts_enabled INTEGER NOT NULL DEFAULT 1 CHECK(ad_scripts_enabled IN (0,1))");
  if (!stepColumns.has('ad_script_one_enabled')) db.exec("ALTER TABLE unlock_step_settings ADD COLUMN ad_script_one_enabled INTEGER NOT NULL DEFAULT 1 CHECK(ad_script_one_enabled IN (0,1))");
  if (!stepColumns.has('ad_script_two_enabled')) db.exec("ALTER TABLE unlock_step_settings ADD COLUMN ad_script_two_enabled INTEGER NOT NULL DEFAULT 1 CHECK(ad_script_two_enabled IN (0,1))");
  db.prepare('INSERT OR IGNORE INTO schema_migrations(version) VALUES (1)').run();
  db.prepare('INSERT OR IGNORE INTO schema_migrations(version) VALUES (2)').run();
  db.prepare('INSERT OR IGNORE INTO schema_migrations(version) VALUES (3)').run();
  db.prepare('INSERT OR IGNORE INTO schema_migrations(version) VALUES (4)').run();
  const scriptToggleMigration = db.prepare('INSERT OR IGNORE INTO schema_migrations(version) VALUES (6)').run();
  if (scriptToggleMigration.changes) db.exec('UPDATE unlock_step_settings SET ad_script_one_enabled=ad_scripts_enabled,ad_script_two_enabled=ad_scripts_enabled');
  seedDefaults(db);
  return db;
}

export function createPublicUserId(db) {
  for (let attempt = 0; attempt < 100; attempt++) {
    const candidate = String(randomInt(10000000, 100000000));
    if (!db.prepare('SELECT 1 FROM users WHERE public_id=?').get(candidate)) return candidate;
  }
  throw new Error('Could not assign a unique 8-digit user ID.');
}

export function seedDefaults(db) {
  const insertStep = db.prepare(`INSERT OR IGNORE INTO unlock_step_settings
    (position,title,button_label,instruction,destination_url,enabled,display_order,policy,retry_limit,timeout_seconds)
    VALUES (?,?,?,?,?,?,?,?,?,?)`);
  for (const s of DEFAULT_STEPS) insertStep.run(s.position, s.title, s.label, s.instruction, s.destination_url, s.enabled, s.position, s.policy, s.retry_limit, s.timeout_seconds);
  const setting = db.prepare('INSERT OR IGNORE INTO app_settings(key,value) VALUES (?,?)');
  for (const [key, value] of Object.entries({ site_name: 'Verdant Links', unlock_enabled: '1', referrals_enabled: '0', earning_rate_paise_per_1000: '0', currency: 'USD', minimum_withdrawal_paise: '200', unlock_ttl_minutes: '60', tree_background_direct_link: '' })) setting.run(key, value);
  const insertContentAd = db.prepare('INSERT OR IGNORE INTO content_ad_scripts(content_type,slot,script_html,enabled) VALUES(?,?,\'\',1)');
  for (const contentType of ['posts','trees','files']) for (const slot of [1,2]) insertContentAd.run(contentType,slot);
  const finalStepUrl = db.prepare('SELECT next_tab_url,destination_url FROM unlock_step_settings WHERE position=5').get();
  setting.run('unlock_previous_tab_url', finalStepUrl?.next_tab_url || finalStepUrl?.destination_url || '');
  db.prepare(`INSERT OR IGNORE INTO earning_rates(id,user_share_paise_per_1000,currency,effective_from)
    VALUES ('initial-rate',0,'USD',datetime('now'))`).run();
}

export function getSetting(db, key, fallback = '') {
  return db.prepare('SELECT value FROM app_settings WHERE key=?').get(key)?.value ?? fallback;
}

export function setSetting(db, key, value, actorId = null) {
  db.prepare(`INSERT INTO app_settings(key,value,updated_by,updated_at) VALUES (?,?,?,datetime('now'))
    ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_by=excluded.updated_by,updated_at=datetime('now')`).run(key, String(value), actorId);
}
