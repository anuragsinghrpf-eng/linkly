import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { loadConfig } from '../src/config.mjs';
import { openDatabase } from '../src/db.mjs';

const INR_PER_USD = 96.52; // ICICI TT selling rate dated 2026-10-30.
const backupPath = resolve('data/verdant-before-usd-20261031.sqlite');
const config = loadConfig();
const db = openDatabase(config.databasePath);

try {
  const currency = db.prepare('SELECT value FROM app_settings WHERE key=?').get('currency')?.value;
  if (currency !== 'INR') throw new Error(`Expected INR source currency; found ${currency || 'unset'}.`);
  if (existsSync(backupPath)) throw new Error(`Refusing to overwrite migration backup: ${backupPath}`);

  for (const table of ['earning_rates', 'earning_ledger', 'withdrawal_requests']) {
    const currencies = db.prepare(`SELECT DISTINCT currency FROM ${table}`).all().map(row => row.currency);
    if (currencies.some(value => value !== 'INR')) throw new Error(`Unexpected mixed currency in ${table}: ${currencies.join(', ')}`);
  }

  db.exec('PRAGMA wal_checkpoint(FULL)');
  const safeBackupPath = backupPath.replaceAll("'", "''");
  db.exec(`VACUUM INTO '${safeBackupPath}'`);

  db.exec('BEGIN IMMEDIATE');
  try {
    db.prepare("UPDATE earning_rates SET user_share_paise_per_1000=CAST(ROUND(user_share_paise_per_1000 / ?) AS INTEGER),currency='USD' WHERE currency='INR'").run(INR_PER_USD);
    db.prepare("UPDATE earning_ledger SET amount_paise=CAST(ROUND(amount_paise / ?) AS INTEGER),rate_paise_per_1000=CAST(ROUND(rate_paise_per_1000 / ?) AS INTEGER),currency='USD' WHERE currency='INR'").run(INR_PER_USD, INR_PER_USD);
    db.prepare("UPDATE withdrawal_requests SET amount_paise=CAST(ROUND(amount_paise / ?) AS INTEGER),currency='USD' WHERE currency='INR'").run(INR_PER_USD);
    db.prepare('UPDATE referral_events SET reward_paise=CAST(ROUND(reward_paise / ?) AS INTEGER) WHERE reward_paise<>0').run(INR_PER_USD);
    db.prepare("UPDATE app_settings SET value='USD',updated_at=datetime('now') WHERE key='currency'").run();
    db.prepare("UPDATE app_settings SET value=CAST(ROUND(CAST(value AS REAL) / ?) AS TEXT),updated_at=datetime('now') WHERE key='earning_rate_paise_per_1000'").run(INR_PER_USD);
    db.prepare("UPDATE app_settings SET value='200',updated_at=datetime('now') WHERE key='minimum_withdrawal_paise'").run();
    db.exec('COMMIT');
  } catch (error) {
    db.exec('ROLLBACK');
    throw error;
  }

  const result = {
    backupPath,
    inrPerUsd: INR_PER_USD,
    currency: db.prepare('SELECT value FROM app_settings WHERE key=?').get('currency').value,
    minimumCents: db.prepare('SELECT value FROM app_settings WHERE key=?').get('minimum_withdrawal_paise').value,
    ledger: db.prepare('SELECT COUNT(*) AS count,COALESCE(SUM(amount_paise),0) AS cents FROM earning_ledger').get(),
    withdrawals: db.prepare('SELECT COUNT(*) AS count,COALESCE(SUM(amount_paise),0) AS cents FROM withdrawal_requests').get(),
    earningRates: db.prepare('SELECT currency,COUNT(*) AS count,COALESCE(SUM(user_share_paise_per_1000),0) AS cents FROM earning_rates GROUP BY currency').all(),
    integrity: db.prepare('PRAGMA quick_check').get(),
  };
  console.log(JSON.stringify(result));
} finally {
  db.close();
}
