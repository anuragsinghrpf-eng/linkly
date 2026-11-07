import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { randomBytes } from 'node:crypto';

export function loadConfig(overrides = {}) {
  const envPath = resolve('.env');
  if (existsSync(envPath)) {
    for (const line of readFileSync(envPath, 'utf8').split(/\r?\n/)) {
      const match = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*?)\s*$/);
      if (match && process.env[match[1]] === undefined) process.env[match[1]] = match[2].replace(/^(['"])(.*)\1$/, '$2');
    }
  }
  const production = (overrides.NODE_ENV ?? process.env.NODE_ENV ?? 'development') === 'production';
  const configuredSessionSecret=overrides.SESSION_SECRET ?? process.env.SESSION_SECRET ?? '';
  const configuredEncryptionKey=overrides.DATA_ENCRYPTION_KEY ?? process.env.DATA_ENCRYPTION_KEY ?? '';
  if (production && (configuredSessionSecret.length < 32 || /^(replace-with|changeme|example)/i.test(configuredSessionSecret))) throw new Error('SESSION_SECRET must be configured with at least 32 non-placeholder characters in production');
  if (production && (configuredEncryptionKey.length < 32 || /^(replace-with|changeme|example)/i.test(configuredEncryptionKey))) throw new Error('DATA_ENCRYPTION_KEY must be configured with at least 32 non-placeholder characters in production');
  const smtpUrl = overrides.SMTP_URL ?? process.env.SMTP_URL ?? '';
  const emailFrom = overrides.EMAIL_FROM ?? process.env.EMAIL_FROM ?? '';
  const corsOrigins = String(overrides.CORS_ORIGINS ?? process.env.CORS_ORIGINS ?? '').split(',').map(value => value.trim()).filter(Boolean);
  if (production && (!smtpUrl || !emailFrom)) throw new Error('Configure SMTP_URL and EMAIL_FROM in production so users can verify accounts and reset passwords');
  const secret = configuredSessionSecret || randomBytes(48).toString('base64url');
  return {
    nodeEnv: overrides.NODE_ENV ?? process.env.NODE_ENV ?? 'development',
    host: overrides.HOST ?? process.env.HOST ?? '127.0.0.1',
    port: Number(overrides.PORT ?? process.env.PORT ?? 3000),
    appUrl: overrides.APP_URL ?? process.env.APP_URL ?? `http://localhost:${overrides.PORT ?? process.env.PORT ?? 3000}`,
    corsOrigins,
    databasePath: overrides.DATABASE_PATH ?? process.env.DATABASE_PATH ?? './data/verdant.sqlite',
    sessionSecret: secret,
    encryptionKey: configuredEncryptionKey || secret,
    sessionTtlHours: Number(overrides.SESSION_TTL_HOURS ?? process.env.SESSION_TTL_HOURS ?? 168),
    unlockTtlMinutes: Number(overrides.UNLOCK_TTL_MINUTES ?? process.env.UNLOCK_TTL_MINUTES ?? 60),
    minWithdrawalPaise: Number(overrides.MINIMUM_WITHDRAWAL_MINOR_UNITS ?? process.env.MINIMUM_WITHDRAWAL_MINOR_UNITS ?? overrides.MINIMUM_WITHDRAWAL_PAISE ?? process.env.MINIMUM_WITHDRAWAL_PAISE ?? 200),
    currency: overrides.DEFAULT_CURRENCY ?? process.env.DEFAULT_CURRENCY ?? 'USD',
    callbackSecret: overrides.AD_CALLBACK_SECRET ?? process.env.AD_CALLBACK_SECRET ?? '',
    smtpUrl,
    emailFrom,
  };
}
