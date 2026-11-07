# Verdant Links

Verdant Links is a dependency-free Node.js link shortener with a responsive user dashboard, admin panel, server-controlled five-step unlock flow, privacy-conscious click analytics, provider callback verification, an auditable earning ledger, and manually reviewed withdrawals.

## Requirements

- Node.js 26 or newer. The application uses Node's built-in SQLite module and has no npm runtime dependencies.
- A stable `SESSION_SECRET` and `DATA_ENCRYPTION_KEY` for production.
- A TLS SMTP account for production email verification and password-reset messages.
- A persistent writable data directory for SQLite.

## Local setup

```powershell
Copy-Item .env.example .env
npm run migrate
npm run seed
npm run create-admin
npm start
```

Open `http://localhost:3000`. The admin provisioning command asks for an email, display name, and a password that is not echoed in an interactive terminal. It does not create a default admin password.

Without SMTP settings in development, verification and password-reset links are printed to the server terminal. In production, configure `SMTP_URL` and `EMAIL_FROM`; only implicit-TLS SMTP (`smtps://...:465`) is supported. Do not expose the development token logs publicly.

New databases contain website defaults and five unlock-step settings only. They do not contain fabricated visitors, earnings, users, or demo metrics.

## Configuration

Copy `.env.example` to `.env` and set:

- `APP_URL` to the canonical HTTPS origin used to make short URLs.
- `SESSION_SECRET` to a unique random value of at least 32 characters.
- `DATA_ENCRYPTION_KEY` to a different unique random value of at least 32 characters. This encrypts payout details at rest; back it up separately. Losing it makes saved payout details unreadable.
- `DATABASE_PATH` to a durable SQLite path.
- `SMTP_URL` and `EMAIL_FROM` for production verification and password reset.
- `AD_CALLBACK_SECRET` only when an advertising provider can send a signed server callback.
- `MINIMUM_WITHDRAWAL_MINOR_UNITS` (USD cents), `DEFAULT_CURRENCY`, `SESSION_TTL_HOURS`, and `UNLOCK_TTL_MINUTES` as required.

Generate secrets with Node:

```powershell
node -e "console.log(require('node:crypto').randomBytes(48).toString('base64url'))"
```

Run that command separately for each secret. Never commit `.env` or put credentials in browser code.

## Database and scripts

The built-in schema bootstrap uses SQLite with foreign keys, WAL mode, indexes, and a `schema_migrations` table. It applies the idempotent schema at startup and records schema version 1. The seed script adds only default settings and the five default steps. Use a regular SQLite backup procedure while accounting for WAL files; stop the service or use SQLite's online backup API for consistent copies.

Useful commands:

```powershell
npm run dev
npm run migrate
npm run seed
npm run create-admin
npm test
```

## Main user workflows

1. Register and verify the email address.
2. Create a short link with optional alias, title, campaign, expiration, visit cap, and password.
3. Copy and share the generated `/s/:code` URL.
4. Visitors progress through the enabled steps. Unlock state is stored server-side and survives refreshes while its session is valid.
5. The original destination is issued only through a short-lived, one-use redirect ticket after the unlock state is complete.
6. Raw visits, unlock completions, provider-verified eligible events, and filtered traffic are recorded separately.
7. Only provider-verified eligible events can create pending ledger earnings. Admins review earnings and manual payout requests.

## Advertising and earning rules

The default step policy is `clickthrough`. Clicking a configured direct link or acknowledging that the visitor returned records a click-through action only. It is not an impression, view, conversion, or payable event.

For providers that support server-side verification, register an integration, set `AD_CALLBACK_SECRET`, enable callback mode for the relevant step, and configure the provider to call the documented callback endpoint. The application verifies HMAC-SHA256 over the exact request body and deduplicates the provider event ID. Only a positive verified callback combined with a completed human-like unlock can mark a visit eligible. This is a generic callback adapter; provider-specific accounts, terms, and callback setup must be completed separately.

Review each provider's policies before using forced-step or incentivized formats. The platform does not fabricate impressions, conversions, or revenue. A CPM rate is an administrator-configured user share in cents per 1,000 verified events. New rates are recorded with effective timestamps and do not rewrite old ledger entries.

## Withdrawals

The initial payout workflow is manual. Users submit encrypted payout details and a request amount. Requested and in-review balances are reserved. Admins may approve, reject, hold, move to processing, and mark paid only with a confirmed payment reference. Viewing sensitive payout details creates an audit event. No payment gateway is connected by default.

## Deployment

The included `Dockerfile` and `compose.yaml` run the app as an unprivileged user and persist the SQLite database in a named volume. Set production values in an untracked `.env`, including HTTPS `APP_URL`, separate secrets, and SMTP credentials, then run:

```powershell
docker compose up --build -d
docker compose exec app node scripts/migrate.mjs
docker compose exec app node scripts/create-admin.mjs
```

Place a reverse proxy or managed HTTPS endpoint in front of port 3000. Configure HSTS and TLS at that edge, restrict access to the host and volume, monitor health at `/api/v1/health`, and test restore procedures. Back up the SQLite database and encryption key using separate protected storage. Do not scale this configuration to multiple application instances: in-memory rate limits and the local SQLite file are single-instance choices.

See [API documentation](docs/API.md) and [operations notes](docs/OPERATIONS.md).

## Scope and deployment notes

This is a functional single-instance foundation, not a claim that third-party services have been connected. SQLite is used instead of PostgreSQL to keep the project runnable in the supplied environment. In-memory rate limiting is process-local. Country-level analytics, OAuth, two-factor authentication, user impersonation, attachments, Redis, PostgreSQL, background aggregation jobs, and provider-specific advertising SDKs are not implemented. Privacy and legal pages are starter copy and need review for the operator's jurisdiction and actual providers before publication. Browser/device data is coarse; full IPs are not stored.

Automated tests cover the core API and business rules. A full browser end-to-end, accessibility, load, backup-restore, and production SMTP/provider certification suite is not included.
