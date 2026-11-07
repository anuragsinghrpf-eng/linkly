# Operations and deployment notes

## Production checklist

1. Configure a canonical HTTPS `APP_URL` and HTTPS reverse proxy.
2. Set unique, persistent `SESSION_SECRET` and `DATA_ENCRYPTION_KEY` values (each at least 32 characters). The encryption key is required to reveal existing encrypted payout details.
3. Configure `smtps://` SMTP delivery and `EMAIL_FROM`; production startup fails without these values.
4. Create the first administrator with `npm run create-admin` or the equivalent interactive command in the container.
5. Apply schema with `npm run migrate`, start one application instance, and verify `/api/v1/health`.
6. Configure only provider integrations whose terms permit the selected unlock experience. Confirm a provider test callback before enabling payable callback mode.
7. Make a small manual test withdrawal before publishing payout instructions.
8. Back up the SQLite database and encryption key in separately protected storage and perform a restore drill.

## Backups

SQLite is configured for WAL mode. For a consistent online backup use SQLite's backup API or the SQLite CLI `.backup` command. Copying only the main database file while the app is writing may omit data still in `-wal`. Keep the encryption key with the protected backup recovery material, but separate from the database backup. Restrict and audit access to payout details.

## Limits and scaling

Rate limiting is currently process-local memory. SQLite and session state are local to one instance. Do not run multiple app replicas or put the SQLite file on a network filesystem. For horizontal scaling, migrate to PostgreSQL, move sessions and rate limits to shared stores, and add queue-backed aggregation and observability before increasing traffic.

## Email delivery

Only implicit TLS SMTP (SMTPS, normally port 465) is implemented. SMTP passwords belong in the deployment secret store. The app does not support STARTTLS, OAuth mail credentials, provider APIs, templates hosted by a service, or email delivery webhooks. Test verification and reset delivery using the actual deployment account.

## Manual payouts

The payout workflow is administrative and manual. The app stores payout instructions encrypted with AES-256-GCM and audits details reads. Verify payment externally, then record the provider or bank reference when marking the request paid. Never ask users for an OTP, PIN, or account password.

## Known implementation boundaries

- Application uses Node's built-in SQLite API, not PostgreSQL or Prisma.
- Rate limiting uses in-memory counters.
- Country/region detection and IP-derived visitor matching are not implemented. Unique visitors are counted as distinct unlock sessions.
- Bot filtering is a coarse user-agent classifier; it is not a fraud verdict.
- Provider callbacks use a generic HMAC contract, not a vendor-specific SDK.
- External OAuth, 2FA, payout gateways, attachments, email-change workflow, rich support assignment, custom public page editing, and background jobs are not implemented.
- Legal copy is starter text; obtain jurisdiction-specific review before launch.
