# API contract

All routes are under `/api/v1`. JSON mutations require `Content-Type: application/json`. Authenticated mutations also require the session's `X-CSRF-Token` returned by `/auth/me` or login. Browser cookies are `HttpOnly`, `SameSite=Strict`, and `Secure` in production. Error responses use `{ "error": { "message": "..." } }`.

## Authentication

- `POST /auth/register` — `{ email, displayName, password }`; creates a pending account and sends a verification link.
- `POST /auth/verify-email` — `{ token }`; activates a pending account.
- `POST /auth/login` — `{ email, password }`; sets the session cookie and returns a CSRF token.
- `POST /auth/logout` — revokes the current session.
- `GET /auth/me` — current account, if any.
- `POST /auth/forgot-password` — `{ email }`; sends a one-hour reset link when the account exists.
- `POST /auth/reset-password` — `{ token, password }`; consumes the reset token and revokes existing sessions.
- `POST /auth/change-password` — `{ currentPassword, newPassword }`; retains the current session and revokes other sessions.

## User resources

- `POST /links`, `GET /links`, `GET /links/:id`, `PATCH /links/:id`, `DELETE /links/:id`
- `GET /analytics/overview`, `GET /analytics/links/:id`, `GET /analytics/export.csv`
- `GET /earnings/summary`, `GET /earnings/transactions`
- `GET /withdrawals`, `POST /withdrawals`
- `GET /referrals`
- `GET /notifications`, `POST /notifications/:id/read`
- `GET /profile`, `PATCH /profile/payout`, `POST /support/tickets`, `GET /support/tickets`, `GET /support/tickets/:id`, `POST /support/tickets/:id`

Link creation accepts an HTTP(S) `destinationUrl` and optional `alias`, `title`, `campaign`, `description`, `expiresAt`, `maxVisits`, and `password`. Original URLs are returned only to the owning signed-in user. User link reads and edits are owner-scoped.

## Five-step unlock

- `POST /unlock/sessions` — `{ code, password? }`; creates or resumes a server-authoritative session. It sets the unlock cookie.
- `GET /unlock/sessions/:code` — returns title, current step, progress, and labels. It never returns the original URL.
- `POST /unlock/sessions/:code/steps/:position/activate` — activates only the next permitted step and returns a configured partner URL for that direct user action, if present.
- `POST /unlock/sessions/:code/steps/:position/complete` — records a visitor acknowledgement for click-through steps. It cannot satisfy a callback-required step before verification.
- `POST /unlock/sessions/:code/redeem` — validates all enabled steps and returns a random one-use redirect path. It does not return the destination URL.
- `GET /r/:ticket` — consumes the ticket exactly once and responds with a redirect to the stored destination.

Activation/acknowledgement is not provider verification. Callback-required steps remain blocked until the signed provider callback arrives.

## Signed provider callback

`POST /integrations/callback` accepts:

```json
{"eventId":"activated-step-event-id","providerEventId":"unique-provider-event","eligible":true}
```

The request must include `X-Provider-Signature: <hex>` containing HMAC-SHA256 of the exact UTF-8 request body with the server's `AD_CALLBACK_SECRET`. A repeated provider event ID is idempotent. The event ID must refer to an activated step configured for an enabled callback integration. The provider-specific adapter must be configured to send only authenticated, real verification data. The generic endpoint cannot independently establish provider truth.

## Administrator resources

- `GET /admin/dashboard`, `GET /admin/users`, `PATCH /admin/users/:id/status`
- `GET /admin/links`, `PATCH /admin/links/:id`
- `GET /admin/settings`, `PATCH /admin/settings`, `PATCH /admin/unlock-steps`
- `GET /admin/integrations`, `POST /admin/integrations`, `GET /admin/unlock-sessions`
- `GET /admin/earnings`, `POST /admin/earnings/:id/approve|reject|hold`, `POST /admin/earnings/adjustments`
- `GET /admin/withdrawals`, `POST /admin/withdrawals/:id/approve|reject|hold|processing|paid`, `GET /admin/withdrawals/:id/payout-details`
- `GET /admin/support/tickets`, `GET /admin/support/tickets/:id`, `POST /admin/support/tickets/:id`
- `GET /admin/audit-logs`, `GET /admin/reports/traffic.csv`, `GET /admin/reports/earnings.csv`

Admin access is checked on the server. Status changes, financial decisions, settings edits, payout-detail reveals, and adjustments are recorded in `audit_logs`. `paid` requires a confirmed reference; details retrieval is audited and should be restricted to authorized staff.
