# Vercel preview deployment

## Current state

The existing Vercel preview serves the React client, but `/api/session` returns 404.
This branch now includes a root Flask entry point, frontend build instructions,
PostgreSQL persistence, and bounded email processing. These changes have been tested
locally, not yet verified as a successful Vercel backend deployment.

Do not promote the preview to production until all checks below pass.

## Hosting setup (requires account access)

1. Use the existing `my-classroom` project and `security-integration` branch.
2. Provision a separate **preview** PostgreSQL database through an approved provider.
   Review pricing/terms first. Use the provider's TLS-enabled connection URL, preferably
   its pooled endpoint; never put credentials in GitHub or the React frontend.
3. Configure these server-side Preview environment variables, preferably scoped to this branch:

| Variable | Value |
|---|---|
| `DATABASE_URL` | Provider PostgreSQL URL with TLS, e.g. `sslmode=require` |
| `SESSION_SECRET` | Privately generated random secret, at least 32 characters |
| `PUBLIC_URL` | `https://my-classroom-git-security-integration-kknpr.vercel.app` |
| `MAIL_MODE` | Start with `disabled`; later explicitly switch to `smtp` |
| `MAIL_DELIVERY` | Start with `manual`; use `inline` after verifying sender/queue |
| `ADMIN_EMAIL` | Approved administrator recipient |
| `SENSOR_TOKEN` | Separate random server-side sensor secret, if enabling flow ingestion |
| `CRON_SECRET` | Separate random secret of at least 32 characters for mail retry requests |

4. Run `python server/manage.py init-db` against that preview database from a secure
   operator environment with the same variables. This creates tables, preserving existing
   records. Then run `python server/manage.py create-admin --email YOUR_ADMIN_EMAIL`;
   the operator enters the password privately. This does **not** copy local users/data.
5. Set Vercel Root Directory to the repository root (not `client`), Framework Preset
   to Flask, and clear the old frontend-only Output Directory/Install overrides.
   The branch's `vercel.json` builds the frontend and copies public assets. The root
   `requirements.txt` includes the real SHAP/LIME dependencies and Python PostgreSQL driver.
   Settings may apply project-wide: do not trigger a main-branch deployment with incompatible
   settings. The already-running production deployment is not changed by a preview build.
6. Build the preview; inspect logs, package-size/time limits and runtime results. Keep
   Vercel deployment protection enabled. Do not resolve a build problem by silently
   removing SHAP/LIME or by using temporary SQLite for user data.

## Email

Set `SMTP_HOST`, `SMTP_PORT` (normally 587), `SMTP_FROM`, `SMTP_USER`, `SMTP_PASSWORD`
only through secure server-side environment settings. Verify sender authorization first.
Do not paste passwords into chat. Review pending notifications before enabling SMTP.

`MAIL_DELIVERY=inline` attempts at most two queued messages during requests that enqueue
mail. Failures remain in PostgreSQL with retries/backoff. It does not guarantee immediate
delivery, and an idle site will not retry by itself. Configure an approved scheduler to
call `GET /api/jobs/mail` with `Authorization: Bearer <CRON_SECRET>` for retries; each
request processes at most two messages. No schedule or billable service is created by
this code. Vercel Cron is production-only; preview tests need an authenticated manual
invocation or another explicitly approved scheduler. Do not disable deployment protection.

Delivery is at-least-once: interruption after SMTP acceptance but before the database
update can cause duplicates. SMTP acceptance is not proof of inbox delivery. `disabled`
mode keeps records pending without writing a disposable filesystem outbox.

## Acceptance checks

- `/api/session` returns JSON, HTTP 200, and a secure session cookie, not 404/HTML.
- `/health` reports a loaded model; `/classroom`, `/login`, `/register` and CSS load.
- Create a synthetic account, verify its email, log in, save progress; confirm progress
  persists across a redeploy and cannot be read by another account.
- Ten wrong passwords for your synthetic account generate one review alert. Validate
  source IP attribution on the deployed platform; do not treat an IP as a person's identity.
- Confirm one administrator/user notification reaches controlled inboxes, then test retries.
- Reject unauthenticated flow ingestion; replay one synthetic flow with the sensor token.
- Run actual SHAP/LIME in the preview and inspect memory/runtime limits and output.
- Check logs for credentials/verification tokens before approving public use.

Keep PostgreSQL backups through the provider. `manage.py backup` remains SQLite-only.
Use separate production credentials/database and review gateway rate limits, recovery,
MFA and retention before production exposure. The database adapter serializes writers
with a transaction-scoped advisory lock: suitable for a small prototype, not high-volume
telemetry. There is no automatic migration of existing local SQLite data.

## References

- https://vercel.com/docs/frameworks/backend/flask
- https://vercel.com/docs/headers/request-headers
- https://vercel.com/docs/cron-jobs/manage-cron-jobs
