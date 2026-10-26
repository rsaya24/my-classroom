# Deployment and operations

For the new Vercel/PostgreSQL preview path, see [VERCEL_SETUP.md](VERCEL_SETUP.md).
The persistent single-host instructions below remain the local/Compose option.

## Supported topology

One persistent Linux host runs the built React client and Flask API on the same origin,
with a separate mail worker sharing a local SQLite volume. This avoids cross-origin session
and CSRF configuration. Do not place the database on an ephemeral serverless filesystem,
share it over a network filesystem, or scale this configuration across multiple hosts.
The existing Vercel-only frontend is not this backend deployment.

## Native run

Build `client/` and install `server/requirements-live.txt` as described in README.
From `server/`, using your installed Python environment:

```bash
gunicorn --config gunicorn.conf.py wsgi:app
python manage.py mail --watch
```

Run these as separate supervised services. Gunicorn binds only to localhost by default.
Use a private persistent `SECURITY_INSTANCE` directory accessible only to the service user.
The directory holds SQLite, the session key, optional operator settings and the local outbox.

## Container option

The Dockerfile builds the frontend and installs the backend. Copy `.env.example` to `.env`,
review it, and run:

```bash
docker compose up --build -d
docker compose exec web python manage.py create-admin --email YOUR_ADMIN_EMAIL
docker compose exec web python manage.py doctor
docker compose logs --tail=50 web mail
```

The port is published on localhost only. The named `security-data` volume persists state.
`docker compose down` keeps that volume. Do not use `down -v` unless deliberately deleting all state.
The image runs as a non-root user. Build exclusions prevent local databases, credentials,
captured traffic and dependencies from entering the image. Container execution requires Docker;
the native entry point is independently testable.

## Before public access

1. Obtain hosting access and use a TLS reverse proxy in front of the backend.
2. Set `PUBLIC_URL` to the actual HTTPS origin and `COOKIE_SECURE=1`.
3. Keep `TRUSTED_PROXY_HOPS=0` unless there is exactly one trusted proxy. To use `1`,
   restrict backend ingress to that proxy and configure it to overwrite forwarded IP and
   scheme headers. Never expose a header-trusting backend directly to the Internet.
4. Provision an administrator locally. Do not use default/demo credentials.
5. Configure a verified SMTP sender. Changing from outbox to SMTP can send pending messages.
   Review the queue first and verify delivery to a controlled test account.
6. Keep sensor and website tokens server-side. Restrict sensor access and rotate compromised tokens.
7. Apply request/resource limits at the gateway, particularly registration, login and XAI routes.
8. Establish data retention, backups, consent and incident ownership. Complete a security review,
   password recovery/MFA design and real deployment validation before relying on this publicly.

This package is a research deployment starting point, not production certification.
No public deployment, actual email delivery or live traffic capture is claimed.

## Backup and recovery

```bash
python manage.py backup --output /secure/location/classroom-backup.sqlite3
```

The command refuses existing destinations and uses SQLite's online backup API, including committed
WAL state. The backup contains private account/alert data. Protect and encrypt it at rest.
For recovery, stop both processes, preserve the existing instance directory separately, restore
the backup as `security.sqlite3` into a fresh private instance directory, and preserve the operator
settings/session key separately if desired. Do not mix stale WAL files with the restored database.
Restart, run `doctor`, and verify accounts/progress using a controlled account before reopening access.
