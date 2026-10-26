# My Classroom + explainable security

The original React dashboard is retained. A Flask/SQLite backend adds real accounts, private saved
progress, explained sign-in alerts, administrator review, verified-user notifications and a separate
CIC-IDS2017 network-flow model. This is a research prototype, not production protection.

## Start

Requires Python 3.12 and Node 22.12+ (tested with Node 24; the system's Node 18 is too old).

```bash
cd client
npm ci
npm run build
cd ../server
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-live.txt
.venv/bin/python manage.py create-admin --email YOUR_ADMIN_EMAIL
.venv/bin/python manage.py serve
```

Open **http://127.0.0.1:5001/classroom**. The admin command prompts for a new password; there is
no default administrator credential. Public registration never grants administrator privileges.
Use a demo-only password, not one you use elsewhere.

On this computer, from `server/`, the installed interpreter can also run the project:
`../../cyber_hybrid_prototype/.venv-live/bin/python manage.py serve`.
That is only an environment shortcut: the repository's code and model are self-contained.

In a second terminal, from `server/`:

```bash
.venv/bin/python manage.py mail --watch
```

Default `outbox` mode saves messages locally, not in real inboxes. Administrators can read messages
and verification links at `/admin/outbox`. Stop either process with Ctrl+C; no background service
is installed. For frontend development, run `npm run dev` in `client/` with the backend on port 5001.
Vite proxies account/API routes. Set `PUBLIC_URL` to the Vite origin when testing verification there.

## Test the account-security flow

1. Create an administrator using the command above, then register a separate student account.
2. As administrator, open Notifications and the student's verification URL; confirm verification.
3. Sign in as student, complete a topic/task and refresh. Progress should remain saved.
4. Sign out. Enter the student's email with a wrong password ten times within five minutes.
5. As administrator, open Security operations → Inspect. Review the rule, failure count and source IP.
6. Notifications contains an administrator warning and a warning for the verified student.
7. The student's My alerts page shows their activity; other students cannot see it or their progress.

Local source IP is normally `127.0.0.1`. Matching alerts are deduplicated for 15 minutes. A successful
login after repeated failures is a separate advisory signal. No passwords submitted at login are logged.
No IP or account is automatically blocked.

## Connection status

| Component | Actual status |
|---|---|
| Classroom accounts, progress and login monitoring | Connected to this repository's new backend |
| Explanations | Login-rule evidence, exact decision paths, and on-demand SHAP/LIME for network alerts |
| Administrator/student notifications | Queued; local outbox by default |
| CIC network detector | Model included and loaded; accepts authenticated flow events |
| Live traffic | Zeek adapter included; authorized capture deployment and validation still required |
| Internet email | SMTP configuration and actual delivery verification still required |
| Approximate IP location | Requires a separately obtained licensed City MMDB |
| Public deployment / GitHub push | Not performed |

Login outcomes are not passed into a network-flow model: CIC does not identify registered users or
encrypted login results. Network-only alerts notify administrators, not an invented account match.

## Configure email, collector and location

From `server/`:

```bash
.venv/bin/python manage.py doctor
.venv/bin/python manage.py configure-email
.venv/bin/python manage.py init-sensor
.venv/bin/python manage.py configure-location --database /path/to/GeoLite2-City.mmdb
```

Email setup prompts privately for host, verified sender and SMTP credentials. Port 587 uses
certificate-verified STARTTLS. Settings are in gitignored, mode-600 `instance/settings.json`.
Restart app and worker after changing configuration. Pending messages will then be sent.
SMTP acceptance does not prove inbox delivery. The low-volume worker claims messages using short
transactions and releases the database lock before SMTP I/O. Delivery is not exactly-once after a crash.

`init-sensor` saves a separate token. Set its value as `SENSOR_TOKEN` in the collector process;
never place it in React or a public environment variable. Restart the app, then replay CIC records:

```bash
.venv/bin/python -m security_app.sensor --url http://127.0.0.1:5001 --format cic --file /path/to/CIC.csv --limit 20
```

Replay is visibly labelled. Its `192.0.2.10` source is a documentation placeholder because these
ML CSVs lack source IPs—not an identified attacker. For authorized Zeek JSON connection logs:

```bash
.venv/bin/python -m security_app.sensor --url http://127.0.0.1:5001 --format zeek --file /path/to/conn.log --watch
```

Install Zeek separately on an authorized interface/mirror. Do not run the web server as root.
Zeek/CIC flow boundaries differ; live model scores remain experimental. Forwarded-IP headers
are ignored by default. See `DEPLOYMENT.md` before enabling trusted-proxy handling. An IP may identify a proxy, not a person.
GeoIP lookup is approximate city/country only; no exact attacker location is claimed.
The administrator Connections page distinguishes configured settings from received telemetry.

## Model evaluation

The tree uses four raw fields (duration, directional packet counts, destination port) and two
deterministic derived fields. Six configurations were compared using a separate validation set.
Neither test set selected the tree. Inference uses JSON arrays, not pickle. See
`server/models/cic-tree/RESULTS.md` and `evaluation.json` for full evidence.

| Same-run comparison | Linear F1 | Tree F1 | Linear false-positive rate | Tree false-positive rate |
|---|---:|---:|---:|---:|
| Same-distribution test | 0.931 | 0.981 | 0.332 | 0.052 |
| Friday capture-day test | 0.350 | 0.464 | 0.378 | 0.073 |

Friday recall remains about **32%**, so many attacks are missed. This is not reliable production
protection. Friday was seen in earlier development: this is a development comparison, not fresh
external validation. Sampling changes prevalence; scores are uncalibrated. Decision paths explain
the model, not causal mechanisms or attacker intent. Binary detection does not name the attack family.

To reproduce training from `server/`, with a new output directory:

```bash
.venv/bin/python -m security_app.train_upgrade --data-dir /path/to/MachineLearningCVE --output instance/new-model
```

## Verification

```bash
cd server
.venv/bin/python -m pytest tests -q
cd ../client
npm run build
npm run lint
npm audit
```

Checks cover private progress, sessions/CSRF, account alerts, verification tokens, access control,
notification deduplication/local delivery, mocked SMTP/TLS, sensor validation and explanation
reconstruction. Mocked SMTP is not real email delivery. Live capture was not performed.

## Deployment boundaries

Do not publish `server/instance/`, `.env` files, captured traffic or credentials. Public deployment
needs HTTPS, a production WSGI server, trusted-proxy handling, abuse/resource controls, MFA/password
recovery, consent/retention policy and security review. Do not expose the Flask development server.
Blocking is intentionally excluded. Existing classroom navigation placeholders are outside this task.

## Layout

- `client/`: original classroom plus account/security wrapper.
- `server/classroom.py`: session/private progress API and built React serving.
- `server/security_app/`: login monitoring, ML, rules, explanations, notifications and collectors.
- `server/manage.py`: operator commands.
- `server/models/cic-tree/`: model/provenance/results.
- `server/tests/`: integration/security tests.
# Explanation and worker update

Network alerts ingested by this version store the four raw model features. Administrators can select **Generate SHAP and LIME** on an alert. This POST requires an administrator session and CSRF token. Older alerts without these features are not silently reconstructed.

- Actual SHAP ExactExplainer: four independently masked raw features, derived features recomputed; signed attack-score contributions reconstruct the model output.
- Actual LIME TabularExplainer: deterministic log-space perturbations, rounded packet counts and ports, bounded ports; displays local fidelity R². Low fidelity means the surrogate is unreliable locally.
- `models/cic-tree/background.json` contains 64 uniformly sampled training records, verified against the original partition manifest and tied to the model's SHA-256 digest. No validation/test data is used as background. The sampled training distribution is not a production traffic distribution.
- Both explanations are descriptive, not causal, and do not validate the detector under deployment shift. LIME coefficients and SHAP values have different meanings and should not be numerically compared.
- The notification worker now uses expiring claims and short database transactions rather than holding a write lock during SMTP. Expired claims can be retried; a crash after SMTP acceptance can still cause duplicate delivery. SMTP acceptance does not guarantee inbox delivery.

## Remaining deployment work

SQLite remains the implemented database. PostgreSQL migration is **not implemented**. Public backend deployment, repository push access, real SMTP credentials, a licensed GeoIP database, and an authorized live Zeek sensor are not configured by this update. The existing Vercel frontend must not be described as an operational security deployment. No automatic blocking is included.

## Final handover

See `DEPLOYMENT.md` for the Gunicorn/container setup, persistent storage, backup and deployment checklist.
See `PROJECT_STATUS.md` for implemented scope, remaining work and the demonstration sequence.
