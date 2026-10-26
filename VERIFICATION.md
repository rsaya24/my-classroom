# Verification record — 26 October 2026 update

| New check | Observed result |
|---|---|
| Full regression suite, including real PostgreSQL | **40 passed in 18.62 seconds** |
| PostgreSQL test environment | Temporary PostgreSQL 16.15, private Unix socket, no TCP listener, synthetic records only |
| PostgreSQL behavior | Registration/duplicate rollback, login alerts, timestamp precision, progress persistence, concurrent flow deduplication and mail claims passed |
| Vercel adapter | Missing configuration returns 503; configured import does not connect to database or initialize schema |
| Email configuration guards | Disabled delivery preserves pending records; authenticated retry endpoint and inline opt-in tests passed |
| Updated React build and lint | Passed |
| Vercel public asset preparation | Executed successfully |
| Live Vercel backend / hosted PostgreSQL / inbox delivery | **Not verified; account and provider setup still required** |

The temporary PostgreSQL process was stopped after the tests. No system PostgreSQL service
was installed. Local unit tests do not verify Vercel packaging limits, runtime performance,
sender verification, or live deployment behavior. SHAP/LIME remain included and locally tested.

## Previous verification — 25 October 2026

| Check | Observed result |
|---|---|
| Backend automated tests | 33 passed in 17.26 seconds |
| Frontend production build | Passed, Vite 8.3.5 with Node 24.22.1 |
| Frontend lint | Passed |
| Locked frontend dependency installation/audit | Completed; 0 reported vulnerabilities |
| Gunicorn WSGI startup | Started on localhost with an isolated temporary instance |
| HTTP /health | 200; status ok and model_loaded true |
| HTTP /classroom | 200 |
| SQLite backup integrity and overwrite protection | Automated tests passed |
| Persistence across application restart | Automated test passed |
| Forwarded IP handling | Default-ignore and explicit-one-proxy tests passed |
| Real SMTP delivery | Not tested; provider credentials unavailable |
| Public deployment | Not performed |
| Authorized live Zeek capture | Not performed |
| Docker image/Compose execution | Not executed; Docker unavailable on this host |
| PostgreSQL migration | Not implemented |

Tests include genuine SHAP/LIME execution and synthetic account/flow integration. Mocked SMTP is
not inbox delivery. Passing software tests does not establish real-network detection accuracy.
The isolated Gunicorn smoke-test process was stopped after verification. No real user credentials
or production databases were used for that smoke test. Existing application state was preserved.
