# Verification record — 25 October 2026

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
