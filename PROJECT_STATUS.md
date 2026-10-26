# Project handover

## Implemented scope

The local research prototype combines classroom account monitoring with a separate CIC-IDS2017
network detector. It provides secure password hashing, verified-user alerts, private progress,
administrator review, flow-token authentication, validation/idempotency, expert rules, exact tree
paths, actual SHAP and LIME explanations, a retrying mail queue, optional approximate GeoIP,
and an experimental Zeek JSON adapter. No automatic blocking or precise person-location tracking.

## Demonstration sequence

1. Build/start the application and mail worker. Create an administrator privately.
2. Register a synthetic student and verify using the local outbox.
3. Show persistent classroom progress and isolation between student accounts.
4. Submit ten deliberate failed logins against your synthetic account within five minutes.
5. Inspect the administrator alert, recorded evidence and advice. Show the verified student's alert.
6. Replay authorized CIC CSV records through the token-protected collector interface.
7. Inspect a network alert, rule/model agreement and the exact tree path.
8. Generate SHAP/LIME and explain signed contributions versus local surrogate weights and R².
9. Review capture-day results: same-distribution F1 is 0.981, Friday F1 is 0.464 and Friday
   recall is roughly 32%. Explain why this cannot yet be relied on for live protection.

## Limitation, test, evidence and extension

| Limitation | Test or check | Evidence | Extension or boundary |
|---|---|---|---|
| Dataset/domain dependency | Separate Friday capture evaluation | F1 0.464; substantial missed attacks | Collect authorized deployment data and validate before trusting scores |
| False alarms and missed attacks | Confusion-matrix analysis | Same-distribution FPR 0.052; Friday recall about 32% | Human investigation; no automatic enforcement |
| Unseen attacks | Held-out web-attack experiment | Stored in model evaluation.json | Development evidence only; configuration selection was not fully family-blind |
| Explanation limitations | SHAP reconstruction and LIME repeatability tests | Numerical consistency, not causal correctness | Show fidelity and correlated-feature warnings |
| Account attribution | User isolation and notification tests | Network flows do not identify accounts | Separate authenticated application events |
| GeoIP uncertainty | Private/missing-database fallbacks | No fabricated location | Optional city/country context only |
| Notification reliability | Mocked SMTP/TLS, lease recovery, outbox integration | Local tests, not actual inbox delivery | Configure provider and verify receipt |

Friday was examined during earlier development and is not a pristine external test. Sampling
changes prevalence and score interpretation. TrafficLabelling overlaps CIC and is not independent.

## Not completed or not connected

PostgreSQL migration is not implemented. Public backend hosting, repository push, real SMTP,
licensed GeoIP data and an authorized live collector remain external setup work. Docker packaging
does not itself demonstrate successful container deployment. This prototype is not a complete
production account-security product: recovery, MFA, retention enforcement and deployment hardening
need additional work. No claims of detecting every attack or identifying an attacker are justified.
