# Security model, threat model and limitations

## Implemented controls
- Passwords hashed with Argon2id; login timing equalised for unknown users; generic failure message.
- JWT (HS256) with required `exp`; the `none` algorithm and forged signatures are rejected (tested). Role and active flag
  are read from the database on every request — token claims are never trusted for authorization.
- Authorization is enforced server-side per endpoint (`require_role`); the UI only hides controls.
- No default administrator. Self-registration yields `viewer` only. Admins are created with the CLI.
- `NEXOPS_SECRET_KEY` is mandatory, ≥ 32 chars, and obvious placeholders are rejected at startup.
- Responses never include password hashes or tokens (other than the login token itself); audit records, structured logs
  and event details are passed through a redactor for secret-looking keys (password, token, authorization, …).
- Input validation (Pydantic): strict service names/versions, metric ranges, bounded sizes, secret-looking metadata keys
  rejected, LIKE wildcards escaped in search.
- Unhandled exceptions return a generic 500 without internals.
- Recovery: closed allowlist (3 actions), demo-only services, separate approver by default, approval TTL, exact typed
  confirmation, re-check of eligibility at execution time, one execution per approval, every attempt audited.
  The recovery module imports no subprocess/OS/network modules and the test suite asserts it.

## Threat model (STRIDE-lite)
| Threat | Mitigation | Residual risk |
|---|---|---|
| Credential guessing | Argon2, generic errors, **detection** of brute-force patterns | **No rate limiting or lockout**; detection is after the fact |
| Privilege escalation via API | Server-side roles, admin-only role changes, last-admin guard, escalation detection | Admin compromise = full control |
| Forged/stolen tokens | Signed, expiring tokens | **No revocation or refresh rotation**; token lives in `sessionStorage` (XSS-readable) |
| Arbitrary command execution via recovery | No execution code exists; allowlisted enum; demo-only | Real recovery is deliberately not implemented |
| Log/audit leakage | Redaction, no password/token fields | Free-text fields (`notes`, `reason`) are the user's responsibility |
| Tampering with audit history | Append-only API (no update/delete endpoints) | DB administrators can still alter rows; no hash chaining |
| Spoofed client IP | `X-Forwarded-For` is ignored | Behind a reverse proxy all clients appear as the proxy IP |
| SSRF | The API never fetches user-supplied URLs (health data is ingested, not probed) | — |

## Known limitations (be honest in interviews)
- Detection is on-demand (button/API/CLI); there is no scheduler.
- `/metrics`, `/docs` and `/openapi.json` are unauthenticated; do not expose the API port publicly.
- No TLS termination, CSRF concerns are avoided only because tokens are in an `Authorization` header.
- Dependencies were installed at the newest versions available during the build; run `pip-audit`/`npm audit` yourself
  before relying on them — this was **not** done here.
- No MFA, email verification, password reset or account lockout.
- Heuristic rules produce false positives (e.g. legitimate admin onboarding) and cannot catch sophisticated attackers.
