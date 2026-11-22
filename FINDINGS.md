# Findings: OWASP Juice Shop baseline assessment

**Target:** OWASP Juice Shop v17.1.1, running locally (deliberately vulnerable training app)
**Method:** OWASP ZAP baseline scan (passive), then manual verification of response headers with `curl -I`
**Scope:** passive checks only; no active attacks were run

## Summary

| # | Finding | Risk | OWASP Top 10 (2021) |
|---|---|---|---|
| 1 | Content Security Policy header not set | Medium | A05 Security Misconfiguration |
| 2 | Permissive CORS policy (`Access-Control-Allow-Origin: *`) | Medium | A05 Security Misconfiguration |
| 3 | Outdated `Feature-Policy` header instead of `Permissions-Policy` | Low | A05 Security Misconfiguration |

## Findings

### 1. Content Security Policy header not set
- **Risk:** Medium (agree with ZAP)
- **What it is:** The app does not tell browsers which sources of scripts and content to trust.
- **Evidence:** `curl -I http://localhost:3000` returns no `Content-Security-Policy` header.
- **Impact:** If an attacker manages to inject a script, nothing stops the browser running it,
  so cross-site scripting would be far more damaging.
- **Fix:** Add a `Content-Security-Policy` header that only allows scripts from the app's own origin.
  Deploy it in report-only mode first so legitimate features don't break.

### 2. Permissive CORS policy
- **Risk:** Medium
- **What it is:** The app sends `Access-Control-Allow-Origin: *`, allowing any website to read its responses.
- **Evidence:** the header is present in the `curl -I` output.
- **Impact:** A malicious site visited by a user could read data from the app's API in their browser.
- **Fix:** Replace `*` with an allow-list of the specific trusted origins.
- **Note:** my summariser mapped this to A01 by its CWE; on review, A05 fits better,
  showing why automated mappings still need a person to check them.

### 3. Outdated Feature-Policy header
- **Risk:** Low
- **What it is:** The app uses `Feature-Policy`, which modern browsers have replaced with `Permissions-Policy`.
- **Evidence:** `Feature-Policy: payment 'self'` in the response, with no `Permissions-Policy` header.
- **Impact:** Restrictions on browser features may not be applied by current browsers.
- **Fix:** Add an equivalent `Permissions-Policy` header.

## Controls already in place
- `X-Content-Type-Options: nosniff` stops browsers guessing content types.
- `X-Frame-Options: SAMEORIGIN` prevents other sites framing the app (clickjacking protection).

## Accepted or not applicable
- **`X-Recruiting` header:** a harmless joke header in Juice Shop. Accepted.
- **Missing `Strict-Transport-Security`:** not applicable to this local HTTP test. HSTS only takes effect
  over HTTPS and should be added when the app is served over HTTPS in production.

## Limitations
A passive baseline scan only sees what the app shows in normal responses. It does not find flaws that need
active testing, such as injection or broken access control, so a clean baseline scan never means an app is secure.