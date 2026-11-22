# Findings: OWASP Juice Shop baseline assessment

**Target:** OWASP Juice Shop v17.1.1, running locally (deliberately vulnerable training app)
**Method:** OWASP ZAP baseline scan (passive), then manual verification of response headers with `curl -I`
**Scope:** passive checks only; no active attacks were run
**Result:** 12 alerts from ZAP, triaged into 6 findings to fix and 5 accepted as not significant

## Summary

| # | Finding | Risk | OWASP Top 10 (2021) |
|---|---|---|---|
| 1 | Content Security Policy header not set | Medium | A05 Security Misconfiguration |
| 2 | Permissive CORS policy (`Access-Control-Allow-Origin: *`) | Medium | A05 Security Misconfiguration |
| 3 | JavaScript loaded from other domains | Low | A08 Software and Data Integrity Failures |
| 4 | Dangerous JavaScript functions (needs code review) | Low | A03 Injection, if confirmed |
| 5 | Cross-origin isolation headers missing (COOP, COEP) | Low | A05 Security Misconfiguration |
| 6 | Outdated `Feature-Policy` header | Low | A05 Security Misconfiguration |

## Findings

### 1. Content Security Policy header not set
- **Risk:** Medium (agree with ZAP)
- **What it is:** The app does not tell browsers which sources of scripts and content to trust.
- **Evidence:** ZAP flagged 5 pages; `curl -I http://localhost:3000` returns no `Content-Security-Policy` header.
- **Impact:** If an attacker manages to inject a script, nothing stops the browser running it,
  so cross-site scripting would be far more damaging.
- **Fix:** Add a `Content-Security-Policy` header that only allows scripts from the app's own origin and
  approved domains. Deploy it in report-only mode first so legitimate features don't break.

### 2. Permissive CORS policy
- **Risk:** Medium (agree with ZAP)
- **What it is:** The app sends `Access-Control-Allow-Origin: *`, allowing any website to read its responses.
- **Evidence:** ZAP flagged 5 responses; the header is present in the `curl -I` output.
- **Impact:** A malicious site visited by a user could read data from the app's API in their browser.
- **Fix:** Replace `*` with an allow-list of specific trusted origins, or remove CORS headers where cross-origin access isn't needed.
- **Note:** my summariser mapped this to A01 from its CWE; on review, A05 fits better,
  showing why automated mappings still need a person to check them.

### 3. JavaScript loaded from other domains
- **Risk:** Low (agree with ZAP)
- **What it is:** Pages load script files from third-party domains.
- **Evidence:** ZAP flagged 5 pages including external script sources.
- **Impact:** If a third-party domain is compromised, its scripts run with full access to the app in users' browsers.
- **Fix:** Host critical scripts locally, or add Subresource Integrity (`integrity` attributes) so browsers reject altered files.

### 4. Dangerous JavaScript functions
- **Risk:** Low per ZAP, but needs manual review before rating
- **What it is:** ZAP found functions in the app's JavaScript that can execute or inject code if fed untrusted input.
- **Evidence:** ZAP flagged 2 locations. A passive scan cannot tell whether user input reaches them.
- **Impact:** If user input reaches these functions, they could allow cross-site scripting.
- **Fix:** Review each location in the source code; replace with safer alternatives or ensure input is strictly validated and encoded.

### 5. Cross-origin isolation headers missing
- **Risk:** Low (agree with ZAP)
- **What it is:** `Cross-Origin-Opener-Policy` and `Cross-Origin-Embedder-Policy` headers are not set.
- **Evidence:** ZAP flagged 5 pages for each header.
- **Impact:** Weaker isolation from other sites' windows and resources; mainly a defence-in-depth gap.
- **Fix:** Set `Cross-Origin-Opener-Policy: same-origin` and test `Cross-Origin-Embedder-Policy: require-corp`.

### 6. Outdated Feature-Policy header
- **Risk:** Low (agree with ZAP)
- **What it is:** The app uses `Feature-Policy`, which modern browsers have replaced with `Permissions-Policy`.
- **Evidence:** `Feature-Policy: payment 'self'` in the `curl -I` output, with no `Permissions-Policy` header.
- **Impact:** Restrictions on browser features may not be applied by current browsers.
- **Fix:** Add an equivalent `Permissions-Policy` header.

## Controls already in place
- `X-Content-Type-Options: nosniff` stops browsers guessing content types.
- `X-Frame-Options: SAMEORIGIN` prevents other sites framing the app (clickjacking protection).

## Accepted or not applicable
| Alert | Reason |
|---|---|
| Timestamp Disclosure (Low) | An ordinary timestamp in a script file, not sensitive information |
| Modern Web Application (Info) | Informational only: the site uses JavaScript |
| Non-Storable / Storable / Storable but Non-Cacheable Content (Info) | Caching of public content is fine; would only matter for personal data |
| `X-Recruiting` header | A harmless joke header in Juice Shop |
| Missing `Strict-Transport-Security` | Not applicable to local HTTP; add HSTS when served over HTTPS in production |

## Limitations
A passive baseline scan only sees what the app shows in normal responses. It does not find flaws that need
active testing, such as injection or broken access control, so a clean baseline scan never means an app is secure.
Juice Shop is deliberately vulnerable and contains many issues this scan cannot detect.