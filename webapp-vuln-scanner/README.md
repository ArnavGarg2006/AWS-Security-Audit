# Web App Vulnerability Scanner

A focused OWASP-flavored scanner for a small API-backed web app — security headers,
HTTPS enforcement, CORS configuration, injection payload resilience, error disclosure,
and rate-limit verification. Built to scan our own [fullstack-contact-app](../fullstack-contact-app/),
but the target URLs are arguments, so it works against anything you're authorized to test.

## Why not a generic OWASP ZAP-style crawler

`fullstack-contact-app` is a single page with one form and a JSON API — there's nothing
to "crawl," and its backend is DynamoDB via the AWS SDK's object-based API, not raw SQL,
so classic string-concatenation SQL injection isn't structurally possible the way it would
be against a traditional server. Rather than build a generic scanner and get mostly `N/A`
results, this tests what's actually applicable: headers, transport security, CORS, and
whether the app degrades gracefully under bad input and load.

## What it checks

| Check | What it does |
|---|---|
| `VULN.1` HTTPS enforcement | Is the frontend served over plain HTTP? |
| `VULN.2` Security headers | CSP, X-Content-Type-Options, X-Frame-Options, HSTS, Referrer-Policy — checked against a request that actually reaches the backend (see note below) |
| `VULN.3` CORS | Wildcard origin, wildcard-with-credentials (the actually-dangerous combination), or Origin-reflection instead of an allowlist |
| `VULN.4`/`VULN.5` Injection resilience | 10 payloads (XSS, SQLi-style, command injection, NoSQL-style, path traversal, template injection, null bytes) — flags 500s or leaked internals, not "did it get rejected," since a clean 400 is the *correct* outcome |
| `VULN.6` Rate limiting | Fires a real concurrent burst (not sequential — see below) and checks for 429/403 |
| `VULN.7` HTTP methods | Confirms unexpected verbs (PUT/DELETE/TRACE/PATCH) aren't silently accepted |

## Two real bugs this scanner had, and what fixing them taught us

**The header check was silently checking the wrong thing.** It did a blind `GET` on
`/contact` — a POST-only route. That hit API Gateway's generic "no route matched" error
page, which never touches the Lambda, so *none* of the headers we'd actually added ever
showed up as present. Fixed by making the check use the HTTP method that actually reaches
the backend (`POST` for `/contact`, matching real traffic).

**The rate-limit check used a sequential loop, then a too-small concurrent burst.** A
`for` loop sending requests one at a time can never exceed a burst-capacity limit — each
request completes before the next starts. Fixed with a `ThreadPoolExecutor`. That then
revealed a second issue: `requests`/`urllib3` defaults to a connection pool of 10 per
host, so even "concurrent" code was serializing at the TCP layer. Fixed by mounting a
`Session` with a widened pool. *That* revealed something real: under genuine concurrent
load, requests were failing with raw `500`s instead of clean `429`s.

Chasing that down (not just reporting it) led to the actual root cause: this AWS
account's Lambda concurrent-execution quota is capped at **10** — versus AWS's normal
default of 1000. Confirmed via `aws lambda get-account-settings`. Requesting a self-service
increase failed with `"You must provide a quota value greater than the default quota
value of 1000.0"` — this reduced quota is a special account-level restriction that needs
an AWS Support ticket, the same pattern as the CloudFront and SES gates documented
elsewhere in this repo. The immediate mitigation applied: lowered the API Gateway stage's
burst limit from 20 to 8 (below the account's Lambda ceiling), so the Gateway's clean 429
has a better chance of intercepting a flood before it reaches Lambda's harder wall — plus
client-side retry-with-backoff on the frontend for whatever still gets through as a 500.

## Results against the live contact form (before → after fixes)

12 findings → 7. Fixed: all 5 missing headers on the API (added directly to the Lambda
response), CSP + Referrer-Policy on the frontend (via `<meta>` tags — partial; `X-Frame-Options`
and HSTS genuinely require real HTTP headers, which plain S3 static hosting can't add
without CloudFront). Remaining 7 all trace back to the same two account-level gates
(CloudFront verification, Lambda concurrency quota) rather than anything left to fix in
code — see `fullstack-contact-app/README.md` for the full picture.

No injection, CORS, or error-disclosure findings survived any run — that's the existing
hardening (input validation, `escapeHtml()` on the frontend, IAM least-privilege, no raw
SQL) holding up under adversarial testing, not an absence of testing.

## Usage

```bash
pip install -r requirements.txt

python scanner.py \
  --frontend http://your-site \
  --contact-url https://your-api/prod/contact \
  --json-out scan-report.json
```

Exit code `1` if any CRITICAL/HIGH finding was reported, `0` otherwise.
