#!/usr/bin/env python
"""
Web app vulnerability scanner.

A focused OWASP-flavored scanner for a small API-backed web app: security
headers, HTTPS enforcement, CORS configuration, injection payload resilience,
error disclosure, and rate-limit verification. Built to scan our own
fullstack-contact-app, but the target URLs are arguments — point it at
anything you're authorized to test.

Deliberately does NOT attempt SQL injection against a real database (there
isn't one here — the backend is DynamoDB, accessed via the AWS SDK's
object-based API, which is not vulnerable to string-concatenation injection
the way raw SQL is) or brute-force anything. This tests what's actually
applicable to a serverless, unauthenticated JSON API.
"""
import argparse
import json
import sys
import time
from dataclasses import dataclass, field
from urllib.parse import urlparse

import requests
from rich.console import Console
from rich.table import Table

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEVERITY_COLOR = {
    "CRITICAL": "bold white on red", "HIGH": "bold red",
    "MEDIUM": "bold yellow", "LOW": "cyan", "INFO": "dim",
}

INJECTION_PAYLOADS = [
    ("XSS (script tag)", "<script>alert(1)</script>"),
    ("XSS (event handler)", '"><img src=x onerror=alert(1)>'),
    ("SQL injection style", "' OR '1'='1"),
    ("SQL injection (drop)", "'; DROP TABLE users; --"),
    ("Command injection", "test; cat /etc/passwd"),
    ("Command substitution", "$(whoami)"),
    ("NoSQL injection style", '{"$gt": ""}'),
    ("Path traversal", "../../../../etc/passwd"),
    ("Template injection", "{{7*7}}"),
    ("Null byte", "test\x00.txt"),
]

RECOMMENDED_HEADERS = {
    "content-security-policy": ("MEDIUM", "Content-Security-Policy",
                                 "Add a CSP restricting script/style sources to mitigate XSS impact."),
    "x-content-type-options": ("LOW", "X-Content-Type-Options",
                                "Add 'X-Content-Type-Options: nosniff' to stop MIME-sniffing."),
    "x-frame-options": ("MEDIUM", "X-Frame-Options",
                         "Add 'X-Frame-Options: DENY' (or CSP frame-ancestors) to prevent clickjacking."),
    "strict-transport-security": ("MEDIUM", "Strict-Transport-Security",
                                   "Add HSTS once served over HTTPS, to prevent protocol downgrade."),
    "referrer-policy": ("LOW", "Referrer-Policy",
                         "Add a Referrer-Policy to avoid leaking full URLs to third parties."),
}

LEAK_PATTERNS = [
    "traceback (most recent call last)", "at Object.", "at exports.",
    "arn:aws:", "/home/", "c:\\users\\", "internal server error: ",
    "nodejs.org", "syntaxerror:", "referenceerror:",
]


@dataclass
class Finding:
    check_id: str
    severity: str
    title: str
    detail: str
    remediation: str

    def sort_key(self):
        return SEVERITY_ORDER.get(self.severity, 99)


@dataclass
class ScanResult:
    findings: list = field(default_factory=list)
    checks_run: int = 0

    def add(self, *findings):
        self.findings.extend(findings)


def check_https(frontend_url):
    findings = []
    scheme = urlparse(frontend_url).scheme
    if scheme != "https":
        findings.append(Finding(
            "VULN.1", "HIGH", "Frontend is not served over HTTPS",
            f"'{frontend_url}' uses '{scheme}://'. Traffic (including anything typed into "
            "the form) is unencrypted and can be intercepted or modified in transit.",
            "Serve the frontend over HTTPS (e.g. via CloudFront with an ACM certificate).",
        ))
    return findings


def check_security_headers(url, label, method="GET", json_body=None):
    """method/json_body let callers hit a route+verb that actually reaches the
    backend — GETing a POST-only route returns API Gateway's generic
    "no route matched" error page, which never touches the Lambda and so never
    carries its custom headers, silently making every header look missing."""
    findings = []
    try:
        resp = requests.request(method, url, json=json_body, timeout=10)
    except requests.RequestException as e:
        return [Finding("VULN.2", "INFO", f"Could not check headers on {label}", str(e), "")]

    headers_lower = {k.lower(): v for k, v in resp.headers.items()}
    for header, (severity, name, remediation) in RECOMMENDED_HEADERS.items():
        if header not in headers_lower:
            findings.append(Finding(
                "VULN.2", severity, f"Missing '{name}' header on {label}",
                f"Response from {url} did not include a '{name}' header.",
                remediation,
            ))
    return findings


def check_cors(api_url):
    findings = []
    try:
        resp = requests.options(api_url, headers={
            "Origin": "https://evil.example.com",
            "Access-Control-Request-Method": "POST",
        }, timeout=10)
    except requests.RequestException as e:
        return [Finding("VULN.3", "INFO", "Could not check CORS", str(e), "")]

    allow_origin = resp.headers.get("Access-Control-Allow-Origin", "")
    allow_creds = resp.headers.get("Access-Control-Allow-Credentials", "").lower() == "true"

    if allow_origin == "*" and allow_creds:
        findings.append(Finding(
            "VULN.3", "CRITICAL", "CORS allows wildcard origin WITH credentials",
            "Access-Control-Allow-Origin: * combined with Allow-Credentials: true lets any "
            "site read authenticated responses on a user's behalf.",
            "Never combine a wildcard origin with credentialed requests.",
        ))
    elif allow_origin == "*":
        findings.append(Finding(
            "VULN.3", "MEDIUM", "CORS allows any origin (Access-Control-Allow-Origin: *)",
            "Any website can call this API from client-side JavaScript.",
            "Restrict Access-Control-Allow-Origin to the specific frontend origin.",
        ))
    elif allow_origin == "https://evil.example.com":
        findings.append(Finding(
            "VULN.3", "CRITICAL", "CORS reflects arbitrary Origin header",
            f"Sending Origin: https://evil.example.com got it echoed back as the allowed origin — "
            "the server is reflecting whatever Origin it receives instead of checking an allowlist.",
            "Validate Origin against an explicit allowlist rather than reflecting it.",
        ))
    return findings


def check_injection_resilience(api_url):
    findings = []
    for label, payload in INJECTION_PAYLOADS:
        try:
            resp = requests.post(api_url, json={"name": payload, "email": "scanner-test@example.com"}, timeout=10)
        except requests.RequestException as e:
            findings.append(Finding("VULN.4", "INFO", f"Request failed for payload '{label}'", str(e), ""))
            continue

        if resp.status_code >= 500:
            findings.append(Finding(
                "VULN.4", "HIGH", f"Payload '{label}' caused a server error ({resp.status_code})",
                f"Sending name='{payload}' returned HTTP {resp.status_code} instead of a handled "
                "400/200 — this may indicate the input isn't being safely handled.",
                "Ensure all input paths are validated and errors are caught, not left to crash the handler.",
            ))

        body_lower = resp.text.lower()
        for pattern in LEAK_PATTERNS:
            if pattern in body_lower:
                findings.append(Finding(
                    "VULN.5", "HIGH", f"Response leaks internal details (payload: '{label}')",
                    f"Response body contains '{pattern}', suggesting a stack trace, file path, "
                    "or internal identifier was exposed to the client.",
                    "Return generic error messages to clients; log details server-side only.",
                ))
                break
    return findings


def check_malformed_input(api_url):
    findings = []
    try:
        resp = requests.post(api_url, data="{not valid json", headers={"Content-Type": "application/json"}, timeout=10)
        if resp.status_code >= 500:
            findings.append(Finding(
                "VULN.4", "HIGH", "Malformed JSON body caused a server error",
                f"POSTing invalid JSON returned HTTP {resp.status_code} instead of a handled 400.",
                "Wrap JSON parsing in a try/except and return 400 on failure.",
            ))
    except requests.RequestException:
        pass

    try:
        oversized = "a" * 100_000
        resp = requests.post(api_url, json={"name": oversized, "email": "scanner-test@example.com"}, timeout=15)
        if resp.status_code >= 500:
            findings.append(Finding(
                "VULN.4", "MEDIUM", "Oversized input caused a server error",
                f"A 100,000-character name field returned HTTP {resp.status_code}.",
                "Enforce input length limits before processing (return 400, not 500).",
            ))
    except requests.RequestException:
        pass
    return findings


def check_rate_limiting(api_url, burst=100):
    """Fires requests CONCURRENTLY — a sequential loop would never exceed a
    burst-capacity limit, since each request completes (with network latency)
    before the next starts, understating the actual request rate. Uses a
    Session with a widened connection pool, since requests/urllib3 defaults
    to a pool of 10 per host — too small to actually achieve 100-way
    concurrency, which would silently serialize the "burst" at the TCP level
    and understate it the same way a sequential loop would."""
    from concurrent.futures import ThreadPoolExecutor

    session = requests.Session()
    adapter = requests.adapters.HTTPAdapter(pool_connections=burst, pool_maxsize=burst)
    session.mount("https://", adapter)
    session.mount("http://", adapter)

    def fire(_):
        try:
            resp = session.post(api_url, json={"name": "rate-test", "email": "rate-test@example.com"}, timeout=10)
            return resp.status_code
        except requests.RequestException:
            return 0

    start = time.time()
    with ThreadPoolExecutor(max_workers=burst) as pool:
        statuses = list(pool.map(fire, range(burst)))
    elapsed = time.time() - start

    findings = []
    # 429 = API Gateway/Lambda-level throttle. 403 = WAF rate-based rule block.
    # Both are legitimate "this burst got rejected" signals, just from different layers.
    throttled_clean = sum(1 for s in statuses if s in (429, 403))
    server_errors = sum(1 for s in statuses if s >= 500)
    status_counts = {s: statuses.count(s) for s in sorted(set(statuses))}

    if throttled_clean > 0:
        blocker = "WAF (403)" if 403 in status_counts else "API Gateway/Lambda (429)"
        findings.append(Finding(
            "VULN.6", "INFO",
            f"Rate limiting confirmed via {blocker}: {throttled_clean}/{burst} requests blocked",
            f"Completed in {elapsed:.1f}s, status codes: {status_counts}.", "",
        ))
    elif server_errors > 0:
        findings.append(Finding(
            "VULN.6", "HIGH",
            f"Burst load causes raw 500 errors instead of clean 429 throttling "
            f"({server_errors}/{burst} requests failed)",
            f"{burst} concurrent requests in {elapsed:.1f}s produced status codes {status_counts}. "
            "The API Gateway stage throttle (rate/burst limit) is not intercepting the flood before "
            "it reaches Lambda — instead, Lambda's own concurrency limit is being exceeded, which "
            "surfaces to callers as an ugly 500 rather than a clean, expected 429. This also makes a "
            "capacity issue look like an application bug in monitoring.",
            "Tune the API Gateway stage burst limit below Lambda's available concurrency (or set "
            "reserved concurrency on the function) so the Gateway's 429 intercepts the flood first, "
            "or add exponential backoff + retry handling on the client for 5xx responses.",
        ))
    else:
        findings.append(Finding(
            "VULN.6", "MEDIUM",
            f"No rate limiting observed across {burst} concurrent requests ({elapsed:.1f}s)",
            f"All {burst} requests fired concurrently returned non-429, non-5xx statuses: {status_counts}.",
            "Add API Gateway throttling and/or a WAF rate-based rule to cap abuse.",
        ))
    return findings


def check_http_methods(api_url):
    findings = []
    for method in ("PUT", "DELETE", "TRACE", "PATCH"):
        try:
            resp = requests.request(method, api_url, timeout=10)
        except requests.RequestException:
            continue
        if resp.status_code not in (403, 404, 405):
            findings.append(Finding(
                "VULN.7", "LOW", f"Unexpected method {method} did not return 403/404/405",
                f"{method} {api_url} returned HTTP {resp.status_code}.",
                "Confirm only the intended HTTP methods are wired up in the API Gateway resource.",
            ))
    return findings


CHECKS = [
    ("VULN.1", "HTTPS enforcement", lambda ctx: check_https(ctx["frontend"])),
    ("VULN.2", "Security headers (frontend)", lambda ctx: check_security_headers(ctx["frontend"], "frontend")),
    ("VULN.2", "Security headers (API)", lambda ctx: check_security_headers(
        ctx["contact_url"], "API", method="POST",
        json_body={"name": "Header Check", "email": "header-check@example.com"})),
    ("VULN.3", "CORS configuration", lambda ctx: check_cors(ctx["contact_url"])),
    ("VULN.4/5", "Injection payload resilience", lambda ctx: check_injection_resilience(ctx["contact_url"])),
    ("VULN.4", "Malformed / oversized input handling", lambda ctx: check_malformed_input(ctx["contact_url"])),
    ("VULN.6", "Rate limit verification", lambda ctx: check_rate_limiting(ctx["contact_url"])),
    ("VULN.7", "HTTP method exposure", lambda ctx: check_http_methods(ctx["contact_url"])),
]


def run_scan(frontend, contact_url):
    ctx = {"frontend": frontend, "contact_url": contact_url}
    result = ScanResult()
    console = Console()
    for check_id, description, fn in CHECKS:
        console.print(f"[dim]Running {check_id}: {description}...[/dim]")
        result.checks_run += 1
        try:
            result.add(*fn(ctx))
        except Exception as e:  # noqa: BLE001 - one check's failure shouldn't kill the scan
            result.add(Finding(check_id, "INFO", f"Check '{description}' failed to run", str(e), ""))
    return result


def print_report(result):
    console = Console()
    findings = sorted(result.findings, key=lambda f: f.sort_key())
    real_findings = [f for f in findings if f.severity != "INFO"]

    console.print(f"\n[bold]Web App Vulnerability Scan[/bold]  "
                  f"checks_run={result.checks_run}  findings={len(real_findings)}\n")

    if not real_findings:
        console.print("[green]No findings.[/green]")
    else:
        table = Table(show_lines=False)
        table.add_column("Severity")
        table.add_column("Check")
        table.add_column("Title", overflow="fold")
        table.add_column("Remediation", overflow="fold")
        for f in real_findings:
            color = SEVERITY_COLOR.get(f.severity, "")
            table.add_row(f"[{color}]{f.severity}[/{color}]", f.check_id, f.title, f.remediation)
        console.print(table)

    info = [f for f in findings if f.severity == "INFO"]
    if info:
        console.print(f"\n[dim]Notes ({len(info)}):[/dim]")
        for f in info:
            console.print(f"  [dim]{f.title}: {f.detail}[/dim]")


def write_json(result, path):
    data = {
        "checks_run": result.checks_run,
        "findings": [
            {"check_id": f.check_id, "severity": f.severity, "title": f.title,
             "detail": f.detail, "remediation": f.remediation}
            for f in sorted(result.findings, key=lambda f: f.sort_key())
        ],
    }
    with open(path, "w", encoding="utf-8") as fp:
        json.dump(data, fp, indent=2)


def main():
    parser = argparse.ArgumentParser(description="Web app vulnerability scanner (headers, CORS, injection, rate limiting).")
    parser.add_argument("--frontend", required=True, help="Frontend URL, e.g. http://your-site")
    parser.add_argument("--contact-url", required=True, help="POST endpoint to test, e.g. https://api/.../contact")
    parser.add_argument("--json-out", help="Write findings to this JSON path")
    args = parser.parse_args()

    result = run_scan(args.frontend, args.contact_url)
    print_report(result)
    if args.json_out:
        write_json(result, args.json_out)
        print(f"\nJSON report written to {args.json_out}")

    critical_or_high = any(f.severity in ("CRITICAL", "HIGH") for f in result.findings)
    sys.exit(1 if critical_or_high else 0)


if __name__ == "__main__":
    main()
