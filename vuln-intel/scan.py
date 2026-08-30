#!/usr/bin/env python
"""
Vulnerability intelligence — cross-references THIS account's real deployed
software against public vulnerability data, instead of only checking AWS
config flags. Two real, different data sources for two real, different
questions:

  Runtime CVEs (NVD)       — is the Lambda runtime's underlying language
                             version affected by published CVEs at all?
  Dependency CVEs (OSV.dev) — does the actual pinned package-lock.json this
                             account deployed contain a package version with
                             a known vulnerability?

Why two sources, not one: NVD is CPE/product-version oriented (great for
"is Node.js 20.0.0 affected by anything," useless for "is
aws-xray-sdk-core@3.9.0 affected by anything" — its own keyword search
returns unrelated noise for that, verified live before building this).
OSV.dev is ecosystem/package-native (npm, PyPI, ...) and answers the
dependency question precisely, but doesn't cover "the language runtime
itself." Using each for what it's actually good at instead of forcing one
API to answer both questions.

Honesty note: for Lambda's AWS-managed runtimes, AWS patches the underlying
OS/runtime layer itself on its own schedule — a CVE against the upstream
Node.js/Python version doesn't necessarily mean AWS's managed build is
still vulnerable. This reports real upstream CVEs against the declared
runtime version as an exposure/awareness signal, not a guaranteed "this
Lambda is exploitable" claim — the same honesty this project applies to
every heuristic-based check elsewhere.

Usage:
    python scan.py [--region ap-south-1]
"""
import argparse
import json
import re
import sys
import time
from pathlib import Path

import boto3
import requests

sys.stdout.reconfigure(encoding="utf-8")

NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{}"

# Lambda runtime identifier -> (NVD vendor, NVD product, representative version).
# Lambda pins a MAJOR version (e.g. "nodejs20.x"); AWS manages the exact patch
# build, so ".0.0" is the best "does this major line have known CVEs at all"
# baseline available without knowing AWS's internal patch level.
RUNTIME_CPE = {
    "nodejs20.x": ("nodejs", "nodejs", "20.0.0"),
    "nodejs18.x": ("nodejs", "nodejs", "18.0.0"),
    "python3.13": ("python", "python", "3.13.0"),
    "python3.12": ("python", "python", "3.12.0"),
    "python3.11": ("python", "python", "3.11.0"),
}

# Manifests this project knows how to map back to a specific deployed
# Lambda function, for the dependency-CVE check.
LAMBDA_DEPENDENCY_MANIFESTS = {
    "contact-form-handler": Path(__file__).parent.parent / "fullstack-contact-app" / "backend" / "package-lock.json",
}


def enumerate_lambda_runtimes(session, region):
    lam = session.client("lambda", region_name=region)
    functions = []
    for page in lam.get_paginator("list_functions").paginate():
        for fn in page["Functions"]:
            functions.append((fn["FunctionName"], fn["Runtime"]))
    return functions


def _is_genuinely_vulnerable(cve, vendor, product):
    """NVD's `virtualMatchString` returns a CVE if OUR cpe appears in ANY
    cpeMatch node of its configurations -- including nodes marked
    `vulnerable: False`, which NVD uses to record "this runs on Python 3.6+"
    as CONTEXT for a vulnerability in some other product entirely (e.g.
    CVE-2020-29396 is an Odoo sandboxing bug; Python 3.6+ is listed only as
    the platform it needs to run on, with an open-ended version range that
    sweeps in every future Python release including ours). Caught live: the
    first version of this function counted that as "Python 3.13 has a HIGH
    CVE," which was true of NVD's response and false as a real finding.
    Fixed by only counting a match where OUR cpe criteria is marked
    `vulnerable: True` -- i.e. it's actually the vulnerable component, not
    a bystander dependency of something else."""
    needle = f"{vendor}:{product}:"
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if match.get("vulnerable") and needle in match.get("criteria", ""):
                    return True
    return False


def check_runtime_cves(runtime):
    """Real CPE version-range match against NVD (not keyword search — see
    module docstring for why keyword search was rejected), filtered to CVEs
    where the runtime is the actual vulnerable component (see
    _is_genuinely_vulnerable). Returns a list of {id, severity, published}
    or None if this runtime isn't mapped."""
    entry = RUNTIME_CPE.get(runtime)
    if not entry:
        return None
    vendor, product, version = entry
    match_string = f"cpe:2.3:a:{vendor}:{product}:{version}"

    try:
        resp = requests.get(NVD_CVE_URL, params={
            "virtualMatchString": match_string,
            "resultsPerPage": 200,
        }, timeout=15)
        resp.raise_for_status()
        data = resp.json()
    except requests.RequestException as e:
        print(f"  (NVD lookup failed for {runtime}: {e})", file=sys.stderr)
        return None

    results = []
    for v in data.get("vulnerabilities", []):
        cve = v["cve"]
        if not _is_genuinely_vulnerable(cve, vendor, product):
            continue
        severity = "UNKNOWN"
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metrics = cve.get("metrics", {}).get(key)
            if metrics:
                severity = metrics[0]["cvssData"].get("baseSeverity", "UNKNOWN")
                break
        results.append({"id": cve["id"], "severity": severity, "published": cve["published"][:10]})
    return results


def parse_npm_lockfile(path):
    """lockfileVersion 3 "packages" map: keys are node_modules paths, which
    may be nested (node_modules/a/node_modules/b) — take the segment after
    the LAST "node_modules/" so scoped packages (@aws-sdk/client-x) stay
    intact. Skips the root "" entry (the project itself, not a dependency)."""
    with open(path, encoding="utf-8") as f:
        data = json.load(f)

    deps = {}
    for pkg_path, info in data.get("packages", {}).items():
        if pkg_path == "" or "version" not in info:
            continue
        name = pkg_path.rsplit("node_modules/", 1)[-1]
        deps[name] = info["version"]
    return deps


def check_npm_vulns(dependencies):
    """Batches every (name, version) through OSV.dev's querybatch endpoint
    in one request, then fetches full details only for packages that
    actually matched something -- not one request per package."""
    names = list(dependencies.keys())
    queries = [{"package": {"name": n, "ecosystem": "npm"}, "version": dependencies[n]} for n in names]

    findings = []
    try:
        resp = requests.post(OSV_BATCH_URL, json={"queries": queries}, timeout=30)
        resp.raise_for_status()
        batch_results = resp.json().get("results", [])
    except requests.RequestException as e:
        print(f"  (OSV.dev batch query failed: {e})", file=sys.stderr)
        return findings

    for name, result in zip(names, batch_results):
        for vuln_ref in result.get("vulns", []):
            vuln_id = vuln_ref["id"]
            try:
                detail = requests.get(OSV_VULN_URL.format(vuln_id), timeout=15).json()
            except requests.RequestException:
                detail = {}
            aliases = detail.get("aliases", [])
            cve_id = next((a for a in aliases if a.startswith("CVE-")), vuln_id)
            summary = detail.get("summary", "(no summary provided)")
            severity = "UNKNOWN"
            for sev in detail.get("severity", []):
                if sev.get("type") == "CVSS_V3":
                    severity = sev["score"]
                    break
            findings.append({
                "package": name, "version": dependencies[name],
                "id": cve_id, "osv_id": vuln_id, "severity": severity, "summary": summary,
            })
            time.sleep(0.1)  # be polite to a free public API
    return findings


def main():
    parser = argparse.ArgumentParser(description="Cross-reference deployed Lambda runtimes/dependencies against public CVE data.")
    parser.add_argument("--region", default="ap-south-1")
    parser.add_argument("--profile")
    args = parser.parse_args()

    session = boto3.Session(profile_name=args.profile)
    functions = enumerate_lambda_runtimes(session, args.region)

    print(f"Scanning {len(functions)} Lambda function(s) against public vulnerability data...\n")

    total_high_or_critical = 0

    for fn_name, runtime in functions:
        print(f"{fn_name}  (runtime: {runtime})")

        cves = check_runtime_cves(runtime)
        if cves is None:
            print(f"    Runtime CVE check: '{runtime}' not in the mapped runtime list — skipped")
        elif not cves:
            print(f"    Runtime CVE check: 0 CVEs found against {runtime}'s baseline version")
        else:
            worst = sorted(cves, key=lambda c: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(c["severity"], 4))[0]
            print(f"    Runtime CVE check: {len(cves)} CVE(s) published against {runtime}'s baseline "
                  f"(worst: {worst['id']} / {worst['severity']}, {worst['published']})")
            print(f"    -> AWS manages OS/runtime patching for managed runtimes; this is upstream "
                  f"exposure awareness, not proof this specific managed build is vulnerable.")
            if worst["severity"] in ("HIGH", "CRITICAL"):
                total_high_or_critical += 1

        manifest = LAMBDA_DEPENDENCY_MANIFESTS.get(fn_name)
        if manifest and manifest.exists():
            deps = parse_npm_lockfile(manifest)
            print(f"    Dependency CVE check: {len(deps)} pinned package(s) in {manifest.name}")
            dep_findings = check_npm_vulns(deps)
            if dep_findings:
                for finding in dep_findings:
                    print(f"      ⚠️  {finding['package']}@{finding['version']}: {finding['id']} "
                          f"({finding['severity']}) — {finding['summary'][:80]}")
                    total_high_or_critical += 1
            else:
                print(f"      0 known vulnerabilities in {len(deps)} pinned dependencies (OSV.dev)")
        else:
            print(f"    Dependency CVE check: no pinned manifest mapped for this function's actual "
                  f"deployed dependencies — skipped rather than guessed")
        print()

    print(f"{total_high_or_critical} HIGH/CRITICAL-or-worse finding(s) across runtimes and dependencies.")
    sys.exit(1 if total_high_or_critical else 0)


if __name__ == "__main__":
    main()
