# Vulnerability Intelligence

Cross-references this account's *actual deployed* Lambda runtimes and pinned
dependencies against public vulnerability data, instead of only checking AWS
config flags the way the rest of this repo does. Two different public
sources for two genuinely different questions:

| Question | Source | Why that source |
|---|---|---|
| Is the Lambda runtime's language version affected by published CVEs? | **NVD** (CPE version-range match) | Product/version-oriented — the right tool for "is Node.js 20.0.0 affected by anything" |
| Does the actual pinned `package-lock.json` this account deployed contain a known-vulnerable version? | **OSV.dev** | Ecosystem-native (npm/PyPI) — NVD's keyword search returns unrelated noise for package-level queries (see below) |

## Two real false-positive mechanisms caught and rejected/fixed before shipping

**1. NVD keyword search was tested first and rejected outright.** Searching NVD for
`"Node.js 20"` returned CVEs about `ShopNx`, `passport-oauth2`, and `mongodb-client-
encryption` — unrelated packages that merely mention "Node.js" somewhere in their
description text. Keyword search is full-text matching, not version matching; it was
never used in the shipped tool.

**2. NVD's precise CPE `virtualMatchString` still had a real bug, caught live.** The
first version reported `python3.13` as affected by `CVE-2020-29396` (rated HIGH) — but
that CVE is actually a sandboxing bug in **Odoo** (an ERP system). NVD's configuration
data lists Python 3.6+ only as a `vulnerable: False` "runs on" context for that CVE, with
an open-ended version range that sweeps in every future Python release including 3.13.
`virtualMatchString` returns a CVE if the CPE matches *any* node in its configuration —
vulnerable or not — so the raw API response can't be trusted directly. Fixed by
[`_is_genuinely_vulnerable()`](scan.py), which only counts a match where the runtime's own
CPE is marked `vulnerable: True` in at least one node — i.e. it's the actual vulnerable
component, not a bystander dependency of something else. Re-verified: `nodejs20.x`
correctly dropped from 6 (spurious) CVEs to 0; `python3.13` dropped from 22 to 18, with
the remaining ones spot-checked as genuinely `vulnerable: True` against `python:python`.

## Honesty about what a runtime-CVE match actually means

AWS manages OS/runtime patching for Lambda's managed runtimes (`nodejs20.x`,
`python3.13`) on its own schedule. A CVE against the upstream language version doesn't
prove AWS's specific managed build is still vulnerable — this reports real, correctly-
filtered upstream exposure as an awareness signal, not a claim that a given Lambda is
exploitable right now. Same honesty standard as every heuristic-based check elsewhere in
this repo.

## Real output against this account

```
contact-form-handler  (runtime: nodejs20.x)
    Runtime CVE check: 0 CVEs found against nodejs20.x's baseline version
    Dependency CVE check: 311 pinned package(s) in package-lock.json
      0 known vulnerabilities in 311 pinned dependencies (OSV.dev)

s3-integrity-monitor  (runtime: python3.13)
    Runtime CVE check: 18 CVE(s) published against python3.13's baseline (worst: CVE-2024-7592 / HIGH, 2024-08-19)
    -> AWS manages OS/runtime patching for managed runtimes; this is upstream exposure awareness, not proof this specific managed build is vulnerable.
    Dependency CVE check: no pinned manifest mapped for this function's actual deployed dependencies — skipped rather than guessed
```

`contact-form-handler`'s 311 real pinned npm dependencies (from its actual
`package-lock.json`, resolved via `lockfileVersion: 3`'s `packages` map) came back clean
against OSV.dev — a genuine negative result, not an unimplemented check (verified the
query path works at all by testing a known package/version against OSV.dev directly
before trusting a batch of "0 vulnerabilities" results).

`s3-integrity-monitor` and `s3-security-audit-webapp` only pin `boto3>=1.34` (provided by
the Lambda runtime itself, not bundled) and dev-only `pytest` — there's no actual
third-party dependency shipped in those deployment packages to scan, so the dependency
check is honestly skipped rather than scanning something that isn't really deployed.

## Usage

```bash
pip install -r requirements.txt
python scan.py [--region ap-south-1]
```

Exit code `1` if any HIGH/CRITICAL runtime CVE or dependency vulnerability was found, `0`
otherwise. No API key needed for either NVD or OSV.dev at this account's query volume
(3 Lambda functions, one dependency manifest) — NVD's public rate limit (5 requests/30s
without a key) comfortably covers 2-3 runtime lookups per run.
