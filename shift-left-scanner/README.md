# Shift-Left Scanner

Scans a CloudFormation/SAM template **before** it's deployed, instead of finding
misconfigurations in the live account afterward. Same categories the runtime audit tool
([`aws_security_audit/`](../aws_security_audit/)) checks for, applied to static template
properties instead of live API responses.

## What it checks

Security groups open to `0.0.0.0/0` on sensitive ports, S3 buckets missing encryption or
with public access block disabled, IAM policies granting `*` action on `*` resource, RDS
instances with `PubliclyAccessible: true` or no storage encryption, DynamoDB tables
without SSE, and Lambda environment variables that look like hardcoded secrets
(name matches `password`/`secret`/`api key`/`token` and has a literal string value
instead of a parameter reference).

## Verified both directions

Scanned the real [`fullstack-contact-app/template.yaml`](../fullstack-contact-app/template.yaml)
— caught exactly the one known, intentional finding (the frontend bucket's public access
block, disabled on purpose for static website hosting) and nothing else. Then scanned a
deliberately broken throwaway template covering all 5 check categories — all 5 fired with
correct severities (2 CRITICAL, 3 HIGH/MEDIUM), confirming the checks work and the clean
template result wasn't just "the tool doesn't check anything."

## Wired into CI

`.github/workflows/deploy-contact-form.yml` runs this as its own `shift-left-scan` job,
which `deploy` now depends on alongside the existing `test` job — a CRITICAL/HIGH finding
blocks the deploy from ever running, not just the merge.

## Usage

```bash
pip install -r requirements.txt
python scan_template.py path/to/template.yaml
```

Exit code `1` on any CRITICAL/HIGH finding (blocks deploy), `0` otherwise. MEDIUM/LOW
findings are reported but don't block.
