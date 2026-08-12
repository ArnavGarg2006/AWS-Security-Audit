# AWS Security Audit

A read-only Python/boto3 CLI that scans an AWS account for common security
misconfigurations, loosely aligned with the CIS AWS Foundations Benchmark.

It never modifies any resource — every API call it makes is a `Describe*`,
`Get*`, or `List*` call.

## What it checks

| Service | Checks |
|---|---|
| **IAM** | Root MFA / root access keys, account password policy, users with console access but no MFA, access keys older than 90 days, unused access keys, customer-managed policies granting `*:*` |
| **S3** | Block Public Access settings, public bucket policy, public ACL grants, default encryption, versioning, access logging |
| **EC2** | Security groups open to `0.0.0.0/0`/`::/0` (flags sensitive ports — SSH/RDP/DB — as CRITICAL), unencrypted EBS volumes, instances with public IPs, presence of a default VPC |
| **RDS** | Publicly accessible instances, unencrypted storage, disabled automated backups, Multi-AZ, auto minor-version upgrades |
| **CloudTrail / Config / GuardDuty** | Missing multi-region trail, trail not logging, log file validation, log encryption, Config recorder status, GuardDuty detector status |

Each finding includes a severity (CRITICAL/HIGH/MEDIUM/LOW), the affected
resource, and a specific remediation step.

## Setup

Requires Python 3.9+.

```bash
pip install -r requirements.txt
```

Configure AWS credentials the normal way — `aws configure`, environment
variables, an SSO profile, or an instance/task role. This tool does not
manage credentials itself.

### Required IAM permissions

Attach the AWS-managed **`SecurityAudit`** or **`ReadOnlyAccess`** policy to
the identity you run this with. Both are read-only and sufficient.

## Usage

```bash
# Scan the default profile's default region
python audit.py

# Use a specific named profile
python audit.py --profile prod

# Scan specific regions
python audit.py --region us-east-1 --region eu-west-1

# Scan every enabled region
python audit.py --all-regions

# Only run certain services
python audit.py --services iam,s3

# Write JSON and/or HTML reports alongside the console output
python audit.py --json-out report.json --html-out report.html
```

Full options:

```
--profile PROFILE     AWS named profile to use
--region REGION       Region to scan (repeatable)
--all-regions         Scan all enabled EC2 regions
--services SERVICES   Comma-separated subset: iam, s3, ec2, rds, logging
--json-out PATH       Write a full JSON report
--html-out PATH       Write a self-contained HTML report
--no-console          Suppress the console table
```

The process exits with code `1` if any CRITICAL or HIGH finding was
reported (useful in CI), `0` if clean, and `2` on a setup/auth error.

## Project layout

```
aws_security_audit/
  cli.py                  argument parsing + orchestration
  models.py                Finding / AuditResult data model
  report.py                console (rich), JSON, and HTML renderers
  checks/
    iam.py
    s3.py
    ec2.py
    rds.py
    logging_monitoring.py  CloudTrail / Config / GuardDuty
audit.py                   entry point: `python audit.py`
```

Each `checks/*.py` module exposes `get_checks(session, region)` returning a
list of `(check_id, description, region, callable)` tuples. The CLI runs
each callable independently and catches exceptions per-check, so a missing
permission on one check (e.g. no `guardduty:ListDetectors`) is reported as
a skipped check rather than crashing the whole audit.

## Extending

To add a new check, add a function to the relevant `checks/*.py` module that
returns a list of `Finding` objects, then register it in that module's
`CHECKS` list (or `REGIONAL_CHECKS`/global helper for logging_monitoring.py).

## Lambda web app

[lambda-s3-audit-webapp/](lambda-s3-audit-webapp/) is a serverless version of the same
checks — a Lambda function behind an IAM-authenticated Function URL that runs the audit
on demand and returns HTML or JSON. See its own [README](lambda-s3-audit-webapp/README.md)
for deployment steps.

## Full-stack contact form (also in this repo)

[fullstack-contact-app/](fullstack-contact-app/) is a separate demo built while exploring
this same account: a public contact form (S3 + API Gateway + Lambda) that's grown into a
small production-shaped stack — DynamoDB persistence, SNS/SES notifications, a WAF rate
limit + CORS lockdown + IAM least-privilege throughout, CloudWatch alarms, X-Ray tracing,
an AWS SAM template for reproducible deploys, and a GitHub Actions pipeline that deploys
on push using its own scoped-down IAM user (not the admin credentials used interactively).
See its [README](fullstack-contact-app/README.md) for the full architecture and the
security/observability tradeoffs documented along the way.
