"""
AWS Security Audit web app.

A Lambda-backed web app (invoked via an IAM-authenticated Function URL) that
runs a live, read-only security audit across IAM, S3, EC2, RDS, CloudTrail,
Config and GuardDuty, and returns the findings as an HTML page (default) or
JSON (?format=json). Same checks as the aws_security_audit CLI tool.
"""
import csv
import io
import json
import os
import time
from datetime import datetime, timezone
from html import escape

import boto3
from botocore.exceptions import ClientError

REGION = os.environ.get("AWS_REGION", "ap-south-1")

iam = boto3.client("iam")
s3 = boto3.client("s3")
ec2 = boto3.client("ec2", region_name=REGION)
rds = boto3.client("rds", region_name=REGION)
cloudtrail = boto3.client("cloudtrail", region_name=REGION)
configservice = boto3.client("config", region_name=REGION)
guardduty = boto3.client("guardduty", region_name=REGION)

_PUBLIC_GRANTEE_URIS = {
    "http://acs.amazonaws.com/groups/global/AllUsers",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
}
_SENSITIVE_PORTS = {22: "SSH", 3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL",
                     1433: "MSSQL", 27017: "MongoDB", 6379: "Redis"}
_OPEN_CIDRS = {"0.0.0.0/0", "::/0"}
_SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def _finding(check_id, service, severity, resource, title, remediation):
    return {
        "check_id": check_id, "service": service, "severity": severity,
        "resource": resource, "title": title, "remediation": remediation,
    }


def _safe_run(checks, findings, errors):
    for check_id, service, fn in checks:
        try:
            findings.extend(fn())
        except Exception as e:  # noqa: BLE001 - isolate one check's failure from the rest
            errors.append({"check_id": check_id, "service": service, "message": str(e)})


# ---------- S3 ----------

def _audit_s3():
    findings = []
    for bucket in s3.list_buckets().get("Buckets", []):
        name = bucket["Name"]
        try:
            pab = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
            fully_blocked = all(pab.get(k, False) for k in (
                "BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"))
        except Exception:
            fully_blocked = False
        if not fully_blocked:
            findings.append(_finding("S3.1", "S3", "HIGH", name,
                                      "Does not fully block public access",
                                      f"Enable all four Block Public Access settings for bucket '{name}'."))
        try:
            if s3.get_bucket_policy_status(Bucket=name)["PolicyStatus"].get("IsPublic"):
                findings.append(_finding("S3.2", "S3", "CRITICAL", name,
                                          "Bucket policy evaluates as publicly accessible",
                                          f"Review and tighten the bucket policy for '{name}'."))
        except Exception:
            pass
        try:
            for grant in s3.get_bucket_acl(Bucket=name).get("Grants", []):
                uri = grant.get("Grantee", {}).get("URI")
                if uri in _PUBLIC_GRANTEE_URIS:
                    findings.append(_finding("S3.3", "S3", "CRITICAL", name,
                                              f"ACL grants '{grant.get('Permission')}' to {uri.rsplit('/', 1)[-1]}",
                                              f"Remove the public ACL grant on bucket '{name}'."))
        except Exception:
            pass
        try:
            s3.get_bucket_encryption(Bucket=name)
        except ClientError as e:
            if e.response.get("Error", {}).get("Code") == "ServerSideEncryptionConfigurationNotFoundError":
                findings.append(_finding("S3.4", "S3", "MEDIUM", name,
                                          "Default encryption not enabled",
                                          f"Enable default server-side encryption on bucket '{name}'."))
        except Exception:
            pass
        try:
            if s3.get_bucket_versioning(Bucket=name).get("Status") != "Enabled":
                findings.append(_finding("S3.5", "S3", "LOW", name,
                                          "Versioning not enabled",
                                          f"Enable versioning on bucket '{name}'."))
        except Exception:
            pass
        try:
            if "LoggingEnabled" not in s3.get_bucket_logging(Bucket=name):
                findings.append(_finding("S3.6", "S3", "LOW", name,
                                          "Access logging not enabled",
                                          f"Enable server access logging on bucket '{name}'."))
        except Exception:
            pass
    return findings


# ---------- IAM ----------

def _days_since(iso_str):
    if not iso_str or iso_str in ("N/A", "not_supported", "no_information"):
        return None
    try:
        dt = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
    except ValueError:
        return None
    return (datetime.now(timezone.utc) - dt).days


def _audit_iam_root():
    findings = []
    summary = iam.get_account_summary()["SummaryMap"]
    if summary.get("AccountMFAEnabled", 0) == 0:
        findings.append(_finding("IAM.1", "IAM", "CRITICAL", "root",
                                  "Root account does not have MFA enabled",
                                  "Enable MFA for the root user."))
    if summary.get("AccountAccessKeysPresent", 0) != 0:
        findings.append(_finding("IAM.2", "IAM", "CRITICAL", "root",
                                  "Root account has active access keys",
                                  "Delete the root user's access keys."))
    return findings


def _audit_iam_password_policy():
    findings = []
    try:
        policy = iam.get_account_password_policy()["PasswordPolicy"]
    except iam.exceptions.NoSuchEntityException:
        return [_finding("IAM.3", "IAM", "HIGH", "account",
                          "No IAM account password policy is set",
                          "Configure a password policy (14+ chars, complexity, expiry, reuse prevention).")]
    if policy.get("MinimumPasswordLength", 0) < 14:
        findings.append(_finding("IAM.3", "IAM", "MEDIUM", "account",
                                  f"Password minimum length is {policy.get('MinimumPasswordLength', 0)} (< 14)",
                                  "Set MinimumPasswordLength to 14 or greater."))
    for flag, label in [("RequireSymbols", "symbols"), ("RequireNumbers", "numbers"),
                         ("RequireUppercaseCharacters", "uppercase"), ("RequireLowercaseCharacters", "lowercase")]:
        if not policy.get(flag, False):
            findings.append(_finding("IAM.3", "IAM", "MEDIUM", "account",
                                      f"Password policy does not require {label}",
                                      f"Enable '{flag}'."))
    if not policy.get("ExpirePasswords", False) or policy.get("MaxPasswordAge", 9999) > 90:
        findings.append(_finding("IAM.3", "IAM", "LOW", "account",
                                  "Password expiration not enforced at <= 90 days",
                                  "Set ExpirePasswords=true, MaxPasswordAge<=90."))
    if policy.get("PasswordReusePrevention", 0) < 24:
        findings.append(_finding("IAM.3", "IAM", "LOW", "account",
                                  "Password reuse prevention < 24",
                                  "Set PasswordReusePrevention to 24."))
    return findings


def _audit_iam_credential_report():
    findings = []
    for _ in range(10):
        resp = iam.generate_credential_report()
        if resp.get("State") == "COMPLETE":
            break
        time.sleep(1)
    report = iam.get_credential_report()
    rows = list(csv.DictReader(io.StringIO(report["Content"].decode("utf-8"))))
    for row in rows:
        user = row.get("user", "?")
        if user == "<root_account>":
            continue
        if row.get("password_enabled") == "true" and row.get("mfa_active") != "true":
            findings.append(_finding("IAM.4", "IAM", "HIGH", user,
                                      f"'{user}' has console access but no MFA",
                                      f"Enable MFA for user '{user}'."))
        for n, active, rotated, used in [
            ("1", "access_key_1_active", "access_key_1_last_rotated", "access_key_1_last_used_date"),
            ("2", "access_key_2_active", "access_key_2_last_rotated", "access_key_2_last_used_date")]:
            if row.get(active) != "true":
                continue
            age = _days_since(row.get(rotated))
            if age is not None and age > 90:
                findings.append(_finding("IAM.5", "IAM", "MEDIUM", f"{user} (key {n})",
                                          f"Access key {n} for '{user}' is {age} days old",
                                          f"Rotate access key {n} for '{user}'."))
            unused = _days_since(row.get(used))
            if unused is not None and unused > 90:
                findings.append(_finding("IAM.6", "IAM", "LOW", f"{user} (key {n})",
                                          f"Access key {n} for '{user}' unused for {unused} days",
                                          f"Deactivate/delete access key {n} for '{user}' if unneeded."))
    return findings


def _audit_iam_permissive_policies():
    findings = []
    paginator = iam.get_paginator("list_policies")
    for page in paginator.paginate(Scope="Local", OnlyAttached=True):
        for policy in page["Policies"]:
            try:
                version = iam.get_policy_version(
                    PolicyArn=policy["Arn"], VersionId=policy["DefaultVersionId"])["PolicyVersion"]
            except Exception:
                continue
            statements = version["Document"].get("Statement", [])
            if isinstance(statements, dict):
                statements = [statements]
            for stmt in statements:
                if stmt.get("Effect") != "Allow":
                    continue
                actions = stmt.get("Action", [])
                resources = stmt.get("Resource", [])
                actions = [actions] if isinstance(actions, str) else actions
                resources = [resources] if isinstance(resources, str) else resources
                if "*" in actions and "*" in resources:
                    findings.append(_finding("IAM.7", "IAM", "HIGH", policy["PolicyName"],
                                              f"Policy '{policy['PolicyName']}' grants '*:*'",
                                              "Scope the policy down to least privilege."))
                    break
    return findings


# ---------- EC2 ----------

def _covers_port(perm, port):
    frm, to = perm.get("FromPort"), perm.get("ToPort")
    if frm is None or to is None:
        return True
    return frm <= port <= to


def _port_range_str(perm):
    frm, to = perm.get("FromPort"), perm.get("ToPort")
    if frm is None and to is None:
        return "all ports"
    return str(frm) if frm == to else f"{frm}-{to}"


def _audit_ec2_security_groups():
    findings = []
    for page in ec2.get_paginator("describe_security_groups").paginate():
        for sg in page["SecurityGroups"]:
            sg_id, sg_name = sg["GroupId"], sg.get("GroupName", sg["GroupId"])
            for perm in sg.get("IpPermissions", []):
                open_ranges = [r["CidrIp"] for r in perm.get("IpRanges", []) if r.get("CidrIp") in _OPEN_CIDRS]
                open_ranges += [r["CidrIpv6"] for r in perm.get("Ipv6Ranges", []) if r.get("CidrIpv6") in _OPEN_CIDRS]
                if not open_ranges:
                    continue
                sensitive = [n for p, n in _SENSITIVE_PORTS.items() if _covers_port(perm, p)]
                if sensitive:
                    findings.append(_finding("EC2.1", "EC2", "CRITICAL", f"{sg_name} ({sg_id})",
                                              f"Allows {', '.join(sensitive)} from the internet ({_port_range_str(perm)})",
                                              f"Restrict ingress on '{sg_id}' to trusted CIDRs."))
                else:
                    findings.append(_finding("EC2.2", "EC2", "MEDIUM", f"{sg_name} ({sg_id})",
                                              f"Allows unrestricted ingress on {_port_range_str(perm)}",
                                              f"Restrict ingress on '{sg_id}' to trusted CIDRs."))
    return findings


def _audit_ec2_volumes():
    findings = []
    for page in ec2.get_paginator("describe_volumes").paginate():
        for vol in page["Volumes"]:
            if not vol.get("Encrypted", False):
                findings.append(_finding("EC2.3", "EC2", "MEDIUM", vol["VolumeId"],
                                          f"EBS volume '{vol['VolumeId']}' is not encrypted",
                                          "Enable EBS encryption by default; migrate via encrypted snapshot copy."))
    return findings


def _audit_ec2_public_ips():
    findings = []
    for page in ec2.get_paginator("describe_instances").paginate(
            Filters=[{"Name": "instance-state-name", "Values": ["running", "stopped"]}]):
        for res in page["Reservations"]:
            for inst in res["Instances"]:
                if inst.get("PublicIpAddress"):
                    findings.append(_finding("EC2.4", "EC2", "LOW", inst["InstanceId"],
                                              f"Instance '{inst['InstanceId']}' has a public IP address",
                                              "Move to a private subnet or confirm this is intentional."))
    return findings


def _audit_ec2_default_vpc():
    findings = []
    for vpc in ec2.describe_vpcs(Filters=[{"Name": "is-default", "Values": ["true"]}]).get("Vpcs", []):
        findings.append(_finding("EC2.5", "EC2", "LOW", vpc["VpcId"],
                                  f"Default VPC '{vpc['VpcId']}' is present",
                                  "Avoid launching into the default VPC; consider deleting if unused."))
    return findings


# ---------- RDS ----------

def _audit_rds():
    findings = []
    for page in rds.get_paginator("describe_db_instances").paginate():
        for db in page["DBInstances"]:
            db_id = db["DBInstanceIdentifier"]
            if db.get("PubliclyAccessible", False):
                findings.append(_finding("RDS.1", "RDS", "CRITICAL", db_id,
                                          f"'{db_id}' is publicly accessible",
                                          "Set PubliclyAccessible=false."))
            if not db.get("StorageEncrypted", False):
                findings.append(_finding("RDS.2", "RDS", "HIGH", db_id,
                                          f"'{db_id}' storage is not encrypted",
                                          "Restore from an encrypted snapshot copy."))
            if db.get("BackupRetentionPeriod", 0) == 0:
                findings.append(_finding("RDS.3", "RDS", "MEDIUM", db_id,
                                          f"'{db_id}' has automated backups disabled",
                                          "Set BackupRetentionPeriod >= 7 days."))
            if not db.get("MultiAZ", False):
                findings.append(_finding("RDS.4", "RDS", "LOW", db_id,
                                          f"'{db_id}' is not Multi-AZ",
                                          "Enable Multi-AZ for production workloads."))
            if not db.get("AutoMinorVersionUpgrade", False):
                findings.append(_finding("RDS.5", "RDS", "LOW", db_id,
                                          f"'{db_id}' does not auto-apply minor version upgrades",
                                          "Enable AutoMinorVersionUpgrade."))
    return findings


# ---------- Logging & Monitoring ----------

def _audit_cloudtrail():
    findings = []
    trails = cloudtrail.describe_trails(includeShadowTrails=True).get("trailList", [])
    multi = [t for t in trails if t.get("IsMultiRegionTrail")]
    if not multi:
        return [_finding("LOG.1", "Logging", "HIGH", "account",
                          "No multi-region CloudTrail trail is configured",
                          "Create a trail with IsMultiRegionTrail=true.")]
    for trail in multi:
        name = trail["Name"]
        try:
            if not cloudtrail.get_trail_status(Name=trail["TrailARN"]).get("IsLogging", False):
                findings.append(_finding("LOG.2", "Logging", "HIGH", name,
                                          f"Trail '{name}' exists but is not logging",
                                          f"Start logging for trail '{name}'."))
        except Exception:
            pass
        if not trail.get("LogFileValidationEnabled", False):
            findings.append(_finding("LOG.3", "Logging", "MEDIUM", name,
                                      f"Trail '{name}' has no log file validation",
                                      f"Enable log file validation on '{name}'."))
        if not trail.get("KmsKeyId"):
            findings.append(_finding("LOG.4", "Logging", "LOW", name,
                                      f"Trail '{name}' logs are not KMS-encrypted",
                                      f"Configure a CMK for trail '{name}'."))
    return findings


def _audit_config():
    recorders = configservice.describe_configuration_recorders().get("ConfigurationRecorders", [])
    if not recorders:
        return [_finding("LOG.5", "Logging", "MEDIUM", "account",
                          f"AWS Config is not enabled in {REGION}",
                          f"Enable a Config recorder in {REGION}.")]
    statuses = configservice.describe_configuration_recorder_status().get("ConfigurationRecordersStatus", [])
    if not any(s.get("recording") for s in statuses):
        return [_finding("LOG.5", "Logging", "MEDIUM", "account",
                          f"AWS Config recorder exists but is not recording in {REGION}",
                          "Start the Config recorder.")]
    return []


def _audit_guardduty():
    ids = guardduty.list_detectors().get("DetectorIds", [])
    if not ids:
        return [_finding("LOG.6", "Logging", "MEDIUM", "account",
                          f"GuardDuty is not enabled in {REGION}",
                          f"Enable a GuardDuty detector in {REGION}.")]
    findings = []
    for det_id in ids:
        if guardduty.get_detector(DetectorId=det_id).get("Status") != "ENABLED":
            findings.append(_finding("LOG.6", "Logging", "MEDIUM", det_id,
                                      f"GuardDuty detector '{det_id}' is disabled",
                                      f"Enable detector '{det_id}'."))
    return findings


CHECKS = [
    ("S3.1-6", "S3", _audit_s3),
    ("IAM.1-2", "IAM", _audit_iam_root),
    ("IAM.3", "IAM", _audit_iam_password_policy),
    ("IAM.4-6", "IAM", _audit_iam_credential_report),
    ("IAM.7", "IAM", _audit_iam_permissive_policies),
    ("EC2.1-2", "EC2", _audit_ec2_security_groups),
    ("EC2.3", "EC2", _audit_ec2_volumes),
    ("EC2.4", "EC2", _audit_ec2_public_ips),
    ("EC2.5", "EC2", _audit_ec2_default_vpc),
    ("RDS.1-5", "RDS", _audit_rds),
    ("LOG.1-4", "Logging", _audit_cloudtrail),
    ("LOG.5", "Logging", _audit_config),
    ("LOG.6", "Logging", _audit_guardduty),
]


def _run_audit():
    findings, errors = [], []
    _safe_run(CHECKS, findings, errors)
    findings.sort(key=lambda f: _SEVERITY_RANK.get(f["severity"], 99))
    return findings, errors


def _render_html(findings, errors):
    counts = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    stat_cells = "".join(
        f'<div class="stat s-{sev.lower()}"><div class="n">{counts[sev]}</div><div class="l">{sev}</div></div>'
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW") if counts.get(sev)
    )
    rows = "".join(
        f'<tr class="sev-{f["severity"].lower()}">'
        f'<td>{escape(f["severity"])}</td><td>{escape(f["service"])}</td><td>{escape(f["check_id"])}</td>'
        f'<td>{escape(f["resource"])}</td><td>{escape(f["title"])}</td>'
        f'<td>{escape(f["remediation"])}</td></tr>'
        for f in findings
    )
    if not findings:
        rows = '<tr><td colspan="6" class="clean">No findings — everything checked passes.</td></tr>'

    error_html = ""
    if errors:
        items = "".join(f'<li>{escape(e["check_id"])} ({escape(e["service"])}): {escape(e["message"])}</li>'
                         for e in errors)
        error_html = f'<div class="errors"><b>{len(errors)} check(s) could not complete:</b><ul>{items}</ul></div>'

    return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>AWS Security Audit</title>
<style>
body {{ font-family: -apple-system, Segoe UI, Arial, sans-serif; margin: 2rem; background:#0b0d12; color:#e6e6e6; }}
h1 {{ font-size: 1.4rem; }}
.meta {{ color:#9aa0a6; margin-bottom: 1.5rem; }}
.stats {{ display:flex; gap:1rem; margin-bottom:1.5rem; }}
.stat {{ padding:0.75rem 1.25rem; border-radius:8px; background:#161a22; min-width:80px; text-align:center; }}
.stat .n {{ font-size:1.5rem; font-weight:bold; }}
.stat .l {{ font-size:0.75rem; color:#9aa0a6; }}
.s-critical .n {{ color:#ff4d4f; }} .s-high .n {{ color:#ff7a45; }}
.s-medium .n {{ color:#ffd666; }} .s-low .n {{ color:#69c0ff; }}
table {{ border-collapse: collapse; width: 100%; font-size: 0.85rem; }}
th, td {{ border: 1px solid #2a2f3a; padding: 6px 10px; text-align: left; vertical-align: top; }}
th {{ background: #161a22; }}
.clean {{ text-align:center; color:#69db7c; padding: 1.5rem; }}
tr.sev-critical td:first-child {{ color:#ff4d4f; font-weight:bold; }}
tr.sev-high td:first-child {{ color:#ff7a45; font-weight:bold; }}
tr.sev-medium td:first-child {{ color:#ffd666; font-weight:bold; }}
tr.sev-low td:first-child {{ color:#69c0ff; }}
.errors {{ margin-top: 1.5rem; color:#9aa0a6; font-size: 0.8rem; }}
</style></head>
<body>
<h1>AWS Security Audit</h1>
<div class="meta">{len(findings)} finding(s) across IAM, S3, EC2, RDS, CloudTrail, Config, GuardDuty &middot; served live from Lambda</div>
<div class="stats">{stat_cells}</div>
<table>
<tr><th>Severity</th><th>Service</th><th>Check</th><th>Resource</th><th>Title</th><th>Remediation</th></tr>
{rows}
</table>
{error_html}
</body></html>"""


def lambda_handler(event, context):
    findings, errors = _run_audit()

    query = (event or {}).get("queryStringParameters") or {}
    if query.get("format") == "json":
        body = json.dumps({"finding_count": len(findings), "findings": findings, "errors": errors}, indent=2)
        return {"statusCode": 200, "headers": {"Content-Type": "application/json"}, "body": body}

    return {"statusCode": 200, "headers": {"Content-Type": "text/html; charset=utf-8"},
            "body": _render_html(findings, errors)}
