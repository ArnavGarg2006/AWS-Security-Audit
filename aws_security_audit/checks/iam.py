"""IAM-related checks (CIS AWS Foundations Benchmark aligned)."""
import csv
import io
import time
from datetime import datetime, timezone

from ..models import Finding, Severity

SERVICE = "IAM"
REGION = "global"


def _get_credential_report(client):
    """Trigger + fetch the IAM credential report, waiting for generation."""
    for _ in range(10):
        resp = client.generate_credential_report()
        if resp.get("State") == "COMPLETE":
            break
        time.sleep(1)
    report = client.get_credential_report()
    csv_text = report["Content"].decode("utf-8")
    return list(csv.DictReader(io.StringIO(csv_text)))


def _days_since(iso_str):
    if not iso_str or iso_str in ("N/A", "not_supported", "no_information"):
        return None
    try:
        dt = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
    except ValueError:
        return None
    return (datetime.now(timezone.utc) - dt).days


def check_root_account(client):
    findings = []
    summary = client.get_account_summary()["SummaryMap"]

    if summary.get("AccountMFAEnabled", 0) == 0:
        findings.append(Finding(
            check_id="IAM.1", service=SERVICE, severity=Severity.CRITICAL,
            resource="root", region=REGION,
            title="Root account does not have MFA enabled",
            description="The AWS account root user does not have multi-factor authentication enabled.",
            remediation="Enable a hardware or virtual MFA device for the root user in IAM > Security credentials.",
        ))

    if summary.get("AccountAccessKeysPresent", 0) != 0:
        findings.append(Finding(
            check_id="IAM.2", service=SERVICE, severity=Severity.CRITICAL,
            resource="root", region=REGION,
            title="Root account has active access keys",
            description="Access keys exist for the root user. Root credentials should never be used programmatically.",
            remediation="Delete the root user's access keys in IAM > Security credentials.",
        ))
    return findings


def check_password_policy(client):
    findings = []
    try:
        policy = client.get_account_password_policy()["PasswordPolicy"]
    except client.exceptions.NoSuchEntityException:
        findings.append(Finding(
            check_id="IAM.3", service=SERVICE, severity=Severity.HIGH,
            resource="account", region=REGION,
            title="No IAM account password policy is set",
            description="There is no password policy configured for IAM users, allowing weak passwords.",
            remediation="Configure a password policy under IAM > Account settings "
                        "(min length 14+, require symbols/numbers/mixed case, expiration, reuse prevention).",
        ))
        return findings

    if policy.get("MinimumPasswordLength", 0) < 14:
        findings.append(Finding(
            check_id="IAM.3", service=SERVICE, severity=Severity.MEDIUM,
            resource="account", region=REGION,
            title=f"Password policy minimum length is {policy.get('MinimumPasswordLength', 0)} (< 14)",
            description="Weak minimum password length increases risk of credential compromise.",
            remediation="Set MinimumPasswordLength to 14 or greater.",
        ))
    for flag, label in [
        ("RequireSymbols", "symbols"),
        ("RequireNumbers", "numbers"),
        ("RequireUppercaseCharacters", "uppercase characters"),
        ("RequireLowercaseCharacters", "lowercase characters"),
    ]:
        if not policy.get(flag, False):
            findings.append(Finding(
                check_id="IAM.3", service=SERVICE, severity=Severity.MEDIUM,
                resource="account", region=REGION,
                title=f"Password policy does not require {label}",
                description="Password complexity requirements are incomplete.",
                remediation=f"Enable the '{flag}' requirement in the account password policy.",
            ))
    if not policy.get("ExpirePasswords", False) or policy.get("MaxPasswordAge", 9999) > 90:
        findings.append(Finding(
            check_id="IAM.3", service=SERVICE, severity=Severity.LOW,
            resource="account", region=REGION,
            title="Password expiration is not enforced at <= 90 days",
            description="Passwords that never expire increase the window of exposure if leaked.",
            remediation="Set ExpirePasswords=true and MaxPasswordAge to 90 days or fewer.",
        ))
    if policy.get("PasswordReusePrevention", 0) < 24:
        findings.append(Finding(
            check_id="IAM.3", service=SERVICE, severity=Severity.LOW,
            resource="account", region=REGION,
            title="Password reuse prevention is not set to remember 24+ previous passwords",
            description="Users can reuse recently retired passwords.",
            remediation="Set PasswordReusePrevention to 24.",
        ))
    return findings


def check_credential_report(client):
    findings = []
    rows = _get_credential_report(client)
    for row in rows:
        user = row.get("user", "?")
        if user == "<root_account>":
            continue

        password_enabled = row.get("password_enabled") == "true"
        mfa_active = row.get("mfa_active") == "true"
        if password_enabled and not mfa_active:
            findings.append(Finding(
                check_id="IAM.4", service=SERVICE, severity=Severity.HIGH,
                resource=user, region=REGION,
                title=f"IAM user '{user}' has console access but no MFA",
                description="A user with a console password does not have multi-factor authentication enabled.",
                remediation=f"Enable MFA for user '{user}' in IAM > Users > Security credentials.",
            ))

        for key_num, active_field, rotated_field, used_field in [
            ("1", "access_key_1_active", "access_key_1_last_rotated", "access_key_1_last_used_date"),
            ("2", "access_key_2_active", "access_key_2_last_rotated", "access_key_2_last_used_date"),
        ]:
            if row.get(active_field) != "true":
                continue
            age = _days_since(row.get(rotated_field))
            if age is not None and age > 90:
                findings.append(Finding(
                    check_id="IAM.5", service=SERVICE, severity=Severity.MEDIUM,
                    resource=f"{user} (access key {key_num})", region=REGION,
                    title=f"Access key {key_num} for '{user}' is {age} days old",
                    description="Access keys older than 90 days should be rotated to limit exposure from leaks.",
                    remediation=f"Rotate access key {key_num} for user '{user}' and update dependent applications.",
                ))
            unused_days = _days_since(row.get(used_field))
            if unused_days is not None and unused_days > 90:
                findings.append(Finding(
                    check_id="IAM.6", service=SERVICE, severity=Severity.LOW,
                    resource=f"{user} (access key {key_num})", region=REGION,
                    title=f"Access key {key_num} for '{user}' unused for {unused_days} days",
                    description="Long-unused access keys are unnecessary attack surface.",
                    remediation=f"Deactivate or delete access key {key_num} for user '{user}' if no longer needed.",
                ))
    return findings


def check_permissive_policies(client):
    findings = []
    paginator = client.get_paginator("list_policies")
    for page in paginator.paginate(Scope="Local", OnlyAttached=True):
        for policy in page["Policies"]:
            try:
                version = client.get_policy_version(
                    PolicyArn=policy["Arn"], VersionId=policy["DefaultVersionId"]
                )["PolicyVersion"]
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
                    findings.append(Finding(
                        check_id="IAM.7", service=SERVICE, severity=Severity.HIGH,
                        resource=policy["PolicyName"], region=REGION,
                        title=f"Customer-managed policy '{policy['PolicyName']}' grants '*:*'",
                        description="This policy allows all actions on all resources, violating least privilege.",
                        remediation="Scope the policy down to only the actions/resources actually required.",
                    ))
                    break
    return findings


CHECKS = [
    ("IAM.1-2", "Root account security", check_root_account),
    ("IAM.3", "Password policy", check_password_policy),
    ("IAM.4-6", "Credential report (MFA / key age / unused keys)", check_credential_report),
    ("IAM.7", "Overly permissive customer-managed policies", check_permissive_policies),
]


def get_checks(session):
    """Return list of (check_id, description, region, callable() -> list[Finding])."""
    client = session.client("iam")
    return [
        (check_id, desc, REGION, lambda fn=fn: fn(client))
        for check_id, desc, fn in CHECKS
    ]
