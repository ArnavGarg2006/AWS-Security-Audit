"""RDS checks: public accessibility, encryption, backups, minor version upgrades."""
from ..models import Finding, Severity

SERVICE = "RDS"


def check_instances(client, region):
    findings = []
    paginator = client.get_paginator("describe_db_instances")
    for page in paginator.paginate():
        for db in page["DBInstances"]:
            db_id = db["DBInstanceIdentifier"]

            if db.get("PubliclyAccessible", False):
                findings.append(Finding(
                    check_id="RDS.1", service=SERVICE, severity=Severity.CRITICAL,
                    resource=db_id, region=region,
                    title=f"RDS instance '{db_id}' is publicly accessible",
                    description="The database has a publicly resolvable endpoint reachable from the internet.",
                    remediation=f"Set PubliclyAccessible=false for '{db_id}' and access it via VPC/VPN/peering only.",
                ))

            if not db.get("StorageEncrypted", False):
                findings.append(Finding(
                    check_id="RDS.2", service=SERVICE, severity=Severity.HIGH,
                    resource=db_id, region=region,
                    title=f"RDS instance '{db_id}' storage is not encrypted",
                    description="Data at rest is not encrypted for this database instance.",
                    remediation=f"Storage encryption cannot be enabled in place; create an encrypted "
                                f"snapshot copy of '{db_id}' and restore into a new encrypted instance.",
                ))

            if db.get("BackupRetentionPeriod", 0) == 0:
                findings.append(Finding(
                    check_id="RDS.3", service=SERVICE, severity=Severity.MEDIUM,
                    resource=db_id, region=region,
                    title=f"RDS instance '{db_id}' has automated backups disabled",
                    description="BackupRetentionPeriod is 0, so there is no point-in-time recovery available.",
                    remediation=f"Set a BackupRetentionPeriod of at least 7 days for '{db_id}'.",
                ))

            if not db.get("MultiAZ", False):
                findings.append(Finding(
                    check_id="RDS.4", service=SERVICE, severity=Severity.LOW,
                    resource=db_id, region=region,
                    title=f"RDS instance '{db_id}' is not configured for Multi-AZ",
                    description="A single-AZ deployment has no automatic failover if the AZ becomes unavailable.",
                    remediation=f"Enable Multi-AZ deployment for '{db_id}' if it serves production workloads.",
                ))

            if not db.get("AutoMinorVersionUpgrade", False):
                findings.append(Finding(
                    check_id="RDS.5", service=SERVICE, severity=Severity.LOW,
                    resource=db_id, region=region,
                    title=f"RDS instance '{db_id}' does not auto-apply minor version upgrades",
                    description="Security patches shipped in minor engine versions will not be applied automatically.",
                    remediation=f"Enable AutoMinorVersionUpgrade for '{db_id}'.",
                ))
    return findings


CHECKS = [
    ("RDS.1-5", "Public access / encryption / backups / Multi-AZ / auto-patching", check_instances),
]


def get_checks(session, region):
    client = session.client("rds", region_name=region)
    return [
        (check_id, desc, region, lambda fn=fn: fn(client, region))
        for check_id, desc, fn in CHECKS
    ]
