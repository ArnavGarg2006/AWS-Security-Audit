"""S3 bucket checks: public access, encryption, versioning, logging."""
from botocore.exceptions import ClientError

from ..models import Finding, Severity

SERVICE = "S3"
REGION = "global"

_PUBLIC_GRANTEE_URIS = {
    "http://acs.amazonaws.com/groups/global/AllUsers",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
}


def _list_buckets(client):
    return client.list_buckets().get("Buckets", [])


def check_public_access(client):
    findings = []
    for bucket in _list_buckets(client):
        name = bucket["Name"]

        try:
            pab = client.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
            fully_blocked = all(pab.get(k, False) for k in (
                "BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"))
        except (ClientError, Exception):
            fully_blocked = False

        if not fully_blocked:
            findings.append(Finding(
                check_id="S3.1", service=SERVICE, severity=Severity.HIGH,
                resource=name, region=REGION,
                title=f"Bucket '{name}' does not fully block public access",
                description="S3 Block Public Access is not fully enabled, which can allow ACLs/policies to expose the bucket.",
                remediation=f"Enable all four Block Public Access settings for bucket '{name}'.",
            ))

        try:
            status = client.get_bucket_policy_status(Bucket=name)["PolicyStatus"]
            if status.get("IsPublic"):
                findings.append(Finding(
                    check_id="S3.2", service=SERVICE, severity=Severity.CRITICAL,
                    resource=name, region=REGION,
                    title=f"Bucket '{name}' has a policy that grants public access",
                    description="The bucket policy evaluates as publicly accessible.",
                    remediation=f"Review and tighten the bucket policy for '{name}' to remove public principals.",
                ))
        except Exception:
            pass

        try:
            acl = client.get_bucket_acl(Bucket=name)
            for grant in acl.get("Grants", []):
                grantee = grant.get("Grantee", {})
                if grantee.get("URI") in _PUBLIC_GRANTEE_URIS:
                    findings.append(Finding(
                        check_id="S3.3", service=SERVICE, severity=Severity.CRITICAL,
                        resource=name, region=REGION,
                        title=f"Bucket '{name}' ACL grants access to {grantee.get('URI').rsplit('/', 1)[-1]}",
                        description=f"The bucket ACL grants '{grant.get('Permission')}' to a public group.",
                        remediation=f"Remove the public ACL grant on bucket '{name}'; use bucket policies with least privilege instead.",
                    ))
        except Exception:
            pass
    return findings


def check_encryption(client):
    findings = []
    for bucket in _list_buckets(client):
        name = bucket["Name"]
        try:
            client.get_bucket_encryption(Bucket=name)
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            if code in ("ServerSideEncryptionConfigurationNotFoundError",):
                findings.append(Finding(
                    check_id="S3.4", service=SERVICE, severity=Severity.MEDIUM,
                    resource=name, region=REGION,
                    title=f"Bucket '{name}' does not have default encryption enabled",
                    description="Objects written without an explicit encryption header will be stored unencrypted.",
                    remediation=f"Enable default server-side encryption (SSE-S3 or SSE-KMS) on bucket '{name}'.",
                ))
        except Exception:
            pass
    return findings


def check_versioning(client):
    findings = []
    for bucket in _list_buckets(client):
        name = bucket["Name"]
        try:
            v = client.get_bucket_versioning(Bucket=name)
            if v.get("Status") != "Enabled":
                findings.append(Finding(
                    check_id="S3.5", service=SERVICE, severity=Severity.LOW,
                    resource=name, region=REGION,
                    title=f"Bucket '{name}' does not have versioning enabled",
                    description="Without versioning, accidental overwrites or deletions cannot be recovered "
                                "and ransomware-style object corruption cannot be rolled back.",
                    remediation=f"Enable versioning on bucket '{name}'.",
                ))
        except Exception:
            pass
    return findings


def check_logging(client):
    findings = []
    for bucket in _list_buckets(client):
        name = bucket["Name"]
        try:
            logging_cfg = client.get_bucket_logging(Bucket=name)
            if "LoggingEnabled" not in logging_cfg:
                findings.append(Finding(
                    check_id="S3.6", service=SERVICE, severity=Severity.LOW,
                    resource=name, region=REGION,
                    title=f"Bucket '{name}' does not have access logging enabled",
                    description="Without server access logging, requests against this bucket are not auditable.",
                    remediation=f"Enable server access logging on bucket '{name}' to a dedicated log bucket.",
                ))
        except Exception:
            pass
    return findings


CHECKS = [
    ("S3.1-3", "Public access (block settings / policy / ACL)", check_public_access),
    ("S3.4", "Default encryption", check_encryption),
    ("S3.5", "Versioning", check_versioning),
    ("S3.6", "Access logging", check_logging),
]


def get_checks(session, region=None):
    client = session.client("s3")
    return [
        (check_id, desc, REGION, lambda fn=fn: fn(client))
        for check_id, desc, fn in CHECKS
    ]
