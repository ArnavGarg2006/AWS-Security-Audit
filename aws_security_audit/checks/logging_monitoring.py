"""CloudTrail / Config / GuardDuty account-visibility checks."""
from ..models import Finding, Severity

SERVICE = "Logging & Monitoring"
REGION = "global"


def check_cloudtrail(session, home_region="us-east-1"):
    """Account-wide check (trails apply account-wide); only needs to run once."""
    findings = []
    client = session.client("cloudtrail", region_name=home_region)
    trails = client.describe_trails(includeShadowTrails=True).get("trailList", [])

    multi_region_trails = [t for t in trails if t.get("IsMultiRegionTrail")]
    if not multi_region_trails:
        findings.append(Finding(
            check_id="LOG.1", service=SERVICE, severity=Severity.HIGH,
            resource="account", region=REGION,
            title="No multi-region CloudTrail trail is configured",
            description="Without a multi-region trail, API activity in un-monitored regions is not logged.",
            remediation="Create a CloudTrail trail with IsMultiRegionTrail=true covering all regions.",
        ))
    else:
        for trail in multi_region_trails:
            name = trail["Name"]
            try:
                status = client.get_trail_status(Name=trail["TrailARN"])
                if not status.get("IsLogging", False):
                    findings.append(Finding(
                        check_id="LOG.2", service=SERVICE, severity=Severity.HIGH,
                        resource=name, region=REGION,
                        title=f"CloudTrail trail '{name}' exists but is not actively logging",
                        description="The trail is configured but logging is currently stopped.",
                        remediation=f"Start logging for trail '{name}' (aws cloudtrail start-logging).",
                    ))
            except Exception:
                pass
            if not trail.get("LogFileValidationEnabled", False):
                findings.append(Finding(
                    check_id="LOG.3", service=SERVICE, severity=Severity.MEDIUM,
                    resource=name, region=REGION,
                    title=f"CloudTrail trail '{name}' does not have log file validation enabled",
                    description="Without log file validation, tampering with delivered log files cannot be detected.",
                    remediation=f"Enable log file integrity validation on trail '{name}'.",
                ))
            if not trail.get("KmsKeyId"):
                findings.append(Finding(
                    check_id="LOG.4", service=SERVICE, severity=Severity.LOW,
                    resource=name, region=REGION,
                    title=f"CloudTrail trail '{name}' logs are not encrypted with a KMS key",
                    description="Trail logs are stored in S3 without SSE-KMS encryption.",
                    remediation=f"Configure a CMK for trail '{name}' (aws cloudtrail update-trail --kms-key-id ...).",
                ))
    return findings


def check_config(session, region):
    findings = []
    client = session.client("config", region_name=region)
    recorders = client.describe_configuration_recorders().get("ConfigurationRecorders", [])
    if not recorders:
        findings.append(Finding(
            check_id="LOG.5", service=SERVICE, severity=Severity.MEDIUM,
            resource="account", region=region,
            title=f"AWS Config is not enabled in {region}",
            description="Without AWS Config, there is no continuous record of resource configuration changes.",
            remediation=f"Enable an AWS Config configuration recorder and delivery channel in {region}.",
        ))
        return findings

    try:
        statuses = client.describe_configuration_recorder_status().get("ConfigurationRecordersStatus", [])
        if not any(s.get("recording") for s in statuses):
            findings.append(Finding(
                check_id="LOG.5", service=SERVICE, severity=Severity.MEDIUM,
                resource="account", region=region,
                title=f"AWS Config recorder exists in {region} but is not recording",
                description="The Config recorder is stopped, so configuration drift will not be captured.",
                remediation=f"Start the AWS Config configuration recorder in {region}.",
            ))
    except Exception:
        pass
    return findings


def check_guardduty(session, region):
    findings = []
    client = session.client("guardduty", region_name=region)
    detector_ids = client.list_detectors().get("DetectorIds", [])
    if not detector_ids:
        findings.append(Finding(
            check_id="LOG.6", service=SERVICE, severity=Severity.MEDIUM,
            resource="account", region=region,
            title=f"GuardDuty is not enabled in {region}",
            description="GuardDuty threat detection is not active in this region.",
            remediation=f"Enable a GuardDuty detector in {region}.",
        ))
    else:
        for det_id in detector_ids:
            detail = client.get_detector(DetectorId=det_id)
            if detail.get("Status") != "ENABLED":
                findings.append(Finding(
                    check_id="LOG.6", service=SERVICE, severity=Severity.MEDIUM,
                    resource=det_id, region=region,
                    title=f"GuardDuty detector '{det_id}' is disabled",
                    description="A GuardDuty detector exists but is not actively enabled.",
                    remediation=f"Enable GuardDuty detector '{det_id}' in {region}.",
                ))
    return findings


REGIONAL_CHECKS = [
    ("LOG.5", "AWS Config recorder enabled", check_config),
    ("LOG.6", "GuardDuty detector enabled", check_guardduty),
]


def get_global_checks(session, home_region="us-east-1"):
    return [
        ("LOG.1-4", "CloudTrail multi-region / logging / validation / encryption", REGION,
         lambda: check_cloudtrail(session, home_region)),
    ]


def get_checks(session, region):
    return [
        (check_id, desc, region, lambda fn=fn: fn(session, region))
        for check_id, desc, fn in REGIONAL_CHECKS
    ]
