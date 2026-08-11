"""EC2 checks: open security groups, unencrypted EBS volumes, default VPC."""
from ..models import Finding, Severity

SERVICE = "EC2"

_SENSITIVE_PORTS = {
    22: "SSH",
    3389: "RDP",
    3306: "MySQL",
    5432: "PostgreSQL",
    1433: "MSSQL",
    27017: "MongoDB",
    6379: "Redis",
    9200: "Elasticsearch",
    5984: "CouchDB",
}

_OPEN_CIDRS = {"0.0.0.0/0", "::/0"}


def _port_range_str(perm):
    frm = perm.get("FromPort")
    to = perm.get("ToPort")
    if frm is None and to is None:
        return "all ports"
    if frm == to:
        return str(frm)
    return f"{frm}-{to}"


def _covers_port(perm, port):
    frm, to = perm.get("FromPort"), perm.get("ToPort")
    if frm is None or to is None:
        return True  # protocol -1 (all traffic)
    return frm <= port <= to


def check_open_security_groups(client, region):
    findings = []
    paginator = client.get_paginator("describe_security_groups")
    for page in paginator.paginate():
        for sg in page["SecurityGroups"]:
            sg_id = sg["GroupId"]
            sg_name = sg.get("GroupName", sg_id)
            for perm in sg.get("IpPermissions", []):
                open_ranges = [r["CidrIp"] for r in perm.get("IpRanges", []) if r.get("CidrIp") in _OPEN_CIDRS]
                open_ranges += [r["CidrIpv6"] for r in perm.get("Ipv6Ranges", []) if r.get("CidrIpv6") in _OPEN_CIDRS]
                if not open_ranges:
                    continue

                matched_sensitive = [name for port, name in _SENSITIVE_PORTS.items() if _covers_port(perm, port)]
                if matched_sensitive:
                    findings.append(Finding(
                        check_id="EC2.1", service=SERVICE, severity=Severity.CRITICAL,
                        resource=f"{sg_name} ({sg_id})", region=region,
                        title=f"Security group '{sg_name}' allows {', '.join(matched_sensitive)} "
                              f"from the internet ({_port_range_str(perm)})",
                        description="Ingress rule permits traffic from 0.0.0.0/0 or ::/0 on a "
                                    "sensitive administrative or database port.",
                        remediation=f"Restrict the ingress rule on '{sg_id}' to specific trusted "
                                    "CIDR ranges or use a bastion/SSM Session Manager instead.",
                    ))
                else:
                    findings.append(Finding(
                        check_id="EC2.2", service=SERVICE, severity=Severity.MEDIUM,
                        resource=f"{sg_name} ({sg_id})", region=region,
                        title=f"Security group '{sg_name}' allows unrestricted ingress on "
                              f"{_port_range_str(perm)}",
                        description="Ingress rule permits traffic from 0.0.0.0/0 or ::/0.",
                        remediation=f"Restrict the ingress rule on '{sg_id}' to only the CIDR "
                                    "ranges that need access.",
                    ))
    return findings


def check_unencrypted_volumes(client, region):
    findings = []
    paginator = client.get_paginator("describe_volumes")
    for page in paginator.paginate():
        for vol in page["Volumes"]:
            if not vol.get("Encrypted", False):
                findings.append(Finding(
                    check_id="EC2.3", service=SERVICE, severity=Severity.MEDIUM,
                    resource=vol["VolumeId"], region=region,
                    title=f"EBS volume '{vol['VolumeId']}' is not encrypted",
                    description="Unencrypted EBS volumes expose data at rest if the underlying storage is compromised.",
                    remediation="Enable EBS encryption by default for the account/region, and "
                                "migrate this volume via a snapshot copy with encryption enabled.",
                ))
    return findings


def check_public_ips(client, region):
    findings = []
    paginator = client.get_paginator("describe_instances")
    for page in paginator.paginate(Filters=[{"Name": "instance-state-name", "Values": ["running", "stopped"]}]):
        for reservation in page["Reservations"]:
            for instance in reservation["Instances"]:
                if instance.get("PublicIpAddress"):
                    findings.append(Finding(
                        check_id="EC2.4", service=SERVICE, severity=Severity.LOW,
                        resource=instance["InstanceId"], region=region,
                        title=f"Instance '{instance['InstanceId']}' has a public IP address",
                        description=f"Public IP {instance['PublicIpAddress']} is directly reachable from the internet.",
                        remediation="Move the instance to a private subnet behind a load balancer/NAT, "
                                    "or confirm this is intentional and locked down via security groups.",
                    ))
    return findings


def check_default_vpc(client, region):
    findings = []
    resp = client.describe_vpcs(Filters=[{"Name": "is-default", "Values": ["true"]}])
    for vpc in resp.get("Vpcs", []):
        findings.append(Finding(
            check_id="EC2.5", service=SERVICE, severity=Severity.LOW,
            resource=vpc["VpcId"], region=region,
            title=f"Default VPC '{vpc['VpcId']}' is present",
            description="Default VPCs have permissive default settings and are commonly misconfigured.",
            remediation="Avoid launching resources into the default VPC; delete it if unused, or "
                        "replace it with a purpose-built VPC with explicit subnet/route/NACL design.",
        ))
    return findings


CHECKS = [
    ("EC2.1-2", "Security groups open to the internet", check_open_security_groups),
    ("EC2.3", "Unencrypted EBS volumes", check_unencrypted_volumes),
    ("EC2.4", "Instances with public IPs", check_public_ips),
    ("EC2.5", "Default VPC present", check_default_vpc),
]


def get_checks(session, region):
    client = session.client("ec2", region_name=region)
    return [
        (check_id, desc, region, lambda fn=fn: fn(client, region))
        for check_id, desc, fn in CHECKS
    ]
