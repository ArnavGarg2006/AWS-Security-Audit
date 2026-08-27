#!/usr/bin/env python
"""
Shift-left scanning — catch misconfigurations in a CloudFormation/SAM
template BEFORE it's ever deployed, instead of finding them in the live
account afterward. Same categories of misconfiguration the runtime audit
tool (aws_security_audit/) checks for, applied to static template
properties instead of live API responses.

Checks:
  - AWS::EC2::SecurityGroup ingress open to 0.0.0.0/0 on a sensitive port
  - AWS::S3::Bucket without encryption / with public access block disabled
  - AWS::IAM policies granting "*" action on "*" resource
  - AWS::RDS::DBInstance with PubliclyAccessible: true
  - AWS::DynamoDB::Table without SSE enabled
  - Hardcoded-looking secrets in Lambda environment variables

Usage:
    python scan_template.py path/to/template.yaml
"""
import re
import sys
from pathlib import Path

import yaml

sys.stdout.reconfigure(encoding="utf-8")

SENSITIVE_PORTS = {22: "SSH", 3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL",
                    1433: "MSSQL", 27017: "MongoDB", 6379: "Redis"}
OPEN_CIDRS = {"0.0.0.0/0", "::/0"}
SECRET_NAME_PATTERN = re.compile(r"(password|secret|api[_-]?key|token)", re.IGNORECASE)


def _cfn_multi_constructor(loader, tag_suffix, node):
    if isinstance(node, yaml.ScalarNode):
        return loader.construct_scalar(node)
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node)
    if isinstance(node, yaml.MappingNode):
        return loader.construct_mapping(node)


def load_template(path):
    yaml.add_multi_constructor("!", _cfn_multi_constructor, Loader=yaml.SafeLoader)
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)


class Finding:
    def __init__(self, severity, resource_name, resource_type, title):
        self.severity = severity
        self.resource_name = resource_name
        self.resource_type = resource_type
        self.title = title


def check_security_groups(name, resource, findings):
    if resource.get("Type") != "AWS::EC2::SecurityGroup":
        return
    props = resource.get("Properties", {})
    for rule in props.get("SecurityGroupIngress", []):
        cidr = rule.get("CidrIp") or rule.get("CidrIpv6")
        if cidr not in OPEN_CIDRS:
            continue
        from_port = rule.get("FromPort")
        to_port = rule.get("ToPort", from_port)
        matched = [svc for port, svc in SENSITIVE_PORTS.items()
                   if from_port is not None and from_port <= port <= (to_port or from_port)]
        if matched:
            findings.append(Finding("CRITICAL", name, "AWS::EC2::SecurityGroup",
                                     f"Ingress open to {cidr} on {', '.join(matched)}"))
        else:
            findings.append(Finding("MEDIUM", name, "AWS::EC2::SecurityGroup",
                                     f"Ingress open to {cidr} on port {from_port}-{to_port}"))


def check_s3_buckets(name, resource, findings):
    if resource.get("Type") != "AWS::S3::Bucket":
        return
    props = resource.get("Properties", {})

    if "BucketEncryption" not in props:
        findings.append(Finding("MEDIUM", name, "AWS::S3::Bucket", "No default encryption configured"))

    pab = props.get("PublicAccessBlockConfiguration")
    if pab:
        disabled = [k for k in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")
                    if pab.get(k) is False]
        if disabled:
            findings.append(Finding("LOW", name, "AWS::S3::Bucket",
                                     f"Public access block partially disabled: {', '.join(disabled)} "
                                     "(only acceptable for an intentional static-website bucket)"))


def check_iam_policies(name, resource, findings):
    if resource.get("Type") not in ("AWS::IAM::Policy", "AWS::IAM::Role", "AWS::IAM::ManagedPolicy"):
        return
    props = resource.get("Properties", {})
    doc = props.get("PolicyDocument") or {}
    statements = doc.get("Statement", [])
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
            findings.append(Finding("HIGH", name, resource["Type"], "Policy grants '*' action on '*' resource"))


def check_rds(name, resource, findings):
    if resource.get("Type") != "AWS::RDS::DBInstance":
        return
    props = resource.get("Properties", {})
    if props.get("PubliclyAccessible") is True:
        findings.append(Finding("CRITICAL", name, "AWS::RDS::DBInstance", "PubliclyAccessible is true"))
    if not props.get("StorageEncrypted"):
        findings.append(Finding("HIGH", name, "AWS::RDS::DBInstance", "StorageEncrypted not set to true"))


def check_dynamodb(name, resource, findings):
    if resource.get("Type") != "AWS::DynamoDB::Table":
        return
    props = resource.get("Properties", {})
    sse = props.get("SSESpecification", {})
    if not sse.get("SSEEnabled"):
        findings.append(Finding("MEDIUM", name, "AWS::DynamoDB::Table", "SSESpecification.SSEEnabled not set to true"))


def check_lambda_secrets(name, resource, findings):
    is_lambda = resource.get("Type") in ("AWS::Lambda::Function", "AWS::Serverless::Function")
    if not is_lambda:
        return
    env_vars = resource.get("Properties", {}).get("Environment", {}).get("Variables", {})
    for key, value in env_vars.items():
        if not SECRET_NAME_PATTERN.search(key):
            continue
        # A !Ref/!Sub/dict value means it's parameterized (fine) - only flag
        # plain string literals, which suggest a hardcoded secret.
        if isinstance(value, str) and value:
            findings.append(Finding("HIGH", name, resource["Type"],
                                     f"Environment variable '{key}' looks secret-like and has a "
                                     "literal string value — should be a parameter/SSM reference, not hardcoded"))


CHECKS = [check_security_groups, check_s3_buckets, check_iam_policies,
          check_rds, check_dynamodb, check_lambda_secrets]


def scan(template_path):
    template = load_template(template_path)
    findings = []
    for name, resource in template.get("Resources", {}).items():
        for check in CHECKS:
            check(name, resource, findings)
    return findings


def main():
    if len(sys.argv) < 2:
        print("Usage: python scan_template.py path/to/template.yaml")
        sys.exit(1)

    path = Path(sys.argv[1])
    print(f"Scanning {path} (before deployment)...\n")
    findings = scan(path)

    if not findings:
        print("No findings. Clean to deploy.")
        sys.exit(0)

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    findings.sort(key=lambda f: severity_order.get(f.severity, 99))

    for f in findings:
        print(f"[{f.severity}] {f.resource_name} ({f.resource_type}): {f.title}")

    blocking = [f for f in findings if f.severity in ("CRITICAL", "HIGH")]
    print(f"\n{len(findings)} finding(s), {len(blocking)} CRITICAL/HIGH.")
    if blocking:
        print("Blocking deploy — fix CRITICAL/HIGH findings before merging.")
    sys.exit(1 if blocking else 0)


if __name__ == "__main__":
    main()
