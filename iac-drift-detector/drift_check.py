#!/usr/bin/env python
"""
IaC drift detection for fullstack-contact-app.

template.yaml is the documented "should be" state — but the live resources
were hand-deployed via CLI, not through an actual `sam deploy`, so there's no
CloudFormation stack to run AWS's native drift detection against. This
compares template.yaml's declared properties directly against what's
actually live via boto3, catching the classic failure mode: someone fixes
something by hand in the console, it works, and the next `sam deploy` would
silently revert it because the template was never updated to match.

Checks:
  - Lambda: MemorySize, Timeout, Runtime, Tracing mode
  - API Gateway stage: throttling rate/burst limit
  - DynamoDB table: billing mode, SSE enabled
  - WAF: rate-based rule limit

Usage:
    python drift_check.py [--region ap-south-1]
"""
import argparse
import sys
from pathlib import Path

import boto3
import yaml

from root_cause import find_root_cause

sys.stdout.reconfigure(encoding="utf-8")

TEMPLATE_PATH = Path(__file__).parent.parent / "fullstack-contact-app" / "template.yaml"

LAMBDA_FUNCTION_NAME = "contact-form-handler"
API_ID = "bv2wjj78b0"
API_STAGE = "prod"
DYNAMODB_TABLE = "contact-form-submissions"
WAF_NAME = "contact-form-waf"
WAF_ID = "570ea088-9e4c-4fa0-b29e-70a6b5095188"

# resource kind (as used in DriftReport rows) -> the identifier CloudTrail
# events for that resource will contain, for root-cause correlation.
RESOURCE_IDENTIFIERS = {
    "Lambda": LAMBDA_FUNCTION_NAME,
    "API Gateway stage": API_ID,
    "DynamoDB table": DYNAMODB_TABLE,
    "WAF rate rule": WAF_ID,
}


def _cfn_multi_constructor(loader, tag_suffix, node):
    """CloudFormation intrinsic functions (!Ref, !Sub, !GetAtt, ...) aren't
    valid plain YAML — load them as opaque markers since we only need the
    plain scalar Properties, not resolved intrinsics."""
    if isinstance(node, yaml.ScalarNode):
        return loader.construct_scalar(node)
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node)
    if isinstance(node, yaml.MappingNode):
        return loader.construct_mapping(node)


def load_template():
    yaml.add_multi_constructor("!", _cfn_multi_constructor, Loader=yaml.SafeLoader)
    with open(TEMPLATE_PATH, encoding="utf-8") as f:
        return yaml.safe_load(f)


class DriftReport:
    def __init__(self):
        self.checks = []

    def compare(self, resource, field, expected, actual):
        drifted = expected != actual
        self.checks.append((resource, field, expected, actual, drifted))
        return drifted

    def print_and_exit(self, cloudtrail=None):
        drifted = [c for c in self.checks if c[4]]
        print(f"{'Resource':30} {'Field':22} {'Template':>12}  {'Live':>12}  Status")
        print("-" * 95)
        for resource, field, expected, actual, is_drift in self.checks:
            status = "⚠️  DRIFT" if is_drift else "✓ match"
            print(f"{resource:30} {field:22} {str(expected):>12}  {str(actual):>12}  {status}")

        print(f"\n{len(drifted)}/{len(self.checks)} field(s) drifted from template.yaml.")

        if drifted and cloudtrail is not None:
            print("\nRoot cause (best-effort, from CloudTrail — last 90 days):")
            seen_resources = set()
            for resource, field, expected, actual, is_drift in drifted:
                if resource in seen_resources:
                    continue
                seen_resources.add(resource)
                identifier = RESOURCE_IDENTIFIERS.get(resource)
                if not identifier:
                    continue
                cause = find_root_cause(cloudtrail, resource, identifier)
                if cause:
                    print(f"  {resource}: changed by {cause['username']} via {cause['event_name']} "
                          f"at {cause['event_time']}")
                else:
                    print(f"  {resource}: no matching CloudTrail event in the last 90 days "
                          f"(older than lookup_events retention, or made outside a logged API call)")

        sys.exit(1 if drifted else 0)


def check_lambda(template, session, region, report):
    globals_cfg = template.get("Globals", {}).get("Function", {})
    fn_props = template["Resources"]["ContactFormFunction"]["Properties"]

    client = session.client("lambda", region_name=region)
    live = client.get_function_configuration(FunctionName=LAMBDA_FUNCTION_NAME)

    report.compare("Lambda", "MemorySize", globals_cfg.get("MemorySize"), live.get("MemorySize"))
    report.compare("Lambda", "Timeout", globals_cfg.get("Timeout"), live.get("Timeout"))
    report.compare("Lambda", "Runtime", globals_cfg.get("Runtime"), live.get("Runtime"))
    report.compare("Lambda", "TracingMode", globals_cfg.get("Tracing"), live.get("TracingConfig", {}).get("Mode"))


def check_api_throttling(template, session, region, report):
    method_settings = template["Resources"]["ContactFormApi"]["Properties"]["MethodSettings"][0]

    client = session.client("apigateway", region_name=region)
    live = client.get_stage(restApiId=API_ID, stageName=API_STAGE)
    live_settings = live.get("methodSettings", {}).get("*/*", {})

    report.compare("API Gateway stage", "ThrottlingRateLimit",
                    method_settings.get("ThrottlingRateLimit"), live_settings.get("throttlingRateLimit"))
    report.compare("API Gateway stage", "ThrottlingBurstLimit",
                    method_settings.get("ThrottlingBurstLimit"), live_settings.get("throttlingBurstLimit"))


def check_dynamodb(template, session, region, report):
    props = template["Resources"]["SubmissionsTable"]["Properties"]

    client = session.client("dynamodb", region_name=region)
    live = client.describe_table(TableName=DYNAMODB_TABLE)["Table"]

    live_billing = live.get("BillingModeSummary", {}).get("BillingMode", "PROVISIONED")
    report.compare("DynamoDB table", "BillingMode", props.get("BillingMode"), live_billing)

    live_sse = live.get("SSEDescription", {}).get("Status") == "ENABLED"
    report.compare("DynamoDB table", "SSEEnabled",
                    props.get("SSESpecification", {}).get("SSEEnabled"), live_sse)


def check_waf(template, session, region, report):
    rule = template["Resources"]["ApiWebAcl"]["Properties"]["Rules"][0]
    template_limit = rule["Statement"]["RateBasedStatement"]["Limit"]
    # Limit is a !Ref to the ApiRateLimitPerIp parameter — resolve its default.
    if not isinstance(template_limit, int):
        template_limit = template["Parameters"]["ApiRateLimitPerIp"]["Default"]

    client = session.client("wafv2", region_name=region)
    live = client.get_web_acl(Name=WAF_NAME, Scope="REGIONAL", Id=WAF_ID)
    live_rule = live["WebACL"]["Rules"][0]
    live_limit = live_rule["Statement"]["RateBasedStatement"]["Limit"]

    report.compare("WAF rate rule", "Limit", template_limit, live_limit)


def main():
    parser = argparse.ArgumentParser(description="Compare template.yaml against live fullstack-contact-app resources.")
    parser.add_argument("--region", default="ap-south-1")
    parser.add_argument("--profile")
    args = parser.parse_args()

    session = boto3.Session(profile_name=args.profile)
    template = load_template()
    report = DriftReport()

    for check_fn in (check_lambda, check_api_throttling, check_dynamodb, check_waf):
        try:
            check_fn(template, session, args.region, report)
        except Exception as e:
            print(f"Could not run {check_fn.__name__}: {e}", file=sys.stderr)

    cloudtrail = session.client("cloudtrail", region_name=args.region)
    report.print_and_exit(cloudtrail=cloudtrail)


if __name__ == "__main__":
    main()
