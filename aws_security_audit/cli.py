import argparse
import sys

import boto3
from botocore.exceptions import (
    ClientError,
    NoCredentialsError,
    NoRegionError,
    ProfileNotFound,
)

from .checks import ec2, iam, logging_monitoring, rds, s3
from .models import AuditResult, CheckError
from .report import print_console_report, write_html_report, write_json_report

GLOBAL_MODULES = [iam, s3]
REGIONAL_MODULES = [ec2, rds, logging_monitoring]

SERVICE_ALIASES = {
    "iam": iam,
    "s3": s3,
    "ec2": ec2,
    "rds": rds,
    "logging": logging_monitoring,
}


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        prog="aws-security-audit",
        description="Read-only AWS security audit: scans IAM, S3, EC2, RDS, "
                     "CloudTrail, Config and GuardDuty for common misconfigurations.",
    )
    parser.add_argument("--profile", help="AWS named profile to use (default: default credential chain)")
    parser.add_argument("--region", action="append",
                         help="Region to scan for regional checks (repeatable). "
                              "Defaults to the profile/session's configured region.")
    parser.add_argument("--all-regions", action="store_true",
                         help="Scan all enabled EC2 regions instead of a single region")
    parser.add_argument("--services", help="Comma-separated subset of services to run: "
                                            f"{', '.join(SERVICE_ALIASES)} (default: all)")
    parser.add_argument("--json-out", help="Write full JSON report to this path")
    parser.add_argument("--html-out", help="Write HTML report to this path")
    parser.add_argument("--no-console", action="store_true", help="Suppress the console table report")
    return parser.parse_args(argv)


def resolve_regions(session, args):
    if args.all_regions:
        ec2_client = session.client("ec2", region_name="us-east-1")
        resp = ec2_client.describe_regions(AllRegions=False)
        return sorted(r["RegionName"] for r in resp["Regions"])
    if args.region:
        return args.region
    region = session.region_name
    return [region] if region else ["us-east-1"]


def run_check_set(check_tuples, result):
    for check_id, description, region, fn in check_tuples:
        result.checks_run += 1
        try:
            findings = fn()
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "Unknown")
            result.add_error(CheckError(check_id, description, region, f"{code}: {e}"))
            continue
        except Exception as e:  # noqa: BLE001 - surface any unexpected check failure, don't crash the run
            result.add_error(CheckError(check_id, description, region, str(e)))
            continue
        for f in findings:
            result.add_finding(f)


def main(argv=None):
    args = parse_args(argv)

    services = None
    if args.services:
        services = {s.strip().lower() for s in args.services.split(",")}
        unknown = services - set(SERVICE_ALIASES)
        if unknown:
            print(f"Unknown service(s): {', '.join(sorted(unknown))}. "
                  f"Valid: {', '.join(SERVICE_ALIASES)}", file=sys.stderr)
            return 2

    try:
        session = boto3.Session(profile_name=args.profile)
        sts = session.client("sts", region_name=session.region_name or "us-east-1")
        identity = sts.get_caller_identity()
    except ProfileNotFound as e:
        print(f"Error: {e}", file=sys.stderr)
        return 2
    except NoRegionError:
        print("Error: no AWS region configured. Pass --region or set AWS_DEFAULT_REGION / "
              "a region in your profile.", file=sys.stderr)
        return 2
    except NoCredentialsError:
        print("Error: no AWS credentials found. Configure credentials via `aws configure`, "
              "environment variables, or --profile.", file=sys.stderr)
        return 2
    except ClientError as e:
        print(f"Error: could not authenticate to AWS ({e}).", file=sys.stderr)
        return 2

    result = AuditResult(account_id=identity["Account"])

    def module_enabled(module):
        if services is None:
            return True
        return any(SERVICE_ALIASES[s] is module for s in services)

    for module in GLOBAL_MODULES:
        if not module_enabled(module):
            continue
        run_check_set(module.get_checks(session), result)

    if module_enabled(logging_monitoring):
        run_check_set(logging_monitoring.get_global_checks(session), result)

    regions = resolve_regions(session, args)
    for region in regions:
        for module in REGIONAL_MODULES:
            if not module_enabled(module):
                continue
            run_check_set(module.get_checks(session, region), result)

    if not args.no_console:
        print_console_report(result)
    if args.json_out:
        write_json_report(result, args.json_out)
        print(f"\nJSON report written to {args.json_out}")
    if args.html_out:
        write_html_report(result, args.html_out)
        print(f"HTML report written to {args.html_out}")

    has_critical_or_high = any(f.severity.value in ("CRITICAL", "HIGH") for f in result.findings)
    return 1 if has_critical_or_high else 0


if __name__ == "__main__":
    sys.exit(main())
