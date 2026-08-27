#!/usr/bin/env python
"""
Cost-of-insecurity estimator.

A security finding usually gets reported as a technical fact ("bucket X is
publicly readable"). This translates it into the language finance/leadership
actually reacts to: what does this resource cost normally, and — separately,
because it's a fundamentally different number — what's the UNBOUNDED
liability if the misconfiguration is actually exploited?

For a public S3 bucket specifically, storage cost is small and bounded; the
real financial exposure is data transfer OUT, which has no ceiling if the
bucket gets scraped, hotlinked, or used to distribute large files. This is
the more accurate and more alarming framing than "your 12KB bucket costs
$0.0003/month" — which is true and also useless.

Pricing below is an approximate, clearly-labeled lookup table (ap-south-1),
not a live Pricing API call — the API's filter syntax buys precision this
tool doesn't need at the cost of real complexity for marginal accuracy gain.

Usage:
    python estimate.py report.json
"""
import json
import sys
from datetime import datetime, timedelta, timezone

import boto3

sys.stdout.reconfigure(encoding="utf-8")

# Approximate ap-south-1 (Mumbai) pricing, USD, as of this writing. Real
# pricing varies by tier/commitment/region-updates — treat as directional.
S3_STANDARD_STORAGE_PER_GB_MONTH = 0.025
S3_DATA_TRANSFER_OUT_PER_GB = 0.1093  # first 10TB/month tier
EC2_HOURLY_APPROX = {
    "t2.micro": 0.0146, "t3.micro": 0.0136, "t3.small": 0.0272,
    "t3.medium": 0.0544, "m5.large": 0.117, "m5.xlarge": 0.234,
}
RDS_HOURLY_APPROX = {
    "db.t3.micro": 0.021, "db.t3.small": 0.042, "db.t3.medium": 0.083,
    "db.m5.large": 0.225,
}

S3_PUBLIC_CHECKS = {"S3.1", "S3.2", "S3.3"}


def bucket_region(session, bucket):
    """S3 findings from the audit tool are recorded with region="global"
    (list_buckets() is a global call) — but CloudWatch metrics for a bucket
    are only published in that bucket's OWN region, so we have to look it
    up rather than assume us-east-1 or reuse the finding's region field."""
    s3 = session.client("s3")
    location = s3.get_bucket_location(Bucket=bucket).get("LocationConstraint")
    return location or "us-east-1"  # get_bucket_location returns None for us-east-1


def estimate_s3(session, bucket):
    region = bucket_region(session, bucket)
    cw = session.client("cloudwatch", region_name=region)
    now = datetime.now(timezone.utc)
    try:
        resp = cw.get_metric_statistics(
            Namespace="AWS/S3", MetricName="BucketSizeBytes",
            Dimensions=[{"Name": "BucketName", "Value": bucket},
                        {"Name": "StorageType", "Value": "StandardStorage"}],
            StartTime=now - timedelta(days=7), EndTime=now,
            Period=86400, Statistics=["Average"],
        )
        points = sorted(resp.get("Datapoints", []), key=lambda p: p["Timestamp"])
        size_bytes = points[-1]["Average"] if points else 0
        if not points:
            print(f"  (no CloudWatch storage datapoints in the last 7 days for {region} — "
                  "S3 storage metrics publish once/day, a brand-new bucket may not have one yet)")
    except Exception as e:
        print(f"  Could not fetch bucket size from CloudWatch ({region}): {e}")
        size_bytes = 0

    size_gb = size_bytes / (1024 ** 3)
    storage_cost = size_gb * S3_STANDARD_STORAGE_PER_GB_MONTH

    print(f"  Current size: {size_bytes:,.0f} bytes ({size_gb:.6f} GB)")
    print(f"  Normal storage cost: ~${storage_cost:.4f}/month (bounded, small)")
    print(f"  If scraped at 1,000 downloads/day: ~${size_gb * 1000 * 30 * S3_DATA_TRANSFER_OUT_PER_GB:.2f}/month in egress")
    print(f"  If scraped at 100,000 downloads/day (e.g. hotlinked or DDoS'd): "
          f"~${size_gb * 100000 * 30 * S3_DATA_TRANSFER_OUT_PER_GB:,.2f}/month")
    print(f"  This bucket's real exposure isn't its ${storage_cost:.4f}/month storage bill — "
          f"it's that egress cost has NO ceiling. A public bucket with no request/egress "
          f"budget alert can turn a $0.0003 resource into an unbounded one.")


def estimate_ec2(instance_type):
    hourly = EC2_HOURLY_APPROX.get(instance_type)
    print(f"  Instance type: {instance_type}")
    if hourly is None:
        print(f"  (no pricing data for this instance type in the built-in table)")
        return
    monthly = hourly * 24 * 30
    print(f"  Normal cost: ~${monthly:.2f}/month")
    print(f"  If compromised for cryptomining (runs 24/7 at this instance's rate regardless): "
          f"the instance cost itself stays ~${monthly:.2f}/month, but a compromised instance "
          f"is also a pivot point into the rest of the account — the real cost is whatever "
          f"else it can reach, which this tool can't put a number on. See attack-path-graph/.")


def estimate_rds(instance_class):
    hourly = RDS_HOURLY_APPROX.get(instance_class)
    print(f"  Instance class: {instance_class}")
    if hourly is None:
        print(f"  (no pricing data for this instance class in the built-in table)")
        return
    monthly = hourly * 24 * 30
    print(f"  Normal cost: ~${monthly:.2f}/month")
    print(f"  A publicly accessible instance at this tier risks the DATA it holds, not just "
          f"the ${monthly:.2f}/month compute — data exposure/exfiltration cost isn't a "
          f"pricing-table number, it's whatever that data is worth.")


def main():
    if len(sys.argv) < 2:
        print("Usage: python estimate.py report.json")
        sys.exit(1)

    with open(sys.argv[1], encoding="utf-8") as f:
        report = json.load(f)

    session = boto3.Session()
    seen_buckets = set()
    any_estimated = False

    for finding in report["findings"]:
        check_id = finding["check_id"]

        if check_id in S3_PUBLIC_CHECKS:
            bucket = finding["resource"]
            if bucket in seen_buckets:
                continue
            seen_buckets.add(bucket)
            print(f"\n=== {bucket} (public S3 bucket) ===")
            estimate_s3(session, bucket)
            any_estimated = True

    if not any_estimated:
        print("No findings in this report have a supported cost estimate "
              f"(currently: {', '.join(sorted(S3_PUBLIC_CHECKS))} for S3; "
              "EC2/RDS estimators exist but need a public-instance finding to run against).")


if __name__ == "__main__":
    main()
