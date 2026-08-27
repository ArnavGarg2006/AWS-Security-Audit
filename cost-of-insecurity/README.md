# Cost-of-Insecurity Estimator

Translates a security finding into the language finance/leadership actually reacts to:
what does this resource cost normally, and — a separately-computed, fundamentally
different number — what's the *unbounded* liability if the misconfiguration is exploited.

## The actual point of this tool

For a public S3 bucket, storage cost is small and bounded. The real financial exposure is
data transfer **out**, which has no ceiling if the bucket gets scraped, hotlinked, or used
to distribute large files. Reporting "your misconfigured bucket costs $0.0003/month" is
true and useless. Reporting "storage is bounded at $0.0003/month, but egress has no
ceiling and 100k scrapes/day would run ~$3.85/month *per day of exposure*" is the framing
that actually motivates a fix.

## A real bug this caught in itself

The first version silently reported `$0.0000/month` and `0 bytes` for every bucket — not
because the buckets were empty, but because `get_metric_statistics` was pointed at
`us-east-1` (wrong assumption: S3 CloudWatch metrics publish in the bucket's own region,
not globally) *and* a hardcoded 2024–2030 time range exceeded CloudWatch's 1,440-datapoint
limit, throwing an exception that a blanket `except Exception: size_bytes = 0` silently
swallowed. Fixed both: look up the bucket's real region via `get_bucket_location`, and use
a bounded 7-day query window. Verified against the real `contact-form-frontend` bucket —
correctly reports its actual 12,595-byte size after the fix.

## Pricing accuracy

Uses a small, clearly-labeled approximate pricing table (ap-south-1, USD) rather than a
live Pricing API call — the API's filter syntax buys precision this tool doesn't need at
real implementation cost. Treat the numbers as directional, not exact.

## Usage

```bash
pip install -r requirements.txt
python estimate.py report.json   # generate report.json via: python audit.py --json-out report.json
```

Currently estimates S3 public-bucket exposure (`S3.1`/`S3.2`/`S3.3` findings). EC2/RDS
estimators are implemented (`estimate_ec2`/`estimate_rds`) but need a public-instance
finding in the report to run against — none exist in this account right now.
