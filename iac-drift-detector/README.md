# IaC Drift Detector

Compares [`fullstack-contact-app/template.yaml`](../fullstack-contact-app/template.yaml)
— the documented "should be" state — against what's actually live, via direct boto3 calls.

## Why not AWS's native drift detection

CloudFormation has a real `detect-stack-drift` feature — but it only works against
resources deployed *through* a CloudFormation/SAM stack. The live resources in this repo
were hand-deployed via CLI (documented in that project's README as a deliberate choice,
since `template.yaml` is a reproducibility snapshot, not the deployment mechanism used).
No stack exists to run native drift detection against, so this compares the template's
declared properties directly against live `describe-*`/`get-*` API responses instead.

## What it checks

Lambda (MemorySize, Timeout, Runtime, tracing mode), API Gateway stage throttling,
DynamoDB (billing mode, encryption), WAF rate-limit value.

## Verified live

Ran clean (0/9 drifted) against the actual deployed stack. Then deliberately introduced
real drift — hand-changed the Lambda's memory from 128MB to 256MB via `aws lambda
update-function-configuration`, exactly the "someone fixed it by hand in the console"
scenario this tool exists to catch — confirmed it was detected (`1/9 field(s) drifted`),
then reverted and confirmed clean again.

## Root cause, not just "it drifted"

[`root_cause.py`](root_cause.py) answers the obvious follow-up question a drift row leaves
open: *who* changed it, and *when*. It correlates a drifted field to the actual CloudTrail
event that caused it and attributes it to a principal and timestamp — best-effort (CloudTrail's
`lookup_events` only covers 90 days, and matching is done by checking whether the resource's
identifier appears in the raw event JSON, since there's no single reliable "ResourceId" field
across every service's event shape), but real correlation, not a guess.

**A real bug caught building this, live**: the first version looked up Lambda's config-change
event by the exact name `UpdateFunctionConfiguration` and found nothing — not because the event
didn't happen, but because Lambda's actual CloudTrail `EventName` is suffixed with the API
version, `UpdateFunctionConfiguration20150331v2`. An exact-match lookup would have silently
returned "no matching event" forever, even for a change that had just happened. Fixed by
looking up events by `EventSource` (`lambda.amazonaws.com`, not versioned) and matching the
event name with `startswith()` instead of equality — confirmed against the same real drift
test above: re-introducing the Lambda memory change now correctly attributes it to
`Arnav@2006` via `UpdateFunctionConfiguration20150331v2` at the exact real timestamp of the
CLI call that caused it.

## Usage

```bash
pip install -r requirements.txt
python drift_check.py [--region ap-south-1]
```

Exit code `1` if anything drifted (wire into CI to catch drift on a schedule), `0` if clean.
Root-cause attribution prints automatically for any drifted field, using the same session's
CloudTrail access — no extra flag needed.
