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

## Usage

```bash
pip install -r requirements.txt
python drift_check.py [--region ap-south-1]
```

Exit code `1` if anything drifted (wire into CI to catch drift on a schedule), `0` if clean.
