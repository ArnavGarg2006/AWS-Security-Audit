# S3 Integrity Monitor

A file integrity monitor, built AWS-native rather than as a generic `watchdog`-on-a-laptop
tool — because the interesting case (detecting tampering with your own audit trail) only
matters if it's watching the actual bucket, continuously, without you having a process
running somewhere. S3 Event Notifications → Lambda → DynamoDB → SNS.

## What it watches

Deployed against `aws-cloudtrail-logs-653011867129-ap-south-1` — the CloudTrail log
bucket created earlier in this project. That's a deliberate choice: an attacker covering
their tracks modifies or deletes audit logs, which makes this bucket specifically worth
watching, more than an arbitrary one.

## Behavior

| Event | Meaning | Action |
|---|---|---|
| New object, key not seen before | Expected — CloudTrail writes new log files continuously | Recorded in DynamoDB, no alert |
| Existing object, ETag changed | **An object was overwritten** — unexpected for an append-only log bucket | Recorded as `MODIFIED`, HIGH-severity SNS alert |
| Object deleted | **Log evidence removed** | Recorded as `DELETED`, CRITICAL-severity SNS alert |

State (per bucket+key: last known ETag, last event, timestamps) lives in DynamoDB
(`s3-integrity-log`), so overwrite/delete detection is correct across cold starts and
concurrent invocations — it's not relying on in-memory state that a Lambda cold start
would lose.

## Live deployment

| Component | Value |
|---|---|
| Lambda | `s3-integrity-monitor`, Python 3.13, `ap-south-1` |
| DynamoDB | `s3-integrity-log` (pk=bucket, sk=key), pay-per-request, encrypted |
| SNS | `s3-integrity-alerts` (email subscription) |
| Watching | `aws-cloudtrail-logs-653011867129-ap-south-1` (ObjectCreated:*, ObjectRemoved:*) |

Verified live: uploaded a test object (recorded, no alert) → overwrote it (flagged
`MODIFIED`, HIGH alert fired) → deleted it (flagged `DELETED`, CRITICAL alert fired) —
see `test_lambda_function.py` for the equivalent logic tested against mocks, and the
project's commit history for the live verification.

## Deploy elsewhere / point at another bucket

```bash
# IAM role
aws iam create-role --role-name s3-integrity-monitor-role \
  --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
aws iam attach-role-policy --role-name s3-integrity-monitor-role \
  --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole
# + an inline policy scoped to dynamodb:GetItem/PutItem/UpdateItem on your table
#   and sns:Publish on your topic

# DynamoDB
aws dynamodb create-table --table-name s3-integrity-log \
  --attribute-definitions AttributeName=pk,AttributeType=S AttributeName=sk,AttributeType=S \
  --key-schema AttributeName=pk,KeyType=HASH AttributeName=sk,KeyType=RANGE \
  --billing-mode PAY_PER_REQUEST --sse-specification Enabled=true

# SNS
aws sns create-topic --name s3-integrity-alerts
aws sns subscribe --topic-arn <topic-arn> --protocol email --notification-endpoint you@example.com

# Lambda (boto3 ships with the runtime — no dependencies to bundle)
zip function.zip lambda_function.py
aws lambda create-function --function-name s3-integrity-monitor --runtime python3.13 \
  --role <role-arn> --handler lambda_function.handler --zip-file fileb://function.zip \
  --timeout 30 --environment "Variables={TABLE_NAME=s3-integrity-log,TOPIC_ARN=<topic-arn>}"

# Wire it to your bucket
aws lambda add-permission --function-name s3-integrity-monitor \
  --statement-id AllowS3Invoke --action lambda:InvokeFunction \
  --principal s3.amazonaws.com --source-arn arn:aws:s3:::YOUR-BUCKET --source-account <account-id>
aws s3api put-bucket-notification-configuration --bucket YOUR-BUCKET \
  --notification-configuration '{"LambdaFunctionConfigurations":[{"Id":"integrity-monitor","LambdaFunctionArn":"<function-arn>","Events":["s3:ObjectCreated:*","s3:ObjectRemoved:*"]}]}'
```

**Note:** `put-bucket-notification-configuration` *replaces* the entire notification
config for a bucket — if the target bucket already has notifications configured for
something else, merge them into one call rather than overwriting.

## Testing

```bash
pip install -r requirements.txt
pytest test_lambda_function.py -v   # 7 tests, mocked DynamoDB/SNS
```
