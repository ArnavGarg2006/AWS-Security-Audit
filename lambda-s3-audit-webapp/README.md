# AWS Security Audit — Lambda Web App

A serverless version of the [aws_security_audit](../aws_security_audit) CLI tool: a single
Lambda function, invoked over an IAM-authenticated Function URL, that runs the same
read-only checks (IAM, S3, EC2, RDS, CloudTrail, Config, GuardDuty) live against your
account and returns the results as HTML or JSON.

No dependencies to package — `boto3` ships with the Lambda Python runtime.

## Deploy

```bash
# 1. IAM role for the function (trusts lambda.amazonaws.com)
aws iam create-role --role-name s3-audit-lambda-role \
  --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
aws iam attach-role-policy --role-name s3-audit-lambda-role \
  --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess
aws iam attach-role-policy --role-name s3-audit-lambda-role \
  --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole

# 2. Package and create the function (replace ACCOUNT_ID / REGION)
zip function.zip lambda_function.py
aws lambda create-function --function-name aws-security-audit-webapp \
  --runtime python3.13 --role arn:aws:iam::ACCOUNT_ID:role/s3-audit-lambda-role \
  --handler lambda_function.lambda_handler --zip-file fileb://function.zip \
  --timeout 60 --memory-size 256 --region REGION

# 3. IAM-authenticated Function URL (private — only signed requests can call it)
aws lambda create-function-url-config --function-name aws-security-audit-webapp \
  --auth-type AWS_IAM --region REGION
aws lambda add-permission --function-name aws-security-audit-webapp \
  --statement-id AllowMyUserInvokeUrl --action lambda:InvokeFunctionUrl \
  --principal arn:aws:iam::ACCOUNT_ID:user/YOUR_USER \
  --function-url-auth-type AWS_IAM --region REGION
```

## Why IAM auth instead of public?

A Function URL can be `AuthType: NONE` (public, anyone with the link can call it) or
`AuthType: AWS_IAM` (only SigV4-signed requests from your own credentials). Since this
returns your account's security findings, public access would hand that same information
to anyone with the URL — so this defaults to IAM-authenticated. A plain browser can't sign
a SigV4 request, which is why `invoke.py` exists.

## Usage

```bash
export AUDIT_FUNCTION_URL="https://your-function-url.lambda-url.your-region.on.aws/"
export AWS_REGION="your-region"

python invoke.py          # saves s3_audit_report.html
python invoke.py --json   # prints raw JSON
```

## IAM permissions

The execution role uses AWS-managed `ReadOnlyAccess` — broader than the CLI tool's minimal
per-check permissions, but still strictly read-only. Scope it down to just the specific
`s3:Get*`, `iam:Get*`/`iam:List*`, `ec2:Describe*`, `rds:Describe*`, `cloudtrail:*`,
`config:Describe*`, `guardduty:List*`/`Get*` actions if you want tighter least-privilege.
