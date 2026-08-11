"""Call the AWS Security Audit Lambda Function URL with a SigV4-signed request.

Usage:
    python invoke.py                # HTML report
    python invoke.py --json         # JSON report

Configure via environment variables (or edit the defaults below):
    AUDIT_FUNCTION_URL  - the Function URL from `aws lambda create-function-url-config`
    AWS_REGION          - region the function is deployed in
"""
import os
import sys
import urllib.parse
import urllib.request

import boto3
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest

FUNCTION_URL = os.environ.get("AUDIT_FUNCTION_URL", "https://your-function-url.lambda-url.your-region.on.aws/")
REGION = os.environ.get("AWS_REGION", "us-east-1")


def main():
    if "your-function-url" in FUNCTION_URL:
        print("Set AUDIT_FUNCTION_URL to your deployed Function URL (see README) before running this.")
        sys.exit(1)

    url = FUNCTION_URL + ("?format=json" if "--json" in sys.argv else "")

    session = boto3.Session(region_name=REGION)
    creds = session.get_credentials().get_frozen_credentials()

    request = AWSRequest(method="GET", url=url)
    request.headers["Host"] = urllib.parse.urlparse(url).netloc
    SigV4Auth(creds, "lambda", REGION).add_auth(request)

    req = urllib.request.Request(url, headers=dict(request.headers))
    with urllib.request.urlopen(req) as resp:
        body = resp.read().decode("utf-8")
        if "--json" in sys.argv:
            print(body)
        else:
            out_path = "s3_audit_report.html"
            with open(out_path, "w", encoding="utf-8") as f:
                f.write(body)
            print(f"Report saved to {out_path} — open it in your browser.")


if __name__ == "__main__":
    main()
