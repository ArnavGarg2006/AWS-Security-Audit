#!/usr/bin/env python
"""
Continuous verification — after a fix (or before trusting a report), don't
just re-read the config API and hope. Actively re-attempt the exploit path
for the finding types where that's meaningful, and report whether the hole
is ACTUALLY closed, not just whether the JSON looks right.

Supported check types:
  S3.1 / S3.2 / S3.3  — real anonymous HTTPS request against the bucket,
                        same as an actual attacker would make
  EC2.1 / EC2.2       — re-evaluates the CURRENT live security group rules
                        using sg-firewall-simulator's real CIDR-containment
                        logic (not a re-read of the same cached finding)

Usage:
    python audit.py --json-out report.json     # first generate a report
    python verify_findings.py report.json
"""
import json
import sys
from pathlib import Path

import boto3
import requests

sys.path.insert(0, str(Path(__file__).parent / "sg-firewall-simulator"))
from simulate import evaluate, fetch_security_groups  # noqa: E402

VERIFIABLE_S3 = {"S3.1", "S3.2", "S3.3"}
VERIFIABLE_EC2 = {"EC2.1", "EC2.2"}


def verify_s3_public_access(bucket, session):
    """Makes real, unauthenticated HTTPS requests to the bucket — the same
    requests an actual attacker would make. Tests TWO separate permissions,
    because they're genuinely different and a bucket can have one without
    the other: s3:ListBucket (can you see what's in it) and s3:GetObject
    (can you read a specific file). A bucket policy scoped to
    `Resource: bucket/*` (a common, deliberate pattern for static website
    hosting) denies listing while still serving objects publicly — testing
    only the bucket root would report "closed" for a bucket that is, in
    fact, serving every object in it to anyone."""
    list_url = f"https://{bucket}.s3.amazonaws.com/"
    try:
        list_resp = requests.get(list_url, timeout=10)
        can_list = list_resp.status_code == 200
    except requests.RequestException as e:
        return None, f"Could not reach bucket endpoint: {e}"

    # Find a real object key to test GetObject against, rather than guessing
    # "index.html" and getting a misleading 404-not-403 for buckets that
    # don't happen to have one.
    can_get = None
    object_key = None
    try:
        s3 = session.client("s3")
        objects = s3.list_objects_v2(Bucket=bucket, MaxKeys=1).get("Contents", [])
        if objects:
            object_key = objects[0]["Key"]
    except Exception:
        pass  # fall through — GetObject test skipped if we can't enumerate a key

    if object_key:
        get_url = f"https://{bucket}.s3.amazonaws.com/{object_key}"
        try:
            get_resp = requests.get(get_url, timeout=10)
            can_get = get_resp.status_code == 200
        except requests.RequestException:
            pass

    if can_list or can_get:
        parts = []
        if can_list:
            parts.append(f"can LIST bucket contents ({list_url})")
        if can_get:
            parts.append(f"can GET object '{object_key}' ({get_url})")
        return True, "Anonymous access confirmed — " + "; ".join(parts)

    if can_get is None and object_key is None:
        return False, (f"HTTP {list_resp.status_code} on list — not publicly listable. "
                        "Bucket appears empty or inaccessible to this session, so GetObject "
                        "could not be tested against a real key.")
    return False, f"Anonymous list AND get both rejected — bucket is NOT publicly accessible ({list_url})"


def verify_ec2_security_group(session, region, sg_id_and_name):
    """Re-fetches the CURRENT live security group (not the cached finding)
    and re-runs the real evaluation logic against it, for every sensitive
    port, from 0.0.0.0/0 — proving the current live state, not the state
    at scan time."""
    sg_id = sg_id_and_name.split("(")[-1].rstrip(")")
    groups = fetch_security_groups(session, region)
    sg = next((g for g in groups if g["GroupId"] == sg_id), None)
    if not sg:
        return None, f"Security group {sg_id} no longer exists (deleted since the finding was recorded)."

    from simulate import SENSITIVE_PORTS
    exposed = []
    for port, service in SENSITIVE_PORTS.items():
        allowed, _, _ = evaluate(sg, "ingress", "tcp", port, "0.0.0.0/0")
        if allowed:
            exposed.append(f"{service}:{port}")

    if exposed:
        return True, f"Currently ALLOWS from 0.0.0.0/0: {', '.join(exposed)}"
    return False, "Currently allows nothing sensitive from 0.0.0.0/0 — re-verified clean."


def main():
    if len(sys.argv) < 2:
        print("Usage: python verify_findings.py report.json")
        sys.exit(1)

    with open(sys.argv[1], encoding="utf-8") as f:
        report = json.load(f)

    session = boto3.Session()
    results = []

    for finding in report["findings"]:
        check_id = finding["check_id"]
        if check_id in VERIFIABLE_S3:
            bucket = finding["resource"]
            still_exposed, evidence = verify_s3_public_access(bucket, session)
        elif check_id in VERIFIABLE_EC2:
            still_exposed, evidence = verify_ec2_security_group(session, finding["region"], finding["resource"])
        else:
            continue

        results.append((finding, still_exposed, evidence))

    if not results:
        print("No findings in this report have a supported active-verification method "
              f"({', '.join(sorted(VERIFIABLE_S3 | VERIFIABLE_EC2))}).")
        return

    print(f"Actively re-testing {len(results)} finding(s) against live infrastructure...\n")
    open_count = 0
    for finding, still_exposed, evidence in results:
        if still_exposed is True:
            open_count += 1
            print(f"[STILL OPEN]  {finding['check_id']}  {finding['resource']}")
        elif still_exposed is False:
            print(f"[CONFIRMED CLOSED]  {finding['check_id']}  {finding['resource']}")
        else:
            print(f"[INCONCLUSIVE]  {finding['check_id']}  {finding['resource']}")
        print(f"    {evidence}\n")

    print(f"{open_count}/{len(results)} finding(s) confirmed still exploitable via live re-test.")
    sys.exit(1 if open_count else 0)


if __name__ == "__main__":
    main()
