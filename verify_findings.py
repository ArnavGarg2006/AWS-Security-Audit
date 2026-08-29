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
  RDS.1               — a real TCP connection attempt to the DB endpoint's
                        current live port, from wherever this runs — proves
                        actual network reachability, not just the
                        PubliclyAccessible API flag (a security group can
                        still block everything even with that flag set)
  IAM.4               — re-lists the user's MFA devices RIGHT NOW via
                        list_mfa_devices, instead of trusting the
                        credential report snapshot (which AWS refreshes on
                        its own schedule, not on request)

Usage:
    python audit.py --json-out report.json     # first generate a report
    python verify_findings.py report.json
"""
import json
import socket
import sys
from pathlib import Path

import boto3
import requests

sys.path.insert(0, str(Path(__file__).parent / "sg-firewall-simulator"))
from simulate import evaluate, fetch_security_groups  # noqa: E402

VERIFIABLE_S3 = {"S3.1", "S3.2", "S3.3"}
VERIFIABLE_EC2 = {"EC2.1", "EC2.2"}
VERIFIABLE_RDS = {"RDS.1"}
VERIFIABLE_IAM = {"IAM.4"}


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


def verify_rds_public_access(session, region, db_id):
    """Real TCP connection attempt against the instance's CURRENT live
    endpoint/port, from wherever this runs. `PubliclyAccessible=true` only
    means the instance HAS a public DNS name that resolves to a public IP —
    a security group with no 0.0.0.0/0 ingress rule can still block every
    real connection attempt, which the config flag alone can't tell you."""
    rds = session.client("rds", region_name=region)
    try:
        instances = rds.describe_db_instances(DBInstanceIdentifier=db_id)["DBInstances"]
    except rds.exceptions.DBInstanceNotFoundFault:
        return None, f"RDS instance '{db_id}' no longer exists (deleted since the finding was recorded)."
    db = instances[0]

    if not db.get("PubliclyAccessible", False):
        return False, f"'{db_id}' is no longer PubliclyAccessible — re-verified clean."

    endpoint = db.get("Endpoint", {})
    host, port = endpoint.get("Address"), endpoint.get("Port")
    if not host:
        return None, f"'{db_id}' has no endpoint yet (instance still starting up?)."

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(6)
    try:
        sock.connect((host, port))
        return True, f"Real TCP connection to {host}:{port} SUCCEEDED — reachable from the internet."
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        return False, (f"PubliclyAccessible=true, but a real TCP connection to {host}:{port} "
                        f"failed ({e}) — security group is blocking it despite the flag.")
    finally:
        sock.close()


def verify_iam_user_mfa(session, username):
    """Re-lists the user's MFA devices right now via list_mfa_devices,
    instead of trusting the credential report's mfa_active column — AWS
    regenerates that report on its own internal cadence (up to ~4 hours
    stale), so a device added minutes ago can still show as "no MFA" in a
    report generated just before."""
    iam = session.client("iam")
    try:
        devices = iam.list_mfa_devices(UserName=username)["MFADevices"]
    except iam.exceptions.NoSuchEntityException:
        return None, f"IAM user '{username}' no longer exists (deleted since the finding was recorded)."

    if devices:
        names = ", ".join(d["SerialNumber"] for d in devices)
        return False, f"'{username}' now has {len(devices)} MFA device(s) registered: {names}"
    return True, f"'{username}' has zero MFA devices registered right now — finding confirmed current."


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
        elif check_id in VERIFIABLE_RDS:
            still_exposed, evidence = verify_rds_public_access(session, finding["region"], finding["resource"])
        elif check_id in VERIFIABLE_IAM:
            still_exposed, evidence = verify_iam_user_mfa(session, finding["resource"])
        else:
            continue

        results.append((finding, still_exposed, evidence))

    all_supported = VERIFIABLE_S3 | VERIFIABLE_EC2 | VERIFIABLE_RDS | VERIFIABLE_IAM
    if not results:
        print("No findings in this report have a supported active-verification method "
              f"({', '.join(sorted(all_supported))}).")
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
