"""
Executable remediation — every finding already carries a plain-English
remediation sentence (see Finding.remediation). That's a sentence a human
has to translate into an actual command. This does the translation for
every check_id that genuinely maps to a single AWS CLI call, substituting
the finding's own resource/region in directly.

This tool NEVER executes anything itself — it only writes a script for a
human to read and run. Some checks honestly don't reduce to one CLI call
(root MFA enrollment is interactive; RDS/EBS encryption requires a
snapshot-and-restore, not an in-place flag) — those get a `#`-comment
explaining why, not a fabricated command that would silently do the wrong
thing if someone ran it unread.
"""


def _sg_id(resource):
    """"my-sg (sg-0123abcd)" -> "sg-0123abcd" """
    return resource.split("(")[-1].rstrip(")")


def _user_and_key_num(resource):
    """"alice (access key 1)" -> ("alice", "1")"""
    name, rest = resource.split(" (access key ")
    return name, rest.rstrip(")")


REMEDIATORS = {
    "IAM.1": lambda f: "# Root MFA enrollment is interactive (scan a QR / insert a hardware key) — "
                        "not scriptable via CLI. IAM console > Security credentials.",
    "IAM.2": lambda f: "aws iam list-access-keys --user-name root  "
                        "# then: aws iam delete-access-key --user-name root --access-key-id <ID_FROM_ABOVE>",
    "IAM.3": lambda f: ("aws iam update-account-password-policy --minimum-password-length 14 "
                         "--require-symbols --require-numbers --require-uppercase-characters "
                         "--require-lowercase-characters --max-password-age 90 "
                         "--password-reuse-prevention 24"),
    "IAM.4": lambda f: f"# MFA enrollment for '{f.resource}' is interactive — not scriptable via CLI. "
                        f"IAM console > Users > {f.resource} > Security credentials.",
    "IAM.5": lambda f: _rotate_key_cmd(f),
    "IAM.6": lambda f: _unused_key_cmd(f),
    "IAM.7": lambda f: f"# Review '{f.resource}' and scope it down, then: "
                        f"aws iam create-policy-version --policy-arn <ARN_OF_{f.resource}> "
                        f"--policy-document file://scoped-down.json --set-as-default",
    "S3.1": lambda f: f"aws s3api put-public-access-block --bucket {f.resource} "
                       f"--public-access-block-configuration "
                       f"BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
    "S3.2": lambda f: f"aws s3api delete-bucket-policy --bucket {f.resource}  "
                       f"# or edit the policy to remove the public statement instead of deleting it outright",
    "S3.3": lambda f: f"aws s3api put-bucket-acl --bucket {f.resource} --acl private",
    "S3.4": lambda f: (f"aws s3api put-bucket-encryption --bucket {f.resource} "
                        f"--server-side-encryption-configuration "
                        f'\'{{"Rules":[{{"ApplyServerSideEncryptionByDefault":{{"SSEAlgorithm":"AES256"}}}}]}}\''),
    "S3.5": lambda f: f"aws s3api put-bucket-versioning --bucket {f.resource} "
                       f"--versioning-configuration Status=Enabled",
    "S3.6": lambda f: (f"aws s3api put-bucket-logging --bucket {f.resource} --bucket-logging-status "
                        f'\'{{"LoggingEnabled":{{"TargetBucket":"<LOG_BUCKET>","TargetPrefix":"{f.resource}/"}}}}\''),
    "EC2.1": lambda f: f"aws ec2 revoke-security-group-ingress --group-id {_sg_id(f.resource)} "
                        f"--protocol tcp --port <SENSITIVE_PORT> --cidr 0.0.0.0/0  # repeat per exposed port",
    "EC2.2": lambda f: f"aws ec2 revoke-security-group-ingress --group-id {_sg_id(f.resource)} "
                        f"--protocol tcp --port <PORT> --cidr 0.0.0.0/0  # repeat per exposed port",
    "EC2.3": lambda f: f"# EBS encryption can't be enabled in place: snapshot {f.resource}, copy the "
                        f"snapshot with --encrypted, create a new volume from the encrypted copy, "
                        f"swap it in, delete the old volume.",
    "EC2.4": lambda f: f"aws ec2 modify-instance-attribute --instance-id {f.resource} "
                        f"--no-associate-public-ip-address  # takes effect on next stop/start; "
                        f"or move the instance to a private subnet behind a NAT/bastion",
    "EC2.5": lambda f: f"# Confirm nothing depends on it first, then: aws ec2 delete-vpc --vpc-id {f.resource}",
    "RDS.1": lambda f: f"aws rds modify-db-instance --db-instance-identifier {f.resource} "
                        f"--no-publicly-accessible --apply-immediately",
    "RDS.2": lambda f: f"# Storage encryption can't be enabled in place for '{f.resource}': create an "
                        f"encrypted snapshot copy (aws rds copy-db-snapshot ... --kms-key-id ...) and "
                        f"restore into a new instance.",
    "RDS.3": lambda f: f"aws rds modify-db-instance --db-instance-identifier {f.resource} "
                        f"--backup-retention-period 7 --apply-immediately",
    "RDS.4": lambda f: f"aws rds modify-db-instance --db-instance-identifier {f.resource} "
                        f"--multi-az --apply-immediately",
    "RDS.5": lambda f: f"aws rds modify-db-instance --db-instance-identifier {f.resource} "
                        f"--auto-minor-version-upgrade --apply-immediately",
    "LOG.1": lambda f: "aws cloudtrail create-trail --name <TRAIL_NAME> --s3-bucket-name <LOG_BUCKET> "
                        "--is-multi-region-trail --enable-log-file-validation",
    "LOG.2": lambda f: f"aws cloudtrail start-logging --name {f.resource}",
    "LOG.3": lambda f: f"aws cloudtrail update-trail --name {f.resource} --enable-log-file-validation",
    "LOG.4": lambda f: f"aws cloudtrail update-trail --name {f.resource} --kms-key-id <KMS_KEY_ARN>",
    "LOG.5": lambda f: f"aws configservice put-configuration-recorder --region {f.region} "
                        f"--configuration-recorder name=default,roleARN=<CONFIG_ROLE_ARN>  "
                        f"# then: aws configservice start-configuration-recorder "
                        f"--region {f.region} --configuration-recorder-name default",
    "LOG.6": lambda f: f"aws guardduty create-detector --enable --region {f.region}",
}


def _rotate_key_cmd(f):
    user, key_num = _user_and_key_num(f.resource)
    return (f"aws iam create-access-key --user-name {user}  "
            f"# migrate secrets to the new key, THEN: "
            f"aws iam delete-access-key --user-name {user} --access-key-id <OLD_KEY_{key_num}_ID>")


def _unused_key_cmd(f):
    user, key_num = _user_and_key_num(f.resource)
    return (f"# Confirm it's really unused, then: "
            f"aws iam delete-access-key --user-name {user} --access-key-id <KEY_{key_num}_ID>")


def remediation_command(finding):
    """Returns a single string for this finding: a ready-to-run `aws ...`
    command with the finding's own resource/region substituted in, or a
    `#`-prefixed comment when the real fix isn't a single CLI call. Returns
    None if this check_id isn't mapped at all."""
    gen = REMEDIATORS.get(finding.check_id)
    if not gen:
        return None
    try:
        return gen(finding)
    except Exception as e:
        return f"# Could not generate a command for {finding.check_id}/{finding.resource}: {e}"


def write_fix_script(findings, path):
    """Writes a shell script covering every finding this generator can map
    to a command (or an explanatory comment). Never executes anything.
    Returns (covered_count, total_count)."""
    lines = [
        "#!/usr/bin/env bash",
        "# Auto-generated by aws_security_audit --fix-script. NOTHING here has been run.",
        "# Review every line before running any of it. Commands with a placeholder",
        "# like <PORT> or <ARN> need a real value filled in by hand first.",
        "set -e",
        "",
    ]
    covered = 0
    for f in findings:
        cmd = remediation_command(f)
        if cmd is None:
            continue
        covered += 1
        lines.append(f"# {f.check_id} — {f.title}")
        lines.append(cmd)
        lines.append("")

    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
    return covered, len(findings)
