"""Ground-truth IAM reachability via AWS's own policy simulator.

build_graph.py originally answered "is this admin" / "can this reach that
bucket" with pragmatic heuristics: string/structure-matching against policy
documents (Allow + Action:* + Resource:*, or Allow + s3:*-style action +
matching Resource). That's honestly documented in this project's README as
NOT a full IAM policy language evaluator -- no Deny precedence, no NotAction,
no Condition blocks, no permissions-boundary awareness.

AWS already has that full evaluator: `iam:SimulatePrincipalPolicy`. It runs
the request against the principal's REAL merged policy set (managed +
inline + permissions boundary) exactly the way IAM itself would at request
time, and returns one of three ground-truth decisions per action/resource:
"allowed", "explicitDeny", "implicitDeny". This module calls that API and
returns `None` (not `False`) when the call itself fails -- e.g. the caller
lacks `iam:SimulatePrincipalPolicy` -- so build_graph.py can tell "the
simulator said no" apart from "the simulator wasn't available" and fall
back to the heuristic only in the latter case.
"""

# A representative sample of high-privilege actions across the primary
# "own the account" primitives: create a new identity, attach power to an
# existing one, or destroy something expensive. Not exhaustive -- an
# attacker only needs ONE of these to matter -- but far more grounded than
# a single "Action: *" string match, and it's evaluated by the real engine.
ADMIN_PROBE_ACTIONS = [
    "iam:CreateUser",
    "iam:CreateAccessKey",
    "iam:AttachUserPolicy",
    "iam:PutUserPolicy",
    "iam:CreateRole",
    "iam:AttachRolePolicy",
    "ec2:TerminateInstances",
    "s3:DeleteBucket",
    "rds:DeleteDBInstance",
]

S3_PROBE_ACTIONS = ["s3:GetObject", "s3:PutObject", "s3:ListBucket", "s3:DeleteObject"]

# Blast-radius probe battery, grouped by what an attacker would actually do
# with the credential rather than by AWS service.
BLAST_RADIUS_ACTIONS = {
    "Exfiltrate": [
        "s3:GetObject",
        "dynamodb:GetItem",
        "dynamodb:Scan",
        "secretsmanager:GetSecretValue",
        "ssm:GetParameter",
        "logs:GetLogEvents",
    ],
    "Persist": [
        "iam:CreateAccessKey",
        "iam:CreateLoginProfile",
        "iam:UpdateLoginProfile",
        "iam:CreateUser",
    ],
    "Pivot": [
        "sts:AssumeRole",
        "lambda:UpdateFunctionCode",
        "lambda:InvokeFunction",
    ],
    "Destroy": [
        "ec2:TerminateInstances",
        "rds:DeleteDBInstance",
        "s3:DeleteBucket",
        "dynamodb:DeleteTable",
    ],
}


def _simulate(iam, principal_arn, action_names, resource_arns):
    """Returns EvaluationResults, or None if the simulator call itself failed
    (permission denied, principal doesn't exist, etc.) -- distinct from a
    real "not allowed" answer."""
    try:
        resp = iam.simulate_principal_policy(
            PolicySourceArn=principal_arn,
            ActionNames=action_names,
            ResourceArns=resource_arns,
        )
        return resp.get("EvaluationResults", [])
    except Exception:
        return None


def simulate_is_admin(iam, principal_arn):
    """Returns (is_admin, matched_policy_ids).

    is_admin is True/False from the real evaluator, or None if the
    simulator call failed and the caller should fall back to the heuristic.
    matched_policy_ids names which attached policy(ies) actually granted
    the access, straight from the simulator's own MatchedStatements --
    something the old heuristic couldn't tell you at all.
    """
    results = _simulate(iam, principal_arn, ADMIN_PROBE_ACTIONS, ["*"])
    if results is None:
        return None, set()
    is_admin = bool(results) and all(r["EvalDecision"] == "allowed" for r in results)
    matched = set()
    for r in results:
        for stmt in r.get("MatchedStatements", []):
            matched.add(stmt.get("SourcePolicyId", "?"))
    return is_admin, matched


def simulate_s3_access(iam, principal_arn, bucket_name):
    """Returns (has_access, allowed_actions). has_access is None if the
    simulator call failed (fall back to heuristic); allowed_actions lists
    exactly which of the probe actions the real evaluator allows."""
    bucket_arn = f"arn:aws:s3:::{bucket_name}"
    results = _simulate(iam, principal_arn, S3_PROBE_ACTIONS, [bucket_arn, f"{bucket_arn}/*"])
    if results is None:
        return None, []
    allowed = sorted({r["EvalActionName"] for r in results if r["EvalDecision"] == "allowed"})
    return bool(allowed), allowed


def simulate_blast_radius(iam, principal_arn):
    """Runs the full BLAST_RADIUS_ACTIONS battery against Resource: "*" and
    returns {category: sorted(allowed_actions)}. A category with a
    non-empty list means the real evaluator allows that action against at
    least a wildcard resource for this principal -- callers should treat a
    non-admin principal with a non-empty Persist/Pivot/Destroy bucket as a
    real finding on its own, independent of whether it's reachable from the
    graph's Internet node."""
    all_actions = [a for actions in BLAST_RADIUS_ACTIONS.values() for a in actions]
    results = _simulate(iam, principal_arn, all_actions, ["*"])
    if results is None:
        return None
    allowed_set = {r["EvalActionName"] for r in results if r["EvalDecision"] == "allowed"}
    return {
        category: sorted(a for a in actions if a in allowed_set)
        for category, actions in BLAST_RADIUS_ACTIONS.items()
    }
