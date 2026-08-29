# Attack Path Graph

Instead of a flat findings list, builds a graph of IAM trust relationships, resource
policies, and network reachability, and answers "what can actually be reached from here?"
— the jump from checklist to compounding risk assessment.

## Ground truth, not just heuristics

Admin/S3-reachability edges are now backed by AWS's own policy evaluator —
[`iam_simulator.py`](iam_simulator.py) calls `iam:SimulatePrincipalPolicy`, which runs the
query against the principal's real merged managed+inline+permissions-boundary policy set
exactly the way IAM does at request time. The original structural heuristics (managed-
policy-name matching, Allow+`s3:*`-style-action+Resource matching) remain **only** as a
fallback for when the simulator call itself fails — every edge label says which method
actually produced it (`[simulator]` vs `[heuristic fallback]`), so nothing is silently
guessed without saying so. This still isn't a claim of *complete* coverage — the simulator
is queried with a curated, documented battery of actions per question ("is this admin,"
"can this reach S3"), not every IAM action that could conceivably matter — but it's real
AWS policy evaluation, not string matching, for everything it does check.

**Ground truth found something the heuristic never could.** Simulating the account's IAM
user found it has admin-equivalent access via **three independent policies** —
`AdministratorAccess`, `AdministratorAccess-Amplify`, and `AIDevOpsAgentActionsPolicy` —
not just the one the old heuristic checked by literal name. Removing `AdministratorAccess`
alone, believing the admin finding fixed, would leave two other paths to full account
compromise completely invisible.

## Blast radius, not just reachability

[`blast_radius.py`](blast_radius.py) answers a different question than the graph: not "can
this be reached from the internet" but "if this credential leaks *right now*, what can
actually be done with it" — independent of network path. It runs the same simulator against
every IAM role/user with a curated battery of high-impact actions grouped by what an
attacker would use them for (**Exfiltrate**, **Persist**, **Pivot**, **Destroy**), and flags
which categories are genuinely open per principal.

Run against this account, it found that `s3-audit-lambda-role` — whose only known job, per
the graph above, is reading S3 buckets — can *also* exfiltrate via `dynamodb:GetItem`,
`dynamodb:Scan`, `ssm:GetParameter`, and `logs:GetLogEvents`, because `ReadOnlyAccess` grants
all of that too. The graph only ever said "reaches every bucket"; the blast-radius battery
is what actually shows the reach goes well beyond S3.

## What it models

- **Nodes**: Internet, S3 buckets, Lambda functions, IAM roles/users, and a
  `FULL ACCOUNT COMPROMISE` sink representing effective admin access
- **Edges**: Internet → S3 bucket (if publicly readable) or → Lambda (if it has a public
  Function URL); Lambda → its execution role; IAM role/user → `FULL ACCOUNT COMPROMISE`
  (if it holds `AdministratorAccess` or an Allow `*:*` policy); IAM role → S3 bucket (if
  its policy — inline **or attached managed** — actually grants that access)

## Two real bugs this caught in itself, verified against the live account

1. **Wrong side of the edge tuple.** The "which principals have admin" summary collected
   `dst` instead of `src` from `(src, dst, label)` edges pointing at the sink — which is
   always the sink's own name, not the actual admin principal. One-line fix.
2. **Missed the biggest finding in the graph.** The S3-reachability heuristic only
   inspected *inline* policies — so `s3-audit-lambda-role`, which has the AWS-managed
   `ReadOnlyAccess` policy attached (no inline policy at all), showed **zero** S3 edges
   despite genuinely being able to read every bucket in the account, including the
   CloudTrail log bucket. Worse, even after fetching managed-policy content, a
   string-match for the literal text `"s3:*"` still missed it, because `ReadOnlyAccess`
   grants individual actions like `s3:GetObject` with `Resource: "*"`, not a wildcard
   action string. Fixed by parsing the actual `Action`/`Resource` structure instead of
   string-matching. After the fix, the graph correctly shows
   `s3-audit-lambda-role → all 4 buckets` (`aws-cloudtrail-logs-...`,
   `aws-config-bucket-...`, `aws-s3-access-logs-...`, `contact-form-frontend-...`).

## Real output against this account

```
Graph: 14 nodes, 9 edges

No path found from Internet to FULL ACCOUNT COMPROMISE via the relationships this tool models.
Principals with effective admin access: Arnav@2006
```

Correctly reports **no automated network path** to full compromise (no Lambda has a public
Function URL; the one public S3 bucket doesn't chain to anything further) — while
*separately* surfacing that the human IAM user has `AdministratorAccess` directly attached,
which is its own real finding regardless of any network path to it. That's the intended
behavior: a graph traversal answers "is there a pivot," not "is everything fine."

## Usage

```bash
pip install -r requirements.txt
python build_graph.py [--region ap-south-1] [--dot graph.dot]
python blast_radius.py [--region ap-south-1]
```

`--dot` writes a Graphviz file; render it with `dot -Tpng graph.dot -o graph.png` if you
have Graphviz installed. Exit code `1` if any Internet→compromise path exists (`build_graph.py`)
or any non-admin principal has an open Persist/Pivot/Destroy category (`blast_radius.py`), `0`
otherwise. Both need `iam:SimulatePrincipalPolicy` permission on the caller to get ground-truth
edges — without it, `build_graph.py` silently falls back to the heuristic and says so in the
edge label; `blast_radius.py` reports the simulator call failed for that principal and skips it.
