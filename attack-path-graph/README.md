# Attack Path Graph

Instead of a flat findings list, builds a graph of IAM trust relationships, resource
policies, and network reachability, and answers "what can actually be reached from here?"
— the jump from checklist to compounding risk assessment.

## Honesty about scope

This is **not** a full IAM policy language evaluator — that's a genuinely hard problem
(Allow/Deny precedence, `NotAction`, `Condition` blocks, resource-ARN wildcards), and it's
what tools like IAM Access Analyzer/Zelkova exist to solve properly. This uses pragmatic,
clearly-labeled heuristics instead: managed-policy-name matching for "is this admin," and
structural Allow+`s3:*`-style-action+Resource matching for "can this reach that bucket."
Good enough to surface real compounding risk; not a completeness guarantee.

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
```

`--dot` writes a Graphviz file; render it with `dot -Tpng graph.dot -o graph.png` if you
have Graphviz installed. Exit code `1` if any Internet→compromise path exists, `0` otherwise.
