#!/usr/bin/env python
"""
Attack path graph — instead of a flat findings list, builds a graph of IAM
trust relationships, resource policies, and network reachability, then
answers "what can actually be reached from here?"

This is deliberately NOT a full IAM policy language evaluator (Allow/Deny
precedence, NotAction, Condition blocks, resource-level wildcards) — that's
a genuinely hard problem (it's what tools like Zelkova/IAM Access Analyzer
exist to solve properly). This uses pragmatic, clearly-labeled heuristics:
managed-policy-name matching for "is this admin", and Allow+Action:*+
Resource:* matching for inline/customer policies. Good enough to surface
real compounding risk; not a guarantee of completeness the way a real
policy simulator would be — see the README for exactly where the line is.

Nodes: Internet, S3 buckets, Lambda functions, IAM roles/users, and a
"Full Account Compromise" sink representing effective admin access.

Edges (reachability, not "this is compromised"):
  Internet -> S3 bucket           if the bucket is publicly readable
  Internet -> Lambda               if it has a public (AuthType=NONE) Function URL
  Lambda -> IAM role                its execution role
  IAM role/user -> FULL COMPROMISE  if it holds AdministratorAccess or an
                                     Allow *:* policy
  IAM role -> S3 bucket             if its policy explicitly grants access
                                     to that bucket (or s3:* broadly)

Usage:
    python build_graph.py [--region ap-south-1] [--dot graph.dot]
"""
import argparse
import json
import sys

import boto3

sys.stdout.reconfigure(encoding="utf-8")

ADMIN_MANAGED_POLICIES = {"AdministratorAccess"}


class Graph:
    def __init__(self):
        self.edges = []  # (from, to, label)
        self.node_kinds = {}  # name -> kind, for DOT coloring

    def add_node(self, name, kind):
        self.node_kinds[name] = kind

    def add_edge(self, src, dst, label=""):
        self.edges.append((src, dst, label))

    def paths_from(self, start, end, max_depth=6):
        """All simple paths start -> end via DFS (small graph, brute force is fine)."""
        results = []

        def dfs(node, path, visited):
            if node == end:
                results.append(list(path))
                return
            if len(path) >= max_depth:
                return
            for src, dst, label in self.edges:
                if src == node and dst not in visited:
                    dfs(dst, path + [(dst, label)], visited | {dst})

        dfs(start, [], {start})
        return results


def policy_is_admin(doc):
    statements = doc.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    for stmt in statements:
        if stmt.get("Effect") != "Allow":
            continue
        actions = stmt.get("Action", [])
        resources = stmt.get("Resource", [])
        actions = [actions] if isinstance(actions, str) else actions
        resources = [resources] if isinstance(resources, str) else resources
        if "*" in actions and "*" in resources:
            return True
    return False


def policy_references_s3(doc, bucket_name=None):
    """Best-effort structural check, not resource-ARN-precise policy
    evaluation (no Deny precedence, no Condition blocks). True if any Allow
    statement grants an s3:* -style action against either Resource: "*" (any
    bucket) or an ARN matching this specific bucket."""
    statements = doc.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    for stmt in statements:
        if stmt.get("Effect") != "Allow":
            continue
        actions = stmt.get("Action", [])
        actions = [actions] if isinstance(actions, str) else actions
        s3_action = any(a == "*" or a.lower().startswith("s3:") for a in actions)
        if not s3_action:
            continue

        resources = stmt.get("Resource", [])
        resources = [resources] if isinstance(resources, str) else resources
        for r in resources:
            if r == "*":
                return True
            if bucket_name and bucket_name.lower() in r.lower():
                return True
    return False


def analyze_iam_principal(iam, principal_type, name, graph):
    """principal_type: 'user' or 'role'. Returns (is_admin, policy_docs).

    policy_docs includes BOTH inline policies and the content of attached
    MANAGED policies (AWS-managed and customer-managed) — a role with only
    ReadOnlyAccess attached and no inline policy has real, broad S3 read
    reachability that a check limited to inline policies would silently miss.
    """
    is_admin = False
    policy_docs = []

    if principal_type == "user":
        attached = iam.list_attached_user_policies(UserName=name)["AttachedPolicies"]
        inline_names = iam.list_user_policies(UserName=name)["PolicyNames"]
        get_inline = lambda pn: iam.get_user_policy(UserName=name, PolicyName=pn)["PolicyDocument"]  # noqa: E731
    else:
        attached = iam.list_attached_role_policies(RoleName=name)["AttachedPolicies"]
        inline_names = iam.list_role_policies(RoleName=name)["PolicyNames"]
        get_inline = lambda pn: iam.get_role_policy(RoleName=name, PolicyName=pn)["PolicyDocument"]  # noqa: E731

    for p in attached:
        if p["PolicyName"] in ADMIN_MANAGED_POLICIES:
            is_admin = True
        try:
            version_id = iam.get_policy(PolicyArn=p["PolicyArn"])["Policy"]["DefaultVersionId"]
            doc = iam.get_policy_version(PolicyArn=p["PolicyArn"], VersionId=version_id)["PolicyVersion"]["Document"]
            policy_docs.append(doc)
            if policy_is_admin(doc):
                is_admin = True
        except Exception:
            continue

    for pn in inline_names:
        try:
            doc = get_inline(pn)
        except Exception:
            continue
        policy_docs.append(doc)
        if policy_is_admin(doc):
            is_admin = True

    return is_admin, policy_docs


def build(session, region):
    graph = Graph()
    graph.add_node("Internet", "internet")
    graph.add_node("FULL ACCOUNT COMPROMISE", "sink")

    s3 = session.client("s3")
    iam = session.client("iam")
    lam = session.client("lambda", region_name=region)

    # --- S3 buckets: public reachability ---
    buckets = s3.list_buckets().get("Buckets", [])
    for b in buckets:
        name = b["Name"]
        graph.add_node(name, "s3")
        try:
            status = s3.get_bucket_policy_status(Bucket=name)["PolicyStatus"]
            if status.get("IsPublic"):
                graph.add_edge("Internet", name, "public bucket policy")
        except Exception:
            pass

    # --- Lambda functions: public Function URLs + execution role ---
    role_to_functions = {}
    for page in lam.get_paginator("list_functions").paginate():
        for fn in page["Functions"]:
            fn_name = fn["FunctionName"]
            role_arn = fn["Role"]
            role_name = role_arn.split("/")[-1]
            graph.add_node(fn_name, "lambda")
            graph.add_edge(fn_name, role_name, "execution role")
            role_to_functions.setdefault(role_name, []).append(fn_name)

            try:
                url_cfg = lam.get_function_url_config(FunctionName=fn_name)
                if url_cfg.get("AuthType") == "NONE":
                    graph.add_edge("Internet", fn_name, "public Function URL")
            except lam.exceptions.ResourceNotFoundException:
                pass
            except Exception:
                pass

    # --- IAM roles referenced by Lambda: admin check + S3 reachability ---
    for role_name in role_to_functions:
        graph.add_node(role_name, "role")
        is_admin, policy_docs = analyze_iam_principal(iam, "role", role_name, graph)
        if is_admin:
            graph.add_edge(role_name, "FULL ACCOUNT COMPROMISE", "AdministratorAccess or *:* policy")
        for b in buckets:
            for doc in policy_docs:
                if policy_references_s3(doc, b["Name"]):
                    graph.add_edge(role_name, b["Name"], "policy grants S3 access")
                    break

    # --- IAM users: admin check (the interactive/human identity) ---
    for page in iam.get_paginator("list_users").paginate():
        for u in page["Users"]:
            uname = u["UserName"]
            graph.add_node(uname, "user")
            is_admin, _ = analyze_iam_principal(iam, "user", uname, graph)
            if is_admin:
                graph.add_edge(uname, "FULL ACCOUNT COMPROMISE", "AdministratorAccess attached")

    return graph


def write_dot(graph, path):
    colors = {"internet": "#7f5af0", "s3": "#69c0ff", "lambda": "#2cb67d",
              "role": "#ffd666", "user": "#ff7a45", "sink": "#ff4d4f"}
    lines = ["digraph AttackPath {", '  bgcolor="#0b0d12";',
             '  node [style=filled, fontname="Segoe UI", fontcolor="#0b0d12"];',
             '  edge [color="#a7a9be", fontcolor="#a7a9be", fontname="Segoe UI", fontsize=9];']
    for node, kind in graph.node_kinds.items():
        color = colors.get(kind, "#a7a9be")
        lines.append(f'  "{node}" [fillcolor="{color}"];')
    for src, dst, label in graph.edges:
        lines.append(f'  "{src}" -> "{dst}" [label="{label}"];')
    lines.append("}")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def main():
    parser = argparse.ArgumentParser(description="Build an attack path graph from IAM/S3/Lambda relationships.")
    parser.add_argument("--region", default="ap-south-1")
    parser.add_argument("--profile")
    parser.add_argument("--dot", help="Write a Graphviz .dot file to this path")
    args = parser.parse_args()

    session = boto3.Session(profile_name=args.profile)
    graph = build(session, args.region)

    print(f"Graph: {len(graph.node_kinds)} nodes, {len(graph.edges)} edges\n")

    paths = graph.paths_from("Internet", "FULL ACCOUNT COMPROMISE")
    if paths:
        print(f"⚠️  {len(paths)} path(s) from Internet to FULL ACCOUNT COMPROMISE:\n")
        for path in paths:
            hops = ["Internet"] + [n for n, _ in path]
            labels = [lbl for _, lbl in path]
            trail = " -> ".join(hops)
            print(f"  {trail}")
            for hop, label in zip(hops[1:], labels):
                print(f"    ({label})")
            print()
    else:
        print("No path found from Internet to FULL ACCOUNT COMPROMISE via the relationships this tool models.")

    # Also surface any IAM user/role with admin, regardless of internet reachability —
    # a human's own credentials being admin is itself the finding, path or no path.
    admin_principals = [src for src, dst, label in graph.edges if dst == "FULL ACCOUNT COMPROMISE"]
    if admin_principals:
        print(f"Principals with effective admin access: {', '.join(sorted(set(admin_principals)))}")

    if args.dot:
        write_dot(graph, args.dot)
        print(f"\nGraphviz file written to {args.dot} — render with: dot -Tpng {args.dot} -o graph.png")

    sys.exit(1 if paths else 0)


if __name__ == "__main__":
    main()
