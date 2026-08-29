#!/usr/bin/env python
"""
Blast radius — attack-path-graph answers "can this principal be reached
from the internet." This answers the next question: "if this principal's
credentials leak right now, what can actually be done with them" —
independent of whether a network path to it exists at all. A role with no
Internet edge in the graph is still a real finding if leaking its access
key (via a laptop, a CI log, a committed .env) hands over the ability to
exfiltrate data, persist a foothold, pivot to other roles, or destroy
resources.

Runs AWS's own policy simulator (iam:SimulatePrincipalPolicy — see
iam_simulator.py) against every IAM role and user in the account with a
curated battery of high-impact actions, grouped by what an attacker would
actually use them for:

    Exfiltrate  — read data out (S3, DynamoDB, Secrets Manager, SSM, logs)
    Persist     — create a new way back in (access keys, login profiles)
    Pivot       — become someone else (AssumeRole) or run more code (Lambda)
    Destroy     — delete something expensive (instances, DBs, buckets, tables)

This is a curated sample, not an exhaustive simulation of every IAM action
in every service — the same honesty applies as the rest of this tool: good
enough to size real blast radius, not a completeness guarantee.

Usage:
    python blast_radius.py [--region ap-south-1]
"""
import argparse
import sys

import boto3

import iam_simulator
from build_graph import build

sys.stdout.reconfigure(encoding="utf-8")


def principals_from_graph(graph, account_id):
    """Every role/user node in the graph, plus whether it's Internet-reachable."""
    reachable = {dst for src, dst, _ in graph.edges if src == "Internet"}
    # transitive: anything reachable FROM a reachable node is also reachable
    changed = True
    while changed:
        changed = False
        for src, dst, _ in graph.edges:
            if src in reachable and dst not in reachable:
                reachable.add(dst)
                changed = True

    principals = []
    for name, kind in graph.node_kinds.items():
        if kind == "role":
            arn = f"arn:aws:iam::{account_id}:role/{name}"
        elif kind == "user":
            arn = f"arn:aws:iam::{account_id}:user/{name}"
        else:
            continue
        principals.append((name, arn, name in reachable))
    return principals


def main():
    parser = argparse.ArgumentParser(description="Simulate real blast radius per IAM principal.")
    parser.add_argument("--region", default="ap-south-1")
    parser.add_argument("--profile")
    args = parser.parse_args()

    session = boto3.Session(profile_name=args.profile)
    account_id = session.client("sts").get_caller_identity()["Account"]
    iam = session.client("iam")

    graph = build(session, args.region)
    principals = principals_from_graph(graph, account_id)

    print(f"Blast-radius simulation for {len(principals)} IAM principal(s)\n")

    worst_non_admin = 0
    for name, arn, reachable in principals:
        radius = iam_simulator.simulate_blast_radius(iam, arn)
        reach_tag = "  ⚠️  Internet-reachable" if reachable else ""
        print(f"{name}{reach_tag}")

        if radius is None:
            print("    (simulator call failed — skipped)\n")
            continue

        is_admin, _ = iam_simulator.simulate_is_admin(iam, arn)
        if is_admin:
            print("    -> FULL BLAST RADIUS (admin: every category below is trivially true)\n")
            continue

        any_open = False
        for category, actions in radius.items():
            if actions:
                any_open = True
                icon = "🔴" if category in ("Persist", "Pivot", "Destroy") else "🟠"
                print(f"    {icon} {category}: {', '.join(actions)}")
        if not any_open:
            print("    ✅ none of the probed actions are allowed")
        else:
            severity = sum(len(a) for c, a in radius.items() if c in ("Persist", "Pivot", "Destroy"))
            worst_non_admin = max(worst_non_admin, severity)
        print()

    sys.exit(1 if worst_non_admin > 0 else 0)


if __name__ == "__main__":
    main()
