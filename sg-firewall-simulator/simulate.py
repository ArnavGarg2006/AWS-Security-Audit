#!/usr/bin/env python
"""
Security group firewall simulator.

Rather than a from-scratch packet filter with invented rules, this evaluates
simulated packets against your account's REAL security groups (fetched
read-only via boto3, same pattern as aws_security_audit) — answering "would
this specific packet actually get through?" and showing exactly which rule
decided that, in plain language.

Usage:
    python simulate.py --list [--region ap-south-1]
    python simulate.py --sg-id sg-xxxx --protocol tcp --port 22 --source 0.0.0.0/0
    python simulate.py --scan-all [--region ap-south-1]   # sensitive ports x every SG
"""
import argparse
import ipaddress
import sys

import boto3
from rich.console import Console
from rich.table import Table

# Same list aws_security_audit/checks/ec2.py uses — duplicated rather than
# cross-imported, since these are meant to be independently runnable tools.
SENSITIVE_PORTS = {
    22: "SSH", 3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL",
    1433: "MSSQL", 27017: "MongoDB", 6379: "Redis",
}


def fetch_security_groups(session, region):
    client = session.client("ec2", region_name=region)
    groups = []
    paginator = client.get_paginator("describe_security_groups")
    for page in paginator.paginate():
        groups.extend(page["SecurityGroups"])
    return groups


def protocol_matches(rule_protocol, test_protocol):
    return rule_protocol in ("-1", test_protocol)


def port_matches(rule, port):
    if rule.get("IpProtocol") == "-1":
        return True
    frm, to = rule.get("FromPort"), rule.get("ToPort")
    if frm is None or to is None:
        return True
    return frm <= port <= to


def source_matches(rule, test_network):
    """Does every address in test_network fall within one of this rule's CIDRs?
    A rule for 10.0.0.0/16 does NOT match a test source of 0.0.0.0/0 (the rule
    doesn't cover the whole internet) — but does match a test source of
    10.0.5.0/24 (fully contained)."""
    for entry in rule.get("IpRanges", []):
        cidr = entry.get("CidrIp")
        if cidr and _contains(cidr, test_network):
            return True, cidr
    for entry in rule.get("Ipv6Ranges", []):
        cidr = entry.get("CidrIpv6")
        if cidr and _contains(cidr, test_network):
            return True, cidr
    return False, None


def _contains(rule_cidr, test_network):
    try:
        rule_network = ipaddress.ip_network(rule_cidr, strict=False)
        return test_network.subnet_of(rule_network) or test_network == rule_network
    except (ValueError, TypeError):
        return False


def evaluate(sg, direction, protocol, port, source_cidr):
    """Returns (allowed: bool, matched_rule_cidr: str|None, all_checked: list)."""
    key = "IpPermissions" if direction == "ingress" else "IpPermissionsEgress"
    test_network = ipaddress.ip_network(source_cidr, strict=False)
    checked = []

    for rule in sg.get(key, []):
        proto_ok = protocol_matches(rule.get("IpProtocol", "-1"), protocol)
        port_ok = port_matches(rule, port) if proto_ok else False
        src_ok, matched_cidr = source_matches(rule, test_network) if port_ok else (False, None)
        checked.append({
            "protocol": rule.get("IpProtocol"),
            "port_range": f"{rule.get('FromPort', 'any')}-{rule.get('ToPort', 'any')}",
            "matched": proto_ok and port_ok and src_ok,
        })
        if proto_ok and port_ok and src_ok:
            return True, matched_cidr, checked

    return False, None, checked


def run_single_test(session, region, sg_id, direction, protocol, port, source):
    console = Console()
    groups = fetch_security_groups(session, region)
    sg = next((g for g in groups if g["GroupId"] == sg_id), None)
    if not sg:
        console.print(f"[red]Security group '{sg_id}' not found in {region}.[/red]")
        sys.exit(1)

    allowed, matched_cidr, checked = evaluate(sg, direction, protocol, port, source)
    verdict = "[bold green]ALLOW[/bold green]" if allowed else "[bold red]DENY[/bold red]"

    console.print(f"\n[bold]{sg['GroupName']}[/bold] ({sg_id})")
    console.print(f"  {direction} {protocol}/{port} from {source}  ->  {verdict}\n")

    if allowed:
        console.print(f"  Matched rule: allows {protocol} port {port} from {matched_cidr}")
        sensitive = SENSITIVE_PORTS.get(port)
        if sensitive and source == "0.0.0.0/0":
            console.print(f"  [bold red]This exposes {sensitive} to the entire internet.[/bold red]")
    else:
        console.print(f"  No rule in this security group permits this traffic ({len(checked)} rule(s) checked).")

    return allowed


def run_scan_all(session, region):
    console = Console()
    groups = fetch_security_groups(session, region)

    table = Table(title=f"Simulated internet-sourced traffic (0.0.0.0/0) — {region}")
    table.add_column("Security Group")
    table.add_column("Port / Service")
    table.add_column("Result")

    exposures = 0
    for sg in groups:
        for port, service in SENSITIVE_PORTS.items():
            allowed, _, _ = evaluate(sg, "ingress", "tcp", port, "0.0.0.0/0")
            if allowed:
                exposures += 1
                table.add_row(
                    f"{sg['GroupName']} ({sg['GroupId']})",
                    f"{port} ({service})",
                    "[bold red]ALLOWED from internet[/bold red]",
                )

    console.print(table if exposures else "[green]No security group allows a sensitive port from 0.0.0.0/0.[/green]")
    console.print(f"\n{len(groups)} security group(s) checked, {exposures} internet exposure(s) found.")
    return exposures


def main():
    parser = argparse.ArgumentParser(description="Simulate packets against real AWS security group rules.")
    parser.add_argument("--profile", help="AWS named profile")
    parser.add_argument("--region", default="ap-south-1")
    parser.add_argument("--list", action="store_true", help="List all security groups in the region")
    parser.add_argument("--scan-all", action="store_true", help="Test every SG against all sensitive ports from 0.0.0.0/0")
    parser.add_argument("--sg-id", help="Security group ID to test")
    parser.add_argument("--direction", choices=["ingress", "egress"], default="ingress")
    parser.add_argument("--protocol", default="tcp")
    parser.add_argument("--port", type=int)
    parser.add_argument("--source", default="0.0.0.0/0", help="Source CIDR to simulate traffic from")
    args = parser.parse_args()

    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    console = Console()

    if args.list:
        groups = fetch_security_groups(session, args.region)
        table = Table(title=f"Security groups in {args.region}")
        table.add_column("Group ID")
        table.add_column("Name")
        table.add_column("VPC")
        for sg in groups:
            table.add_row(sg["GroupId"], sg["GroupName"], sg.get("VpcId", "-"))
        console.print(table)
        return

    if args.scan_all:
        exposures = run_scan_all(session, args.region)
        sys.exit(1 if exposures else 0)

    if not args.sg_id or args.port is None:
        parser.error("--sg-id and --port are required unless using --list or --scan-all")

    allowed = run_single_test(session, args.region, args.sg_id, args.direction, args.protocol, args.port, args.source)
    sys.exit(0 if not allowed else 1)


if __name__ == "__main__":
    main()
