import pytest

from simulate import evaluate, port_matches, protocol_matches, source_matches


def test_protocol_matches_exact():
    assert protocol_matches("tcp", "tcp")
    assert not protocol_matches("tcp", "udp")


def test_protocol_matches_all():
    assert protocol_matches("-1", "tcp")
    assert protocol_matches("-1", "udp")


def test_port_matches_within_range():
    rule = {"IpProtocol": "tcp", "FromPort": 20, "ToPort": 25}
    assert port_matches(rule, 22)
    assert not port_matches(rule, 80)


def test_port_matches_all_protocol():
    rule = {"IpProtocol": "-1"}
    assert port_matches(rule, 22)
    assert port_matches(rule, 99999)


def test_source_matches_exact_cidr():
    rule = {"IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
    matched, cidr = source_matches(rule, __import__("ipaddress").ip_network("0.0.0.0/0"))
    assert matched
    assert cidr == "0.0.0.0/0"


def test_source_matches_subnet_contained_in_rule():
    import ipaddress
    rule = {"IpRanges": [{"CidrIp": "10.0.0.0/16"}]}
    matched, cidr = source_matches(rule, ipaddress.ip_network("10.0.5.0/24"))
    assert matched
    assert cidr == "10.0.0.0/16"


def test_source_does_not_match_when_rule_is_narrower():
    """A rule scoped to 10.0.0.0/16 must NOT match a test source of the whole internet —
    the rule doesn't grant access to everything just because it grants access to a subset."""
    import ipaddress
    rule = {"IpRanges": [{"CidrIp": "10.0.0.0/16"}]}
    matched, _ = source_matches(rule, ipaddress.ip_network("0.0.0.0/0"))
    assert not matched


def make_sg(ip_permissions):
    return {"GroupId": "sg-test", "GroupName": "test-sg", "IpPermissions": ip_permissions, "IpPermissionsEgress": []}


def test_evaluate_allows_open_ssh():
    sg = make_sg([{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
    allowed, cidr, _ = evaluate(sg, "ingress", "tcp", 22, "0.0.0.0/0")
    assert allowed
    assert cidr == "0.0.0.0/0"


def test_evaluate_denies_when_port_not_covered():
    sg = make_sg([{"IpProtocol": "tcp", "FromPort": 80, "ToPort": 80, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
    allowed, _, _ = evaluate(sg, "ingress", "tcp", 22, "0.0.0.0/0")
    assert not allowed


def test_evaluate_denies_when_no_rules():
    sg = make_sg([])
    allowed, _, checked = evaluate(sg, "ingress", "tcp", 22, "0.0.0.0/0")
    assert not allowed
    assert checked == []


def test_evaluate_allows_via_all_traffic_rule():
    sg = make_sg([{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
    allowed, _, _ = evaluate(sg, "ingress", "tcp", 9999, "0.0.0.0/0")
    assert allowed


def test_evaluate_restricted_source_blocks_internet_test():
    sg = make_sg([{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "203.0.113.5/32"}]}])
    allowed, _, _ = evaluate(sg, "ingress", "tcp", 22, "0.0.0.0/0")
    assert not allowed
    allowed, _, _ = evaluate(sg, "ingress", "tcp", 22, "203.0.113.5/32")
    assert allowed
