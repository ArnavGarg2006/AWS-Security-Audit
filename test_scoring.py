from aws_security_audit.models import AuditResult, Finding, Severity
from aws_security_audit.scoring import compute_score, grade_for


def make_finding(severity, check_id="X.1"):
    return Finding(check_id=check_id, service="TEST", severity=severity, resource="r",
                    region="us-east-1", title=f"{severity.value} finding", description="",
                    remediation="")


def test_no_findings_is_perfect_score():
    result = AuditResult(account_id="123")
    score = compute_score(result)
    assert score.value == 100
    assert score.grade == "A+"


def test_critical_finding_deducts_20():
    result = AuditResult(account_id="123", findings=[make_finding(Severity.CRITICAL)])
    score = compute_score(result)
    assert score.value == 80
    assert score.grade == "B-"


def test_score_floors_at_zero():
    result = AuditResult(account_id="123", findings=[make_finding(Severity.CRITICAL) for _ in range(10)])
    score = compute_score(result)
    assert score.value == 0
    assert score.grade == "F"


def test_info_findings_do_not_affect_score():
    result = AuditResult(account_id="123", findings=[make_finding(Severity.INFO)])
    score = compute_score(result)
    assert score.value == 100


def test_top_costly_findings_sorted_by_points_descending():
    result = AuditResult(account_id="123", findings=[
        make_finding(Severity.LOW, "L.1"),
        make_finding(Severity.CRITICAL, "C.1"),
        make_finding(Severity.MEDIUM, "M.1"),
    ])
    score = compute_score(result, top_n=2)
    assert len(score.top_costly_findings) == 2
    assert score.top_costly_findings[0][0].check_id == "C.1"
    assert score.top_costly_findings[0][1] == 20
    assert score.top_costly_findings[1][0].check_id == "M.1"


def test_grade_thresholds():
    assert grade_for(100) == "A+"
    assert grade_for(97) == "A+"
    assert grade_for(96) == "A"
    assert grade_for(90) == "A-"
    assert grade_for(89) == "B+"
    assert grade_for(60) == "D"
    assert grade_for(59) == "F"
    assert grade_for(0) == "F"


def test_mixed_severities_combine_correctly():
    result = AuditResult(account_id="123", findings=[
        make_finding(Severity.HIGH), make_finding(Severity.HIGH),
        make_finding(Severity.MEDIUM), make_finding(Severity.LOW),
    ])
    score = compute_score(result)
    # 100 - (10*2) - 5 - 2 = 73
    assert score.value == 73
    assert score.grade == "C"
