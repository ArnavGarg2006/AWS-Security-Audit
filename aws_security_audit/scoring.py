"""
Security score / letter grade — collapses a full findings list into a single
0-100 score and letter grade (Mozilla Observatory / SSL Labs style).

This is deliberately NOT a replacement for the findings list — it's a
different audience's entry point. A CISO or a non-technical stakeholder
reacts to "your account is a B+, here's the two things costing you the
most points" in ten seconds; the same person will not read a 20-row table.

Scoring model: start at 100, deduct per finding by severity, floor at 0.
Deductions are points, not percentages, so a handful of CRITICAL findings
can drive the score to F even if hundreds of LOW findings wouldn't.
"""
from dataclasses import dataclass, field

from .models import Severity

DEDUCTIONS = {
    Severity.CRITICAL: 20,
    Severity.HIGH: 10,
    Severity.MEDIUM: 5,
    Severity.LOW: 2,
    Severity.INFO: 0,
}

GRADE_THRESHOLDS = [
    (97, "A+"), (93, "A"), (90, "A-"),
    (87, "B+"), (83, "B"), (80, "B-"),
    (77, "C+"), (73, "C"), (70, "C-"),
    (60, "D"), (0, "F"),
]

GRADE_COLOR = {
    "A+": "#2cb67d", "A": "#2cb67d", "A-": "#2cb67d",
    "B+": "#69c0ff", "B": "#69c0ff", "B-": "#69c0ff",
    "C+": "#ffd666", "C": "#ffd666", "C-": "#ffd666",
    "D": "#ff7a45", "F": "#ff4d4f",
}


@dataclass
class Score:
    value: int
    grade: str
    deductions_by_severity: dict = field(default_factory=dict)
    top_costly_findings: list = field(default_factory=list)
    accepted_findings: list = field(default_factory=list)

    @property
    def color(self):
        return GRADE_COLOR.get(self.grade, "#a7a9be")


def grade_for(value: int) -> str:
    for threshold, grade in GRADE_THRESHOLDS:
        if value >= threshold:
            return grade
    return "F"


def compute_score(result, top_n: int = 3, accepted_risks=None) -> Score:
    """result: an AuditResult (or anything with a .findings list of Finding).

    accepted_risks: an iterable of (check_id, resource) pairs to exclude from
    the score. These findings still show up in the full report (nothing is
    hidden) — they just don't count against the grade. This exists because a
    generic check can't know a public S3 bucket is a deliberately public
    static website vs. a real misconfiguration; the operator has to say so.
    """
    accepted_set = set(accepted_risks or [])
    deductions_by_severity = {s: 0 for s in Severity}
    total_deduction = 0

    scored_findings = []
    accepted_findings = []
    for f in result.findings:
        points = DEDUCTIONS.get(f.severity, 0)
        if (f.check_id, f.resource) in accepted_set:
            accepted_findings.append(f)
            continue
        deductions_by_severity[f.severity] += points
        total_deduction += points
        if points > 0:
            scored_findings.append((f, points))

    value = max(0, 100 - total_deduction)
    scored_findings.sort(key=lambda pair: (-pair[1], pair[0].sort_key()))

    return Score(
        value=value,
        grade=grade_for(value),
        deductions_by_severity=deductions_by_severity,
        top_costly_findings=scored_findings[:top_n],
        accepted_findings=accepted_findings,
    )
