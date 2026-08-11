from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


_SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


@dataclass
class Finding:
    check_id: str
    service: str
    severity: Severity
    resource: str
    region: str
    title: str
    description: str
    remediation: str

    def sort_key(self):
        return (_SEVERITY_ORDER.get(self.severity, 99), self.service, self.resource)


@dataclass
class CheckError:
    check_id: str
    service: str
    region: str
    message: str


@dataclass
class AuditResult:
    account_id: str
    findings: list = field(default_factory=list)
    errors: list = field(default_factory=list)
    checks_run: int = 0

    def add_finding(self, finding: Finding):
        self.findings.append(finding)

    def add_error(self, error: CheckError):
        self.errors.append(error)

    def sorted_findings(self):
        return sorted(self.findings, key=lambda f: f.sort_key())

    def counts_by_severity(self):
        counts = {s: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts
