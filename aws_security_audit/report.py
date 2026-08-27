import json
from datetime import datetime, timezone
from html import escape

from rich.console import Console
from rich.table import Table

from .models import Severity, AuditResult
from .scoring import compute_score, GRADE_COLOR

_SEVERITY_COLOR = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "bold yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}


def print_console_report(result: AuditResult, accepted_risks=None):
    console = Console()
    console.print(f"\n[bold]AWS Security Audit[/bold]  account=[cyan]{result.account_id}[/cyan]  "
                  f"checks_run={result.checks_run}  findings={len(result.findings)}\n")

    score = compute_score(result, accepted_risks=accepted_risks)
    console.print(f"[bold {score.color}]Security score: {score.value}/100 ({score.grade})[/bold {score.color}]")
    if score.top_costly_findings:
        console.print("[dim]Costing you the most:[/dim]")
        for finding, points in score.top_costly_findings:
            console.print(f"  [dim]-{points} pts[/dim]  {finding.check_id}: {finding.title}")
    if score.accepted_findings:
        console.print(f"[dim]{len(score.accepted_findings)} finding(s) excluded from score "
                       f"(--accept-risk-file): {', '.join(f.check_id for f in score.accepted_findings)}[/dim]")
    console.print()

    counts = result.counts_by_severity()
    summary = "  ".join(
        f"[{_SEVERITY_COLOR[s]}]{s.value}: {counts[s]}[/{_SEVERITY_COLOR[s]}]"
        for s in Severity if counts[s]
    )
    if summary:
        console.print(summary + "\n")

    if result.findings:
        table = Table(show_lines=False)
        table.add_column("Severity")
        table.add_column("Service")
        table.add_column("Check")
        table.add_column("Resource", overflow="fold")
        table.add_column("Region")
        table.add_column("Title", overflow="fold")

        for f in result.sorted_findings():
            table.add_row(
                f"[{_SEVERITY_COLOR[f.severity]}]{f.severity.value}[/{_SEVERITY_COLOR[f.severity]}]",
                f.service,
                f.check_id,
                f.resource,
                f.region,
                f.title,
            )
        console.print(table)
    else:
        console.print("[green]No findings.[/green]")

    if result.errors:
        console.print(f"\n[yellow]{len(result.errors)} check(s) could not complete "
                       f"(likely missing permissions):[/yellow]")
        for e in result.errors:
            console.print(f"  [dim]{e.check_id} ({e.service}, {e.region}): {e.message}[/dim]")


def to_dict(result: AuditResult, accepted_risks=None) -> dict:
    score = compute_score(result, accepted_risks=accepted_risks)
    return {
        "account_id": result.account_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "checks_run": result.checks_run,
        "score": {
            "value": score.value,
            "grade": score.grade,
            "top_costly_findings": [
                {"check_id": f.check_id, "title": f.title, "points": points}
                for f, points in score.top_costly_findings
            ],
            "accepted_findings": [f.check_id for f in score.accepted_findings],
        },
        "summary": {s.value: c for s, c in result.counts_by_severity().items()},
        "findings": [
            {
                "check_id": f.check_id,
                "service": f.service,
                "severity": f.severity.value,
                "resource": f.resource,
                "region": f.region,
                "title": f.title,
                "description": f.description,
                "remediation": f.remediation,
            }
            for f in result.sorted_findings()
        ],
        "errors": [
            {"check_id": e.check_id, "service": e.service, "region": e.region, "message": e.message}
            for e in result.errors
        ],
    }


def write_json_report(result: AuditResult, path: str, accepted_risks=None):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(to_dict(result, accepted_risks=accepted_risks), f, indent=2)


def write_html_report(result: AuditResult, path: str, accepted_risks=None):
    data = to_dict(result, accepted_risks=accepted_risks)
    rows = "\n".join(
        f"<tr class='sev-{f['severity'].lower()}'>"
        f"<td>{escape(f['severity'])}</td><td>{escape(f['service'])}</td>"
        f"<td>{escape(f['check_id'])}</td><td>{escape(f['resource'])}</td>"
        f"<td>{escape(f['region'])}</td><td>{escape(f['title'])}</td>"
        f"<td>{escape(f['remediation'])}</td></tr>"
        for f in data["findings"]
    )
    summary_cells = "".join(
        f"<div class='stat stat-{k.lower()}'><div class='n'>{v}</div><div class='l'>{k}</div></div>"
        for k, v in data["summary"].items() if v
    )
    score = data["score"]
    costly_items = "".join(
        f"<li><b>-{f['points']} pts</b> &middot; {escape(f['check_id'])}: {escape(f['title'])}</li>"
        for f in score["top_costly_findings"]
    )
    html = f"""<!doctype html>
<html><head><meta charset="utf-8"><title>AWS Security Audit — {escape(data['account_id'])}</title>
<style>
body {{ font-family: -apple-system, Segoe UI, Arial, sans-serif; margin: 2rem; background:#0b0d12; color:#e6e6e6; }}
h1 {{ font-size: 1.4rem; }}
.meta {{ color:#9aa0a6; margin-bottom: 1.5rem; }}
.score-banner {{ display:flex; align-items:center; gap:1.5rem; background:#161a22; border-radius:14px;
  padding:1.25rem 1.75rem; margin-bottom:1.5rem; border:1px solid #2a2f3a; }}
.score-grade {{ font-size:3rem; font-weight:800; line-height:1; }}
.score-value {{ color:#9aa0a6; font-size:0.9rem; }}
.score-costly {{ margin:0; padding-left:1.1rem; font-size:0.85rem; color:#c9cbdb; }}
.score-costly li {{ margin-bottom:0.2rem; }}
.stats {{ display:flex; gap:1rem; margin-bottom:1.5rem; }}
.stat {{ padding:0.75rem 1.25rem; border-radius:8px; background:#161a22; min-width:80px; text-align:center; }}
.stat .n {{ font-size:1.5rem; font-weight:bold; }}
.stat .l {{ font-size:0.75rem; color:#9aa0a6; }}
.stat-critical .n {{ color:#ff4d4f; }}
.stat-high .n {{ color:#ff7a45; }}
.stat-medium .n {{ color:#ffd666; }}
.stat-low .n {{ color:#69c0ff; }}
table {{ border-collapse: collapse; width: 100%; font-size: 0.85rem; }}
th, td {{ border: 1px solid #2a2f3a; padding: 6px 10px; text-align: left; vertical-align: top; }}
th {{ background: #161a22; }}
tr.sev-critical td:first-child {{ color:#ff4d4f; font-weight:bold; }}
tr.sev-high td:first-child {{ color:#ff7a45; font-weight:bold; }}
tr.sev-medium td:first-child {{ color:#ffd666; font-weight:bold; }}
tr.sev-low td:first-child {{ color:#69c0ff; }}
</style></head>
<body>
<h1>AWS Security Audit Report</h1>
<div class="meta">Account: {escape(data['account_id'])} &middot; Generated: {escape(data['generated_at'])} &middot; Checks run: {data['checks_run']}</div>
<div class="score-banner">
  <div class="score-grade" style="color:{GRADE_COLOR.get(score['grade'], '#a7a9be')}">{escape(score['grade'])}</div>
  <div>
    <div class="score-value">Security score: {score['value']}/100</div>
    {"<div style='font-size:0.8rem;color:#9aa0a6;margin-top:0.4rem;'>Costing you the most:</div><ul class='score-costly'>" + costly_items + "</ul>" if costly_items else ""}
  </div>
</div>
<div class="stats">{summary_cells}</div>
<table>
<tr><th>Severity</th><th>Service</th><th>Check</th><th>Resource</th><th>Region</th><th>Title</th><th>Remediation</th></tr>
{rows}
</table>
</body></html>"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
