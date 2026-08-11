import json
from datetime import datetime, timezone
from html import escape

from rich.console import Console
from rich.table import Table

from .models import Severity, AuditResult

_SEVERITY_COLOR = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "bold yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}


def print_console_report(result: AuditResult):
    console = Console()
    console.print(f"\n[bold]AWS Security Audit[/bold]  account=[cyan]{result.account_id}[/cyan]  "
                  f"checks_run={result.checks_run}  findings={len(result.findings)}\n")

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


def to_dict(result: AuditResult) -> dict:
    return {
        "account_id": result.account_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "checks_run": result.checks_run,
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


def write_json_report(result: AuditResult, path: str):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(to_dict(result), f, indent=2)


def write_html_report(result: AuditResult, path: str):
    data = to_dict(result)
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
    html = f"""<!doctype html>
<html><head><meta charset="utf-8"><title>AWS Security Audit — {escape(data['account_id'])}</title>
<style>
body {{ font-family: -apple-system, Segoe UI, Arial, sans-serif; margin: 2rem; background:#0b0d12; color:#e6e6e6; }}
h1 {{ font-size: 1.4rem; }}
.meta {{ color:#9aa0a6; margin-bottom: 1.5rem; }}
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
<div class="stats">{summary_cells}</div>
<table>
<tr><th>Severity</th><th>Service</th><th>Check</th><th>Resource</th><th>Region</th><th>Title</th><th>Remediation</th></tr>
{rows}
</table>
</body></html>"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
