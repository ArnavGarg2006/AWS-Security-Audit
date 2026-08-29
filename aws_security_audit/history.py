"""
Score history — every check in this repo answers "what's true right now."
None of them answer "is this getting better or worse." This appends each
run's score/grade/severity breakdown to a small local JSON file and prints
the delta against the previous run, so a regression ("this was a 94 last
week, it's a 74 now") is visible in the console output itself instead of
requiring someone to diff two report.json files by hand.

Opt-in via --history-file — this writes a local file as a side effect, so
it shouldn't happen silently on every run (e.g. in CI, where a persisted
history file usually isn't wanted or would need to live somewhere durable).
"""
import json
import os
from datetime import datetime, timezone


def load_history(path):
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def append_history(score, result, path):
    """Appends this run to the history file at `path` and returns
    (this_entry, full_history_including_this_entry)."""
    history = load_history(path)

    severity_counts = {}
    for f in result.findings:
        severity_counts[f.severity.value] = severity_counts.get(f.severity.value, 0) + 1

    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "score": score.value,
        "grade": score.grade,
        "finding_count": len(result.findings),
        "severity_counts": severity_counts,
        "accepted_count": len(score.accepted_findings),
    }
    history.append(entry)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(history, f, indent=2)
    return entry, history


def trend_line(entry, history):
    """One-line human summary comparing this run to the immediately
    preceding one, or None if there's no prior run yet."""
    if len(history) < 2:
        return None
    prev = history[-2]
    delta = entry["score"] - prev["score"]

    if delta == 0 and entry["grade"] == prev["grade"]:
        return f"No change since {prev['timestamp'][:10]} (still {prev['score']}/{prev['grade']})"

    arrow = "↑" if delta > 0 else "↓"
    sign = f"+{delta}" if delta > 0 else str(delta)
    verdict = "improved" if delta > 0 else "regressed"
    return (f"{arrow} Score {verdict} {sign} points since {prev['timestamp'][:10]}: "
            f"{prev['score']}/{prev['grade']} -> {entry['score']}/{entry['grade']}")
