"""Report generation: terminal summary, JSON document and HTML-ready model.

Reports contain only synthetic lab data and never include signing secrets or
test tokens. Severity reflects the demonstrated business impact of a failure,
not merely a non-2xx HTTP status.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import __version__
from .scenarios.base import (
    SEVERITY_ORDER,
    STATUS_ERROR,
    STATUS_FAIL,
    STATUS_PASS,
    ScenarioResult,
)

SCHEMA_VERSION = 1

LIMITATIONS = [
    "EffectProof requires the target to expose a restricted test-state interface "
    "(the HookProof lab provides one). Internal effects of an arbitrary API cannot "
    "be observed without suitable instrumentation.",
    "HookProof only scans explicitly allowed hosts; the default allow-list is loopback.",
    "The MVP includes a single event type (payment.succeeded) and a single 'core' suite.",
    "Timing/race findings are probabilistic: a clean concurrent test does not prove the "
    "absence of a race under all conditions.",
]


def _now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _summarise(results: Iterable[ScenarioResult]) -> dict[str, Any]:
    results = list(results)
    passed = [r for r in results if r.status == STATUS_PASS]
    failed = [r for r in results if r.status == STATUS_FAIL]
    errors = [r for r in results if r.status == STATUS_ERROR]

    by_severity: dict[str, int] = {}
    for r in failed:
        by_severity[r.severity] = by_severity.get(r.severity, 0) + 1

    highest = None
    for r in failed:
        if highest is None or SEVERITY_ORDER.get(r.severity, 0) > SEVERITY_ORDER.get(highest, 0):
            highest = r.severity

    if failed:
        outcome = "FAIL"
    elif errors:
        outcome = "INCONCLUSIVE"
    else:
        outcome = "PASS"

    return {
        "total": len(results),
        "passed": len(passed),
        "failed": len(failed),
        "errors": len(errors),
        "confirmed_lab_failures": len(failed),
        "inconclusive_or_errors": len(errors),
        "highest_severity": highest,
        "failed_by_severity": by_severity,
        "outcome": outcome,
    }


def build_report(
    *,
    target: dict[str, Any],
    suite: str,
    results: list[ScenarioResult],
    detected_mode: str,
    request_count: int,
    started_at: float,
    finished_at: float,
    run_id: str,
    interface_error: str | None = None,
    extra_notes: list[str] | None = None,
) -> dict[str, Any]:
    """Build the JSON-serialisable report document."""
    summary = _summarise(results)
    summary["request_count"] = request_count
    summary["duration_seconds"] = round(finished_at - started_at, 3)

    notes = list(extra_notes or [])
    if detected_mode == "vulnerable":
        notes.append(
            "Target reports itself as the deliberately vulnerable lab mode. "
            "Failures are expected and demonstrate detectable weaknesses."
        )
    elif detected_mode == "secure":
        notes.append("Target reports itself as secure lab mode; all core tests are expected to pass.")
    else:
        notes.append("Target mode could not be determined from /health.")

    report = {
        "schema_version": SCHEMA_VERSION,
        "tool": "HookProof",
        "tool_version": __version__,
        "generated_at": _now_iso(),
        "run_id": run_id,
        "target": target,
        "suite": suite,
        "detected_mode": detected_mode,
        "summary": summary,
        "notes": notes,
        "limitations": LIMITATIONS,
        "results": [r.to_dict() for r in results],
    }
    if interface_error:
        report["interface_error"] = interface_error
    report["html_ready"] = _build_html_model(report)
    return report


def _build_html_model(report: dict[str, Any]) -> dict[str, Any]:
    """A neutral, structured view that a future HTML renderer can consume."""
    summary = report["summary"]
    return {
        "title": f"HookProof report - {report['suite']} suite",
        "subtitle": (f"Target {report['target'].get('url')} (detected mode: {report['detected_mode']})"),
        "summary_cards": [
            {"label": "Outcome", "value": summary["outcome"]},
            {"label": "Total", "value": summary["total"]},
            {"label": "Passed", "value": summary["passed"]},
            {"label": "Failed", "value": summary["failed"]},
            {"label": "Errors", "value": summary["errors"]},
        ],
        "sections": [
            {
                "heading": "Findings",
                "rows": [
                    {
                        "id": r["id"],
                        "title": r["title"],
                        "status": r["status"],
                        "severity": r["severity"],
                        "expected": r["expected"],
                        "observed": r["observed"],
                        "remediation": r["remediation"],
                    }
                    for r in report["results"]
                ],
            }
        ],
    }


def render_terminal(report: dict[str, Any]) -> str:
    """Render a readable terminal summary."""
    summary = report["summary"]
    lines: list[str] = []
    target = report["target"]
    lines.append("=" * 68)
    lines.append("HookProof scan report")
    lines.append("=" * 68)
    lines.append(f"Target     : {target.get('url')}")
    lines.append(f"Detected   : {report['detected_mode']} mode")
    lines.append(f"Suite      : {report['suite']}")
    lines.append(f"Run id     : {report['run_id']}")
    lines.append(f"Requests   : {summary['request_count']} ({summary['duration_seconds']}s)")
    lines.append(
        f"Outcome    : {summary['outcome']}  "
        f"(passed={summary['passed']} failed={summary['failed']} errors={summary['errors']})"
    )
    if summary.get("highest_severity"):
        lines.append(f"Highest sev: {summary['highest_severity']}")
    lines.append("-" * 68)

    for result in report["results"]:
        marker = {
            STATUS_PASS: "PASS",
            STATUS_FAIL: "FAIL",
            STATUS_ERROR: "ERR ",
        }.get(result["status"], result["status"])
        sev = f"[{result['severity']}]" if result["status"] == STATUS_FAIL else ""
        lines.append(f"{marker} {result['id']:<22} {result['title']} {sev}")
        lines.append(f"      expected: {result['expected']}")
        lines.append(f"      observed: {result['observed']}")
        if result["status"] == STATUS_FAIL and result.get("remediation"):
            lines.append(f"      remediate: {result['remediation']}")
        for note in result.get("notes", []):
            lines.append(f"      note     : {note}")
        if result.get("error"):
            lines.append(f"      error    : {result['error']}")

    lines.append("-" * 68)
    if summary["outcome"] == "PASS":
        lines.append("Result: all core security tests passed.")
    elif summary["outcome"] == "FAIL":
        lines.append(
            f"Result: {summary['confirmed_lab_failures']} confirmed failure(s) detected. "
            "See remediation for each finding."
        )
    else:
        lines.append(
            f"Result: inconclusive - {summary['inconclusive_or_errors']} test(s) could not "
            "be evaluated (operational error)."
        )
    lines.append("=" * 68)
    return "\n".join(lines)


def write_json(report: dict[str, Any], path: str | Path) -> Path:
    """Write the report as pretty-printed JSON and return the resolved path."""
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(report, indent=2, sort_keys=False), encoding="utf-8")
    return destination


__all__ = ["build_report", "render_terminal", "write_json", "SCHEMA_VERSION", "LIMITATIONS"]
