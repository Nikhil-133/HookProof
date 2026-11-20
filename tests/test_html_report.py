from __future__ import annotations

import json

from hookproof.html_report import render_html, write_html
from hookproof.reports import build_report
from hookproof.scenarios.base import (
    SEVERITY_HIGH,
    STATUS_FAIL,
    STATUS_PASS,
    ScenarioResult,
)


def _report() -> dict:
    pass_result = ScenarioResult(
        id="valid_signature",
        title="Valid signed event is processed",
        status=STATUS_PASS,
        severity=SEVERITY_HIGH,
        description="control",
        expected="one payment",
        observed="payment_count=1",
    )
    fail_result = ScenarioResult(
        id="missing_signature",
        title="Unsigned event does not change protected state",
        status=STATUS_FAIL,
        severity=SEVERITY_HIGH,
        description="auth bypass",
        expected="no payment",
        observed="payment_count=1 <script>alert('x')</script>",
        remediation="Verify signatures before processing.",
        notes=["dangerous <b>markup</b>"],
    )
    fail_result.exchanges = [
        {
            "label": "missing-signature",
            "status_code": 200,
            "response_body": {"detail": "<img src=x onerror=alert(1)>"},
        }
    ]
    return build_report(
        target={"url": "http://127.0.0.1:8000/webhooks/payment?x=<bad>"},
        suite="core",
        results=[pass_result, fail_result],
        detected_mode="vulnerable",
        request_count=3,
        started_at=0.0,
        finished_at=0.2,
        run_id="htmltest",
    )


def test_render_html_contains_summary_and_findings():
    html = render_html(_report())
    assert "<!doctype html>" in html
    assert "HookProof" in html
    assert "valid_signature" in html
    assert "missing_signature" in html
    assert "Verify signatures before processing." in html
    assert "Outcome: FAIL" in html
    assert "<details>" in html


def test_render_html_escapes_untrusted_values():
    html = render_html(_report())
    assert "<script>alert" not in html
    assert "&lt;script&gt;" in html
    assert "<img src=x" not in html
    assert "&lt;img src=x" in html
    assert "<b>markup</b>" not in html
    assert "&lt;b&gt;markup&lt;/b&gt;" in html


def test_write_html(tmp_path):
    path = write_html(_report(), tmp_path / "nested" / "report.html")
    assert path.is_file()
    text = path.read_text(encoding="utf-8")
    assert "HookProof" in text
    assert json.dumps("htmltest").strip('"') in text
