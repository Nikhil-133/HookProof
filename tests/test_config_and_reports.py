from __future__ import annotations

import json

from hookproof.config import load_dotenv, load_settings, redact
from hookproof.reports import build_report, render_terminal, write_json
from hookproof.scenarios.base import (
    SEVERITY_HIGH,
    STATUS_ERROR,
    STATUS_FAIL,
    STATUS_PASS,
    ScenarioResult,
)


def _result(sid, status, severity=SEVERITY_HIGH):
    return ScenarioResult(
        id=sid,
        title=sid.title(),
        status=status,
        severity=severity,
        description="desc",
        expected="expected",
        observed="observed",
    )


def test_redact_hides_most_of_secret():
    assert redact("supersecretvalue") == "su***e"
    assert redact("") == "<unset>"
    assert redact(None) == "<unset>"
    assert redact("abc") == "***"


def test_load_dotenv_does_not_override(monkeypatch, tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text(
        "# comment\nHOOKPROOF_WEBHOOK_SECRET=from-file\nOTHER_KEY='quoted value'\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("HOOKPROOF_WEBHOOK_SECRET", "from-env")
    monkeypatch.delenv("OTHER_KEY", raising=False)
    load_dotenv(env_file)
    import os

    assert os.environ["HOOKPROOF_WEBHOOK_SECRET"] == "from-env"
    assert os.environ["OTHER_KEY"] == "quoted value"


def test_load_settings_defaults(monkeypatch):
    for key in (
        "HOOKPROOF_WEBHOOK_SECRET",
        "HOOKPROOF_TEST_TOKEN",
        "HOOKPROOF_FRESHNESS_WINDOW",
        "HOOKPROOF_LAB_HOST",
        "HOOKPROOF_LAB_PORT",
        "HOOKPROOF_ENV_FILE",
    ):
        monkeypatch.delenv(key, raising=False)
    settings = load_settings()
    assert settings.uses_dev_webhook_secret is True
    assert settings.uses_dev_test_token is True
    assert settings.freshness_window_seconds == 300


def test_report_summary_and_rendering():
    results = [
        _result("a", STATUS_PASS, SEVERITY_HIGH),
        _result("b", STATUS_FAIL, SEVERITY_HIGH),
        _result("c", STATUS_ERROR, SEVERITY_HIGH),
    ]
    report = build_report(
        target={"url": "http://127.0.0.1:8000/webhooks/payment"},
        suite="core",
        results=results,
        detected_mode="secure",
        request_count=12,
        started_at=100.0,
        finished_at=101.5,
        run_id="abc",
    )
    summary = report["summary"]
    assert summary["total"] == 3
    assert summary["passed"] == 1
    assert summary["failed"] == 1
    assert summary["errors"] == 1
    assert summary["outcome"] == "FAIL"
    assert summary["highest_severity"] == SEVERITY_HIGH
    assert report["html_ready"]["sections"]

    text = render_terminal(report)
    assert "HookProof scan report" in text
    assert "FAIL" in text


def test_write_json_and_no_secret_leak(tmp_path):
    report = build_report(
        target={"url": "http://127.0.0.1:8000/webhooks/payment"},
        suite="core",
        results=[_result("a", STATUS_PASS)],
        detected_mode="secure",
        request_count=1,
        started_at=0.0,
        finished_at=0.1,
        run_id="xyz",
    )
    out = write_json(report, tmp_path / "nested" / "report.json")
    assert out.is_file()
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["schema_version"] == 1
    text = out.read_text(encoding="utf-8")
    assert "webhook-secret" not in text.lower()
