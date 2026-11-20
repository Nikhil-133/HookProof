from __future__ import annotations

import json

from typer.testing import CliRunner

from hookproof.cli import app

from .conftest import TEST_SECRET, TEST_TOKEN

runner = CliRunner()


def test_version_command():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "HookProof" in result.stdout


def test_serve_rejects_invalid_mode():
    result = runner.invoke(app, ["lab", "serve", "--mode", "bogus", "--port", "0"])
    assert result.exit_code == 2


def test_serve_rejects_non_loopback_host():
    result = runner.invoke(app, ["lab", "serve", "--mode", "secure", "--host", "0.0.0.0"])
    assert result.exit_code == 2


def test_scan_rejects_public_target():
    result = runner.invoke(app, ["scan", "--target", "http://example.com/webhooks/payment"])
    assert result.exit_code == 2


def test_cli_scan_secure_writes_report(secure_lab, tmp_path, monkeypatch):
    monkeypatch.setenv("HOOKPROOF_WEBHOOK_SECRET", TEST_SECRET)
    monkeypatch.setenv("HOOKPROOF_TEST_TOKEN", TEST_TOKEN)
    report_path = tmp_path / "report.json"
    result = runner.invoke(
        app,
        ["scan", "--target", secure_lab["webhook_url"], "--report", str(report_path)],
    )
    assert result.exit_code == 0, result.output
    assert report_path.is_file()
    data = json.loads(report_path.read_text(encoding="utf-8"))
    assert data["summary"]["outcome"] == "PASS"
    assert data["detected_mode"] == "secure"


def test_cli_scan_writes_html_report(secure_lab, tmp_path, monkeypatch):
    monkeypatch.setenv("HOOKPROOF_WEBHOOK_SECRET", TEST_SECRET)
    monkeypatch.setenv("HOOKPROOF_TEST_TOKEN", TEST_TOKEN)
    html_path = tmp_path / "report.html"
    result = runner.invoke(
        app,
        ["scan", "--target", secure_lab["webhook_url"], "--html", str(html_path)],
    )
    assert result.exit_code == 0, result.output
    assert html_path.is_file()
    text = html_path.read_text(encoding="utf-8")
    assert "<!doctype html>" in text
    assert "HookProof" in text
    assert "Outcome: PASS" in text


def test_cli_scan_vulnerable_exits_nonzero(vulnerable_lab, monkeypatch):
    monkeypatch.setenv("HOOKPROOF_WEBHOOK_SECRET", TEST_SECRET)
    monkeypatch.setenv("HOOKPROOF_TEST_TOKEN", TEST_TOKEN)
    result = runner.invoke(app, ["scan", "--target", vulnerable_lab["webhook_url"]])
    assert result.exit_code == 1
    assert "FAIL" in result.output
