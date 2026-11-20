"""End-to-end scanner tests against real loopback lab servers."""

from __future__ import annotations

import pytest

from hookproof.scanner import Scanner, TargetValidationError, validate_target

from .conftest import TEST_SETTINGS

CORE_IDS = {
    "valid_signature",
    "missing_signature",
    "invalid_signature",
    "payload_tampering",
    "unsupported_event_type",
    "invalid_amount",
    "duplicate_event",
    "concurrent_duplicate",
    "event_id_reuse",
    "stale_timestamp",
    "malformed_payload",
}

VULNERABLE_EXPECTED_FAILURES = {
    "missing_signature",
    "invalid_signature",
    "payload_tampering",
    "unsupported_event_type",
    "invalid_amount",
    "duplicate_event",
    "concurrent_duplicate",
    "event_id_reuse",
    "stale_timestamp",
}


def _run(lab, suite="core"):
    scanner = Scanner(
        target=lab["webhook_url"],
        settings=TEST_SETTINGS,
        suite=suite,
        timeout=10.0,
        run_id="itest",
    )
    try:
        return scanner.run()
    finally:
        scanner.close()


def test_secure_lab_passes_all_core_tests(secure_lab):
    outcome = _run(secure_lab)
    by_id = {r.id: r for r in outcome.results}
    assert set(by_id) == CORE_IDS
    failed = [r.id for r in outcome.results if r.status != "PASS"]
    assert failed == [], f"expected all PASS, failures: {failed}"
    assert outcome.report["summary"]["outcome"] == "PASS"
    assert outcome.report["detected_mode"] == "secure"


def test_vulnerable_lab_detects_expected_failures(vulnerable_lab):
    outcome = _run(vulnerable_lab)
    failed = {r.id for r in outcome.results if r.status == "FAIL"}
    assert failed == VULNERABLE_EXPECTED_FAILURES
    assert outcome.report["summary"]["outcome"] == "FAIL"
    assert outcome.report["detected_mode"] == "vulnerable"

    by_id = {r.id: r for r in outcome.results}
    assert by_id["valid_signature"].status == "PASS"
    assert by_id["malformed_payload"].status == "PASS"


def test_effectproof_sees_duplicate_business_operation(vulnerable_lab):
    outcome = _run(vulnerable_lab)
    by_id = {r.id: r for r in outcome.results}
    dup = by_id["concurrent_duplicate"]
    assert dup.status == "FAIL"
    assert dup.after_state["payment_count"] > 1
    assert dup.after_state["amount_total"] > 1000


def test_secure_duplicate_has_single_effect(secure_lab):
    outcome = _run(secure_lab)
    by_id = {r.id: r for r in outcome.results}
    dup = by_id["duplicate_event"]
    assert dup.status == "PASS"
    assert dup.after_state["payment_count"] == 1
    assert dup.after_state["amount_total"] == 1000


def test_invalid_signature_no_side_effect_secure(secure_lab):
    outcome = _run(secure_lab)
    by_id = {r.id: r for r in outcome.results}
    for sid in ("invalid_signature", "payload_tampering", "stale_timestamp"):
        assert by_id[sid].after_state["payment_count"] == 0
        assert by_id[sid].after_state["amount_total"] == 0


def test_secure_event_id_reuse_blocked(secure_lab):
    outcome = _run(secure_lab)
    by_id = {r.id: r for r in outcome.results}
    reuse = by_id["event_id_reuse"]
    assert reuse.status == "PASS"
    assert reuse.after_state["primary"]["payment_count"] == 1
    assert reuse.after_state["secondary"]["payment_count"] == 0
    assert reuse.after_state["secondary"]["amount_total"] == 0


def test_vulnerable_event_id_reuse_detected(vulnerable_lab):
    outcome = _run(vulnerable_lab)
    by_id = {r.id: r for r in outcome.results}
    reuse = by_id["event_id_reuse"]
    assert reuse.status == "FAIL"
    assert reuse.after_state["secondary"]["payment_count"] == 1


@pytest.mark.parametrize(
    "target",
    [
        "http://8.8.8.8/webhooks/payment",
        "http://example.com/webhooks/payment",
        "ftp://127.0.0.1/webhooks/payment",
        "",
    ],
)
def test_target_validation_rejects_unsafe_targets(target):
    with pytest.raises(TargetValidationError):
        validate_target(target)


def test_target_validation_allows_loopback():
    parsed = validate_target("http://127.0.0.1:8000/webhooks/payment")
    assert parsed.host == "127.0.0.1"
    assert parsed.origin == "http://127.0.0.1:8000"
