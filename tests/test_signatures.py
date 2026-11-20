from __future__ import annotations

import time

from hookproof.signatures import (
    SIGNATURE_PREFIX,
    compute_signature,
    format_signature_header,
    is_fresh,
    parse_signature_header,
    signing_payload,
    verify_signature,
)

SECRET = "unit-test-secret"
BODY = b'{"event_id":"evt-1","amount":1000}'


def test_sign_and_verify_roundtrip():
    ts = int(time.time())
    header = format_signature_header(compute_signature(SECRET, ts, BODY))
    assert header.startswith(SIGNATURE_PREFIX)
    assert verify_signature(SECRET, ts, BODY, header) is True


def test_wrong_secret_fails():
    ts = int(time.time())
    header = format_signature_header(compute_signature("other-secret", ts, BODY))
    assert verify_signature(SECRET, ts, BODY, header) is False


def test_tampered_body_fails():
    ts = int(time.time())
    header = format_signature_header(compute_signature(SECRET, ts, BODY))
    assert verify_signature(SECRET, ts, BODY + b" ", header) is False


def test_timestamp_is_bound_to_signature():
    ts = int(time.time())
    header = format_signature_header(compute_signature(SECRET, ts, BODY))
    assert verify_signature(SECRET, ts + 1, BODY, header) is False


def test_missing_or_bad_header_fails():
    assert verify_signature(SECRET, 1, BODY, None) is False
    assert verify_signature(SECRET, 1, BODY, "") is False
    assert verify_signature(SECRET, 1, BODY, "sha256=not-hex!!") is False
    assert parse_signature_header("sha256=abc123") == "abc123"
    assert parse_signature_header(None) is None


def test_signing_payload_format():
    assert signing_payload(42, b"body") == b"42.body"


def test_is_fresh():
    now = time.time()
    assert is_fresh(int(now), 300, now=now) is True
    assert is_fresh(int(now) - 100, 300, now=now) is True
    assert is_fresh(int(now) - 1000, 300, now=now) is False
    assert is_fresh(int(now) + 1000, 300, now=now) is False
    assert is_fresh("not-a-number", 300, now=now) is False
