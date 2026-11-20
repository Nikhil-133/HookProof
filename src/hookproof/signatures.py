"""Signature and freshness utilities for the HookProof webhook protocol.

Protocol (deliberately simple and fully documented):

* The raw HTTP body is signed together with an authenticated timestamp header.
* ``signing_payload`` = ``<timestamp>.<raw body>`` encoded as UTF-8 bytes.
* ``X-HookProof-Signature`` = ``sha256=<hex hmac-sha256 of signing_payload>``.
* ``X-HookProof-Timestamp`` = Unix seconds at which the event was produced.

Signing the timestamp binds it to the body so a captured signature cannot be
replayed with a different (fresh) timestamp.
"""

from __future__ import annotations

import hashlib
import hmac
import time

SIGNATURE_HEADER = "X-HookProof-Signature"
TIMESTAMP_HEADER = "X-HookProof-Timestamp"
SIGNATURE_PREFIX = "sha256="


def signing_payload(timestamp: int, body: bytes) -> bytes:
    """Return the canonical bytes that are signed."""
    return str(int(timestamp)).encode("ascii") + b"." + body


def compute_signature(secret: str, timestamp: int, body: bytes) -> str:
    """Return the hex HMAC-SHA256 signature for ``body`` and ``timestamp``."""
    digest = hmac.new(
        secret.encode("utf-8"),
        signing_payload(timestamp, body),
        hashlib.sha256,
    )
    return digest.hexdigest()


def format_signature_header(signature: str) -> str:
    """Wrap a raw hex signature in the protocol header format."""
    return f"{SIGNATURE_PREFIX}{signature}"


def parse_signature_header(header_value: str | None) -> str | None:
    """Extract the hex signature from a header value, or ``None`` if invalid."""
    if not header_value:
        return None
    value = header_value.strip()
    if value.lower().startswith(SIGNATURE_PREFIX):
        value = value[len(SIGNATURE_PREFIX) :]
    if not value or not all(c in "0123456789abcdefABCDEF" for c in value):
        return None
    return value.lower()


def verify_signature(
    secret: str,
    timestamp: int,
    body: bytes,
    header_value: str | None,
) -> bool:
    """Constant-time verification of a signed request."""
    provided = parse_signature_header(header_value)
    if provided is None:
        return False
    expected = compute_signature(secret, timestamp, body)
    return hmac.compare_digest(expected, provided)


def is_fresh(timestamp: int, window_seconds: int, now: float | None = None) -> bool:
    """Return True if ``timestamp`` is within ``window_seconds`` of now.

    Guards against both past-replay and far-future timestamps.
    """
    reference = time.time() if now is None else now
    try:
        ts = int(timestamp)
    except (TypeError, ValueError):
        return False
    return abs(reference - ts) <= window_seconds
