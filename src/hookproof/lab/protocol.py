"""Shared webhook protocol definition used by both lab modes and the scanner.

Both the vulnerable and the secure lab implement the *same* documented
interface so HookProof can test them consistently and compare behaviour.
"""

from __future__ import annotations

from typing import Any

# The single business event type supported by the MVP.
EVENT_TYPE_PAYMENT_SUCCEEDED = "payment.succeeded"

WEBHOOK_PATH = "/webhooks/payment"
HEALTH_PATH = "/health"

# Restricted state-inspection interface (loopback + test token only).
TEST_TOKEN_HEADER = "X-HookProof-Test-Token"
TEST_HEALTH_PATH = "/__test__/health"
TEST_ORDER_PATH = "/__test__/orders/{order_id}"
TEST_STATE_PATH = "/__test__/state"
TEST_RESET_PATH = "/__test__/reset"

REQUIRED_FIELDS = ("event_id", "type", "order_id", "amount", "currency", "timestamp")

STATUS_PENDING = "pending"
STATUS_PAID = "paid"


def validate_event(data: Any) -> list[str]:
    """Return a list of validation error strings (empty means valid).

    Used by the *secure* mode. The vulnerable mode only performs a shallow
    check so that missing-payload security tests remain meaningful.
    """
    errors: list[str] = []
    if not isinstance(data, dict):
        return ["payload is not a JSON object"]

    for field in REQUIRED_FIELDS:
        if field not in data:
            errors.append(f"missing field: {field}")

    event_id = data.get("event_id")
    if event_id is not None and (not isinstance(event_id, str) or not event_id.strip()):
        errors.append("field 'event_id' must be a non-empty string")

    order_id = data.get("order_id")
    if order_id is not None and (not isinstance(order_id, str) or not order_id.strip()):
        errors.append("field 'order_id' must be a non-empty string")

    event_type = data.get("type")
    if event_type is not None and event_type != EVENT_TYPE_PAYMENT_SUCCEEDED:
        errors.append(f"unsupported event type: {event_type!r}")

    amount = data.get("amount")
    if amount is not None and (not isinstance(amount, int) or isinstance(amount, bool)):
        errors.append("field 'amount' must be an integer")
    elif isinstance(amount, int) and amount <= 0:
        errors.append("field 'amount' must be positive")

    currency = data.get("currency")
    if currency is not None and (not isinstance(currency, str) or len(currency) != 3):
        errors.append("field 'currency' must be a 3-letter code")

    timestamp = data.get("timestamp")
    if timestamp is not None and (not isinstance(timestamp, int) or isinstance(timestamp, bool)):
        errors.append("field 'timestamp' must be an integer")

    return errors
