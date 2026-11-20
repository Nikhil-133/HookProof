"""The ``core`` HookProof webhook security suite.

Every scenario defines a security invariant and uses EffectProof to verify the
observed application state, not just the HTTP response code.
"""

from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import httpx

from ..state_observer import ObserverError
from .base import (
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    STATUS_FAIL,
    STATUS_PASS,
    ScanContext,
    Scenario,
    ScenarioResult,
    describe_exchange,
)


class ValidSignatureScenario(Scenario):
    id = "valid_signature"
    title = "Valid signed event is processed"
    description = (
        "A correctly signed, fresh payment event must be accepted and must "
        "create exactly one payment business operation."
    )
    severity = SEVERITY_MEDIUM
    remediation = (
        "Investigate the webhook handler, signature verification and payload "
        "validation. A valid event should result in one processed operation."
    )

    def run(self, ctx: ScanContext) -> ScenarioResult:
        order_id = ctx.new_order_id(self.id)
        event_id = ctx.new_event_id(self.id)
        amount = ctx.default_amount
        timestamp = int(time.time())
        body = ctx.build_body(event_id=event_id, order_id=order_id, amount=amount, timestamp=timestamp)
        headers = ctx.signed_headers(body, timestamp)

        expected = f"exactly one payment of {amount}; order status 'paid'"
        try:
            before = self._observe(ctx, order_id)
            response = ctx.post(headers=headers, content=body)
            after = self._observe(ctx, order_id)
        except ObserverError as exc:
            return self._error_result(f"state observation failed: {exc}", expected=expected)
        except httpx.HTTPError as exc:
            return self._error_result(f"request failed: {exc}", expected=expected)

        ok, observed = self._single_payment_invariant(after, amount)
        notes: list[str] = []
        if response.status_code != 200:
            notes.append(f"unexpected HTTP status {response.status_code} for a valid event")

        status = STATUS_PASS if ok and response.status_code == 200 else STATUS_FAIL
        return ScenarioResult(
            id=self.id,
            title=self.title,
            status=status,
            severity=self.severity,
            description=self.description,
            expected=expected,
            observed=observed,
            remediation=self.remediation,
            exchanges=[describe_exchange("valid-event", response)],
            before_state=before,
            after_state=after,
            notes=notes,
        )


class _NoSideEffectScenario(Scenario):
    """Base class for scenarios asserting that protected state is unchanged."""

    severity = SEVERITY_HIGH

    def _send(self, ctx: ScanContext, order_id: str, event_id: str) -> httpx.Response:
        raise NotImplementedError

    def run(self, ctx: ScanContext) -> ScenarioResult:
        order_id = ctx.new_order_id(self.id)
        event_id = ctx.new_event_id(self.id)
        expected = "no payment recorded and amount_total remains 0 (no protected side effect)"
        try:
            before = self._observe(ctx, order_id)
            response = self._send(ctx, order_id, event_id)
            after = self._observe(ctx, order_id)
        except ObserverError as exc:
            return self._error_result(f"state observation failed: {exc}", expected=expected)
        except httpx.HTTPError as exc:
            return self._error_result(f"request failed: {exc}", expected=expected)

        ok, observed = self._no_side_effect_invariant(after)
        notes: list[str] = []
        if ok and response.status_code < 400:
            notes.append(
                "request was accepted at the HTTP layer but produced no protected "
                "side effect, which is the required behaviour"
            )
        if after.get("found") and int(after.get("amount_total", 0)) == 0:
            notes.append("an order row was created but no payment was fulfilled")
        return ScenarioResult(
            id=self.id,
            title=self.title,
            status=STATUS_PASS if ok else STATUS_FAIL,
            severity=self.severity,
            description=self.description,
            expected=expected,
            observed=observed,
            remediation=self.remediation,
            exchanges=[describe_exchange(self.id, response)],
            before_state=before,
            after_state=after,
            notes=notes,
        )


class MissingSignatureScenario(_NoSideEffectScenario):
    id = "missing_signature"
    title = "Unsigned event does not change protected state"
    description = (
        "An event without any signature header must be rejected and must not "
        "create or modify protected business records."
    )
    remediation = (
        "Require and verify a signature header on every webhook request before "
        "processing. Reject unsigned requests with 401."
    )

    def _send(self, ctx: ScanContext, order_id: str, event_id: str) -> httpx.Response:
        body = ctx.build_body(event_id=event_id, order_id=order_id)
        return ctx.post(headers={"Content-Type": "application/json"}, content=body)


class InvalidSignatureScenario(_NoSideEffectScenario):
    id = "invalid_signature"
    title = "Forged signature is rejected without side effects"
    description = "A request signed with the wrong secret must be rejected and must not trigger processing."
    remediation = (
        "Verify signatures with a constant-time comparison against the expected "
        "HMAC and reject mismatches with 401 before any side effect."
    )

    def _send(self, ctx: ScanContext, order_id: str, event_id: str) -> httpx.Response:
        timestamp = int(time.time())
        body = ctx.build_body(event_id=event_id, order_id=order_id, timestamp=timestamp)
        headers = ctx.signed_headers(body, timestamp, secret="attacker-controlled-wrong-secret")
        return ctx.post(headers=headers, content=body)


class PayloadTamperingScenario(_NoSideEffectScenario):
    id = "payload_tampering"
    title = "Tampered payload is rejected without side effects"
    description = (
        "A signed body whose content was modified (without recomputing a valid "
        "signature) must not be processed."
    )
    remediation = (
        "Sign the raw request body and verify it before parsing. Never trust "
        "fields that were not covered by the signature."
    )

    def _send(self, ctx: ScanContext, order_id: str, event_id: str) -> httpx.Response:
        timestamp = int(time.time())
        original = ctx.build_body(
            event_id=event_id, order_id=order_id, amount=ctx.default_amount, timestamp=timestamp
        )
        headers = ctx.signed_headers(original, timestamp)
        # Tamper: raise the amount but keep the original signature.
        tampered = json.loads(original.decode("utf-8"))
        tampered["amount"] = ctx.default_amount * 99
        tampered_body = json.dumps(tampered, separators=(",", ":"), sort_keys=True).encode("utf-8")
        return ctx.post(headers=headers, content=tampered_body)


class StaleTimestampScenario(_NoSideEffectScenario):
    id = "stale_timestamp"
    title = "Stale signed timestamp is rejected"
    description = (
        "A correctly signed event whose authenticated timestamp is outside the "
        "freshness window must be rejected and cause no side effects."
    )
    severity = SEVERITY_MEDIUM
    remediation = (
        "Reject events whose authenticated timestamp is outside the accepted "
        "freshness window (for example +/- 300 seconds) and record a replay "
        "guard for accepted event IDs."
    )

    def _send(self, ctx: ScanContext, order_id: str, event_id: str) -> httpx.Response:
        stale = int(time.time()) - (ctx.settings.freshness_window_seconds + 900)
        body = ctx.build_body(event_id=event_id, order_id=order_id, timestamp=stale)
        headers = ctx.signed_headers(body, stale)
        return ctx.post(headers=headers, content=body)


class DuplicateEventScenario(Scenario):
    id = "duplicate_event"
    title = "Duplicate delivery creates only one business operation"
    description = (
        "Delivering the same valid event twice must produce exactly one "
        "protected business operation (persistent idempotency)."
    )
    severity = SEVERITY_HIGH
    remediation = (
        "Persist event IDs and make the business operation idempotent using a "
        "unique constraint plus a transaction. Return a safe success for "
        "already-processed events instead of repeating the operation."
    )

    def run(self, ctx: ScanContext) -> ScenarioResult:
        order_id = ctx.new_order_id(self.id)
        event_id = ctx.new_event_id(self.id)
        amount = ctx.default_amount
        timestamp = int(time.time())
        body = ctx.build_body(event_id=event_id, order_id=order_id, amount=amount, timestamp=timestamp)
        headers = ctx.signed_headers(body, timestamp)

        expected = f"exactly one payment of {amount} after two identical deliveries"
        try:
            before = self._observe(ctx, order_id)
            first = ctx.post(headers=headers, content=body)
            second = ctx.post(headers=headers, content=body)
            after = self._observe(ctx, order_id)
        except ObserverError as exc:
            return self._error_result(f"state observation failed: {exc}", expected=expected)
        except httpx.HTTPError as exc:
            return self._error_result(f"request failed: {exc}", expected=expected)

        ok, observed = self._single_payment_invariant(after, amount)
        notes: list[str] = []
        if second.status_code < 400 and not ok:
            notes.append(
                "the duplicate was acknowledged successfully yet the operation "
                "was repeated, which is the dangerous case"
            )
        if second.status_code < 400 and ok:
            notes.append(
                "the duplicate received a success response, which is acceptable "
                "because no operation was repeated"
            )
        return ScenarioResult(
            id=self.id,
            title=self.title,
            status=STATUS_PASS if ok else STATUS_FAIL,
            severity=self.severity,
            description=self.description,
            expected=expected,
            observed=observed,
            remediation=self.remediation,
            exchanges=[
                describe_exchange("first-delivery", first),
                describe_exchange("second-delivery", second),
            ],
            before_state=before,
            after_state=after,
            notes=notes,
        )


class ConcurrentDuplicateScenario(Scenario):
    id = "concurrent_duplicate"
    title = "Concurrent duplicate deliveries cannot bypass idempotency"
    description = (
        "Simultaneous copies of the same valid event must still result in "
        "exactly one protected business operation."
    )
    severity = SEVERITY_CRITICAL
    remediation = (
        "Enforce idempotency at the database level (unique event ID constraint) "
        "inside an immediate/atomic transaction so that concurrent deliveries "
        "cannot each create a payment."
    )
    concurrency = 8

    def run(self, ctx: ScanContext) -> ScenarioResult:
        order_id = ctx.new_order_id(self.id)
        event_id = ctx.new_event_id(self.id)
        amount = ctx.default_amount
        timestamp = int(time.time())
        body = ctx.build_body(event_id=event_id, order_id=order_id, amount=amount, timestamp=timestamp)
        headers = ctx.signed_headers(body, timestamp)

        expected = f"exactly one payment of {amount} after {self.concurrency} concurrent deliveries"
        try:
            before = self._observe(ctx, order_id)
        except ObserverError as exc:
            return self._error_result(f"state observation failed: {exc}", expected=expected)

        responses: list[httpx.Response | None] = [None] * self.concurrency
        errors: list[str] = []

        def deliver(index: int) -> None:
            try:
                responses[index] = ctx.post(headers=headers, content=body)
            except httpx.HTTPError as exc:  # pragma: no cover - network dependent
                errors.append(str(exc))

        with ThreadPoolExecutor(max_workers=self.concurrency) as pool:
            list(pool.map(deliver, range(self.concurrency)))

        try:
            after = self._observe(ctx, order_id)
        except ObserverError as exc:
            return self._error_result(f"state observation failed: {exc}", expected=expected)

        if errors:
            return self._error_result(
                "one or more concurrent requests failed: " + "; ".join(errors[:3]),
                expected=expected,
            )

        ok, observed = self._single_payment_invariant(after, amount)
        codes = [r.status_code for r in responses if r is not None]
        notes = [f"concurrent response codes: {codes}"]
        if not ok:
            notes.append(
                f"{after.get('payment_count')} payments were created, indicating a "
                "race condition that bypassed idempotency controls"
            )
        exchanges = [
            describe_exchange(f"concurrent-{i}", r) for i, r in enumerate(responses) if r is not None
        ]
        return ScenarioResult(
            id=self.id,
            title=self.title,
            status=STATUS_PASS if ok else STATUS_FAIL,
            severity=self.severity,
            description=self.description,
            expected=expected,
            observed=observed,
            remediation=self.remediation,
            exchanges=exchanges,
            before_state=before,
            after_state=after,
            notes=notes,
        )


class UnsupportedEventTypeScenario(_NoSideEffectScenario):
    id = "unsupported_event_type"
    title = "Unsupported event type does not move money"
    description = (
        "A correctly signed event whose type is not supported (for example a "
        "refund event) must not trigger a payment fulfilment."
    )
    severity = SEVERITY_MEDIUM
    remediation = (
        "Accept only explicitly supported event types and reject or ignore "
        "unknown types before any business logic runs."
    )

    def _send(self, ctx: ScanContext, order_id: str, event_id: str) -> httpx.Response:
        timestamp = int(time.time())
        body = ctx.build_body(
            event_id=event_id,
            order_id=order_id,
            timestamp=timestamp,
            event_type="payment.refunded",
        )
        headers = ctx.signed_headers(body, timestamp)
        return ctx.post(headers=headers, content=body)


class InvalidAmountScenario(_NoSideEffectScenario):
    id = "invalid_amount"
    title = "Negative amount is rejected without side effects"
    description = (
        "A signed event with an invalid (negative) amount must be rejected and "
        "must not create a payment or alter protected state."
    )
    severity = SEVERITY_HIGH
    remediation = (
        "Validate amount boundaries (positive, within expected limits) before "
        "processing, and reject invalid payloads with 422."
    )

    def _send(self, ctx: ScanContext, order_id: str, event_id: str) -> httpx.Response:
        timestamp = int(time.time())
        body = ctx.build_body(
            event_id=event_id,
            order_id=order_id,
            amount=-500,
            timestamp=timestamp,
        )
        headers = ctx.signed_headers(body, timestamp)
        return ctx.post(headers=headers, content=body)


class EventIdReuseScenario(Scenario):
    id = "event_id_reuse"
    title = "Event ID cannot be reused for another order"
    description = (
        "Reusing an already processed event ID with a different order must not "
        "create a second protected business operation."
    )
    severity = SEVERITY_HIGH
    remediation = (
        "Make the idempotency ledger global to the event ID (unique constraint), "
        "not scoped per order, and reject reused IDs atomically."
    )

    def run(self, ctx: ScanContext) -> ScenarioResult:
        primary_order = ctx.new_order_id(f"{self.id}-primary")
        secondary_order = ctx.new_order_id(f"{self.id}-secondary")
        event_id = ctx.new_event_id(self.id)
        amount = ctx.default_amount
        timestamp = int(time.time())

        first_body = ctx.build_body(
            event_id=event_id, order_id=primary_order, amount=amount, timestamp=timestamp
        )
        first_headers = ctx.signed_headers(first_body, timestamp)
        reused_body = ctx.build_body(
            event_id=event_id, order_id=secondary_order, amount=amount, timestamp=timestamp
        )
        reused_headers = ctx.signed_headers(reused_body, timestamp)

        expected = "original order charged once; reused event ID creates no payment for the second order"
        try:
            before = self._observe(ctx, secondary_order)
            first = ctx.post(headers=first_headers, content=first_body)
            reused = ctx.post(headers=reused_headers, content=reused_body)
            primary_state = self._observe(ctx, primary_order)
            secondary_state = self._observe(ctx, secondary_order)
        except ObserverError as exc:
            return self._error_result(f"state observation failed: {exc}", expected=expected)
        except httpx.HTTPError as exc:
            return self._error_result(f"request failed: {exc}", expected=expected)

        primary_count = int(primary_state.get("payment_count", 0))
        secondary_count = int(secondary_state.get("payment_count", 0))
        secondary_total = int(secondary_state.get("amount_total", 0))
        ok = primary_count == 1 and secondary_count == 0 and secondary_total == 0
        observed = (
            f"primary_payment_count={primary_count}, "
            f"secondary_payment_count={secondary_count}, "
            f"secondary_amount_total={secondary_total}"
        )
        notes: list[str] = []
        if secondary_count:
            notes.append(
                "the same event ID was applied to a different order, so the "
                "idempotency ledger is scoped incorrectly"
            )
        return ScenarioResult(
            id=self.id,
            title=self.title,
            status=STATUS_PASS if ok else STATUS_FAIL,
            severity=self.severity,
            description=self.description,
            expected=expected,
            observed=observed,
            remediation=self.remediation,
            exchanges=[
                describe_exchange("original-order", first),
                describe_exchange("reused-event-id", reused),
            ],
            before_state=before,
            after_state={
                "primary": primary_state,
                "secondary": secondary_state,
            },
            notes=notes,
        )


class MalformedPayloadScenario(Scenario):
    id = "malformed_payload"
    title = "Malformed payload causes no unintended state change"
    description = (
        "Invalid JSON and structurally invalid events (including with a valid "
        "signature) must be handled safely without side effects."
    )
    severity = SEVERITY_LOW
    remediation = (
        "Validate JSON parsing and every required field before processing, and "
        "respond with 400/422 without touching business state."
    )

    def run(self, ctx: ScanContext) -> ScenarioResult:
        order_id = ctx.new_order_id(self.id)
        event_id = ctx.new_event_id(self.id)
        expected = "no payment recorded for malformed payloads"
        exchanges: list[dict[str, Any]] = []
        notes: list[str] = []

        cases = {
            "invalid-json": b'{"event_id": "broken", "amount": ',
            "missing-required-fields": json.dumps({"event_id": event_id, "order_id": order_id}).encode(),
        }

        try:
            before = self._observe(ctx, order_id)
            for label, payload in cases.items():
                timestamp = int(time.time())
                headers = ctx.signed_headers(payload, timestamp)
                response = ctx.post(headers=headers, content=payload)
                exchanges.append(describe_exchange(label, response))
                if response.status_code < 400:
                    notes.append(f"case {label} was not rejected (HTTP {response.status_code})")
            after = self._observe(ctx, order_id)
        except ObserverError as exc:
            return self._error_result(f"state observation failed: {exc}", expected=expected)
        except httpx.HTTPError as exc:
            return self._error_result(f"request failed: {exc}", expected=expected)

        ok, observed = self._no_side_effect_invariant(after)
        return ScenarioResult(
            id=self.id,
            title=self.title,
            status=STATUS_PASS if ok else STATUS_FAIL,
            severity=self.severity,
            description=self.description,
            expected=expected,
            observed=observed,
            remediation=self.remediation,
            exchanges=exchanges,
            before_state=before,
            after_state=after,
            notes=notes,
        )


CORE_SCENARIOS: list[Scenario] = [
    ValidSignatureScenario(),
    MissingSignatureScenario(),
    InvalidSignatureScenario(),
    PayloadTamperingScenario(),
    UnsupportedEventTypeScenario(),
    InvalidAmountScenario(),
    DuplicateEventScenario(),
    ConcurrentDuplicateScenario(),
    EventIdReuseScenario(),
    StaleTimestampScenario(),
    MalformedPayloadScenario(),
]
