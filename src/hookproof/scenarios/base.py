"""Scenario framework: context, results and shared helpers.

Each scenario performs a complete EffectProof cycle:

1. generate a unique synthetic record,
2. observe its initial state,
3. send the webhook request(s),
4. observe the resulting state,
5. compare actual change against the expected security invariant,
6. return ``PASS`` / ``FAIL`` / ``ERROR`` with evidence.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

from ..config import Settings
from ..lab.protocol import EVENT_TYPE_PAYMENT_SUCCEEDED
from ..signatures import (
    SIGNATURE_HEADER,
    TIMESTAMP_HEADER,
    compute_signature,
    format_signature_header,
)
from ..state_observer import ObserverError, StateObserver

STATUS_PASS = "PASS"
STATUS_FAIL = "FAIL"
STATUS_ERROR = "ERROR"

SEVERITY_INFO = "INFO"
SEVERITY_LOW = "LOW"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_HIGH = "HIGH"
SEVERITY_CRITICAL = "CRITICAL"

SEVERITY_ORDER = {
    SEVERITY_INFO: 0,
    SEVERITY_LOW: 1,
    SEVERITY_MEDIUM: 2,
    SEVERITY_HIGH: 3,
    SEVERITY_CRITICAL: 4,
}


class RequestBudgetExceeded(RuntimeError):
    """Raised when a scan exceeds its configured request budget."""


@dataclass
class ScanContext:
    """Shared services and identifiers for a single scan run."""

    target_url: str
    origin: str
    settings: Settings
    client: httpx.Client
    run_id: str
    timeout: float = 5.0
    max_requests: int = 200
    default_amount: int = 1000
    request_count: int = 0
    dry_run: bool = False
    observer: StateObserver | None = None

    # -- identifiers --------------------------------------------------------
    def new_order_id(self, tag: str) -> str:
        return f"ord-{tag}-{self.run_id}"

    def new_event_id(self, tag: str) -> str:
        return f"evt-{tag}-{self.run_id}"

    # -- request helpers ----------------------------------------------------
    def build_body(
        self,
        *,
        event_id: str,
        order_id: str,
        amount: int | None = None,
        timestamp: int | None = None,
        event_type: str = EVENT_TYPE_PAYMENT_SUCCEEDED,
        currency: str = "usd",
    ) -> bytes:
        payload = {
            "event_id": event_id,
            "type": event_type,
            "order_id": order_id,
            "amount": amount if amount is not None else self.default_amount,
            "currency": currency,
            "timestamp": int(timestamp if timestamp is not None else time.time()),
        }
        return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")

    def signed_headers(
        self,
        body: bytes,
        timestamp: int,
        secret: str | None = None,
    ) -> dict[str, str]:
        signing_secret = self.settings.webhook_secret if secret is None else secret
        signature = compute_signature(signing_secret, timestamp, body)
        return {
            "Content-Type": "application/json",
            SIGNATURE_HEADER: format_signature_header(signature),
            TIMESTAMP_HEADER: str(int(timestamp)),
        }

    def post(
        self,
        headers: dict[str, str] | None = None,
        content: bytes | None = None,
    ) -> httpx.Response:
        """Send one webhook request, enforcing the request budget."""
        if self.request_count >= self.max_requests:
            raise RequestBudgetExceeded(f"request budget of {self.max_requests} exceeded")
        self.request_count += 1
        return self.client.post(
            self.target_url,
            headers=headers,
            content=content,
            timeout=self.timeout,
        )


def describe_exchange(label: str, response: httpx.Response) -> dict[str, Any]:
    """Create a redacted evidence record for one HTTP exchange."""
    return {
        "label": label,
        "status_code": response.status_code,
        "response_body": _safe_json(response),
    }


def _safe_json(response: httpx.Response, limit: int = 800) -> Any:
    try:
        data = response.json()
    except ValueError:
        text = response.text or ""
        return text[:limit]
    rendered = json.dumps(data, sort_keys=True)
    if len(rendered) > limit:
        return {"_truncated": True, "preview": rendered[:limit]}
    return data


@dataclass
class ScenarioResult:
    id: str
    title: str
    status: str
    severity: str
    description: str
    expected: str
    observed: str
    remediation: str = ""
    exchanges: list[dict[str, Any]] = field(default_factory=list)
    before_state: dict[str, Any] | None = None
    after_state: dict[str, Any] | None = None
    notes: list[str] = field(default_factory=list)
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "id": self.id,
            "title": self.title,
            "status": self.status,
            "severity": self.severity if self.status == STATUS_FAIL else SEVERITY_INFO,
            "severity_if_failed": self.severity,
            "description": self.description,
            "expected": self.expected,
            "observed": self.observed,
            "remediation": self.remediation,
            "notes": list(self.notes),
            "evidence": {
                "exchanges": self.exchanges,
                "before_state": self.before_state,
                "after_state": self.after_state,
            },
        }
        if self.error:
            payload["error"] = self.error
        return payload


class Scenario:
    """Base class for HookProof test scenarios."""

    id: str = "scenario"
    title: str = "Scenario"
    description: str = ""
    severity: str = SEVERITY_MEDIUM
    remediation: str = ""

    # -- invariant helpers --------------------------------------------------
    @staticmethod
    def _no_side_effect_invariant(state: dict[str, Any]) -> tuple[bool, str]:
        """True when no protected business operation was recorded."""
        count = int(state.get("payment_count", 0))
        total = int(state.get("amount_total", 0))
        ok = count == 0 and total == 0
        observed = (
            f"payment_count={count}, amount_total={total}, "
            f"order_created={state.get('found')}, status={state.get('status')}"
        )
        return ok, observed

    @staticmethod
    def _single_payment_invariant(state: dict[str, Any], amount: int) -> tuple[bool, str]:
        """True when exactly one payment of ``amount`` was recorded."""
        count = int(state.get("payment_count", 0))
        total = int(state.get("amount_total", 0))
        ok = count == 1 and total == amount and state.get("status") == "paid"
        observed = (
            f"payment_count={count}, amount_total={total}, "
            f"expected_total={amount}, status={state.get('status')}"
        )
        return ok, observed

    # -- execution ----------------------------------------------------------
    def run(self, ctx: ScanContext) -> ScenarioResult:  # pragma: no cover - overridden
        raise NotImplementedError

    def _error_result(self, message: str, **kwargs: Any) -> ScenarioResult:
        return ScenarioResult(
            id=self.id,
            title=self.title,
            status=STATUS_ERROR,
            severity=self.severity,
            description=self.description,
            expected=kwargs.pop("expected", ""),
            observed=kwargs.pop("observed", message),
            remediation=self.remediation,
            error=message,
            **kwargs,
        )

    def _observe(self, ctx: ScanContext, order_id: str) -> dict[str, Any]:
        if ctx.observer is None:  # pragma: no cover - defensive
            raise ObserverError("state observer is not configured for this scan")
        return ctx.observer.get_order_state(order_id)


__all__ = [
    "ScanContext",
    "Scenario",
    "ScenarioResult",
    "ObserverError",
    "STATUS_PASS",
    "STATUS_FAIL",
    "STATUS_ERROR",
    "SEVERITY_INFO",
    "SEVERITY_LOW",
    "SEVERITY_MEDIUM",
    "SEVERITY_HIGH",
    "SEVERITY_CRITICAL",
    "SEVERITY_ORDER",
    "RequestBudgetExceeded",
    "describe_exchange",
]
