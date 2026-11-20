"""EffectProof state observation via the lab's restricted test interface.

IMPORTANT LIMITATION
--------------------
HookProof can only observe the *internal effects* of a webhook handler when the
target exposes a suitable test-state interface (or equivalent instrumentation).
Against an arbitrary third-party API without such access, HookProof can only
report response-level behaviour and must not claim to have verified internal
state changes.
"""

from __future__ import annotations

from typing import Any

import httpx

from .lab.protocol import TEST_HEALTH_PATH, TEST_ORDER_PATH, TEST_STATE_PATH, TEST_TOKEN_HEADER


class ObserverError(RuntimeError):
    """Raised when the test-state interface cannot be queried."""


class StateObserver:
    """Client for the lab's restricted state-inspection interface."""

    def __init__(
        self,
        base_url: str,
        token: str,
        client: httpx.Client,
        timeout: float = 5.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.client = client
        self.timeout = timeout

    def _headers(self) -> dict[str, str]:
        return {TEST_TOKEN_HEADER: self.token}

    def _get(self, path: str) -> dict[str, Any]:
        url = f"{self.base_url}{path}"
        try:
            response = self.client.get(url, headers=self._headers(), timeout=self.timeout)
        except httpx.HTTPError as exc:  # network/transport problems
            raise ObserverError(f"state interface unreachable at {url}: {exc}") from exc

        if response.status_code != 200:
            raise ObserverError(
                f"state interface returned HTTP {response.status_code} for {path}: {_safe_text(response)}"
            )
        try:
            return response.json()
        except ValueError as exc:
            raise ObserverError(f"state interface returned non-JSON for {path}") from exc

    def test_health(self) -> dict[str, Any]:
        return self._get(TEST_HEALTH_PATH)

    def get_order_state(self, order_id: str) -> dict[str, Any]:
        return self._get(TEST_ORDER_PATH.format(order_id=order_id))

    def snapshot(self) -> dict[str, Any]:
        return self._get(TEST_STATE_PATH)


def _safe_text(response: httpx.Response, limit: int = 200) -> str:
    text = response.text or ""
    return text[:limit]
