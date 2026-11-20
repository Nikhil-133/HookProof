"""Scan orchestration: target validation, suite execution and reporting.

SAFETY
------
The MVP refuses any target whose host is not on the allowed list. By default
only loopback hosts are permitted, so HookProof cannot be pointed at public IP
addresses, arbitrary domains or third-party webhook endpoints.
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

import httpx

from .config import Settings, load_settings
from .reports import build_report
from .scenarios import Scenario, get_suite
from .scenarios.base import (
    STATUS_ERROR,
    ScanContext,
    ScenarioResult,
)
from .state_observer import ObserverError, StateObserver

DEFAULT_ALLOWED_HOSTS = ("127.0.0.1", "::1", "localhost")
DEFAULT_MAX_REQUESTS = 500
DEFAULT_TIMEOUT = 5.0


class TargetValidationError(ValueError):
    """Raised when a scan target is not explicitly permitted."""


@dataclass(frozen=True)
class ScanTarget:
    url: str
    scheme: str
    host: str
    port: int | None
    path: str

    @property
    def origin(self) -> str:
        host = self.host
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        if self.port is not None and not _is_default_port(self.scheme, self.port):
            return f"{self.scheme}://{host}:{self.port}"
        return f"{self.scheme}://{host}"

    def to_dict(self) -> dict[str, Any]:
        return {"url": self.url, "scheme": self.scheme, "host": self.host, "port": self.port}


def _is_default_port(scheme: str, port: int) -> bool:
    return (scheme == "http" and port == 80) or (scheme == "https" and port == 443)


def validate_target(
    target: str,
    allowed_hosts: Sequence[str] | None = None,
) -> ScanTarget:
    """Validate a scan target and return a parsed :class:`ScanTarget`."""
    if not target or not target.strip():
        raise TargetValidationError("target URL is empty")

    parts = urlsplit(target.strip())
    if parts.scheme not in ("http", "https"):
        raise TargetValidationError(f"unsupported scheme {parts.scheme!r}; only http/https are allowed")
    if not parts.hostname:
        raise TargetValidationError("target URL has no host")

    allowed = {h.lower() for h in (allowed_hosts if allowed_hosts is not None else DEFAULT_ALLOWED_HOSTS)}
    host = parts.hostname.lower()
    if host not in allowed:
        raise TargetValidationError(
            f"target host {host!r} is not permitted. HookProof only scans explicitly "
            f"allowed hosts (default: loopback). Allowed: {sorted(allowed)}"
        )

    path = parts.path or "/"
    return ScanTarget(
        url=target.strip(),
        scheme=parts.scheme,
        host=host,
        port=parts.port,
        path=path,
    )


@dataclass
class ScanOutcome:
    report: dict[str, Any]
    results: list[ScenarioResult] = field(default_factory=list)


class Scanner:
    """Runs a HookProof suite against a validated local target."""

    def __init__(
        self,
        target: str,
        settings: Settings | None = None,
        suite: str = "core",
        timeout: float = DEFAULT_TIMEOUT,
        max_requests: int = DEFAULT_MAX_REQUESTS,
        client: httpx.Client | None = None,
        allowed_hosts: Sequence[str] | None = None,
        run_id: str | None = None,
    ) -> None:
        self.settings = settings or load_settings()
        self.suite_name = suite.lower().strip()
        self.timeout = timeout
        self.max_requests = max_requests
        self.scenarios: list[Scenario] = get_suite(self.suite_name)
        self.target = validate_target(target, allowed_hosts=allowed_hosts)
        self._client = client
        self._owns_client = client is None
        self.run_id = run_id or uuid.uuid4().hex[:10]

    # -- lifecycle ----------------------------------------------------------
    def _get_client(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(
                timeout=self.timeout,
                follow_redirects=False,
                limits=httpx.Limits(max_connections=32, max_keepalive_connections=16),
            )
        return self._client

    def close(self) -> None:
        if self._owns_client and self._client is not None:
            self._client.close()
            self._client = None

    # -- execution ----------------------------------------------------------
    def run(
        self,
        on_test_start: Callable[[str], None] | None = None,
        on_test_complete: Callable[[str, str], None] | None = None,
    ) -> ScanOutcome:
        """Run the suite, optionally reporting progress to UI callbacks."""

        def notify_start(scenario_id: str) -> None:
            if on_test_start is not None:
                on_test_start(scenario_id)

        def notify_complete(scenario_id: str, status: str) -> None:
            if on_test_complete is not None:
                on_test_complete(scenario_id, status)

        client = self._get_client()
        observer = StateObserver(
            base_url=self.target.origin,
            token=self.settings.test_token,
            client=client,
            timeout=self.timeout,
        )
        ctx = ScanContext(
            target_url=self.target.url,
            origin=self.target.origin,
            settings=self.settings,
            client=client,
            run_id=self.run_id,
            timeout=self.timeout,
            max_requests=self.max_requests,
            observer=observer,
        )

        started = time.time()
        detected_mode = self._detect_mode(client)
        interface_error = self._check_interface(observer)

        results: list[ScenarioResult] = []
        for scenario in self.scenarios:
            notify_start(scenario.id)
            if interface_error is not None:
                result = ScenarioResult(
                    id=scenario.id,
                    title=scenario.title,
                    status=STATUS_ERROR,
                    severity=scenario.severity,
                    description=scenario.description,
                    expected="state interface available for EffectProof",
                    observed=interface_error,
                    remediation=scenario.remediation,
                    error=interface_error,
                )
            else:
                try:
                    result = scenario.run(ctx)
                except Exception as exc:  # pragma: no cover - defensive
                    result = ScenarioResult(
                        id=scenario.id,
                        title=scenario.title,
                        status=STATUS_ERROR,
                        severity=scenario.severity,
                        description=scenario.description,
                        expected="scenario completes without operational error",
                        observed=f"scenario raised {type(exc).__name__}: {exc}",
                        remediation=scenario.remediation,
                        error=f"{type(exc).__name__}: {exc}",
                    )
            results.append(result)
            notify_complete(scenario.id, result.status)

        finished = time.time()
        report = build_report(
            target=self.target.to_dict(),
            suite=self.suite_name,
            results=results,
            detected_mode=detected_mode,
            request_count=ctx.request_count,
            started_at=started,
            finished_at=finished,
            run_id=self.run_id,
            interface_error=interface_error,
        )
        return ScanOutcome(report=report, results=results)

    def _detect_mode(self, client: httpx.Client) -> str:
        try:
            response = client.get(f"{self.target.origin}/health", timeout=self.timeout)
            if response.status_code == 200:
                mode = response.json().get("mode")
                if isinstance(mode, str):
                    return mode
        except (httpx.HTTPError, ValueError):
            pass
        return "unknown"

    def _check_interface(self, observer: StateObserver) -> str | None:
        try:
            observer.test_health()
        except ObserverError as exc:
            return (
                "EffectProof could not query the restricted state interface. "
                f"Reason: {exc}. Ensure the target is a HookProof lab with a matching "
                "test token, or provide equivalent instrumentation."
            )
        return None


__all__ = [
    "Scanner",
    "ScanOutcome",
    "ScanTarget",
    "TargetValidationError",
    "validate_target",
    "DEFAULT_ALLOWED_HOSTS",
]
