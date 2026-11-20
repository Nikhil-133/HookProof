"""FastAPI application implementing the vulnerable and secure lab modes.

SAFETY
------
The ``vulnerable`` mode contains *deliberate, controlled* security weaknesses.
It must only ever run on loopback in an isolated lab. Both modes use synthetic
data and the restricted state endpoint refuses non-loopback clients.
"""

from __future__ import annotations

import json
import secrets
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from ..config import Settings, load_settings
from ..signatures import (
    SIGNATURE_HEADER,
    TIMESTAMP_HEADER,
    is_fresh,
    verify_signature,
)
from .db import LabDB
from .protocol import (
    HEALTH_PATH,
    TEST_HEALTH_PATH,
    TEST_ORDER_PATH,
    TEST_RESET_PATH,
    TEST_STATE_PATH,
    TEST_TOKEN_HEADER,
    WEBHOOK_PATH,
    validate_event,
)

LAB_MODES = ("vulnerable", "secure")
LOOPBACK_HOSTS = ("127.0.0.1", "::1", "localhost")


def default_db_path(mode: str, base_dir: str | Path | None = None) -> Path:
    root = Path(base_dir) if base_dir else Path.cwd()
    return root / "data" / f"lab_{mode}.sqlite3"


def create_app(
    mode: str,
    db_path: str | Path | None = None,
    settings: Settings | None = None,
    trusted_hosts: Sequence[str] | None = None,
) -> FastAPI:
    """Create a lab application for ``mode`` (``vulnerable`` or ``secure``)."""
    mode = mode.lower().strip()
    if mode not in LAB_MODES:
        raise ValueError(f"mode must be one of {LAB_MODES}, got {mode!r}")

    settings = settings or load_settings()
    trusted = set(trusted_hosts) if trusted_hosts is not None else set(LOOPBACK_HOSTS)
    secure = mode == "secure"

    resolved_db = Path(db_path) if db_path else default_db_path(mode)
    db = LabDB(resolved_db, secure=secure)
    db.init()

    app = FastAPI(
        title=f"HookProof lab ({mode})",
        description=("Synthetic payment webhook lab. Never deploy the vulnerable mode."),
        version="0.1.0",
    )
    app.state.lab_db = db
    app.state.lab_mode = mode
    app.state.lab_settings = settings

    # ------------------------------------------------------------------ utils
    def _client_is_trusted(request: Request) -> bool:
        client = request.client
        if client is None:
            return False
        return client.host in trusted

    def _require_test_access(request: Request) -> None:
        """Enforce loopback + test-token protection for the state interface."""
        if not _client_is_trusted(request):
            raise HTTPException(status_code=403, detail="test interface restricted to loopback")
        provided = request.headers.get(TEST_TOKEN_HEADER, "")
        if not secrets.compare_digest(provided, settings.test_token):
            raise HTTPException(status_code=401, detail="invalid test token")

    def _apply_payment(event: dict[str, Any]) -> dict[str, Any]:
        return db.process_payment(event)

    # --------------------------------------------------------------- webhook
    @app.post(WEBHOOK_PATH)
    async def webhook_payment(request: Request) -> JSONResponse:
        raw = await request.body()
        timestamp_raw = request.headers.get(TIMESTAMP_HEADER)
        signature_header = request.headers.get(SIGNATURE_HEADER)

        if secure:
            return await _handle_secure(raw, timestamp_raw, signature_header)
        return await _handle_vulnerable(raw)

    async def _handle_vulnerable(raw: bytes) -> JSONResponse:
        # VULNERABLE: no signature check, no timestamp freshness check,
        # and no idempotency guard on the business operation.
        try:
            data = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return JSONResponse(status_code=400, content={"detail": "invalid JSON payload"})

        if not isinstance(data, dict):
            return JSONResponse(status_code=400, content={"detail": "payload must be a JSON object"})

        shallow = validate_event(data)
        fatal = [
            e
            for e in shallow
            if e.startswith("missing field") or "non-empty" in e or "must be an integer" in e
        ]
        if fatal:
            return JSONResponse(status_code=422, content={"detail": fatal})

        event = _normalise_event(data)
        result = await run_in_threadpool(_apply_payment, event)
        return JSONResponse(status_code=200, content={"mode": "vulnerable", **result})

    async def _handle_secure(
        raw: bytes,
        timestamp_raw: str | None,
        signature_header: str | None,
    ) -> JSONResponse:
        if not timestamp_raw or not signature_header:
            return JSONResponse(
                status_code=401,
                content={"detail": "missing signature or timestamp header"},
            )

        try:
            timestamp = int(timestamp_raw)
        except ValueError:
            return JSONResponse(status_code=401, content={"detail": "invalid timestamp header"})

        if not verify_signature(settings.webhook_secret, timestamp, raw, signature_header):
            return JSONResponse(status_code=401, content={"detail": "invalid signature"})

        if not is_fresh(timestamp, settings.freshness_window_seconds):
            return JSONResponse(status_code=401, content={"detail": "stale timestamp"})

        try:
            data = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return JSONResponse(status_code=400, content={"detail": "invalid JSON payload"})

        errors = validate_event(data)
        if errors:
            return JSONResponse(status_code=422, content={"detail": errors})

        if int(data["timestamp"]) != timestamp:
            return JSONResponse(
                status_code=422,
                content={"detail": "body timestamp does not match authenticated header"},
            )

        event = _normalise_event(data)
        result = await run_in_threadpool(_apply_payment, event)
        status_code = 200
        return JSONResponse(status_code=status_code, content={"mode": "secure", **result})

    def _normalise_event(data: dict[str, Any]) -> dict[str, Any]:
        return {
            "event_id": str(data["event_id"]),
            "order_id": str(data["order_id"]),
            "amount": int(data["amount"]),
            "type": data.get("type"),
            "currency": data.get("currency"),
            "timestamp": data.get("timestamp"),
        }

    # ---------------------------------------------------------------- health
    @app.get(HEALTH_PATH)
    async def health() -> dict[str, Any]:
        return {"status": "ok", "mode": mode}

    # ----------------------------------------------------- test-state access
    @app.get(TEST_HEALTH_PATH)
    async def test_health(request: Request) -> dict[str, Any]:
        _require_test_access(request)
        return {"status": "ok", "mode": mode, "secure": secure}

    @app.get(TEST_ORDER_PATH)
    async def test_order_state(order_id: str, request: Request) -> dict[str, Any]:
        _require_test_access(request)
        state = await run_in_threadpool(db.get_order_state, order_id)
        return state

    @app.get(TEST_STATE_PATH)
    async def test_state(request: Request) -> dict[str, Any]:
        _require_test_access(request)
        snapshot = await run_in_threadpool(db.snapshot)
        return {"mode": mode, "secure": secure, **snapshot}

    @app.post(TEST_RESET_PATH)
    async def test_reset(request: Request) -> dict[str, Any]:
        _require_test_access(request)
        await run_in_threadpool(db.reset)
        return {"status": "reset"}

    return app
