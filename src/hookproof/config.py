"""Configuration and secret handling for HookProof.

Secrets are read from environment variables. Development-only placeholder
values are provided so a beginner can run the demo immediately, but they are
never real payment credentials and must be overridden outside the lab.

A tiny ``.env`` reader is included so the project does not need extra
dependencies. Existing environment variables always win over ``.env`` values.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

# Development-only defaults. NEVER use these outside the local lab.
DEV_WEBHOOK_SECRET = "dev-webhook-secret-change-me"
DEV_TEST_TOKEN = "dev-test-token-change-me"

ENV_WEBHOOK_SECRET = "HOOKPROOF_WEBHOOK_SECRET"
ENV_TEST_TOKEN = "HOOKPROOF_TEST_TOKEN"
ENV_FRESHNESS_WINDOW = "HOOKPROOF_FRESHNESS_WINDOW"
ENV_LAB_HOST = "HOOKPROOF_LAB_HOST"
ENV_LAB_PORT = "HOOKPROOF_LAB_PORT"

DEFAULT_FRESHNESS_WINDOW_SECONDS = 300
DEFAULT_LAB_HOST = "127.0.0.1"
DEFAULT_LAB_PORT = 8000


def redact(value: str | None) -> str:
    """Return a safe, non-reversible marker for a secret value."""
    if not value:
        return "<unset>"
    if len(value) <= 4:
        return "***"
    return f"{value[:2]}***{value[-1:]}"


def load_dotenv(path: str | os.PathLike[str]) -> dict[str, str]:
    """Load a minimal subset of ``.env`` syntax without extra dependencies.

    Supports ``KEY=VALUE`` lines, ``#`` comments, blank lines, optional single
    or double quotes around values. Never overrides already-set environment
    variables. Returns the values that were applied to ``os.environ``.
    """
    applied: dict[str, str] = {}
    env_path = Path(path)
    if not env_path.is_file():
        return applied

    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        if not key or key in os.environ:
            continue
        os.environ[key] = value
        applied[key] = value
    return applied


@dataclass(frozen=True)
class Settings:
    """Runtime settings for both the lab application and the scanner."""

    webhook_secret: str = DEV_WEBHOOK_SECRET
    test_token: str = DEV_TEST_TOKEN
    freshness_window_seconds: int = DEFAULT_FRESHNESS_WINDOW_SECONDS
    lab_host: str = DEFAULT_LAB_HOST
    lab_port: int = DEFAULT_LAB_PORT

    @property
    def uses_dev_webhook_secret(self) -> bool:
        return self.webhook_secret == DEV_WEBHOOK_SECRET

    @property
    def uses_dev_test_token(self) -> bool:
        return self.test_token == DEV_TEST_TOKEN


def load_settings(env_file: str | os.PathLike[str] | None = None) -> Settings:
    """Build :class:`Settings` from the environment.

    If ``env_file`` is given (or ``HOOKPROOF_ENV_FILE`` is set) and the file
    exists, it is loaded before the values are read.
    """
    candidate = env_file or os.environ.get("HOOKPROOF_ENV_FILE")
    if candidate:
        load_dotenv(candidate)
    else:
        default_env = Path.cwd() / ".env"
        if default_env.is_file():
            load_dotenv(default_env)

    window_raw = os.environ.get(ENV_FRESHNESS_WINDOW)
    try:
        freshness_window = int(window_raw) if window_raw else DEFAULT_FRESHNESS_WINDOW_SECONDS
    except ValueError:
        freshness_window = DEFAULT_FRESHNESS_WINDOW_SECONDS

    port_raw = os.environ.get(ENV_LAB_PORT)
    try:
        lab_port = int(port_raw) if port_raw else DEFAULT_LAB_PORT
    except ValueError:
        lab_port = DEFAULT_LAB_PORT

    return Settings(
        webhook_secret=os.environ.get(ENV_WEBHOOK_SECRET, DEV_WEBHOOK_SECRET),
        test_token=os.environ.get(ENV_TEST_TOKEN, DEV_TEST_TOKEN),
        freshness_window_seconds=freshness_window,
        lab_host=os.environ.get(ENV_LAB_HOST, DEFAULT_LAB_HOST),
        lab_port=lab_port,
    )
