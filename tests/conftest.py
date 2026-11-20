"""Shared pytest fixtures: real local lab servers running over loopback HTTP."""

from __future__ import annotations

import socket
import threading
import time
from pathlib import Path

import pytest
import uvicorn

from hookproof.config import Settings
from hookproof.lab.app import create_app

TEST_SECRET = "test-webhook-secret-1234"
TEST_TOKEN = "test-token-5678"
TEST_SETTINGS = Settings(
    webhook_secret=TEST_SECRET,
    test_token=TEST_TOKEN,
    freshness_window_seconds=300,
)


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class LabServer:
    def __init__(self, app, host: str, port: int) -> None:
        self.host = host
        self.port = port
        config = uvicorn.Config(
            app,
            host=host,
            port=port,
            log_level="warning",
            access_log=False,
        )
        self.server = uvicorn.Server(config)
        self.thread = threading.Thread(target=self.server.run, daemon=True)

    def start(self, timeout: float = 20.0) -> None:
        self.thread.start()
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.server.started:
                return
            if not self.thread.is_alive():
                raise RuntimeError("uvicorn server thread exited during startup")
            time.sleep(0.02)
        raise RuntimeError("uvicorn server did not start in time")

    def stop(self) -> None:
        self.server.should_exit = True
        self.thread.join(timeout=10)


def make_lab(mode: str, tmp_path: Path) -> dict:
    db_path = tmp_path / f"lab_{mode}.sqlite3"
    app = create_app(mode=mode, db_path=db_path, settings=TEST_SETTINGS)
    port = free_port()
    server = LabServer(app, "127.0.0.1", port)
    server.start()
    info = {
        "mode": mode,
        "base_url": f"http://127.0.0.1:{port}",
        "webhook_url": f"http://127.0.0.1:{port}/webhooks/payment",
        "port": port,
        "server": server,
        "db_path": db_path,
        "settings": TEST_SETTINGS,
    }
    return info


@pytest.fixture(params=["vulnerable", "secure"])
def lab(request, tmp_path):
    info = make_lab(request.param, tmp_path)
    try:
        yield info
    finally:
        info["server"].stop()


@pytest.fixture
def vulnerable_lab(tmp_path):
    info = make_lab("vulnerable", tmp_path)
    try:
        yield info
    finally:
        info["server"].stop()


@pytest.fixture
def secure_lab(tmp_path):
    info = make_lab("secure", tmp_path)
    try:
        yield info
    finally:
        info["server"].stop()
