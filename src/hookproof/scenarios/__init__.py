"""Test scenario registry."""

from __future__ import annotations

from .base import ScanContext, Scenario, ScenarioResult
from .core import CORE_SCENARIOS

SUITES: dict[str, list[Scenario]] = {
    "core": CORE_SCENARIOS,
}

__all__ = [
    "Scenario",
    "ScenarioResult",
    "ScanContext",
    "SUITES",
    "CORE_SCENARIOS",
]


def get_suite(name: str) -> list[Scenario]:
    key = name.lower().strip()
    if key not in SUITES:
        raise KeyError(f"unknown suite {name!r}; available: {sorted(SUITES)}")
    return SUITES[key]
