"""Local, isolated webhook security lab (vulnerable and secure modes)."""

from __future__ import annotations

from .app import create_app
from .db import LabDB

__all__ = ["create_app", "LabDB"]
