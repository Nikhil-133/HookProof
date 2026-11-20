"""HookProof - webhook security testing tool with EffectProof state verification.

HookProof tests whether webhook handlers securely process incoming events.
Its differentiator is *EffectProof*: it inspects the real application state
after each security test instead of trusting HTTP status codes alone.
"""

from __future__ import annotations

__version__ = "0.1.0"
__all__ = ["__version__"]
