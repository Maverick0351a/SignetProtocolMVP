from __future__ import annotations
from typing import Dict, Any, Tuple

"""SFT (Sanitize/Filter/Transform) pipeline for inbound exchange payloads.

Guardrails:
- Minimal, deterministic; avoid side effects or hidden coercions.
- Policy evaluated exactly once; caller maps PermissionError to HTTP 403.
"""


def sanitize(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Drop any field whose key starts with '_' (non‑exportable/internal)."""
    return {k: v for k, v in payload.items() if not str(k).startswith("_")}


def normalize(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Placeholder normalization (future: enforce schemas / coercions)."""
    return payload


def policy(payload: Dict[str, Any]) -> Tuple[bool, str]:
    """Simple content policy.

    Deny if payload contains message.text beginning with 'blocked:' prefix.
    Returns (ok, reason).
    """
    try:
        msg = payload.get("message", {})
        if isinstance(msg, dict):
            text = msg.get("text")
            if isinstance(text, str) and text.startswith("blocked:"):
                return False, "blocked prefix"
    except Exception:
        # Fail closed only for explicit matches; otherwise allow to avoid DOS via structure
        pass
    return True, "allow"


def run_sft(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Run the SFT pipeline once and raise PermissionError if policy blocks."""
    x = sanitize(payload)
    x = normalize(x)
    ok, reason = policy(x)
    if not ok:
        raise PermissionError(f"policy denied: {reason}")
    return x
