from __future__ import annotations
from typing import Optional, Dict, Any
from pydantic import BaseModel, Field, field_validator
from pydantic import ConfigDict


class ExchangePayload(BaseModel):
    """Inbound exchange payload (strict).

    Strictly enforces that `message` is a dict whose keys are already strings.
    Non‑string keys trigger a validation error BEFORE any coercion, yielding
    an HTTP 400 at the API layer. This keeps canonical hashing deterministic
    and prevents silent key transformation (e.g., ints → strings).
    """

    model_config = ConfigDict(strict=True)

    message: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("message", mode="before")
    @classmethod
    def _keys_must_be_strings(cls, v):  # type: ignore[override]
        if not isinstance(v, dict):
            raise TypeError("message must be an object")
        for k in v.keys():
            if not isinstance(k, str):
                raise ValueError("message dictionary keys must be strings")
            # Additional guard: a numeric-only key likely came from a non-string
            # original (e.g., int) which JSON coerced; reject to avoid silent
            # semantic changes.
            if k.isdigit():
                raise ValueError("numeric-only message keys are not allowed")
        return v


class SR1Receipt(BaseModel):
    receipt_id: str
    chain_id: str
    ts: str
    payload_hash_b64: str
    prev_receipt_hash_b64: Optional[str] = None
    signer_pubkey_b64: str
    signature_b64: str
    http: Dict[str, Any] = Field(default_factory=dict)


class STH(BaseModel):
    tree_size: int
    merkle_root_b64: str
    ts: str
    signature_b64: str
    signer_pubkey_b64: str
