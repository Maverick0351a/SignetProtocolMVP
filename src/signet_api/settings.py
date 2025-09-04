from __future__ import annotations
from pydantic_settings import BaseSettings
from pydantic import Field


class Settings(BaseSettings):
    chain_id: str = Field(default="dev-signet-1", alias="SIGNET_CHAIN_ID")
    storage_dir: str = Field(default="./storage", alias="SIGNET_STORAGE_DIR")

    signing_key_path: str = Field(
        default="./keys/ed25519_private.key", alias="SIGNET_SIGNING_KEY_PATH"
    )
    signing_pubkey_path: str = Field(
        default="./keys/ed25519_public.key", alias="SIGNET_SIGNING_PUBKEY_PATH"
    )

    ingress_hmac_path: str = Field(
        default="./keys/ingress_hmac.json", alias="SIGNET_INGRESS_HMAC_PATH"
    )
    ingress_max_skew: int = Field(default=300, alias="SIGNET_INGRESS_MAX_SKEW")
    ingress_max_body_bytes: int = Field(
        default=1048576, alias="SIGNET_INGRESS_MAX_BODY_BYTES"
    )

    # Maximum age for signature 'created' parameter (seconds)
    sig_max_skew_seconds: int = Field(default=300, alias="SIGNET_SIG_MAX_SKEW_SECONDS")

    # Global request size limit enforced by middleware (bytes)
    max_request_bytes: int = Field(default=262144, alias="SIGNET_MAX_REQUEST_BYTES")

    allow_dev_keygen: bool = Field(default=False, alias="SIGNET_ALLOW_DEV_KEYGEN")
    allow_missing_alg: bool = Field(default=False, alias="SIGNET_ALLOW_MISSING_ALG")

    log_level: str = Field(default="INFO", alias="SIGNET_LOG_LEVEL")

    class Config:
        env_file = ".env"
        case_sensitive = False


settings = Settings()  # load at import
