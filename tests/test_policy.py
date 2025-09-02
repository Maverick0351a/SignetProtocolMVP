import base64
import json
import hashlib
from fastapi.testclient import TestClient
from http_message_signatures import HTTPMessageSigner, algorithms


class _StaticResolver:
    def __init__(self, key_id: str, secret: bytes):
        self.key_id = key_id
        self.secret = secret

    def resolve_public_key(self, key_id: str):
        return self.secret

    def resolve_private_key(self, key_id: str):
        return self.secret


def _client(tmp_path, monkeypatch, secret: bytes):
    monkeypatch.setenv("SIGNET_STORAGE_DIR", str(tmp_path / "storage"))
    monkeypatch.setenv(
        "SIGNET_SIGNING_KEY_PATH", str(tmp_path / "keys/ed25519_private.key")
    )
    monkeypatch.setenv(
        "SIGNET_SIGNING_PUBKEY_PATH", str(tmp_path / "keys/ed25519_public.key")
    )
    monkeypatch.setenv(
        "SIGNET_INGRESS_HMAC_PATH", str(tmp_path / "keys/ingress_hmac.json")
    )
    (tmp_path / "keys").mkdir(parents=True, exist_ok=True)
    (tmp_path / "keys/ingress_hmac.json").write_text(
        json.dumps({"key_id": "k1", "secret_b64": base64.b64encode(secret).decode()})
    )
    from signet_api.main import app as _app

    return TestClient(_app)


def _signed(prepared_secret: bytes, payload):
    import requests

    req = requests.Request("POST", "http://testserver/vex/exchange", json=payload)
    prepared = req.prepare()
    d = hashlib.sha256(prepared.body).digest()
    prepared.headers["Content-Digest"] = f"sha-256=:{base64.b64encode(d).decode()}:"
    signer = HTTPMessageSigner(
        signature_algorithm=algorithms.HMAC_SHA256,
        key_resolver=_StaticResolver("k1", prepared_secret),
    )
    signer.sign(
        prepared,
        key_id="k1",
        covered_component_ids=("@method", "@path", "content-digest"),
    )
    prepared.headers.setdefault("host", "testserver")
    return prepared


def test_policy_blocked_payload_returns_403(tmp_path, monkeypatch):
    secret = b"0" * 32
    client = _client(tmp_path, monkeypatch, secret)
    prepared = _signed(secret, {"message": {"text": "blocked: deny"}})
    resp = client.post(
        "/vex/exchange", data=prepared.body, headers=dict(prepared.headers)
    )
    assert resp.status_code == 403, resp.text
