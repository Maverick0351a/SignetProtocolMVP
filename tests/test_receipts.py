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


def _hmac_client(tmp_path, monkeypatch, secret: bytes = b"0" * 32):
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


def _signed(payload, secret: bytes):
    import requests

    req = requests.Request("POST", "http://testserver/vex/exchange", json=payload)
    prepared = req.prepare()
    d = hashlib.sha256(prepared.body).digest()
    prepared.headers["Content-Digest"] = f"sha-256=:{base64.b64encode(d).decode()}:"
    signer = HTTPMessageSigner(
        signature_algorithm=algorithms.HMAC_SHA256,
        key_resolver=_StaticResolver("k1", secret),
    )
    signer.sign(
        prepared,
        key_id="k1",
        covered_component_ids=("@method", "@path", "content-digest"),
    )
    prepared.headers.setdefault("host", "testserver")
    return prepared


def test_prev_hash_linking(tmp_path, monkeypatch):
    client = _hmac_client(tmp_path, monkeypatch)
    s = b"0" * 32
    p1 = _signed({"message": {"text": "a"}}, s)
    r1 = client.post("/vex/exchange", data=p1.body, headers=dict(p1.headers))
    assert r1.status_code == 200
    rec1 = r1.json()
    p2 = _signed({"message": {"text": "b"}}, s)
    r2 = client.post("/vex/exchange", data=p2.body, headers=dict(p2.headers))
    assert r2.status_code == 200
    rec2 = r2.json()
    assert rec2.get("prev_receipt_hash_b64") == rec1.get("payload_hash_b64")


def test_content_type_and_size_limits(tmp_path, monkeypatch):
    # Ensure non-JSON is rejected and size limits enforce 413
    monkeypatch.setenv("SIGNET_INGRESS_MAX_BODY_BYTES", "10")
    client = _hmac_client(tmp_path, monkeypatch)
    # Non-JSON
    resp = client.post(
        "/vex/exchange",
        data=b"not-json",
        headers={"host": "testserver", "content-type": "text/plain"},
    )
    assert resp.status_code == 415
    # Oversized JSON
    big = {"message": {"text": "x" * 100}}
    import requests

    req = requests.Request("POST", "http://testserver/vex/exchange", json=big)
    prepared = req.prepare()
    prepared.headers["host"] = "testserver"
    resp2 = client.post(
        "/vex/exchange",
        data=prepared.body,
        headers={"host": "testserver", "content-type": "application/json"},
    )
    assert resp2.status_code == 413
