from fastapi.testclient import TestClient
import base64
import json
import hashlib
from http_message_signatures import HTTPMessageSigner, algorithms
from signet_cli.__main__ import StaticResolver
from tests._helpers import ensure_host_header


def test_exchange_roundtrip(tmp_path, monkeypatch):
    # point storage to temp
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
    secret = b"0" * 32
    (tmp_path / "keys/ingress_hmac.json").write_text(
        json.dumps({"key_id": "k1", "secret_b64": base64.b64encode(secret).decode()})
    )

    from signet_api.main import app as _app

    client = TestClient(_app)

    payload = {"message": {"text": "hi"}}
    import requests

    req = requests.Request("POST", "http://testserver/vex/exchange", json=payload)
    prepared = req.prepare()

    # add digest and sign with HMAC
    d = hashlib.sha256(prepared.body).digest()
    prepared.headers["Content-Digest"] = f"sha-256=:{base64.b64encode(d).decode()}:"
    signer = HTTPMessageSigner(
        signature_algorithm=algorithms.HMAC_SHA256,
        key_resolver=StaticResolver("k1", secret),
    )
    prepared = ensure_host_header(prepared)
    signer.sign(
        prepared,
        key_id="k1",
        covered_component_ids=("@method", "@path", "content-digest"),
    )

    # FastAPI TestClient expects path-only URL
    hdrs = dict(prepared.headers)
    hdrs.setdefault("host", "testserver")
    response = client.post("/vex/exchange", data=prepared.body, headers=hdrs)
    assert response.status_code == 200, response.text
    data = response.json()
    assert "signature_b64" in data


def _client_with_hmac(tmp_path, monkeypatch, secret: bytes = b"0" * 32):
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


def _signed_request(payload, secret: bytes):
    import requests

    req = requests.Request("POST", "http://testserver/vex/exchange", json=payload)
    prepared = req.prepare()
    d = hashlib.sha256(prepared.body).digest()
    prepared.headers["Content-Digest"] = f"sha-256=:{base64.b64encode(d).decode()}:"
    signer = HTTPMessageSigner(
        signature_algorithm=algorithms.HMAC_SHA256,
        key_resolver=StaticResolver("k1", secret),
    )
    prepared = ensure_host_header(prepared)
    signer.sign(
        prepared,
        key_id="k1",
        covered_component_ids=("@method", "@path", "content-digest"),
    )
    return prepared


def test_exchange_schema_validation(tmp_path, monkeypatch):
    client = _client_with_hmac(tmp_path, monkeypatch)
    prepared = _signed_request({"message": {"text": "ok"}}, b"0" * 32)
    r = client.post("/vex/exchange", data=prepared.body, headers=dict(prepared.headers))
    assert r.status_code == 200
    bad = _signed_request({"message": {1: "no"}}, b"0" * 32)  # type: ignore
    r2 = client.post("/vex/exchange", data=bad.body, headers=dict(bad.headers))
    assert r2.status_code == 400


def test_policy_blocked_prefix(tmp_path, monkeypatch):
    client = _client_with_hmac(tmp_path, monkeypatch)
    prepared = _signed_request({"message": {"text": "blocked:secret"}}, b"0" * 32)
    r = client.post("/vex/exchange", data=prepared.body, headers=dict(prepared.headers))
    assert r.status_code == 403


def test_verify_endpoint(tmp_path, monkeypatch):
    client = _client_with_hmac(tmp_path, monkeypatch)
    prepared = _signed_request({"message": {"text": "hello"}}, b"0" * 32)
    r = client.post("/vex/exchange", data=prepared.body, headers=dict(prepared.headers))
    assert r.status_code == 200
    receipt = r.json()
    vr = client.post("/vex/verify", json=receipt)
    assert vr.status_code == 200
    assert vr.json().get("signature_valid") is True


def test_receipt_signature_stable(tmp_path, monkeypatch):
    """Same payload should yield identical canonical hash; signatures verify."""
    client = _client_with_hmac(tmp_path, monkeypatch)
    secret = b"0" * 32
    p1 = _signed_request({"message": {"text": "stable"}}, secret)
    r1 = client.post("/vex/exchange", data=p1.body, headers=dict(p1.headers))
    assert r1.status_code == 200
    rec1 = r1.json()
    # Second request same payload
    p2 = _signed_request({"message": {"text": "stable"}}, secret)
    r2 = client.post("/vex/exchange", data=p2.body, headers=dict(p2.headers))
    assert r2.status_code == 200
    rec2 = r2.json()
    # Canonical payload hash should match
    assert rec1["payload_hash_b64"] == rec2["payload_hash_b64"]
    # Signatures must verify via /vex/verify
    v1 = client.post("/vex/verify", json=rec1)
    v2 = client.post("/vex/verify", json=rec2)
    assert v1.status_code == 200 and v1.json()["signature_valid"] is True
    assert v2.status_code == 200 and v2.json()["signature_valid"] is True


def test_provenance_missing_digest(tmp_path, monkeypatch):
    """Request lacking Content-Digest should be rejected with 401."""
    client = _client_with_hmac(tmp_path, monkeypatch)
    import requests
    from http_message_signatures import HTTPMessageSigner, algorithms
    from signet_cli.__main__ import StaticResolver

    secret = b"0" * 32
    payload = {"message": {"text": "no digest"}}
    req = requests.Request("POST", "http://testserver/vex/exchange", json=payload)
    prepared = req.prepare()
    # Intentionally omit Content-Digest
    signer = HTTPMessageSigner(
        signature_algorithm=algorithms.HMAC_SHA256,
        key_resolver=StaticResolver("k1", secret),
    )
    # We still sign method/path so signature headers exist
    signer.sign(
        prepared,
        key_id="k1",
        covered_component_ids=("@method", "@path"),
    )
    prepared.headers.setdefault("host", "testserver")
    resp = client.post(
        "/vex/exchange", data=prepared.body, headers=dict(prepared.headers)
    )
    assert resp.status_code == 401, resp.text
