import base64
import hashlib
import json
from fastapi.testclient import TestClient
from http_message_signatures import HTTPMessageSigner, algorithms
from nacl.signing import SigningKey
from tests._helpers import ensure_host_header
from tests.conftest import NaClToPEMResolver  # type: ignore


def _client_ed25519(tmp_path, monkeypatch):
    # Configure server storage and signing keys
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
    monkeypatch.setenv("SIGNET_ALLOW_DEV_KEYGEN", "true")
    (tmp_path / "keys").mkdir(parents=True, exist_ok=True)
    from signet_api.main import app as _app

    return TestClient(_app)


def _ed25519_signer(sk: SigningKey):
    return NaClToPEMResolver(sk)


def _prep_request(payload, url="http://testserver/vex/exchange"):
    import requests

    req = requests.Request("POST", url, json=payload)
    p = req.prepare()
    d = hashlib.sha256(p.body).digest()
    p.headers["Content-Digest"] = f"sha-256=:{base64.b64encode(d).decode()}:"
    p.headers.setdefault("content-type", "application/json")
    ensure_host_header(p)
    return p


def test_ed25519_valid_path(tmp_path, monkeypatch):
    # Prepare Ed25519 signer and ingress pubkey map for caller
    sk = SigningKey.generate()
    pk = sk.verify_key
    (tmp_path / "keys").mkdir(parents=True, exist_ok=True)
    (tmp_path / "keys/ingress_ed25519_pubkeys.json").write_text(
        json.dumps({"caller-1": base64.b64encode(bytes(pk)).decode()})
    )
    monkeypatch.setenv(
        "SIGNET_INGRESS_ED25519_PUBKEYS_PATH",
        str(tmp_path / "keys/ingress_ed25519_pubkeys.json"),
    )
    client = _client_ed25519(tmp_path, monkeypatch)

    prepared = _prep_request({"message": {"text": "ok"}})
    signer = HTTPMessageSigner(
        signature_algorithm=algorithms.ED25519,
        key_resolver=_ed25519_signer(sk),
    )
    import datetime as _dt

    signer.sign(
        prepared,
        key_id="caller-1",
        covered_component_ids=(
            "@method",
            "@path",
            "content-digest",
            "content-type",
            "host",
        ),
        created=_dt.datetime.now(),
    )
    r = client.post("/vex/exchange", data=prepared.body, headers=dict(prepared.headers))
    assert r.status_code == 200, r.text
    data = r.json()
    assert "signature_b64" in data


def test_signature_missing_component(tmp_path, monkeypatch):
    sk = SigningKey.generate()
    pk = sk.verify_key
    (tmp_path / "keys").mkdir(parents=True, exist_ok=True)
    (tmp_path / "keys/ingress_ed25519_pubkeys.json").write_text(
        json.dumps({"caller-1": base64.b64encode(bytes(pk)).decode()})
    )
    client = _client_ed25519(tmp_path, monkeypatch)

    prepared = _prep_request({"message": {"text": "ok"}})
    signer = HTTPMessageSigner(
        signature_algorithm=algorithms.ED25519,
        key_resolver=_ed25519_signer(sk),
    )
    # Omit content-type from covered components
    import datetime as _dt

    signer.sign(
        prepared,
        key_id="caller-1",
        covered_component_ids=("@method", "@path", "content-digest", "host"),
        created=_dt.datetime.now(),
    )
    r = client.post("/vex/exchange", data=prepared.body, headers=dict(prepared.headers))
    assert r.status_code == 401


def test_signature_stale_created(tmp_path, monkeypatch):
    sk = SigningKey.generate()
    pk = sk.verify_key
    (tmp_path / "keys").mkdir(parents=True, exist_ok=True)
    (tmp_path / "keys/ingress_ed25519_pubkeys.json").write_text(
        json.dumps({"caller-1": base64.b64encode(bytes(pk)).decode()})
    )
    client = _client_ed25519(tmp_path, monkeypatch)

    prepared = _prep_request({"message": {"text": "old"}})
    signer = HTTPMessageSigner(
        signature_algorithm=algorithms.ED25519,
        key_resolver=_ed25519_signer(sk),
    )
    # created far in the past beyond default skew 300s
    import datetime as _dt

    signer.sign(
        prepared,
        key_id="caller-1",
        covered_component_ids=(
            "@method",
            "@path",
            "content-digest",
            "content-type",
            "host",
        ),
        created=_dt.datetime.now() - _dt.timedelta(seconds=100000),
    )
    r = client.post("/vex/exchange", data=prepared.body, headers=dict(prepared.headers))
    assert r.status_code == 401


def test_oversize_payload(tmp_path, monkeypatch):
    # lower the request limit to make a deterministic oversize case
    monkeypatch.setenv("SIGNET_MAX_REQUEST_BYTES", "512")
    client = _client_ed25519(tmp_path, monkeypatch)

    # Build an oversized payload (> 512 bytes after JSON serialization)
    big_text = "A" * 600
    prepared = _prep_request({"message": {"text": big_text}})
    # HMAC path is fine; middleware will reject before provenance
    from signet_cli.__main__ import StaticResolver

    secret = b"0" * 32
    signer = HTTPMessageSigner(
        signature_algorithm=algorithms.HMAC_SHA256,
        key_resolver=StaticResolver("k1", secret),
    )
    import datetime as _dt

    signer.sign(
        prepared,
        key_id="k1",
        covered_component_ids=(
            "@method",
            "@path",
            "content-digest",
            "content-type",
            "host",
        ),
        created=_dt.datetime.now(),
    )
    r = client.post("/vex/exchange", data=prepared.body, headers=dict(prepared.headers))
    assert r.status_code == 413
