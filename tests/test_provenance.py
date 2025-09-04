import base64
import json
import hashlib
from fastapi.testclient import TestClient
from http_message_signatures import HTTPMessageSigner, algorithms
from nacl.signing import SigningKey
from tests._helpers import ensure_host_header
from tests.crypto_compat import NaClToPEMResolver


class _StaticResolver:
    def __init__(self, key_id: str, secret: bytes):
        self.key_id = key_id
        self.secret = secret

    def resolve_public_key(self, key_id: str):
        return self.secret

    def resolve_private_key(self, key_id: str):
        return self.secret


def _client_hmac(tmp_path, monkeypatch, secret: bytes = b"0" * 32):
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


def _signed_request(
    payload, headers=None, *, alg=algorithms.HMAC_SHA256, key_id="k1", secret=b"0" * 32
):
    import requests

    req = requests.Request("POST", "http://testserver/vex/exchange", json=payload)
    prepared = req.prepare()
    d = hashlib.sha256(prepared.body).digest()
    prepared.headers["Content-Digest"] = f"sha-256=:{base64.b64encode(d).decode()}:"
    signer = HTTPMessageSigner(
        signature_algorithm=alg, key_resolver=_StaticResolver(key_id, secret)
    )
    covered = ("@method", "@path", "content-digest")
    import datetime as _dt

    signer.sign(
        prepared,
        key_id=key_id,
        covered_component_ids=covered,
        created=_dt.datetime.now(),
    )
    if headers:
        if isinstance(headers, dict):
            prepared.headers.update(headers)
    prepared.headers.setdefault("host", "testserver")
    prepared.headers.setdefault("content-type", "application/json")
    return prepared


def test_alg_missing_rejected(tmp_path, monkeypatch):
    monkeypatch.setenv("SIGNET_ALLOW_MISSING_ALG", "false")
    client = _client_hmac(tmp_path, monkeypatch)
    prepared = _signed_request({"message": {"text": "x"}}, b"0" * 32)
    # Remove alg="..." from Signature-Input header (force legacy style)
    si = prepared.headers.get("Signature-Input")
    if si and ";alg=" in si:
        si = ";".join(
            part for part in si.split(";") if not part.strip().startswith("alg=")
        )
        prepared.headers["Signature-Input"] = si
    r = client.post("/vex/exchange", data=prepared.body, headers=dict(prepared.headers))
    assert r.status_code == 401


def test_content_digest_mismatch(tmp_path, monkeypatch):
    client = _client_hmac(tmp_path, monkeypatch)
    prepared = _signed_request({"message": {"text": "digest-mismatch"}}, b"0" * 32)
    # Corrupt Content-Digest value
    prepared.headers["Content-Digest"] = "sha-256=:AAAA:"
    r = client.post("/vex/exchange", data=prepared.body, headers=dict(prepared.headers))
    assert r.status_code == 401


def test_ed25519_ok(tmp_path, monkeypatch):
    # Prepare Ed25519 keys and ingress pubkey map
    sk = SigningKey.generate()
    pk = sk.verify_key
    (tmp_path / "keys").mkdir(parents=True, exist_ok=True)
    (tmp_path / "keys/ingress_ed25519_pubkeys.json").write_text(
        json.dumps({"caller1": base64.b64encode(bytes(pk)).decode()})
    )
    monkeypatch.setenv(
        "SIGNET_INGRESS_ED25519_PUBKEYS_PATH",
        str(tmp_path / "keys/ingress_ed25519_pubkeys.json"),
    )
    # Configure storage & signing (server keys)
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

    from signet_api.main import app as _app

    client = TestClient(_app)
    import requests

    payload = {"message": {"text": "ed"}}
    req = requests.Request("POST", "http://testserver/vex/exchange", json=payload)
    prepared = req.prepare()
    d = hashlib.sha256(prepared.body).digest()
    prepared.headers["Content-Digest"] = f"sha-256=:{base64.b64encode(d).decode()}:"

    signer = HTTPMessageSigner(
        signature_algorithm=algorithms.ED25519, key_resolver=NaClToPEMResolver(sk)
    )
    import datetime as _dt

    prepared = ensure_host_header(prepared)
    signer.sign(
        prepared,
        key_id="caller1",
        covered_component_ids=(
            "@method",
            "@path",
            "content-digest",
            "content-type",
            "host",
        ),
        created=_dt.datetime.now(_dt.timezone.utc),
    )
    prepared.headers.setdefault("host", "testserver")
    r = client.post("/vex/exchange", data=prepared.body, headers=dict(prepared.headers))
    assert r.status_code == 200, r.text
