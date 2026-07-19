from __future__ import annotations

from copy import deepcopy

import pytest
from starlette.requests import Request

from hap.auth import (
    require_admin_token,
    require_submission_token,
    token_rate_key,
    trusted_client_ip,
)
from hap.batches import create_batch_manifest
from hap.codec import (
    CanonicalEncodingError,
    MAX_SAFE_JSON_INTEGER,
    canonical_json_bytes,
)
from hap.config import (
    Settings,
    _env_bool,
    _env_csv,
    _env_int,
    _read_secret,
    _read_tokens,
)
from hap.crypto import generate_keypair
from hap.merkle import merkle_proof, merkle_root, verify_merkle_proof
from hap.packages import (
    PackageValidationError,
    create_package,
    validate_package,
)
from hap.policy import (
    MAX_DECLARED_EVIDENCE_BYTES,
    PolicyError,
    leading_zero_bits,
    mine_relay_pow,
    relay_pow_digest,
    validate_safe_relay_record,
    verify_relay_pow,
)
from hap.records import create_signed_record
from hap.wallets import WalletError, create_encrypted_wallet, decrypt_wallet


def request(*, headers=None, client=("127.0.0.1", 1234)):
    raw_headers = [
        (name.lower().encode(), value.encode())
        for name, value in (headers or {}).items()
    ]
    return Request({"type": "http", "headers": raw_headers, "client": client})


def settings(tmp_path, **overrides):
    values = dict(
        data_dir=str(tmp_path),
        role="relay",
        node_name="x",
        max_request_bytes=65536,
        max_record_bytes=49152,
        max_statement_chars=10000,
        write_requests_per_minute=10,
        relay_pow_bits=0,
        allow_mainnet=False,
        allow_snapshot_import=False,
        expose_docs=False,
    )
    values.update(overrides)
    return Settings(**values)


def record(**overrides):
    key = generate_keypair()
    kwargs = dict(
        private_key=key.private_key,
        kind="claim",
        title="Title",
        statement="Statement",
        tags=["hap:person-impact:none"],
        created_at="2026-07-19T10:00:00Z",
    )
    kwargs.update(overrides)
    return create_signed_record(**kwargs)


def test_auth_submission_admin_tokens_and_rate_keys():
    req = request(headers={"X-HAP-Submission-Token": "good"})
    assert require_submission_token(req, False, ("good",)) == "good"
    assert require_submission_token(request(), False, ("good",)) is None
    assert require_submission_token(req, True, ("good",)) == "good"
    with pytest.raises(Exception) as exc:
        require_submission_token(request(), True, ("good",))
    assert exc.value.status_code == 401
    with pytest.raises(Exception) as exc:
        require_submission_token(
            request(headers={"X-HAP-Submission-Token": "bad"}), True, ("good",)
        )
    assert exc.value.status_code == 401

    with pytest.raises(Exception) as exc:
        require_admin_token(request(), None)
    assert exc.value.status_code == 503
    with pytest.raises(Exception) as exc:
        require_admin_token(request(headers={"Authorization": "Basic x"}), "secret")
    assert exc.value.status_code == 401
    require_admin_token(request(headers={"Authorization": "Bearer secret"}), "secret")

    assert token_rate_key(None) is None
    assert token_rate_key("secret").startswith("token:")
    assert token_rate_key("secret") == token_rate_key("secret")


def test_trusted_client_ip_proxy_rules():
    assert trusted_client_ip(request(client=None), ()) == "unknown"
    req = request(
        client=("203.0.113.9", 1), headers={"X-Forwarded-For": "198.51.100.2"}
    )
    assert trusted_client_ip(req, ()) == "203.0.113.9"
    assert trusted_client_ip(req, ("10.0.0.0/8",)) == "203.0.113.9"

    trusted = request(
        client=("127.0.0.1", 1),
        headers={"X-Forwarded-For": "198.51.100.2, 127.0.0.1"},
    )
    assert trusted_client_ip(trusted, ("127.0.0.0/8",)) == "198.51.100.2"
    no_header = request(client=("127.0.0.1", 1))
    assert trusted_client_ip(no_header, ("127.0.0.0/8",)) == "127.0.0.1"
    bad_header = request(client=("127.0.0.1", 1), headers={"X-Forwarded-For": "bad"})
    assert trusted_client_ip(bad_header, ("127.0.0.0/8",)) == "127.0.0.1"
    malformed_peer = request(
        client=("not-an-ip", 1), headers={"X-Forwarded-For": "1.1.1.1"}
    )
    assert trusted_client_ip(malformed_peer, ("0.0.0.0/0",)) == "not-an-ip"


def test_config_environment_helpers(tmp_path, monkeypatch):
    monkeypatch.delenv("BOOL", raising=False)
    assert _env_bool("BOOL", True) is True
    for value in ("1", "TRUE", " yes ", "on"):
        monkeypatch.setenv("BOOL", value)
        assert _env_bool("BOOL") is True
    monkeypatch.setenv("BOOL", "no")
    assert _env_bool("BOOL") is False

    monkeypatch.setenv("INT", "100")
    assert _env_int("INT", 5, 1, 10) == 10
    monkeypatch.setenv("INT", "-5")
    assert _env_int("INT", 5, 1, 10) == 1

    monkeypatch.setenv("SECRET", " value ")
    assert _read_secret("SECRET", "SECRET_FILE") == "value"
    monkeypatch.setenv("SECRET", " ")
    assert _read_secret("SECRET", "SECRET_FILE") is None
    monkeypatch.delenv("SECRET", raising=False)
    secret_file = tmp_path / "secret"
    secret_file.write_text("from-file\n")
    monkeypatch.setenv("SECRET_FILE", str(secret_file))
    assert _read_secret("SECRET", "SECRET_FILE") == "from-file"
    monkeypatch.delenv("SECRET_FILE")
    assert _read_secret("SECRET", "SECRET_FILE") is None

    monkeypatch.setenv("TOKENS", "a,b\na,,b,c")
    assert _read_tokens("TOKENS", "TOKENS_FILE") == ("a", "b", "c")
    monkeypatch.setenv("CSV", " a, ,b ")
    assert _env_csv("CSV") == ("a", "b")


def test_settings_validation_and_from_environment(tmp_path, monkeypatch):
    invalids = [
        (settings(tmp_path, role="bad"), "HAP_ROLE"),
        (settings(tmp_path, role="coordinator"), "ADMIN_TOKEN"),
        (settings(tmp_path, require_submission_token=True), "SUBMISSION_TOKENS"),
        (settings(tmp_path, bitcoin_expected_network="mars"), "EXPECTED_NETWORK"),
        (settings(tmp_path, bitcoin_expected_network="mainnet"), "mainnet"),
        (settings(tmp_path, peers=("peer",)), "HAP_PEERS"),
    ]
    for item, message in invalids:
        with pytest.raises(ValueError, match=message):
            item.validate()

    monkeypatch.setenv("HAP_DATA_DIR", str(tmp_path / "env"))
    monkeypatch.setenv("HAP_ROLE", "coordinator")
    monkeypatch.setenv("HAP_ADMIN_TOKEN", "admin")
    monkeypatch.setenv("HAP_PEERS", "https://one,http://two")
    monkeypatch.setenv("HAP_NODE_NAME", "n" * 200)
    monkeypatch.setenv("HAP_RECOGNISED_ACCOUNTABLE_AUTHORS", "b,a")
    value = Settings.from_environment()
    assert value.role == "coordinator"
    assert value.admin_token == "admin"
    assert value.peers == ("https://one", "http://two")
    assert len(value.node_name) == 120
    assert value.recognised_accountable_authors == ("b", "a")


def test_canonical_json_restrictions_and_determinism():
    assert canonical_json_bytes({"b": 1, "a": "é"}) == b'{"a":"\xc3\xa9","b":1}'
    with pytest.raises(CanonicalEncodingError, match="floating"):
        canonical_json_bytes({"x": 1.2})
    with pytest.raises(CanonicalEncodingError, match="safe range"):
        canonical_json_bytes(MAX_SAFE_JSON_INTEGER + 1)
    with pytest.raises(CanonicalEncodingError, match="keys must be strings"):
        canonical_json_bytes({1: "x"})
    with pytest.raises(CanonicalEncodingError, match="unsupported"):
        canonical_json_bytes({1, 2})
    value = None
    for _ in range(34):
        value = [value]
    with pytest.raises(CanonicalEncodingError, match="nesting"):
        canonical_json_bytes(value)


def test_merkle_edges_and_invalid_proofs():
    ids = ["11" * 32, "22" * 32, "33" * 32]
    assert merkle_root([]) == "00" * 32
    root = merkle_root(ids)
    for index, record_id in enumerate(ids):
        proof = merkle_proof(ids, index)
        assert verify_merkle_proof(record_id, proof, root)
    with pytest.raises(IndexError):
        merkle_proof(ids, 3)
    with pytest.raises(ValueError):
        merkle_root(["00"])
    proof = merkle_proof(ids, 0)
    bad = deepcopy(proof)
    bad[0]["sibling"] = "00"
    assert not verify_merkle_proof(ids[0], bad, root)
    bad = deepcopy(proof)
    bad[0]["side"] = "up"
    assert not verify_merkle_proof(ids[0], bad, root)
    assert not verify_merkle_proof("bad", proof, root)
    assert not verify_merkle_proof(ids[0], [{}], root)


def test_package_validation_failures():
    first = record(title="A")
    second = record(title="B")
    batch = create_batch_manifest(
        record_ids=[first["record_id"], second["record_id"]],
        network="regtest",
        created_at=1,
    )
    package = create_package(batch, [second, first])
    validate_package(package)

    cases = []
    bad = deepcopy(package)
    bad.pop("version")
    cases.append((bad, "fields"))
    bad = deepcopy(package)
    bad["schema"] = "x"
    cases.append((bad, "schema"))
    bad = deepcopy(package)
    bad["batch"] = []
    cases.append((bad, "batch is required"))
    bad = deepcopy(package)
    bad["records"] = []
    cases.append((bad, "non-empty"))
    bad = deepcopy(package)
    bad["records"] = bad["records"][:1]
    cases.append((bad, "count"))
    bad = deepcopy(package)
    bad["records"] = [bad["records"][0], bad["records"][0]]
    cases.append((bad, "duplicate"))
    bad = deepcopy(package)
    bad["records"].reverse()
    cases.append((bad, "exact committed"))
    bad = deepcopy(package)
    bad["package_id"] = "00" * 32
    cases.append((bad, "package_id"))
    for value, message in cases:
        with pytest.raises(PackageValidationError, match=message):
            validate_package(value)

    with pytest.raises(KeyError):
        create_package(batch, [first])


def test_safe_relay_policy_text_sources_evidence_and_pow(tmp_path):
    cfg = settings(tmp_path)
    valid = record(sources=[{"uri": "https://example.org", "label": "source"}])
    validate_safe_relay_record(valid, cfg)
    hap_source = record(sources=[{"uri": "hap:record:" + "11" * 32, "label": None}])
    validate_safe_relay_record(hap_source, cfg)

    cases = []
    bad = deepcopy(valid)
    bad["title"] = 1
    cases.append((bad, "title must be text"))
    bad = deepcopy(valid)
    bad["title"] = "x\n"
    cases.append((bad, "single line"))
    bad = deepcopy(valid)
    bad["statement"] = "x\x01"
    cases.append((bad, "control"))
    bad = deepcopy(valid)
    bad["statement"] = "x" * 10001
    cases.append((bad, "safe relay limit"))
    bad = deepcopy(valid)
    bad["event_time"] = "x\x00"
    cases.append((bad, "control"))
    bad = deepcopy(valid)
    bad["tags"] = ["x\n"]
    cases.append((bad, "single line"))
    bad = deepcopy(valid)
    bad["sources"] = [{"uri": "file:///x", "label": None}]
    cases.append((bad, "https"))
    bad = deepcopy(valid)
    bad["sources"] = [{"uri": "hap:record:bad", "label": None}]
    cases.append((bad, "32-byte"))
    bad = deepcopy(valid)
    bad["sources"] = [{"uri": "https:///x", "label": None}]
    cases.append((bad, "hostname"))
    bad = deepcopy(valid)
    bad["sources"] = [{"uri": "https://u:p@example.org", "label": None}]
    cases.append((bad, "credentials"))
    bad = deepcopy(valid)
    bad["sources"] = [{"uri": "https://e", "label": "x\n"}]
    cases.append((bad, "single line"))

    evidence = {
        "filename": "x.bin",
        "size": 1,
        "mime_type": None,
        "sha256": "11" * 32,
        "cid": None,
    }
    bad = record(evidence=[{**evidence, "filename": "../x"}])
    cases.append((bad, "path"))
    bad = record(evidence=[{**evidence, "size": MAX_DECLARED_EVIDENCE_BYTES + 1}])
    cases.append((bad, "ceiling"))
    bad = record(evidence=[{**evidence, "cid": "locator"}])
    cases.append((bad, "locators"))

    for value, message in cases:
        with pytest.raises(PolicyError, match=message):
            validate_safe_relay_record(value, cfg)

    tiny = settings(tmp_path, max_record_bytes=1)
    with pytest.raises(PolicyError, match="relay limit"):
        validate_safe_relay_record(valid, tiny)

    assert leading_zero_bits(b"\x00\x0f") == 12
    assert verify_relay_pow(valid["record_id"], None, 0)
    assert not verify_relay_pow(valid["record_id"], None, 1)
    assert not verify_relay_pow(valid["record_id"], "bad", 1)
    with pytest.raises(PolicyError, match="decimal"):
        relay_pow_digest(valid["record_id"], "bad")
    assert mine_relay_pow(valid["record_id"], 0) == "0"
    nonce = mine_relay_pow(valid["record_id"], 4, start=-2, max_attempts=1000)
    assert verify_relay_pow(valid["record_id"], nonce, 4)
    with pytest.raises(PolicyError, match="not found"):
        mine_relay_pow(valid["record_id"], 30, max_attempts=1)


def test_wallet_rejects_bad_password_format_and_metadata():
    with pytest.raises(WalletError, match="empty"):
        create_encrypted_wallet("")
    wallet = create_encrypted_wallet("password")
    assert decrypt_wallet(wallet, "password")

    cases = []
    bad = deepcopy(wallet)
    bad["schema"] = "x"
    cases.append((bad, "format"))
    bad = deepcopy(wallet)
    bad["author_id"] = "wrong"
    cases.append((bad, "author_id"))
    bad = deepcopy(wallet)
    bad["kdf"]["name"] = "pbkdf2"
    cases.append((bad, "encryption"))
    bad = deepcopy(wallet)
    bad["kdf"]["n"] = 1
    cases.append((bad, "KDF"))
    for value, message in cases:
        with pytest.raises(WalletError, match=message):
            decrypt_wallet(value, "password")

    with pytest.raises(WalletError, match="could not be decrypted"):
        decrypt_wallet(wallet, "wrong")
    bad = deepcopy(wallet)
    bad["cipher"]["nonce"] = "***"
    with pytest.raises(WalletError, match="could not be decrypted"):
        decrypt_wallet(bad, "password")
