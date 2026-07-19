from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

import hap.cli as cli


class FakeStorage:
    def backup_database(self, path):
        Path(path).write_text("db", encoding="utf-8")
        return Path(path)

    def check(self):
        return {"ok": True}

    def counts(self):
        return {"records": 1}


class FakeEvidenceStore:
    def add_file(self, path, *, max_bytes):
        return {"sha256": "ab" * 32, "path": str(path), "max_bytes": max_bytes}

    def store_stream(self, sha256, handle, *, max_bytes, expected_size):
        return {
            "sha256": sha256,
            "size": len(handle.read()),
            "max_bytes": max_bytes,
            "expected_size": expected_size,
        }

    def count(self):
        return 2


class FakeService:
    instances = []
    package_value = {"package_id": "pkg", "records": []}

    def __init__(self, directory):
        self.directory = directory
        self.closed = False
        self.storage = FakeStorage()
        self.evidence_store = FakeEvidenceStore()
        self.__class__.instances.append(self)

    def close(self):
        self.closed = True

    def submit_record(self, record, *, require_local_target=False):
        return {"status": "accepted", "record_id": record["record_id"]}

    def create_direct_batch(self, *, record_id, network):
        return {"batch_id": "ba" * 32, "record_id": record_id, "network": network}

    def package_for_batch(self, batch_id):
        if self.package_value is None:
            return None
        return {**self.package_value, "package_id": "pkg", "batch_id": batch_id}

    def anchor_batch(self, batch_id, *, allow_mainnet):
        return {"batch_id": batch_id, "allow_mainnet": allow_mainnet}

    def import_package(self, value):
        return {"status": "imported", "value": value}

    def export_snapshot(self):
        return {"snapshot_id": "cd" * 32, "records": []}

    def import_snapshot(self, value):
        return 3

    def verify_proof_bundle(self, value):
        return {"valid": True, "kind": "bundle"}

    def verify_package(self, *, record, proof):
        return {"valid": True, "proof": proof, "record": record}

    def verify_proof_bundle_against_bitcoin(self, value):
        return {"valid": True, "bitcoin": value}


class FakeStreamResponse:
    def __init__(self, chunks=(b"abc",)):
        self.chunks = chunks

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def raise_for_status(self):
        return None

    def iter_bytes(self):
        yield from self.chunks


def invoke(monkeypatch, *args):
    output = []
    monkeypatch.setattr(cli, "print_json", output.append)
    monkeypatch.setattr(sys, "argv", ["hap", *map(str, args)])
    cli.main()
    return output


def test_cli_helpers_and_http(monkeypatch, tmp_path):
    value = {"hello": "world"}
    target = cli.atomic_write_json(tmp_path / "x.json", value)
    assert target.exists()
    assert cli.load_json(str(target)) == value
    (tmp_path / "list.json").write_text("[]", encoding="utf-8")
    with pytest.raises(SystemExit, match="expected a JSON object"):
        cli.load_json(str(tmp_path / "list.json"))

    monkeypatch.delenv("MISSING", raising=False)
    assert cli.env_secret(None) is None
    with pytest.raises(SystemExit, match="empty or missing"):
        cli.env_secret("MISSING")
    monkeypatch.setenv("TOKEN", "secret")
    assert cli.env_secret("TOKEN") == "secret"
    assert cli.auth_headers(submission_token="s", admin_token="a") == {
        "X-HAP-Submission-Token": "s",
        "Authorization": "Bearer a",
    }

    file_path = tmp_path / "blob"
    file_path.write_bytes(b"abc")
    assert (
        cli.hash_file(file_path)
        == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )

    class Response:
        is_error = False
        status_code = 200
        text = "ok"

        def json(self):
            return {"ok": True}

    monkeypatch.setattr(cli.httpx, "request", lambda *a, **k: Response())
    assert cli.request("GET", "http://node/", "/x") == {"ok": True}
    assert cli.get("http://node", "/x") == {"ok": True}
    assert cli.post("http://node", "/x", {"a": 1}) == {"ok": True}
    Response.is_error = True
    Response.status_code = 418
    Response.text = "teapot"
    with pytest.raises(SystemExit, match="HTTP 418: teapot"):
        cli.request("GET", "http://node", "/x")


def test_wallet_password_and_submission_policy(monkeypatch):
    monkeypatch.setenv("PASS", "pw")
    assert cli.wallet_password("PASS", confirm=True) == "pw"
    monkeypatch.setenv("PASS", "")
    with pytest.raises(SystemExit, match="empty or missing"):
        cli.wallet_password("PASS")
    monkeypatch.delenv("PASS")
    prompts = iter(["pw", "pw"])
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt: next(prompts))
    assert cli.wallet_password(None, confirm=True) == "pw"
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt: "")
    with pytest.raises(SystemExit, match="cannot be empty"):
        cli.wallet_password(None)
    prompts = iter(["a", "b"])
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt: next(prompts))
    with pytest.raises(SystemExit, match="do not match"):
        cli.wallet_password(None, confirm=True)

    monkeypatch.setattr(
        cli, "get", lambda *a, **k: {"relay_policy": {"accepts_records": False}}
    )
    with pytest.raises(SystemExit, match="read-only"):
        cli.submit_signed_record("http://n", {"record_id": "id"}, None)

    monkeypatch.setattr(
        cli,
        "get",
        lambda *a, **k: {
            "relay_policy": {"accepts_records": True, "proof_of_work_bits": 4}
        },
    )
    monkeypatch.setattr(cli, "mine_relay_pow", lambda record_id, bits: "nonce")
    captured = {}
    monkeypatch.setattr(
        cli,
        "post",
        lambda url, path, value, headers: captured.update(headers=headers)
        or {"ok": True},
    )
    assert cli.submit_signed_record("http://n", {"record_id": "id"}, "token") == {
        "ok": True
    }
    assert captured["headers"]["X-HAP-Relay-Nonce"] == "nonce"


def test_serve_and_keygen_commands(monkeypatch, tmp_path):
    called = {}
    monkeypatch.setattr(
        cli.uvicorn, "run", lambda *a, **k: called.update(args=a, kwargs=k)
    )
    invoke(
        monkeypatch,
        "serve",
        "--data-dir",
        tmp_path,
        "--port",
        "9000",
        "--role",
        "archive",
        "--node-name",
        "test",
        "--relay-pow-bits",
        "4",
        "--write-rpm",
        "20",
        "--expose-docs",
        "--require-submission-token",
        "--peers",
        "http://a,http://b",
        "--sync-interval",
        "5",
        "--scan-interval",
        "6",
        "--scan-start-height",
        "7",
        "--resolve-interval",
        "8",
        "--serve-evidence",
        "--allow-mainnet",
        "--disable-responsible-profile",
        "--responsible-cooling-blocks",
        "9",
        "--responsible-notice-protection-blocks",
        "10",
        "--recognised-accountable-authors",
        "author",
    )
    assert called["kwargs"]["port"] == 9000
    assert cli.os.environ["HAP_ROLE"] == "archive"
    assert cli.os.environ["HAP_ALLOW_MAINNET"] == "1"
    assert cli.os.environ["HAP_RESPONSIBLE_PUBLICATION_PROFILE"] == "0"
    for name in tuple(cli.os.environ):
        if name.startswith("HAP_"):
            cli.os.environ.pop(name, None)

    wallet_path = tmp_path / "wallet.json"
    monkeypatch.setenv("PW", "secret")
    monkeypatch.setattr(
        cli, "create_encrypted_wallet", lambda password: {"author_id": "author"}
    )
    result = invoke(monkeypatch, "keygen", "--out", wallet_path, "--password-env", "PW")
    assert result[0]["author_id"] == "author"
    assert wallet_path.exists()
    with pytest.raises(SystemExit, match="refusing to overwrite"):
        invoke(monkeypatch, "keygen", "--out", wallet_path, "--password-env", "PW")
    invoke(
        monkeypatch, "keygen", "--out", wallet_path, "--password-env", "PW", "--force"
    )


def test_create_submit_and_remote_commands(monkeypatch, tmp_path):
    wallet = tmp_path / "wallet.json"
    wallet.write_text("{}", encoding="utf-8")
    evidence = tmp_path / "photo.jpg"
    evidence.write_bytes(b"picture")
    monkeypatch.setenv("PW", "secret")
    monkeypatch.setattr(cli, "decrypt_wallet", lambda wallet, password: "private")
    monkeypatch.setattr(
        cli,
        "create_signed_record",
        lambda **kwargs: {"record_id": "aa" * 32, "schema": "hap.record", **kwargs},
    )
    monkeypatch.setattr(
        cli, "submit_signed_record", lambda *a, **k: {"status": "accepted"}
    )
    out = tmp_path / "record.json"
    result = invoke(
        monkeypatch,
        "create",
        "--wallet",
        wallet,
        "--password-env",
        "PW",
        "--kind",
        "view_decision",
        "--title",
        "Title",
        "--statement",
        "Statement",
        "--target",
        "bb" * 32,
        "--source",
        "https://example.test",
        "--evidence",
        evidence,
        "--tag",
        "custom",
        "--person-impact",
        "direct",
        "--view-action",
        "enable-discovery",
        "--out",
        out,
    )
    assert result[0]["submission"]["status"] == "accepted"
    assert "hap:person-impact:direct" in result[0]["record"]["tags"]
    assert "hap:view:enable-discovery" in result[0]["record"]["tags"]
    assert out.exists()

    with pytest.raises(SystemExit, match="requires --view-action"):
        invoke(
            monkeypatch,
            "create",
            "--wallet",
            wallet,
            "--password-env",
            "PW",
            "--kind",
            "view_decision",
            "--title",
            "x",
            "--statement",
            "x",
        )
    with pytest.raises(SystemExit, match="only valid"):
        invoke(
            monkeypatch,
            "create",
            "--wallet",
            wallet,
            "--password-env",
            "PW",
            "--title",
            "x",
            "--statement",
            "x",
            "--view-action",
            "enable-discovery",
        )
    with pytest.raises(SystemExit, match="evidence file not found"):
        invoke(
            monkeypatch,
            "create",
            "--wallet",
            wallet,
            "--password-env",
            "PW",
            "--title",
            "x",
            "--statement",
            "x",
            "--evidence",
            tmp_path / "missing",
        )

    record_file = tmp_path / "submitted.json"
    record_file.write_text(json.dumps({"record_id": "id"}), encoding="utf-8")
    monkeypatch.setattr(
        cli, "submit_signed_record", lambda *a, **k: {"submitted": True}
    )
    assert invoke(monkeypatch, "submit", record_file)[0] == {"submitted": True}

    gets = []
    posts = []
    monkeypatch.setattr(
        cli,
        "get",
        lambda url, path, headers=None: gets.append(path)
        or ({"bundle_id": "bundle"} if "proof-bundle" in path else {"path": path}),
    )
    monkeypatch.setattr(
        cli,
        "post",
        lambda url, path, value, headers=None: posts.append((path, value, headers))
        or {"path": path},
    )

    for command, extra in [
        ("assessment", ["rid"]),
        ("responsible-view", ["rid"]),
        ("provenance", ["rid"]),
        ("show", ["rid"]),
        ("info", []),
        ("records", []),
        ("batches", []),
        ("ready", []),
        ("commitments", []),
        ("view-manifest", []),
    ]:
        invoke(monkeypatch, command, *extra)
    invoke(monkeypatch, "batch", "--network", "regtest", "--limit", "4")
    invoke(monkeypatch, "anchor", "bid")
    invoke(monkeypatch, "verify-anchor", "bid")
    assert any(path == "/v1/batches" for path, *_ in posts)
    assert invoke(monkeypatch, "funding")[0]["genesis_donation_address"].startswith(
        "bc1p"
    )
    bundle_out = tmp_path / "bundle.json"
    invoke(monkeypatch, "proof-bundle", "rid", "--out", bundle_out)
    assert json.loads(bundle_out.read_text())["bundle_id"] == "bundle"


def test_verify_commands(monkeypatch, tmp_path):
    monkeypatch.setattr(cli, "HistoryAnchorService", FakeService)
    monkeypatch.setattr(cli, "validate_proof_bundle_shape", lambda value: None)
    proof_bundle = tmp_path / "proof-bundle.json"
    proof_bundle.write_text(
        json.dumps({"schema": "hap.proof-bundle"}), encoding="utf-8"
    )
    assert invoke(monkeypatch, "verify", proof_bundle)[0]["kind"] == "bundle"

    record = tmp_path / "record.json"
    proof = tmp_path / "proof.json"
    record.write_text(
        json.dumps({"schema": "hap.record", "record_id": "id"}), encoding="utf-8"
    )
    proof.write_text(json.dumps({"proof": True}), encoding="utf-8")
    assert invoke(monkeypatch, "verify", record, "--proof", proof)[0]["valid"] is True
    assert (
        invoke(monkeypatch, "verify-bitcoin", proof_bundle)[0]["bitcoin"]["schema"]
        == "hap.proof-bundle"
    )
    assert all(instance.closed for instance in FakeService.instances)


def test_local_service_commands(monkeypatch, tmp_path):
    monkeypatch.setattr(cli, "HistoryAnchorService", FakeService)
    monkeypatch.setattr(
        cli,
        "sync_peer",
        lambda service, peer, page_size: SimpleNamespace(
            as_dict=lambda: {"peer": peer, "page_size": page_size}
        ),
    )
    monkeypatch.setattr(
        cli,
        "scan_bitcoin",
        lambda service, start_height, max_blocks: {
            "start": start_height,
            "max": max_blocks,
        },
    )
    monkeypatch.setattr(
        cli, "resolve_commitments", lambda service, peers: {"peers": list(peers)}
    )
    monkeypatch.setattr(
        cli, "export_survival_archive", lambda **kwargs: {"exported": kwargs["output"]}
    )
    monkeypatch.setattr(
        cli,
        "import_survival_archive",
        lambda **kwargs: {"imported": kwargs["archive_path"]},
    )

    record = tmp_path / "record.json"
    record.write_text(json.dumps({"record_id": "aa" * 32}), encoding="utf-8")
    package = tmp_path / "package.json"
    package.write_text(json.dumps({"package": True}), encoding="utf-8")
    snapshot = tmp_path / "snapshot.json"
    snapshot.write_text(json.dumps({"snapshot": True}), encoding="utf-8")
    evidence = tmp_path / "evidence.bin"
    evidence.write_bytes(b"abc")

    assert (
        invoke(
            monkeypatch,
            "sync",
            "--peer",
            "http://peer",
            "--data-dir",
            tmp_path,
            "--page-size",
            "5000",
        )[0]["page_size"]
        == 1000
    )
    assert invoke(
        monkeypatch,
        "scan-bitcoin",
        "--data-dir",
        tmp_path,
        "--start-height",
        "5",
        "--max-blocks",
        "9",
    )[0] == {"start": 5, "max": 9}
    assert invoke(
        monkeypatch, "resolve", "--data-dir", tmp_path, "--peers", "http://a, ,http://b"
    )[0]["peers"] == ["http://a", "http://b"]

    direct_out = tmp_path / "direct.json"
    monkeypatch.setenv("HAP_ALLOW_MAINNET", "true")
    direct_result = invoke(
        monkeypatch,
        "direct-anchor",
        record,
        "--data-dir",
        tmp_path,
        "--network",
        "mainnet",
        "--package-out",
        direct_out,
    )[0]
    assert direct_result["anchor"]["allow_mainnet"] is True
    assert direct_out.exists()

    package_out = tmp_path / "out-package.json"
    assert (
        invoke(
            monkeypatch, "package", "bid", "--data-dir", tmp_path, "--out", package_out
        )[0]["package_id"]
        == "pkg"
    )
    original = FakeService.package_value
    FakeService.package_value = None
    with pytest.raises(SystemExit, match="batch not found"):
        invoke(
            monkeypatch,
            "package",
            "missing",
            "--data-dir",
            tmp_path,
            "--out",
            package_out,
        )
    with pytest.raises(SystemExit, match="could not construct"):
        invoke(
            monkeypatch,
            "direct-anchor",
            record,
            "--data-dir",
            tmp_path,
            "--package-out",
            direct_out,
        )
    FakeService.package_value = original

    assert (
        invoke(monkeypatch, "import-package", package, "--data-dir", tmp_path)[0][
            "status"
        ]
        == "imported"
    )
    assert (
        invoke(
            monkeypatch,
            "evidence-add",
            evidence,
            "--data-dir",
            tmp_path,
            "--max-bytes",
            "10",
        )[0]["max_bytes"]
        == 10
    )

    monkeypatch.setattr(
        cli.httpx, "stream", lambda *a, **k: FakeStreamResponse((b"ab", b"c"))
    )
    fetched = invoke(
        monkeypatch,
        "evidence-fetch",
        "ab" * 32,
        "--peer",
        "http://peer",
        "--data-dir",
        tmp_path,
        "--expected-size",
        "3",
        "--max-bytes",
        "4",
    )[0]
    assert fetched["size"] == 3
    monkeypatch.setattr(
        cli.httpx, "stream", lambda *a, **k: FakeStreamResponse((b"abcde",))
    )
    with pytest.raises(SystemExit, match="exceeds"):
        invoke(
            monkeypatch,
            "evidence-fetch",
            "ab" * 32,
            "--peer",
            "http://peer",
            "--data-dir",
            tmp_path,
            "--max-bytes",
            "4",
        )

    backup_dir = tmp_path / "backup"
    assert (
        "snapshot"
        in invoke(
            monkeypatch, "backup", "--data-dir", tmp_path, "--out-dir", backup_dir
        )[0]
    )
    assert invoke(monkeypatch, "check", "--data-dir", tmp_path)[0]["evidence"] == 2
    assert (
        invoke(monkeypatch, "import", snapshot, "--data-dir", tmp_path)[0]["imported"]
        == 3
    )
    assert invoke(
        monkeypatch,
        "survival-export",
        "--data-dir",
        tmp_path,
        "--out",
        tmp_path / "survival.tar.gz",
    )[0]["exported"].endswith("survival.tar.gz")
    assert invoke(
        monkeypatch,
        "survival-import",
        tmp_path / "survival.tar.gz",
        "--data-dir",
        tmp_path,
        "--max-evidence-bytes",
        "10",
        "--max-metadata-bytes",
        "20",
    )[0]["imported"].endswith("survival.tar.gz")
    assert all(instance.closed for instance in FakeService.instances)
