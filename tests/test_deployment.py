from __future__ import annotations

from fastapi.testclient import TestClient

from hap.api import create_app
from hap.config import Settings
from hap.crypto import generate_keypair
from hap.records import create_signed_record
from hap.service import HistoryAnchorService


def deployment_settings(
    tmp_path, *, role="relay", require_token=False, admin_token=None
):
    return Settings(
        data_dir=str(tmp_path),
        role=role,
        node_name="deployment-test",
        max_request_bytes=65536,
        max_record_bytes=49152,
        max_statement_chars=10000,
        write_requests_per_minute=50,
        relay_pow_bits=0,
        allow_mainnet=False,
        allow_snapshot_import=False,
        expose_docs=False,
        require_submission_token=require_token,
        submission_tokens=("submit-secret",) if require_token else (),
        admin_token=admin_token,
        allow_snapshot_export=False,
    )


def signed_record():
    wallet = generate_keypair()
    return create_signed_record(
        private_key=wallet.private_key,
        kind="claim",
        title="Private deployment",
        statement="A signed deployment-stage record.",
        tags=["hap:person-impact:none"],
        created_at="2026-07-18T20:00:00Z",
    )


def test_private_relay_submission_allowlist(tmp_path) -> None:
    settings = deployment_settings(tmp_path, require_token=True)
    with TestClient(create_app(settings)) as client:
        assert client.post("/v1/records", json=signed_record()).status_code == 401
        assert (
            client.post(
                "/v1/records",
                json=signed_record(),
                headers={"X-HAP-Submission-Token": "wrong"},
            ).status_code
            == 401
        )
        response = client.post(
            "/v1/records",
            json=signed_record(),
            headers={"X-HAP-Submission-Token": "submit-secret"},
        )
        assert response.status_code == 200
        assert response.json()["status"] == "accepted"


def test_coordinator_actions_require_bearer_admin_token(tmp_path) -> None:
    settings = deployment_settings(
        tmp_path, role="coordinator", admin_token="admin-secret"
    )
    with TestClient(create_app(settings)) as client:
        assert client.post("/v1/records", json=signed_record()).status_code == 200
        assert client.post("/v1/batches", json={"network": "signet"}).status_code == 401
        assert (
            client.post(
                "/v1/batches",
                json={"network": "signet"},
                headers={"Authorization": "Bearer wrong"},
            ).status_code
            == 401
        )
        response = client.post(
            "/v1/batches",
            json={"network": "signet"},
            headers={"Authorization": "Bearer admin-secret"},
        )
        assert response.status_code == 200
        assert response.json()["network"] == "signet"


def test_snapshot_export_is_not_an_open_http_endpoint(tmp_path) -> None:
    settings = deployment_settings(
        tmp_path, role="coordinator", admin_token="admin-secret"
    )
    with TestClient(create_app(settings)) as client:
        assert client.get("/v1/snapshot").status_code == 401
        response = client.get(
            "/v1/snapshot",
            headers={"Authorization": "Bearer admin-secret"},
        )
        assert response.status_code == 403


def test_readiness_checks_database(tmp_path) -> None:
    with TestClient(create_app(deployment_settings(tmp_path))) as client:
        response = client.get("/readyz")
        assert response.status_code == 200
        assert response.json()["checks"]["storage"]["database"] == "ok"


def test_local_database_backup_is_readable(tmp_path) -> None:
    service = HistoryAnchorService(str(tmp_path / "source"))
    try:
        service.submit_record(signed_record())
        backup = service.storage.backup_database(tmp_path / "backup.sqlite3")
        assert backup.exists()
        assert backup.stat().st_size > 0
    finally:
        service.close()


def test_sync_endpoints_are_cursor_ordered(tmp_path) -> None:
    settings = deployment_settings(tmp_path)
    with TestClient(create_app(settings)) as client:
        for index in range(3):
            wallet = generate_keypair()
            item = create_signed_record(
                private_key=wallet.private_key,
                kind="claim",
                title=f"Record {index}",
                statement=f"Statement {index}",
                tags=["hap:person-impact:none"],
                created_at=f"2026-07-18T20:00:0{index}Z",
            )
            assert client.post("/v1/records", json=item).status_code == 200
        first = client.get("/v1/sync/records", params={"limit": 2}).json()
        assert len(first["items"]) == 2
        cursor = first["cursor"]
        second = client.get(
            "/v1/sync/records",
            params={"limit": 2, "after_seq": cursor["seq"]},
        ).json()
        assert len(second["items"]) == 1


def test_peer_sync_cursor_state_is_persistent(tmp_path) -> None:
    service = HistoryAnchorService(str(tmp_path / "node"))
    try:
        service.storage.set_peer_sync_state(
            "peer-key",
            {
                "peer": "https://peer.example",
                "sync_epoch": "epoch-1",
                "records_seq": 12,
                "batches_seq": 7,
                "anchors_seq": 3,
            },
        )
        reopened = service.storage.peer_sync_state("peer-key")
        assert reopened is not None
        assert reopened["records_seq"] == 12
    finally:
        service.close()


def test_peer_anchor_status_is_untrusted_until_local_bitcoin_verification(
    tmp_path,
) -> None:
    service = HistoryAnchorService(str(tmp_path / "node"))
    try:
        item = signed_record()
        service.submit_record(item)
        batch = service.create_batch(network="signet")
        service.import_anchor_reference(
            {
                "txid": "aa" * 32,
                "vout": 0,
                "batch_id": batch["batch_id"],
                "network": "signet",
                "status": "confirmed",
                "anchored_at": 1,
                "block_hash": "bb" * 32,
                "block_height": 100,
            }
        )
        stored = service.storage.anchor("aa" * 32)
        assert stored is not None
        assert stored["status"] == "unverified"
    finally:
        service.close()


def test_records_reject_unknown_versioned_fields(tmp_path) -> None:
    item = signed_record()
    item["hidden_extension"] = {"deep": ["payload"]}
    with TestClient(create_app(deployment_settings(tmp_path))) as client:
        response = client.post("/v1/records", json=item)
        assert response.status_code == 400
        assert "fields do not match" in response.json()["detail"]


def test_canonical_encoding_rejects_excessive_nesting() -> None:
    from hap.codec import CanonicalEncodingError, canonical_json_bytes

    value: object = "leaf"
    for _ in range(40):
        value = [value]
    try:
        canonical_json_bytes(value)
    except CanonicalEncodingError as exc:
        assert "nesting" in str(exc)
    else:
        raise AssertionError("deeply nested JSON should be rejected")


def test_readiness_rejects_wrong_bitcoin_network(tmp_path, monkeypatch) -> None:
    import hap.api as api_module

    settings = deployment_settings(
        tmp_path, role="coordinator", admin_token="admin-secret"
    )
    settings = type(settings)(
        **{
            **settings.__dict__,
            "bitcoin_required_for_readiness": True,
            "bitcoin_expected_network": "signet",
        }
    )

    class FakeRPC:
        @classmethod
        def from_environment(cls):
            return cls()

        def network(self):
            return "regtest"

    monkeypatch.setattr(api_module, "BitcoinRPC", FakeRPC)
    with TestClient(create_app(settings)) as client:
        response = client.get("/readyz")
        assert response.status_code == 503
        assert response.json()["checks"]["bitcoin"]["status"] == "wrong-network"


def test_peer_cannot_overwrite_locally_verified_anchor_context(tmp_path) -> None:
    service = HistoryAnchorService(str(tmp_path / "node-anchor-context"))
    try:
        item = signed_record()
        service.submit_record(item)
        batch = service.create_batch(network="signet")
        service.storage.add_anchor(
            {
                "txid": "ab" * 32,
                "vout": 0,
                "batch_id": batch["batch_id"],
                "network": "signet",
                "status": "confirmed",
                "anchored_at": 100,
                "block_hash": "cd" * 32,
                "block_height": 200,
            }
        )
        service.import_anchor_reference(
            {
                "txid": "ab" * 32,
                "vout": 0,
                "batch_id": batch["batch_id"],
                "network": "signet",
                "status": "confirmed",
                "anchored_at": 999,
                "block_hash": "ef" * 32,
                "block_height": 999,
            }
        )
        stored = service.storage.anchor("ab" * 32)
        assert stored is not None
        assert stored["anchored_at"] == 100
        assert stored["block_hash"] == "cd" * 32
        assert stored["block_height"] == 200
    finally:
        service.close()
