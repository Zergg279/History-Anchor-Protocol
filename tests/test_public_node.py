from __future__ import annotations

from fastapi.testclient import TestClient

from hap.api import create_app
from hap.config import Settings
from hap.crypto import generate_keypair
from hap.policy import mine_relay_pow, verify_relay_pow
from hap.records import create_signed_record
from hap.wallets import create_encrypted_wallet, decrypt_wallet


def settings(tmp_path, *, role="relay", bits=0, max_request=65536):
    return Settings(
        data_dir=str(tmp_path),
        role=role,
        node_name="test-node",
        max_request_bytes=max_request,
        max_record_bytes=49152,
        max_statement_chars=10000,
        write_requests_per_minute=50,
        relay_pow_bits=bits,
        allow_mainnet=False,
        allow_snapshot_import=False,
        expose_docs=False,
    )


def record(*, source="https://example.org", cid=None):
    wallet = generate_keypair()
    return create_signed_record(
        private_key=wallet.private_key,
        kind="claim",
        title="Public node test",
        statement="A signed test statement.",
        sources=[{"uri": source, "label": None}],
        evidence=[
            {
                "filename": "photo.jpg",
                "size": 42,
                "mime_type": "image/jpeg",
                "sha256": "11" * 32,
                "cid": cid,
            }
        ],
        tags=["hap:person-impact:none"],
        created_at="2026-07-18T20:00:00Z",
    )


def test_observer_is_read_only(tmp_path) -> None:
    client = TestClient(create_app(settings(tmp_path, role="observer")))
    response = client.post("/v1/records", json=record())
    assert response.status_code == 403
    assert client.get("/healthz").status_code == 200


def test_server_side_private_key_endpoints_do_not_exist(tmp_path) -> None:
    client = TestClient(create_app(settings(tmp_path)))
    assert client.post("/v1/wallets/generate").status_code == 404
    assert client.post("/v1/records/sign", json={}).status_code in {404, 405}


def test_relay_pow_is_enforced(tmp_path) -> None:
    item = record()
    bits = 10
    client = TestClient(create_app(settings(tmp_path, bits=bits)))
    assert client.post("/v1/records", json=item).status_code == 400
    nonce = mine_relay_pow(item["record_id"], bits)
    assert verify_relay_pow(item["record_id"], nonce, bits)
    response = client.post(
        "/v1/records", json=item, headers={"X-HAP-Relay-Nonce": nonce}
    )
    assert response.status_code == 200
    assert response.json()["classification"] == "unverified"


def test_public_node_rejects_retrieval_locators_and_unsafe_sources(tmp_path) -> None:
    client = TestClient(create_app(settings(tmp_path)))
    assert (
        client.post("/v1/records", json=record(cid="bafy-example")).status_code == 400
    )
    assert (
        client.post("/v1/records", json=record(source="file:///etc/passwd")).status_code
        == 400
    )


def test_body_limit(tmp_path) -> None:
    client = TestClient(create_app(settings(tmp_path, max_request=16384)))
    response = client.post(
        "/v1/records",
        content=b"x" * 17000,
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 413


def test_encrypted_wallet_round_trip() -> None:
    wallet = create_encrypted_wallet("correct horse battery staple")
    private_key = decrypt_wallet(wallet, "correct horse battery staple")
    signed = create_signed_record(
        private_key=private_key,
        kind="claim",
        title="Wallet",
        statement="Encrypted locally",
    )
    assert signed["author_id"] == wallet["author_id"]


def test_proof_bundle_can_be_checked_against_independent_bitcoin_rpc(tmp_path) -> None:
    from hap.service import HistoryAnchorService

    service = HistoryAnchorService(str(tmp_path / "node"))
    item = record(source="https://example.org")
    service.submit_record(item)
    batch = service.create_batch(network="signet")
    service.storage.add_anchor(
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
    bundle = service.proof_bundle_for_record(item["record_id"])
    assert bundle is not None

    class FakeRPC:
        def network(self):
            return "signet"

        def find_payload(
            self, txid, block_hash=None, expected_payload_hex=None, expected_vout=None
        ):
            assert txid == "aa" * 32
            assert expected_payload_hex == batch["payload_hex"]
            return batch["payload_hex"], {"confirmations": 6, "blockhash": "bb" * 32}, 0

        def block_context(self, block_hash):
            return {
                "block_hash": block_hash,
                "block_height": 100,
                "in_active_chain": True,
            }

    result = service.verify_proof_bundle_against_bitcoin(bundle, rpc=FakeRPC())
    assert result["all_proofs_valid"] is True
    assert result["any_bitcoin_anchor_verified"] is True


def test_bitcoin_payload_match_without_active_confirmation_is_not_verified(
    tmp_path,
) -> None:
    from hap.service import HistoryAnchorService

    service = HistoryAnchorService(str(tmp_path / "node-unconfirmed"))
    try:
        item = record(source="https://example.org")
        service.submit_record(item)
        batch = service.create_batch(network="signet")
        service.storage.add_anchor(
            {
                "txid": "cc" * 32,
                "vout": 0,
                "batch_id": batch["batch_id"],
                "network": "signet",
                "status": "broadcast",
                "anchored_at": 1,
                "block_hash": None,
                "block_height": None,
            }
        )
        bundle = service.proof_bundle_for_record(item["record_id"])
        assert bundle is not None

        class FakeRPC:
            def network(self):
                return "signet"

            def find_payload(
                self,
                txid,
                block_hash=None,
                expected_payload_hex=None,
                expected_vout=None,
            ):
                return batch["payload_hex"], {"confirmations": 0, "blockhash": None}, 0

        result = service.verify_proof_bundle_against_bitcoin(bundle, rpc=FakeRPC())
        assert result["any_bitcoin_payload_match"] is True
        assert result["any_bitcoin_anchor_verified"] is False
    finally:
        service.close()


def test_reorganised_anchor_is_not_reported_as_confirmed(tmp_path) -> None:
    from hap.service import HistoryAnchorService

    service = HistoryAnchorService(str(tmp_path / "node-reorg"))
    try:
        item = record(source="https://example.org")
        service.submit_record(item)
        batch = service.create_batch(network="signet")
        service.storage.add_anchor(
            {
                "txid": "12" * 32,
                "vout": 0,
                "batch_id": batch["batch_id"],
                "network": "signet",
                "status": "confirmed",
                "anchored_at": 1,
                "block_hash": "34" * 32,
                "block_height": 100,
            }
        )

        class FakeRPC:
            def network(self):
                return "signet"

            def find_payload(
                self,
                txid,
                block_hash=None,
                expected_payload_hex=None,
                expected_vout=None,
            ):
                assert block_hash == "34" * 32
                return (
                    batch["payload_hex"],
                    {
                        "confirmations": -1,
                        "blockhash": "34" * 32,
                    },
                    0,
                )

            def block_context(self, block_hash):
                return {
                    "block_hash": block_hash,
                    "block_height": 100,
                    "in_active_chain": False,
                }

        result = service.verify_bitcoin_anchor(batch["batch_id"], rpc=FakeRPC())
        assert result["verified"] is False
        assert result["payload_matches"] is True
        assert result["status"] == "reorganised"
        assert service.storage.anchor("12" * 32)["status"] == "reorganised"
    finally:
        service.close()


def test_rate_limiter_bounds_identity_memory() -> None:
    from hap.middleware import FixedWindowRateLimiter

    limiter = FixedWindowRateLimiter(requests=1, window_seconds=60, max_keys=2)
    assert limiter.allow("one") is True
    assert limiter.allow("two") is True
    assert limiter.allow("three") is False
    assert len(limiter.events) == 2


def test_funding_endpoint_is_informational_only(tmp_path) -> None:
    client = TestClient(create_app(settings(tmp_path, role="observer")))
    response = client.get("/v1/funding")
    assert response.status_code == 200
    value = response.json()
    assert value["schema"] == "hap.funding"
    assert value["consensus_effect"] is False
    assert value["governance_rights"] is False
    assert value["protocol_dependency"] is False
