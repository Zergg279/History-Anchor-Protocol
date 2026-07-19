from __future__ import annotations

from hap.crypto import generate_keypair
from hap.records import create_signed_record
from hap.service import HistoryAnchorService


def make_records(service: HistoryAnchorService, count: int = 3):
    wallet = generate_keypair()
    records = []
    for index in range(count):
        record = create_signed_record(
            private_key=wallet.private_key,
            kind="claim",
            title=f"Claim {index}",
            statement=f"Statement {index}",
            event_time="2026-07-18",
            created_at=f"2026-07-18T20:00:0{index}Z",
        )
        service.submit_record(record)
        records.append(record)
    return records


def test_submit_batch_and_verify(tmp_path) -> None:
    service = HistoryAnchorService(str(tmp_path / "source"))
    records = make_records(service)
    batch = service.create_batch(network="regtest")
    assert batch["record_count"] == 3
    proof = service.proof_for_record(records[1]["record_id"])
    assert proof is not None
    result = service.verify_package(record=records[1], proof=proof)
    assert result["valid_structure"] is True
    assert result["checks"]["batch_manifest"] is True
    assert result["checks"]["merkle_membership"] is True
    assert result["checks"]["anchor_payload"] is True


def test_dispute_requires_existing_target(tmp_path) -> None:
    service = HistoryAnchorService(str(tmp_path))
    wallet = generate_keypair()
    dispute = create_signed_record(
        private_key=wallet.private_key,
        kind="dispute",
        title="Dispute",
        statement="I dispute this record.",
        target_record_id="11" * 32,
    )
    try:
        service.submit_record(dispute)
    except ValueError as exc:
        assert "does not exist" in str(exc)
    else:
        raise AssertionError("missing target should be rejected")


def test_one_node_snapshot_recovery(tmp_path) -> None:
    source = HistoryAnchorService(str(tmp_path / "source"))
    records = make_records(source, 4)
    source.create_batch(network="regtest")
    snapshot = source.export_snapshot()

    restored = HistoryAnchorService(str(tmp_path / "restored"))
    result = restored.import_snapshot(snapshot)
    assert result == {"records": 4, "batches": 1, "anchors": 0}
    assert restored.storage.counts() == source.storage.counts()

    proof = restored.proof_for_record(records[2]["record_id"])
    assert proof is not None
    assert (
        restored.verify_package(record=records[2], proof=proof)["valid_structure"]
        is True
    )


def test_record_can_appear_in_multiple_batches(tmp_path) -> None:
    service = HistoryAnchorService(str(tmp_path))
    record = make_records(service, 1)[0]
    first = service.create_batch(network="regtest")
    # A separate coordinator may independently batch the same record.
    from hap.batches import create_batch_manifest

    second = create_batch_manifest(
        record_ids=[record["record_id"]],
        network="regtest",
        created_at=first["created_at"] + 1,
    )
    service.storage.add_batch(second)
    assert len(service.proofs_for_record(record["record_id"])) == 2


def test_snapshot_recovery_does_not_trust_exported_anchor_status(tmp_path) -> None:
    source = HistoryAnchorService(str(tmp_path / "source-anchor"))
    restored = HistoryAnchorService(str(tmp_path / "restored-anchor"))
    try:
        record = make_records(source, 1)[0]
        batch = source.create_batch(network="regtest")
        source.storage.add_anchor(
            {
                "txid": "dd" * 32,
                "vout": 0,
                "batch_id": batch["batch_id"],
                "network": "regtest",
                "status": "confirmed",
                "anchored_at": 1,
                "block_hash": "ee" * 32,
                "block_height": 10,
            }
        )
        snapshot = source.export_snapshot()
        restored.import_snapshot(snapshot)
        imported = restored.storage.anchor("dd" * 32)
        assert imported is not None
        assert imported["status"] == "unverified"
        assert restored.storage.record(record["record_id"]) is not None
    finally:
        source.close()
        restored.close()


def test_batch_creation_respects_package_size_policy(tmp_path) -> None:
    service = HistoryAnchorService(str(tmp_path / "package-policy"))
    try:
        records = make_records(service, 3)
        batch = service.create_batch(
            network="regtest", limit=3, max_package_bytes=5_000
        )
        assert 1 <= batch["record_count"] < 3
        assert set(batch["record_ids"]).issubset(
            {item["record_id"] for item in records}
        )
    finally:
        service.close()
