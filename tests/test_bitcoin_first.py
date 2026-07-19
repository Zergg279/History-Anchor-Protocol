from __future__ import annotations


from hap.assessment import ASSESSMENT_RULE
from hap.bitcoin import build_op_return_script
from hap.crypto import generate_keypair
from hap.discovery import resolve_commitments, scan_bitcoin
from hap.records import create_signed_record
from hap.service import HistoryAnchorService
from hap.survival import export_survival_archive, import_survival_archive


def make_record(
    service: HistoryAnchorService, *, kind="claim", target=None, author=None
):
    author = author or generate_keypair()
    record = create_signed_record(
        private_key=author.private_key,
        kind=kind,
        title=f"{kind} record",
        statement=f"A {kind} statement.",
        target_record_id=target,
        created_at="2026-07-19T10:00:00Z",
    )
    service.submit_record(record, require_local_target=False)
    return record, author


class FakeChain:
    def __init__(self, payload_hex: str, *, network="regtest"):
        self.payload_hex = payload_hex
        self._network = network
        self.hashes = {0: "00" * 32, 1: "11" * 32}

    def network(self):
        return self._network

    def block_count(self):
        return 1

    def block_hash(self, height):
        return self.hashes[height]

    def block(self, block_hash, *, verbosity=2):
        height = 0 if block_hash == self.hashes[0] else 1
        tx = []
        if height == 1:
            tx = [
                {
                    "txid": "aa" * 32,
                    "vout": [
                        {
                            "n": 0,
                            "scriptPubKey": {
                                "hex": build_op_return_script(self.payload_hex)
                            },
                        }
                    ],
                }
            ]
        return {"height": height, "time": 100 + height, "tx": tx}


def test_bitcoin_scan_is_canonical_publication(tmp_path):
    service = HistoryAnchorService(str(tmp_path / "node"))
    record, _ = make_record(service)
    batch = service.create_direct_batch(
        record_id=record["record_id"], network="regtest"
    )
    result = scan_bitcoin(
        service, rpc=FakeChain(batch["payload_hex"]), start_height=0, max_blocks=10
    )
    assert result["commitments_found"] == 1
    assert service.storage.anchor("aa" * 32)["status"] == "confirmed"
    assert (
        service.record_assessment(record["record_id"])["classification"]
        == "bitcoin-anchored-claim"
    )


def test_package_is_portable_and_committed(tmp_path):
    source = HistoryAnchorService(str(tmp_path / "source"))
    record, _ = make_record(source)
    batch = source.create_direct_batch(record_id=record["record_id"], network="regtest")
    package = source.package_for_batch(batch["batch_id"])
    target = HistoryAnchorService(str(tmp_path / "target"))
    result = target.import_package(package)
    assert result["batch_id"] == batch["batch_id"]
    assert target.storage.record(record["record_id"]) == record


def test_resolve_fetches_package_for_bitcoin_commitment(tmp_path, monkeypatch):
    source = HistoryAnchorService(str(tmp_path / "source-resolve"))
    record, _ = make_record(source)
    batch = source.create_direct_batch(record_id=record["record_id"], network="regtest")
    package = source.package_for_batch(batch["batch_id"])

    target = HistoryAnchorService(str(tmp_path / "target-resolve"))
    target.storage.add_commitment(
        {
            "txid": "bb" * 32,
            "vout": 0,
            "batch_id": batch["batch_id"],
            "payload_hex": batch["payload_hex"],
            "network": "regtest",
            "block_height": 10,
            "block_hash": "cc" * 32,
            "block_time": 123,
            "status": "confirmed",
            "discovered_at": 123,
        }
    )
    monkeypatch.setattr(
        "hap.discovery._download_package", lambda *args, **kwargs: package
    )
    result = resolve_commitments(target, ["http://peer.invalid"])
    assert result["resolved"] == 1
    assert target.storage.anchor("bb" * 32)["status"] == "confirmed"


def test_assessment_uses_only_anchored_links(tmp_path):
    service = HistoryAnchorService(str(tmp_path / "assessment"))
    claim, _ = make_record(service)
    for _ in range(2):
        attestation, _ = make_record(
            service, kind="attestation", target=claim["record_id"]
        )
        batch = service.create_direct_batch(
            record_id=attestation["record_id"], network="regtest"
        )
        service.storage.add_anchor(
            {
                "txid": attestation["record_id"],
                "vout": 0,
                "batch_id": batch["batch_id"],
                "network": "regtest",
                "status": "confirmed",
                "anchored_at": 1,
                "block_hash": "dd" * 32,
                "block_height": 1,
            }
        )
    claim_batch = service.create_direct_batch(
        record_id=claim["record_id"], network="regtest"
    )
    service.storage.add_anchor(
        {
            "txid": claim["record_id"],
            "vout": 0,
            "batch_id": claim_batch["batch_id"],
            "network": "regtest",
            "status": "confirmed",
            "anchored_at": 1,
            "block_hash": "ee" * 32,
            "block_height": 1,
        }
    )
    assessment = service.record_assessment(claim["record_id"])
    assert assessment["rule"] == ASSESSMENT_RULE
    assert assessment["classification"] == "multi-attested"
    assert assessment["truth_determination"] == "not asserted by protocol"


def test_evidence_and_survival_archive_recover_bytes(tmp_path):
    source = HistoryAnchorService(str(tmp_path / "survival-source"))
    evidence_path = tmp_path / "evidence.bin"
    evidence_path.write_bytes(b"historical evidence")
    stored = source.evidence_store.add_file(evidence_path)
    record, _ = make_record(source)
    snapshot = source.export_snapshot()
    archive_path = tmp_path / "survival.tar.gz"
    export_survival_archive(
        snapshot=snapshot, evidence_store=source.evidence_store, output=archive_path
    )

    restored = HistoryAnchorService(str(tmp_path / "survival-restored"))
    result = import_survival_archive(
        archive_path=archive_path, service=restored, max_evidence_bytes=1024 * 1024
    )
    assert result["evidence"] == 1
    assert restored.evidence_store.verify(stored["sha256"])
    assert restored.storage.record(record["record_id"]) is not None


class FakeBroadcastRPC:
    def network(self):
        return "regtest"

    def broadcast_op_return(self, payload_hex):
        assert len(bytes.fromhex(payload_hex)) == 38
        return {
            "txid": "12" * 32,
            "vout": 0,
            "fee_btc": 0.00001,
            "raw_transaction": "00",
        }


def test_direct_anchor_is_one_record_bitcoin_publication(tmp_path):
    service = HistoryAnchorService(str(tmp_path / "direct"))
    record, _ = make_record(service)
    result = service.direct_anchor_record(
        record["record_id"], network="regtest", rpc=FakeBroadcastRPC()
    )
    assert result["batch"]["record_ids"] == [record["record_id"]]
    assert result["anchor"]["txid"] == "12" * 32
    assert service.storage.anchor("12" * 32)["status"] == "broadcast"


def test_scanner_rewinds_on_bitcoin_reorganisation(tmp_path):
    service = HistoryAnchorService(str(tmp_path / "reorg-scan"))
    record, _ = make_record(service)
    batch = service.create_direct_batch(
        record_id=record["record_id"], network="regtest"
    )
    chain = FakeChain(batch["payload_hex"])
    scan_bitcoin(service, rpc=chain, start_height=0, max_blocks=10)
    assert service.storage.anchor("aa" * 32)["status"] == "confirmed"

    chain.hashes[1] = "22" * 32
    # Replacement block contains no HAP commitment.
    chain.payload_hex = ""
    original_block = chain.block

    def replacement_block(block_hash, *, verbosity=2):
        if block_hash == chain.hashes[1]:
            return {"height": 1, "time": 202, "tx": []}
        return original_block(block_hash, verbosity=verbosity)

    chain.block = replacement_block
    scan_bitcoin(service, rpc=chain, start_height=0, max_blocks=10)
    assert service.storage.anchor("aa" * 32)["status"] == "reorganised"
    assert service.storage.commitments(limit=100) == []


def test_legacy_database_filename_migrates_in_place(tmp_path):
    legacy_dir = tmp_path / "legacy"
    legacy_dir.mkdir()
    first = HistoryAnchorService(str(legacy_dir))
    record, _ = make_record(first)
    first.close()
    current = legacy_dir / "hap.sqlite3"
    legacy = legacy_dir / "hap-v4.sqlite3"
    current.replace(legacy)
    restored = HistoryAnchorService(str(legacy_dir))
    try:
        assert restored.storage.db_path.name == "hap.sqlite3"
        assert restored.storage.record(record["record_id"]) is not None
    finally:
        restored.close()


def test_failed_survival_evidence_validation_does_not_import_protocol_state(tmp_path):
    source = HistoryAnchorService(str(tmp_path / "atomic-survival-source"))
    evidence_path = tmp_path / "large-evidence.bin"
    evidence_path.write_bytes(b"x" * 64)
    source.evidence_store.add_file(evidence_path)
    record, _ = make_record(source)
    archive_path = tmp_path / "atomic-survival.tar.gz"
    export_survival_archive(
        snapshot=source.export_snapshot(),
        evidence_store=source.evidence_store,
        output=archive_path,
    )
    restored = HistoryAnchorService(str(tmp_path / "atomic-survival-restored"))
    try:
        try:
            import_survival_archive(
                archive_path=archive_path,
                service=restored,
                max_evidence_bytes=32,
            )
        except Exception:
            pass
        else:
            raise AssertionError("oversized survival evidence should be rejected")
        assert restored.storage.record(record["record_id"]) is None
    finally:
        source.close()
        restored.close()


def test_schema_v3_anchor_migrates_to_output_aware_identity(tmp_path):
    import sqlite3

    data_dir = tmp_path / "schema-v3"
    data_dir.mkdir()
    db = sqlite3.connect(data_dir / "hap.sqlite3")
    try:
        db.executescript(
            """
            CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            INSERT INTO metadata(key, value) VALUES ('schema_version', '3');
            CREATE TABLE records (
                ingest_seq INTEGER PRIMARY KEY AUTOINCREMENT,
                record_id TEXT NOT NULL UNIQUE,
                kind TEXT NOT NULL,
                created_at TEXT NOT NULL,
                target_record_id TEXT,
                author_id TEXT NOT NULL,
                body TEXT NOT NULL
            );
            CREATE TABLE batches (
                ingest_seq INTEGER PRIMARY KEY AUTOINCREMENT,
                batch_id TEXT NOT NULL UNIQUE,
                created_at INTEGER NOT NULL,
                network TEXT NOT NULL,
                merkle_root TEXT NOT NULL,
                payload_hex TEXT NOT NULL,
                body TEXT NOT NULL
            );
            CREATE TABLE anchors (
                ingest_seq INTEGER PRIMARY KEY AUTOINCREMENT,
                txid TEXT NOT NULL UNIQUE,
                batch_id TEXT NOT NULL,
                network TEXT NOT NULL,
                status TEXT NOT NULL,
                anchored_at INTEGER NOT NULL,
                block_hash TEXT,
                block_height INTEGER
            );
            """
        )
        db.execute(
            "INSERT INTO batches(batch_id, created_at, network, merkle_root, payload_hex, body) "
            "VALUES (?, 1, 'regtest', ?, ?, '{}')",
            ("11" * 32, "22" * 32, "00"),
        )
        db.execute(
            "INSERT INTO anchors(txid, batch_id, network, status, anchored_at) "
            "VALUES (?, ?, 'regtest', 'unverified', 1)",
            ("aa" * 32, "11" * 32),
        )
        db.commit()
    finally:
        db.close()

    service = HistoryAnchorService(str(data_dir))
    try:
        assert service.storage.check()["schema_version"] == 4
        migrated = service.storage.anchor("aa" * 32, 0)
        assert migrated is not None
        assert migrated["vout"] == 0
    finally:
        service.close()


def test_scanner_preserves_multiple_hap_outputs_in_one_bitcoin_transaction(tmp_path):
    service = HistoryAnchorService(str(tmp_path / "multi-output-scan"))
    first, _ = make_record(service)
    second, _ = make_record(service)
    first_batch = service.create_direct_batch(
        record_id=first["record_id"], network="regtest"
    )
    second_batch = service.create_direct_batch(
        record_id=second["record_id"], network="regtest"
    )

    class MultiOutputChain(FakeChain):
        def block(self, block_hash, *, verbosity=2):
            height = 0 if block_hash == self.hashes[0] else 1
            tx = []
            if height == 1:
                tx = [
                    {
                        "txid": "fa" * 32,
                        "vout": [
                            {
                                "n": 0,
                                "scriptPubKey": {
                                    "hex": build_op_return_script(
                                        first_batch["payload_hex"]
                                    )
                                },
                            },
                            {
                                "n": 2,
                                "scriptPubKey": {
                                    "hex": build_op_return_script(
                                        second_batch["payload_hex"]
                                    )
                                },
                            },
                        ],
                    }
                ]
            return {"height": height, "time": 100 + height, "tx": tx}

    result = scan_bitcoin(
        service,
        rpc=MultiOutputChain(first_batch["payload_hex"]),
        start_height=0,
        max_blocks=10,
    )
    assert result["commitments_found"] == 2
    assert service.storage.anchor("fa" * 32, 0)["batch_id"] == first_batch["batch_id"]
    assert service.storage.anchor("fa" * 32, 2)["batch_id"] == second_batch["batch_id"]


def test_service_refuses_mainnet_anchor_without_explicit_opt_in(tmp_path):
    service = HistoryAnchorService(str(tmp_path / "mainnet-guard"))
    record, _ = make_record(service)
    batch = service.create_direct_batch(
        record_id=record["record_id"], network="mainnet"
    )

    class MainnetRPC(FakeBroadcastRPC):
        def network(self):
            return "mainnet"

    try:
        service.anchor_batch(batch["batch_id"], rpc=MainnetRPC())
    except Exception as exc:
        assert "mainnet anchoring is disabled" in str(exc)
    else:
        raise AssertionError("mainnet anchoring should require explicit opt-in")


def test_resolver_never_imports_wrong_commitment_package(tmp_path, monkeypatch):
    source = HistoryAnchorService(str(tmp_path / "wrong-source"))
    target = HistoryAnchorService(str(tmp_path / "wrong-target"))
    try:
        record, _ = make_record(source)
        wrong_batch = source.create_direct_batch(
            record_id=record["record_id"], network="regtest"
        )
        wrong_package = source.package_for_batch(wrong_batch["batch_id"])
        expected_batch_id = "99" * 32
        target.storage.add_commitment(
            {
                "txid": "88" * 32,
                "vout": 0,
                "batch_id": expected_batch_id,
                "payload_hex": build_op_return_script("00")[:0]
                + "484953540301"
                + expected_batch_id,
                "network": "regtest",
                "block_height": 10,
                "block_hash": "77" * 32,
                "block_time": 123,
                "status": "confirmed",
                "discovered_at": 123,
            }
        )
        monkeypatch.setattr(
            "hap.discovery._download_package", lambda *args, **kwargs: wrong_package
        )
        result = resolve_commitments(target, ["http://malicious.invalid"])
        assert result["resolved"] == 0
        assert result["still_missing"] == 1
        assert target.storage.batch(wrong_batch["batch_id"]) is None
        assert target.storage.record(record["record_id"]) is None
    finally:
        source.close()
        target.close()
