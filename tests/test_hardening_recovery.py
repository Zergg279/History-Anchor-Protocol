from __future__ import annotations

import json
from copy import deepcopy

import pytest

from hap.archive import (
    SnapshotValidationError,
    calculate_snapshot_id,
    validate_snapshot,
)
from hap.crypto import generate_keypair
from hap.discovery import (
    _download_package,
    _find_common_ancestor,
    resolve_commitments,
    scan_bitcoin,
)
from hap.records import create_signed_record
from hap.service import HistoryAnchorService, ServiceError


def signed_claim():
    key = generate_keypair()
    return create_signed_record(
        private_key=key.private_key,
        kind="claim",
        title="claim",
        statement="statement",
        created_at="2026-07-19T10:00:00Z",
    )


def snapshot_with_state(tmp_path):
    service = HistoryAnchorService(str(tmp_path / "snapshot-source"))
    record = signed_claim()
    service.submit_record(record)
    batch = service.create_direct_batch(
        record_id=record["record_id"], network="regtest"
    )
    service.storage.add_anchor(
        {
            "txid": "aa" * 32,
            "vout": 0,
            "batch_id": batch["batch_id"],
            "network": "regtest",
            "status": "confirmed",
            "anchored_at": 1,
            "block_hash": "bb" * 32,
            "block_height": 1,
        }
    )
    value = service.export_snapshot()
    service.close()
    return value


def resign(snapshot):
    snapshot["snapshot_id"] = calculate_snapshot_id(snapshot)
    return snapshot


def test_snapshot_schema_and_integrity_failures(tmp_path):
    valid = snapshot_with_state(tmp_path)
    validate_snapshot(valid)
    cases = []
    cases.append(({"bad": True}, "fields"))
    bad = deepcopy(valid)
    bad["version"] = 2
    cases.append((bad, "unsupported"))
    bad = deepcopy(valid)
    bad["created_at"] = True
    cases.append((bad, "created_at"))
    for field in ("records", "batches", "anchors"):
        bad = deepcopy(valid)
        bad[field] = {}
        bad = resign(bad)
        cases.append((bad, "must be a list"))
    bad = deepcopy(valid)
    bad["snapshot_id"] = "00" * 32
    cases.append((bad, "snapshot_id"))
    for value, message in cases:
        with pytest.raises(SnapshotValidationError, match=message):
            validate_snapshot(value)


def test_snapshot_duplicate_and_missing_relationships(tmp_path):
    valid = snapshot_with_state(tmp_path)
    bad = deepcopy(valid)
    bad["records"].append(deepcopy(bad["records"][0]))
    resign(bad)
    with pytest.raises(SnapshotValidationError, match="duplicate record"):
        validate_snapshot(bad)

    targeted = deepcopy(valid)
    targeted["records"][0]["target_record_id"] = "11" * 32
    # Keep the nested record formally valid out of scope so the archive relation branch is isolated.
    import hap.archive as archive

    original = archive.validate_record
    archive.validate_record = lambda record: None
    try:
        resign(targeted)
        with pytest.raises(SnapshotValidationError, match="missing target"):
            validate_snapshot(targeted)
    finally:
        archive.validate_record = original

    bad = deepcopy(valid)
    bad["batches"].append(deepcopy(bad["batches"][0]))
    resign(bad)
    with pytest.raises(SnapshotValidationError, match="duplicate batch"):
        validate_snapshot(bad)
    bad = deepcopy(valid)
    bad["batches"][0]["record_ids"] = ["22" * 32]
    import hap.archive as archive2

    original_batch = archive2.validate_batch
    archive2.validate_batch = lambda batch: None
    try:
        resign(bad)
        with pytest.raises(SnapshotValidationError, match="record missing"):
            validate_snapshot(bad)
    finally:
        archive2.validate_batch = original_batch

    bad = deepcopy(valid)
    bad["anchors"].append(deepcopy(bad["anchors"][0]))
    resign(bad)
    with pytest.raises(SnapshotValidationError, match="duplicate anchor"):
        validate_snapshot(bad)
    bad = deepcopy(valid)
    bad["anchors"][0]["batch_id"] = "33" * 32
    import hap.archive as archive3

    original_anchor = archive3.validate_anchor_reference
    archive3.validate_anchor_reference = lambda anchor: None
    try:
        resign(bad)
        with pytest.raises(SnapshotValidationError, match="batch missing"):
            validate_snapshot(bad)
    finally:
        archive3.validate_anchor_reference = original_anchor


def test_common_ancestor_tolerates_missing_and_rpc_errors():
    class Storage:
        def scanned_block(self, height):
            return {2: {"block_hash": "two"}, 0: {"block_hash": "zero"}}.get(height)

    class Service:
        storage = Storage()

    class RPC:
        def block_hash(self, height):
            if height == 2:
                raise RuntimeError("temporary")
            return "zero" if height == 0 else "other"

    assert _find_common_ancestor(Service(), RPC(), 3) == 0

    class EmptyStorage:
        def scanned_block(self, height):
            return None

    class EmptyService:
        storage = EmptyStorage()

    assert _find_common_ancestor(EmptyService(), RPC(), 1) == -1


def test_scan_edges_and_malformed_transactions(tmp_path):
    service = HistoryAnchorService(str(tmp_path / "scan-edges"))

    class RPC:
        def network(self):
            return "regtest"

        def block_count(self):
            return 0

        def block_hash(self, height):
            return "00" * 32

        def block(self, block_hash, *, verbosity=2):
            return {
                "time": None,
                "tx": [
                    {"txid": 123, "vout": []},
                    {"txid": "aa" * 32, "vout": [{"scriptPubKey": {"hex": "6a01ff"}}]},
                ],
            }

    try:
        result = scan_bitcoin(service, rpc=RPC(), start_height=0, max_blocks=0)
        assert result["blocks_scanned"] == 1
        assert result["commitments_found"] == 0
        result = scan_bitcoin(service, rpc=RPC(), start_height=5, max_blocks=1)
        assert result["blocks_scanned"] == 0
    finally:
        service.close()


def test_download_package_stream_limits_and_shape(monkeypatch):
    class Response:
        def __init__(self, chunks):
            self.chunks = chunks

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def raise_for_status(self):
            return None

        def iter_bytes(self):
            yield from self.chunks

    class Client:
        chunks = [json.dumps({"ok": True}).encode()]

        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def stream(self, *args, **kwargs):
            return Response(self.chunks)

    monkeypatch.setattr("hap.discovery.httpx.Client", Client)
    monkeypatch.setattr("hap.discovery.validate_package", lambda value: None)
    assert _download_package("http://peer/", "id", max_bytes=100) == {"ok": True}
    Client.chunks = [b"[]"]
    with pytest.raises(ServiceError, match="not a JSON object"):
        _download_package("http://peer", "id", max_bytes=100)
    Client.chunks = [b"{}"]
    with pytest.raises(ServiceError, match="response limit"):
        _download_package("http://peer", "id", max_bytes=1)


def test_resolver_fallback_and_all_missing(monkeypatch):
    commitments = [
        {"batch_id": "aa" * 32, "txid": "11" * 32, "vout": 0},
        {"batch_id": "bb" * 32, "txid": "22" * 32, "vout": 1},
    ]

    class Storage:
        def commitments(self, **kwargs):
            return commitments

        def mark_commitment_resolved(self, txid, vout):
            self.marked = (txid, vout)

    class Service:
        storage = Storage()

        def import_package(self, package):
            self.imported = package

        def register_scanned_anchor(self, batch_id, txid, vout):
            self.anchor = (batch_id, txid, vout)

    calls = []

    def download(peer, batch_id, **kwargs):
        calls.append((peer, batch_id))
        if batch_id.startswith("aa") and peer.endswith("one"):
            raise RuntimeError("down")
        if batch_id.startswith("bb"):
            raise RuntimeError("missing")
        return {"batch": {"batch_id": batch_id}}

    monkeypatch.setattr("hap.discovery._download_package", download)
    service = Service()
    result = resolve_commitments(service, ["http://one", "http://two"])
    assert result["resolved"] == 1
    assert result["still_missing"] == 1
    assert len(result["errors"]) == 3
