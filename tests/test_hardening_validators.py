from __future__ import annotations

from copy import deepcopy

import pytest

from hap.anchors import AnchorValidationError, validate_anchor_reference
from hap.batches import (
    MAX_BATCH_RECORDS,
    BatchValidationError,
    create_batch_manifest,
    validate_batch,
)
from hap.bitcoin import encode_anchor_payload
from hap.crypto import generate_keypair
from hap.proofs import (
    ProofBundleError,
    calculate_proof_bundle_id,
    validate_proof_bundle_shape,
)
from hap.records import (
    MAX_EVIDENCE_ITEMS,
    MAX_SOURCES,
    MAX_TAGS,
    RecordValidationError,
    calculate_record_id,
    create_signed_record,
    normalize_list,
    validate_record,
)
from hap.service import HistoryAnchorService


def make_record(**overrides):
    key = generate_keypair()
    kwargs = {
        "private_key": key.private_key,
        "kind": "claim",
        "title": "Title",
        "statement": "Statement",
        "created_at": "2026-07-19T10:00:00Z",
    }
    kwargs.update(overrides)
    return create_signed_record(**kwargs)


def make_anchor():
    return {
        "txid": "11" * 32,
        "vout": 0,
        "batch_id": "22" * 32,
        "network": "regtest",
        "status": "confirmed",
        "anchored_at": 1,
        "block_hash": "33" * 32,
        "block_height": 2,
    }


def test_anchor_validation_accepts_valid_and_null_block_context():
    anchor = make_anchor()
    validate_anchor_reference(anchor)
    anchor["block_hash"] = None
    anchor["block_height"] = None
    validate_anchor_reference(anchor)


@pytest.mark.parametrize(
    "mutate,message",
    [
        (lambda a: a.pop("vout"), "fields"),
        (lambda a: a.__setitem__("txid", 1), "txid"),
        (lambda a: a.__setitem__("txid", "z" * 64), "hexadecimal"),
        (lambda a: a.__setitem__("vout", True), "vout"),
        (lambda a: a.__setitem__("vout", -1), "vout"),
        (lambda a: a.__setitem__("batch_id", "00"), "batch_id"),
        (lambda a: a.__setitem__("network", "mars"), "network"),
        (lambda a: a.__setitem__("status", "magic"), "status"),
        (lambda a: a.__setitem__("anchored_at", True), "anchored_at"),
        (lambda a: a.__setitem__("anchored_at", -1), "anchored_at"),
        (lambda a: a.__setitem__("block_hash", "x" * 64), "hexadecimal"),
        (lambda a: a.__setitem__("block_height", True), "block_height"),
        (lambda a: a.__setitem__("block_height", -1), "block_height"),
    ],
)
def test_anchor_validation_rejects_invalid_fields(mutate, message):
    anchor = make_anchor()
    mutate(anchor)
    with pytest.raises(AnchorValidationError, match=message):
        validate_anchor_reference(anchor)


def test_normalize_list():
    assert normalize_list(None, "x") == []
    assert normalize_list([1], "x") == [1]
    with pytest.raises(RecordValidationError, match="must be a list"):
        normalize_list("x", "field")


def test_record_validation_claim_and_target_rules():
    claim = make_record()
    validate_record(claim)
    claim["target_record_id"] = "11" * 32
    with pytest.raises(RecordValidationError, match="claim records cannot target"):
        validate_record(claim)

    dispute = make_record(kind="dispute", target_record_id="11" * 32)
    validate_record(dispute)
    dispute["target_record_id"] = None
    with pytest.raises(RecordValidationError, match="target_record_id"):
        validate_record(dispute)


@pytest.mark.parametrize(
    "mutate,message",
    [
        (lambda r: r.pop("title"), "fields"),
        (lambda r: r.__setitem__("schema", "x"), "schema"),
        (lambda r: r.__setitem__("version", 2), "version"),
        (lambda r: r.__setitem__("kind", "rumour"), "kind"),
        (lambda r: r.__setitem__("title", " "), "title is required"),
        (lambda r: r.__setitem__("created_at", "x" * 65), "too long"),
        (lambda r: r.__setitem__("created_at", "not-a-date"), "RFC 3339"),
        (lambda r: r.__setitem__("created_at", "2026-07-19T10:00:00"), "timezone"),
        (lambda r: r.__setitem__("event_time", 7), "event_time"),
        (lambda r: r.__setitem__("event_time", "x" * 513), "event_time"),
        (lambda r: r.__setitem__("title", "x" * 241), "title must"),
        (lambda r: r.__setitem__("statement", "x" * 100001), "too large"),
        (lambda r: r.__setitem__("author_public_key", "00"), "Ed25519"),
        (lambda r: r.__setitem__("author_public_key", "z" * 64), "hexadecimal"),
        (lambda r: r.__setitem__("author_id", "wrong"), "does not match"),
        (lambda r: r.__setitem__("sources", "x"), "sources must be a list"),
        (lambda r: r.__setitem__("evidence", "x"), "evidence must be a list"),
        (lambda r: r.__setitem__("tags", "x"), "tags must be a list"),
        (lambda r: r.__setitem__("tags", [""]), "invalid tags"),
        (lambda r: r.__setitem__("tags", ["x" * 65]), "invalid tags"),
        (lambda r: r.__setitem__("signature", 7), "signature"),
        (lambda r: r.__setitem__("record_id", "00"), "record_id"),
    ],
)
def test_record_validation_rejects_common_invalid_shapes(mutate, message):
    record = make_record()
    mutate(record)
    with pytest.raises(RecordValidationError, match=message):
        validate_record(record)


def test_record_validation_limits_and_source_fields():
    record = make_record()
    record["sources"] = [{"uri": "https://e", "label": None}] * (MAX_SOURCES + 1)
    with pytest.raises(RecordValidationError, match="at most"):
        validate_record(record)

    record = make_record()
    record["evidence"] = [
        {
            "filename": "x",
            "size": 1,
            "mime_type": None,
            "sha256": "11" * 32,
            "cid": None,
        }
    ] * (MAX_EVIDENCE_ITEMS + 1)
    with pytest.raises(RecordValidationError, match="at most"):
        validate_record(record)

    record = make_record()
    record["tags"] = ["x"] * (MAX_TAGS + 1)
    with pytest.raises(RecordValidationError, match="invalid tags"):
        validate_record(record)

    invalid_sources = [
        ([{"uri": "x"}], "source fields"),
        ([{"uri": "", "label": None}], "non-empty uri"),
        ([{"uri": "x" * 2049, "label": None}], "too long"),
        ([{"uri": "https://e", "label": 1}], "label"),
        ([{"uri": "https://e", "label": "x" * 241}], "label"),
    ]
    for sources, message in invalid_sources:
        record = make_record()
        record["sources"] = sources
        with pytest.raises(RecordValidationError, match=message):
            validate_record(record)


def test_record_validation_evidence_fields():
    base = {
        "filename": "x.bin",
        "size": 1,
        "mime_type": "application/octet-stream",
        "sha256": "11" * 32,
        "cid": None,
    }
    cases = [
        ({"filename": "x"}, "evidence fields"),
        ({**base, "sha256": "bad"}, "sha256"),
        ({**base, "filename": ""}, "filename"),
        ({**base, "filename": "x" * 256}, "filename"),
        ({**base, "size": True}, "size"),
        ({**base, "size": -1}, "size"),
        ({**base, "mime_type": 1}, "mime_type"),
        ({**base, "mime_type": "x" * 256}, "mime_type"),
        ({**base, "cid": 1}, "cid"),
        ({**base, "cid": "x" * 513}, "cid"),
    ]
    for evidence, message in cases:
        record = make_record()
        record["evidence"] = [evidence]
        with pytest.raises(RecordValidationError, match=message):
            validate_record(record)


def test_record_id_and_signature_failures_are_distinct():
    record = make_record()
    record["title"] = "changed"
    with pytest.raises(RecordValidationError, match="record_id does not match"):
        validate_record(record)

    record = make_record()
    record["signature"] = "00" * 64
    record["record_id"] = calculate_record_id(record)
    with pytest.raises(RecordValidationError, match="invalid record signature"):
        validate_record(record)
    validate_record(record, verify_signature=False)


def test_batch_validation_happy_and_empty_creation():
    batch = create_batch_manifest(
        record_ids=["22" * 32, "11" * 32], network="regtest", created_at=1
    )
    assert batch["record_ids"] == ["11" * 32, "22" * 32]
    validate_batch(batch)
    with pytest.raises(BatchValidationError, match="at least one"):
        create_batch_manifest(record_ids=[], network="regtest", created_at=1)


@pytest.mark.parametrize(
    "mutate,message",
    [
        (lambda b: b.pop("network"), "fields"),
        (lambda b: b.__setitem__("schema", "x"), "schema"),
        (lambda b: b.__setitem__("version", 9), "schema"),
        (lambda b: b.__setitem__("record_ordering", "x"), "ordering"),
        (lambda b: b.__setitem__("network", "x"), "network"),
        (lambda b: b.__setitem__("created_at", True), "created_at"),
        (lambda b: b.__setitem__("created_at", -1), "created_at"),
        (lambda b: b.__setitem__("record_ids", []), "non-empty"),
        (lambda b: b.__setitem__("record_ids", ["bad"]), "record_id"),
        (lambda b: b.__setitem__("record_ids", ["zz" * 32]), "hexadecimal"),
        (
            lambda b: b.__setitem__("record_ids", ["22" * 32, "11" * 32]),
            "lexicographic",
        ),
        (lambda b: b.__setitem__("record_ids", ["11" * 32, "11" * 32]), "duplicate"),
        (lambda b: b.__setitem__("record_count", 9), "record_count"),
        (lambda b: b.__setitem__("merkle_root", "00" * 32), "merkle_root"),
        (lambda b: b.__setitem__("algorithms", {}), "algorithm"),
        (lambda b: b.__setitem__("batch_id", "00" * 32), "batch_id does not match"),
        (lambda b: b.__setitem__("payload_hex", "00"), "invalid anchor payload"),
    ],
)
def test_batch_validation_rejects_invalid_fields(mutate, message):
    batch = create_batch_manifest(
        record_ids=["11" * 32, "22" * 32], network="regtest", created_at=1
    )
    mutate(batch)
    with pytest.raises(BatchValidationError, match=message):
        validate_batch(batch)


def test_batch_record_limit_and_payload_commitment_checks(monkeypatch):
    batch = create_batch_manifest(
        record_ids=["11" * 32], network="regtest", created_at=1
    )
    oversized = deepcopy(batch)
    oversized["record_ids"] = [f"{i:064x}" for i in range(MAX_BATCH_RECORDS + 1)]
    with pytest.raises(BatchValidationError, match="at most"):
        validate_batch(oversized)

    wrong_type = deepcopy(batch)
    wrong_type["payload_hex"] = encode_anchor_payload(
        manifest_hash=batch["batch_id"], commitment_type=2
    )
    with pytest.raises(BatchValidationError, match="commitment type"):
        validate_batch(wrong_type)

    wrong_hash = deepcopy(batch)
    wrong_hash["payload_hex"] = encode_anchor_payload(manifest_hash="ff" * 32)
    with pytest.raises(BatchValidationError, match="does not commit"):
        validate_batch(wrong_hash)


def make_bundle(tmp_path):
    with HistoryAnchorService(str(tmp_path / "node")) as service:
        record = make_record()
        service.submit_record(record)
        service.create_batch(network="regtest")
        bundle = service.proof_bundle_for_record(record["record_id"])
        assert bundle is not None
        return bundle


def refresh_bundle_id(bundle):
    bundle["bundle_id"] = calculate_proof_bundle_id(bundle)
    return bundle


def test_proof_bundle_validation_happy(tmp_path):
    bundle = make_bundle(tmp_path)
    validate_proof_bundle_shape(bundle)


@pytest.mark.parametrize(
    "mutate,message,refresh",
    [
        (lambda b: b.pop("version"), "fields", False),
        (lambda b: b.__setitem__("schema", "x"), "schema", False),
        (lambda b: b.__setitem__("version", 2), "schema", False),
        (lambda b: b.__setitem__("record", []), "record is required", False),
        (lambda b: b.__setitem__("proofs", {}), "proofs must be a list", False),
        (lambda b: b["proofs"].__setitem__(0, {}), "proof fields", True),
        (lambda b: b["proofs"][0].__setitem__("schema", "x"), "proof schema", True),
        (
            lambda b: b["proofs"][0].__setitem__("record_id", "00" * 32),
            "does not match",
            True,
        ),
        (lambda b: b["proofs"][0].__setitem__("index", True), "non-negative", True),
        (lambda b: b["proofs"][0].__setitem__("index", 99), "outside", True),
        (lambda b: b["proofs"][0].__setitem__("path", {}), "path is invalid", True),
        (lambda b: b["proofs"][0].__setitem__("path", [{}]), "step fields", True),
        (
            lambda b: b["proofs"][0].__setitem__("anchors", {}),
            "anchors must be a list",
            True,
        ),
        (lambda b: b.__setitem__("bundle_id", "00" * 32), "bundle_id", False),
    ],
)
def test_proof_bundle_validation_rejects_invalid(tmp_path, mutate, message, refresh):
    bundle = make_bundle(tmp_path)
    mutate(bundle)
    if refresh:
        refresh_bundle_id(bundle)
    with pytest.raises(
        (ProofBundleError, BatchValidationError, AnchorValidationError), match=message
    ):
        validate_proof_bundle_shape(bundle)


def test_proof_step_sibling_side_and_anchor_validation(tmp_path):
    bundle = make_bundle(tmp_path)
    proof = bundle["proofs"][0]
    proof["path"] = [{"sibling": "bad", "side": "left"}]
    refresh_bundle_id(bundle)
    with pytest.raises(ProofBundleError, match="proof sibling"):
        validate_proof_bundle_shape(bundle)

    bundle = make_bundle(tmp_path)
    proof = bundle["proofs"][0]
    proof["path"] = [{"sibling": "11" * 32, "side": "up"}]
    refresh_bundle_id(bundle)
    with pytest.raises(ProofBundleError, match="left or right"):
        validate_proof_bundle_shape(bundle)

    bundle = make_bundle(tmp_path)
    bundle["proofs"][0]["anchors"] = [{"bad": True}]
    refresh_bundle_id(bundle)
    with pytest.raises(AnchorValidationError, match="fields"):
        validate_proof_bundle_shape(bundle)
