from __future__ import annotations

from hap.batches import create_batch_manifest, validate_batch
from hap.bitcoin import (
    build_op_return_script,
    decode_anchor_payload,
    encode_anchor_payload,
    extract_payload_from_script,
)
from hap.crypto import generate_keypair
from hap.merkle import merkle_proof, merkle_root, verify_merkle_proof
from hap.records import create_signed_record, validate_record


def test_signed_record_round_trip() -> None:
    wallet = generate_keypair()
    record = create_signed_record(
        private_key=wallet.private_key,
        kind="claim",
        title="A test event",
        statement="This record exists for a test.",
        event_time="2026-07-18",
        sources=[{"uri": "https://example.org", "label": None}],
        evidence=[
            {
                "filename": "evidence.txt",
                "size": 5,
                "mime_type": "text/plain",
                "sha256": "00" * 32,
                "cid": None,
            }
        ],
        tags=["test"],
        created_at="2026-07-18T20:00:00Z",
    )
    validate_record(record)
    assert record["author_id"] == wallet.author_id
    assert len(record["record_id"]) == 64


def test_merkle_proofs() -> None:
    record_ids = [f"{number:064x}" for number in range(1, 6)]
    root = merkle_root(record_ids)
    for index, record_id in enumerate(record_ids):
        proof = merkle_proof(record_ids, index)
        assert verify_merkle_proof(record_id, proof, root)
        assert not verify_merkle_proof("ff" * 32, proof, root)


def test_batch_manifest_and_38_byte_anchor_round_trip() -> None:
    batch = create_batch_manifest(
        record_ids=[f"{number:064x}" for number in range(1, 4)],
        network="signet",
        created_at=1_721_330_000,
    )
    validate_batch(batch)
    payload = encode_anchor_payload(manifest_hash=batch["batch_id"])
    assert len(bytes.fromhex(payload)) == 38
    decoded = decode_anchor_payload(payload)
    assert decoded.manifest_hash == batch["batch_id"]
    script = build_op_return_script(payload)
    assert extract_payload_from_script(script) == payload


def test_bitcoin_rpc_scans_all_op_return_outputs_for_expected_payload() -> None:
    from hap.bitcoin import BitcoinRPC, build_op_return_script, encode_anchor_payload

    first = encode_anchor_payload(manifest_hash="11" * 32)
    expected = encode_anchor_payload(manifest_hash="22" * 32)
    rpc = BitcoinRPC(url="http://127.0.0.1:1")
    rpc.transaction = lambda txid, block_hash=None: {
        "vout": [
            {"scriptPubKey": {"hex": build_op_return_script(first)}},
            {"scriptPubKey": {"hex": build_op_return_script(expected)}},
        ]
    }
    found = rpc.find_payload("aa" * 32, expected_payload_hex=expected)
    assert found is not None
    assert found[0] == expected


def test_canonical_json_rejects_integer_outside_cross_language_safe_range() -> None:
    from hap.codec import (
        CanonicalEncodingError,
        MAX_SAFE_JSON_INTEGER,
        canonical_json_bytes,
    )

    assert canonical_json_bytes({"value": MAX_SAFE_JSON_INTEGER})
    try:
        canonical_json_bytes({"value": MAX_SAFE_JSON_INTEGER + 1})
    except CanonicalEncodingError as exc:
        assert "JSON-safe range" in str(exc)
    else:
        raise AssertionError("unsafe integer should be rejected")


def test_anchor_identity_includes_transaction_output(tmp_path) -> None:
    from hap.records import create_signed_record
    from hap.crypto import generate_keypair
    from hap.service import HistoryAnchorService

    service = HistoryAnchorService(str(tmp_path / "anchors"))
    try:
        key = generate_keypair()
        first_record = create_signed_record(
            private_key=key.private_key,
            kind="claim",
            title="First output",
            statement="First commitment in one transaction.",
        )
        second_record = create_signed_record(
            private_key=key.private_key,
            kind="claim",
            title="Second output",
            statement="Second commitment in one transaction.",
        )
        service.submit_record(first_record)
        service.submit_record(second_record)
        first_batch = service.create_direct_batch(
            record_id=first_record["record_id"], network="regtest"
        )
        second_batch = service.create_direct_batch(
            record_id=second_record["record_id"], network="regtest"
        )
        shared_txid = "ab" * 32
        service.storage.add_anchor(
            {
                "txid": shared_txid,
                "vout": 0,
                "batch_id": first_batch["batch_id"],
                "network": "regtest",
                "status": "confirmed",
                "anchored_at": 1,
                "block_hash": "cd" * 32,
                "block_height": 1,
            }
        )
        service.storage.add_anchor(
            {
                "txid": shared_txid,
                "vout": 2,
                "batch_id": second_batch["batch_id"],
                "network": "regtest",
                "status": "confirmed",
                "anchored_at": 1,
                "block_hash": "cd" * 32,
                "block_height": 1,
            }
        )
        assert (
            service.storage.anchor(shared_txid, 0)["batch_id"]
            == first_batch["batch_id"]
        )
        assert (
            service.storage.anchor(shared_txid, 2)["batch_id"]
            == second_batch["batch_id"]
        )
        assert len(service.storage.anchors()) == 2
    finally:
        service.close()


def test_context_kinds_require_targets() -> None:
    from hap.records import RecordValidationError

    for kind in (
        "subject_response",
        "person_impact_notice",
        "restriction_notice",
        "withdrawal_notice",
        "legal_adjudication",
        "public_interest_justification",
        "view_decision",
        "provenance_assertion",
    ):
        key = generate_keypair()
        try:
            create_signed_record(
                private_key=key.private_key,
                kind=kind,
                title=kind,
                statement="Missing target",
                created_at="2026-07-19T12:00:00Z",
            )
        except RecordValidationError:
            pass
        else:
            raise AssertionError(f"{kind} unexpectedly accepted without target")
