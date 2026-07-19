from __future__ import annotations

import json
from pathlib import Path

from hap.batches import create_batch_manifest, validate_batch
from hap.codec import canonical_json_bytes
from hap.crypto import derive_public_key, public_key_to_author_id
from hap.records import create_signed_record, signing_body, validate_record
from hap.packages import create_package, validate_package


def test_v1_conformance_vector() -> None:
    vector = json.loads(
        Path("conformance/v1.0-vector.json").read_text(encoding="utf-8")
    )
    private_key = vector["test_private_key_base64"]
    assert derive_public_key(private_key) == vector["expected_public_key_hex"]
    assert (
        public_key_to_author_id(vector["expected_public_key_hex"])
        == vector["expected_author_id"]
    )

    expected = vector["record"]
    regenerated = create_signed_record(
        private_key=private_key,
        kind=expected["kind"],
        title=expected["title"],
        statement=expected["statement"],
        event_time=expected["event_time"],
        target_record_id=expected["target_record_id"],
        sources=expected["sources"],
        evidence=expected["evidence"],
        tags=expected["tags"],
        created_at=expected["created_at"],
    )
    assert regenerated == expected
    assert (
        canonical_json_bytes(signing_body(regenerated)).hex()
        == vector["canonical_signing_body_hex"]
    )
    validate_record(regenerated)

    batch = create_batch_manifest(
        record_ids=vector["batch"]["record_ids"],
        network=vector["batch"]["network"],
        created_at=vector["batch"]["created_at"],
    )
    assert batch == vector["batch"]
    validate_batch(batch)


def test_v1_package_conformance_vector() -> None:
    vector = json.loads(
        Path("conformance/v1.0-vector.json").read_text(encoding="utf-8")
    )
    package = create_package(vector["batch"], [vector["record"]])
    assert package == vector["package"]
    validate_package(package)


def test_responsible_publication_conformance_vector() -> None:
    from hap.responsible import assess_responsible_publication

    value = json.loads(Path("conformance/v1.0-responsible-vector.json").read_text())
    inputs = value["inputs"]
    result = assess_responsible_publication(
        record=inputs["record"],
        linked_records=inputs["linked_records"],
        anchored_record_ids=set(inputs["anchored_record_ids"]),
        anchor_heights={
            key: int(item) for key, item in inputs["anchor_heights"].items()
        },
        chain_height=inputs["chain_height"],
        recognised_accountable_authors=tuple(inputs["recognised_accountable_authors"]),
        cooling_blocks=inputs["cooling_blocks"],
    )
    assert result == value["expected"]


def test_provenance_conformance_vector() -> None:
    from hap.provenance import build_provenance_graph

    value = json.loads(Path("conformance/v1.0-provenance-vector.json").read_text())
    inputs = value["inputs"]
    result = build_provenance_graph(
        record=inputs["record"],
        all_records=inputs["all_records"],
        linked_records=inputs["linked_records"],
        anchored_record_ids=set(inputs["anchored_record_ids"]),
    )
    assert result == value["expected"]
