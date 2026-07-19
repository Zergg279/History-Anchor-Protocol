from __future__ import annotations

from typing import Any

ASSESSMENT_RULE = "hap-evidence-assessment-v1"


def assess_record(
    *,
    record: dict[str, Any],
    linked_records: list[dict[str, Any]],
    anchored_record_ids: set[str],
    available_evidence: set[str],
) -> dict[str, Any]:
    """Return a deterministic evidence-state summary.

    This deliberately does not declare arbitrary real-world claims true. It reports only
    reproducible protocol facts: publication in Bitcoin, signed support/dispute links,
    corrections, and local byte-for-byte evidence availability.
    """
    record_id = record["record_id"]
    anchored = record_id in anchored_record_ids
    anchored_links = [
        item for item in linked_records if item["record_id"] in anchored_record_ids
    ]
    attestations = [item for item in anchored_links if item["kind"] == "attestation"]
    disputes = [item for item in anchored_links if item["kind"] == "dispute"]
    corrections = [item for item in anchored_links if item["kind"] == "correction"]
    distinct_attesters = sorted(
        {
            item["author_id"]
            for item in attestations
            if item["author_id"] != record["author_id"]
        }
    )
    evidence = record.get("evidence", [])
    verified_evidence = sorted(
        {item["sha256"] for item in evidence if item["sha256"] in available_evidence}
    )

    if not anchored:
        classification = "unpublished"
    elif disputes:
        classification = "contested"
    elif corrections:
        classification = "corrected"
    elif len(distinct_attesters) >= 2:
        classification = "multi-attested"
    elif len(distinct_attesters) == 1:
        classification = "attested"
    else:
        classification = "bitcoin-anchored-claim"

    return {
        "schema": "hap.assessment",
        "version": 1,
        "rule": ASSESSMENT_RULE,
        "record_id": record_id,
        "classification": classification,
        "cryptographic_facts": {
            "record_signature_valid": True,
            "bitcoin_anchor_confirmed": anchored,
            "evidence_items_committed": len(evidence),
            "evidence_items_available_and_hash_verified": len(verified_evidence),
        },
        "evidence_graph": {
            "anchored_attestations": len(attestations),
            "distinct_attesting_keys": len(distinct_attesters),
            "attester_independence_proven": False,
            "anchored_disputes": len(disputes),
            "anchored_corrections": len(corrections),
        },
        "verified_evidence_sha256": verified_evidence,
        "truth_determination": "not asserted by protocol",
        "note": (
            "The classification is reproducible from signed, Bitcoin-anchored protocol data. "
            "Multiple keys do not prove multiple independent people. It is not an oracle or a declaration "
            "that an external-world interpretation is objectively true."
        ),
    }
