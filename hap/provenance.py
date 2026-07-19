from __future__ import annotations

from typing import Any

PROVENANCE_GRAPH = "hap-provenance-graph-v1"
RULESET_PREFIX = "hap:analysis-ruleset:"
CONFIDENCE_PREFIX = "hap:analysis-confidence:"


def _ruleset(record: dict[str, Any]) -> str | None:
    for tag in record.get("tags", []):
        if isinstance(tag, str) and tag.startswith(RULESET_PREFIX):
            value = tag.removeprefix(RULESET_PREFIX)
            return value or None
    return None


def _confidence(record: dict[str, Any]) -> int | None:
    for tag in record.get("tags", []):
        if isinstance(tag, str) and tag.startswith(CONFIDENCE_PREFIX):
            try:
                value = int(tag.removeprefix(CONFIDENCE_PREFIX))
            except ValueError:
                return None
            return value if 0 <= value <= 100 else None
    return None


def build_provenance_graph(
    *,
    record: dict[str, Any],
    all_records: list[dict[str, Any]],
    linked_records: list[dict[str, Any]],
    anchored_record_ids: set[str],
) -> dict[str, Any]:
    """Build the minimal reproducible provenance graph.

    Byte equality and signed HAP links are protocol facts. Source URIs and lineage
    statements are declarations. Provenance assertions are signed analytical
    overlays and never become protocol facts merely because they are repeated.
    """
    record_id = record["record_id"]
    evidence_hashes = sorted({item["sha256"] for item in record.get("evidence", [])})
    exact_matches: dict[str, list[str]] = {}
    for digest in evidence_hashes:
        matches = sorted(
            {
                candidate["record_id"]
                for candidate in all_records
                if candidate["record_id"] != record_id
                and any(
                    item.get("sha256") == digest
                    for item in candidate.get("evidence", [])
                )
            }
        )
        exact_matches[digest] = matches

    declarations = [
        {
            "type": "declared-source",
            "uri": source["uri"],
            "label": source.get("label"),
            "declared_by_record_id": record_id,
            "statement_is_authenticated": True,
            "external_truth_independently_verified": False,
        }
        for source in record.get("sources", [])
    ]

    overlays = []
    for item in linked_records:
        if item.get("kind") != "provenance_assertion":
            continue
        overlays.append(
            {
                "record_id": item["record_id"],
                "author_id": item["author_id"],
                "bitcoin_anchored": item["record_id"] in anchored_record_ids,
                "ruleset": _ruleset(item) or "unspecified",
                "confidence_percent": _confidence(item),
                "statement": item["statement"],
                "related_record_references": [
                    source["uri"]
                    for source in item.get("sources", [])
                    if source["uri"].startswith("hap:record:")
                ],
                "epistemic_type": "signed-derived-inference",
                "becomes_protocol_fact": False,
            }
        )

    return {
        "schema": "hap.provenance-graph",
        "version": 1,
        "rule": PROVENANCE_GRAPH,
        "record_id": record_id,
        "protocol_facts": {
            "record_signed_by_author_id": record["author_id"],
            "record_bitcoin_anchored": record_id in anchored_record_ids,
            "target_record_id": record.get("target_record_id"),
            "committed_evidence_sha256": evidence_hashes,
            "exact_evidence_matches": exact_matches,
        },
        "signed_declarations": declarations,
        "analysis_overlays": overlays,
        "source_independence": {
            "proven": False,
            "reason": (
                "Different keys, URLs, organisations, or timestamps do not prove independent upstream origin. "
                "Exact duplicates are grouped, while stronger lineage conclusions remain signed overlays."
            ),
        },
        "epistemic_legend": {
            "protocol_fact": "reproducible from bytes, signatures, HAP links, and Bitcoin state",
            "signed_declaration": "the protocol proves who declared it, not that the declaration is honest",
            "derived_inference": "a named analytical overlay that can be reproduced, challenged, or ignored",
            "external_world_claim": "not determined by HAP consensus",
        },
    }
