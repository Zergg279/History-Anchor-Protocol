from __future__ import annotations

from hap.crypto import generate_keypair
from hap.provenance import PROVENANCE_GRAPH
from hap.records import create_signed_record
from hap.service import HistoryAnchorService


def make_claim(key, *, title, digest, sources=None):
    return create_signed_record(
        private_key=key,
        kind="claim",
        title=title,
        statement="A signed claim.",
        evidence=[
            {
                "filename": "evidence.bin",
                "size": 3,
                "mime_type": "application/octet-stream",
                "sha256": digest,
                "cid": None,
            }
        ],
        sources=sources or [],
        tags=["hap:person-impact:none"],
        created_at="2026-07-19T10:00:00Z",
    )


def test_exact_hash_relationship_is_fact_but_source_is_declaration(tmp_path):
    service = HistoryAnchorService(str(tmp_path))
    try:
        first_key = generate_keypair().private_key
        second_key = generate_keypair().private_key
        digest = "11" * 32
        first = make_claim(
            first_key,
            title="First",
            digest=digest,
            sources=[
                {
                    "uri": "https://wire.example/item",
                    "label": "Declared wire source",
                }
            ],
        )
        second = make_claim(second_key, title="Second", digest=digest)
        service.submit_record(first)
        service.submit_record(second)
        graph = service.provenance_graph(first["record_id"])
        assert graph["rule"] == PROVENANCE_GRAPH
        assert graph["protocol_facts"]["exact_evidence_matches"][digest] == [
            second["record_id"]
        ]
        assert (
            graph["signed_declarations"][0]["external_truth_independently_verified"]
            is False
        )
        assert graph["source_independence"]["proven"] is False
    finally:
        service.close()


def test_provenance_assertion_remains_overlay(tmp_path):
    service = HistoryAnchorService(str(tmp_path))
    try:
        claim_key = generate_keypair().private_key
        analyst_key = generate_keypair().private_key
        claim = make_claim(claim_key, title="Claim", digest="22" * 32)
        service.submit_record(claim)
        overlay = create_signed_record(
            private_key=analyst_key,
            kind="provenance_assertion",
            title="Likely shared origin",
            statement="The media appears to derive from a common upstream source.",
            target_record_id=claim["record_id"],
            sources=[
                {"uri": f"hap:record:{claim['record_id']}", "label": "Primary record"}
            ],
            tags=["hap:analysis-ruleset:lineage-v1", "hap:analysis-confidence:72"],
            created_at="2026-07-19T10:01:00Z",
        )
        service.submit_record(overlay)
        graph = service.provenance_graph(claim["record_id"])
        item = graph["analysis_overlays"][0]
        assert item["ruleset"] == "lineage-v1"
        assert item["confidence_percent"] == 72
        assert item["becomes_protocol_fact"] is False
        assert item["epistemic_type"] == "signed-derived-inference"
    finally:
        service.close()
