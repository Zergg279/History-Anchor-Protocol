from __future__ import annotations

from typing import Any

from .codec import canonical_json_bytes, sha256_hex


def create_view_manifest(
    *,
    node_name: str,
    profile_enabled: bool,
    cooling_blocks: int,
    notice_protection_blocks: int,
    recognised_accountable_authors: tuple[str, ...],
) -> dict[str, Any]:
    manifest: dict[str, Any] = {
        "schema": "hap.view-manifest",
        "version": 1,
        "node_name": node_name,
        "responsible_publication_profile": "hap-responsible-publication-v1"
        if profile_enabled
        else None,
        "profile_enabled": profile_enabled,
        "bitcoin_confirmation_required_for_feed": True,
        "cooling_blocks": cooling_blocks,
        "notice_protection_blocks": notice_protection_blocks,
        "later_unrecognised_notices_extend_window": False,
        "recognised_accountable_authors": sorted(set(recognised_accountable_authors)),
        "public_interest_declaration_automatically_enables_discovery": False,
        "unilateral_emergency_override": False,
        "subject_responses_receive_context_prominence": True,
        "subject_response_automatically_suppresses_discovery": False,
        "raw_protocol_endpoint_is_editorial_feed": False,
        "reference_feed_endpoint": "/v1/feed",
        "raw_protocol_endpoint": "/v1/records",
        "exact_id_context_endpoint": "/v1/records/{record_id}",
        "base_protocol_validity_unchanged": True,
        "good_faith_infrastructure_only": True,
    }
    manifest["manifest_id"] = sha256_hex(canonical_json_bytes(manifest))
    return manifest
