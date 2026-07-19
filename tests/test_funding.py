from __future__ import annotations

from hap.funding import canonical_funding_manifest, funding_info, funding_manifest_id


def test_funding_metadata_has_no_protocol_power() -> None:
    manifest = canonical_funding_manifest()
    assert manifest["schema"] == "hap.funding"
    assert manifest["consensus_effect"] is False
    assert manifest["governance_rights"] is False
    assert manifest["protocol_dependency"] is False
    assert funding_info()["manifest_id"] == funding_manifest_id()
