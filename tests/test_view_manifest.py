from hap.view_manifest import create_view_manifest


def test_view_manifest_is_deterministic_and_discloses_local_trust_store():
    first = create_view_manifest(
        node_name="reference-node",
        profile_enabled=True,
        cooling_blocks=6,
        notice_protection_blocks=6,
        recognised_accountable_authors=("hap1b", "hap1a", "hap1a"),
    )
    second = create_view_manifest(
        node_name="reference-node",
        profile_enabled=True,
        cooling_blocks=6,
        notice_protection_blocks=6,
        recognised_accountable_authors=("hap1a", "hap1b"),
    )
    assert first == second
    assert first["recognised_accountable_authors"] == ["hap1a", "hap1b"]
    assert first["unilateral_emergency_override"] is False
    assert first["raw_protocol_endpoint_is_editorial_feed"] is False
    assert len(first["manifest_id"]) == 64
