from __future__ import annotations

from fastapi.testclient import TestClient

from hap.api import create_app
from hap.config import Settings
from hap.crypto import generate_keypair
from hap.records import create_signed_record
from hap.responsible import RESPONSIBLE_PROFILE
from hap.service import HistoryAnchorService


def make_record(kind="claim", *, target=None, tags=None, private_key=None, title=None):
    wallet = generate_keypair() if private_key is None else None
    key = private_key or wallet.private_key
    return create_signed_record(
        private_key=key,
        kind=kind,
        title=title or kind.replace("_", " ").title(),
        statement=f"Signed {kind} statement.",
        target_record_id=target,
        tags=tags or (["hap:person-impact:uncertain"] if kind == "claim" else []),
        created_at="2026-07-19T10:00:00Z",
    )


def anchor_record(service, record, *, height):
    service.submit_record(record, require_local_target=False)
    batch = service.create_direct_batch(record_id=record["record_id"], network="signet")
    service.storage.add_anchor(
        {
            "txid": record["record_id"],
            "vout": 0,
            "batch_id": batch["batch_id"],
            "network": "signet",
            "status": "confirmed",
            "anchored_at": height,
            "block_hash": f"{height:064x}"[-64:],
            "block_height": height,
        }
    )
    service.storage.add_scanned_block(height, f"{height:064x}"[-64:], height)


def test_person_impact_is_protected_but_exact_id_access_remains(tmp_path):
    service = HistoryAnchorService(str(tmp_path))
    try:
        claim = make_record(tags=["hap:person-impact:indirect-or-mosaic"])
        anchor_record(service, claim, height=100)
        view = service.responsible_publication_view(claim["record_id"])
        assert view["profile"] == RESPONSIBLE_PROFILE
        assert view["discovery"]["state"] == "protected"
        assert view["discovery"]["exact_identifier_access"] is True
        assert view["discovery"]["listed_in_reference_feed"] is False
    finally:
        service.close()


def test_public_interest_declaration_never_lifts_protection(tmp_path):
    service = HistoryAnchorService(str(tmp_path))
    try:
        claim = make_record(tags=["hap:person-impact:direct"])
        anchor_record(service, claim, height=100)
        justification = make_record(
            "public_interest_justification",
            target=claim["record_id"],
            title="Public interest claimed",
        )
        anchor_record(service, justification, height=101)
        service.storage.add_scanned_block(120, "ff" * 32, 120)
        view = service.responsible_publication_view(
            claim["record_id"], cooling_blocks=6
        )
        assert view["discovery"]["state"] == "protected"
        assert len(view["context"]["public_interest_justifications"]) == 1
        assert view["discovery"]["public_interest_claim_has_automatic_effect"] is False
    finally:
        service.close()


def test_only_recognised_anchored_view_decision_can_lift_after_cooling(tmp_path):
    service = HistoryAnchorService(str(tmp_path))
    try:
        claim = make_record(tags=["hap:person-impact:direct"])
        anchor_record(service, claim, height=100)
        decision_key = generate_keypair()
        decision = make_record(
            "view_decision",
            target=claim["record_id"],
            private_key=decision_key.private_key,
            tags=["hap:view:enable-discovery"],
        )
        anchor_record(service, decision, height=101)

        service.storage.add_scanned_block(104, "aa" * 32, 104)
        before = service.responsible_publication_view(
            claim["record_id"],
            recognised_accountable_authors=(decision["author_id"],),
            cooling_blocks=6,
        )
        assert before["discovery"]["state"] == "protected"

        service.storage.add_scanned_block(106, "bb" * 32, 106)
        after = service.responsible_publication_view(
            claim["record_id"],
            recognised_accountable_authors=(decision["author_id"],),
            cooling_blocks=6,
        )
        assert after["discovery"]["state"] == "discoverable-by-accountable-decision"

        unrecognised = service.responsible_publication_view(
            claim["record_id"], recognised_accountable_authors=(), cooling_blocks=6
        )
        assert unrecognised["discovery"]["state"] == "protected"
    finally:
        service.close()


def test_subject_response_has_equal_context_prominence_without_burner_suppression(
    tmp_path,
):
    service = HistoryAnchorService(str(tmp_path))
    try:
        claim = make_record(tags=["hap:person-impact:none"])
        anchor_record(service, claim, height=100)
        response = make_record("subject_response", target=claim["record_id"])
        service.submit_record(response)
        view = service.responsible_publication_view(claim["record_id"])
        assert view["discovery"]["state"] == "discoverable"
        assert (
            view["context"]["subject_responses"][0]["record_id"]
            == response["record_id"]
        )
        assert view["context"]["subject_responses"][0]["bitcoin_anchored"] is False
        assert "one or more subject responses exist" in view["review_flags"]
    finally:
        service.close()


def test_unrecognised_notice_creates_fixed_nonrenewable_window(tmp_path):
    service = HistoryAnchorService(str(tmp_path))
    try:
        claim = make_record(tags=["hap:person-impact:none"])
        anchor_record(service, claim, height=100)
        first = make_record("restriction_notice", target=claim["record_id"])
        anchor_record(service, first, height=101)
        service.storage.add_scanned_block(103, "ab" * 32, 103)
        during = service.responsible_publication_view(
            claim["record_id"], notice_protection_blocks=6
        )
        assert during["discovery"]["state"] == "protected"
        assert during["challenge_window"]["ends_at_height"] == 107

        second = make_record("restriction_notice", target=claim["record_id"])
        anchor_record(service, second, height=106)
        service.storage.add_scanned_block(108, "cd" * 32, 108)
        after = service.responsible_publication_view(
            claim["record_id"], notice_protection_blocks=6
        )
        assert after["challenge_window"]["ends_at_height"] == 107
        assert after["challenge_window"]["later_burner_notices_extend_window"] is False
        assert after["discovery"]["state"] == "discoverable"
    finally:
        service.close()


def test_reference_feed_omits_protected_records(tmp_path):
    settings = Settings(
        data_dir=str(tmp_path),
        role="relay",
        node_name="feed-test",
        max_request_bytes=65536,
        max_record_bytes=49152,
        max_statement_chars=10000,
        write_requests_per_minute=50,
        relay_pow_bits=0,
        allow_mainnet=False,
        allow_snapshot_import=False,
        expose_docs=False,
    )
    with TestClient(create_app(settings)) as client:
        protected = make_record(tags=["hap:person-impact:uncertain"])
        safe = make_record(
            tags=["hap:person-impact:none"], title="Non-person historical record"
        )
        assert client.post("/v1/records", json=protected).status_code == 200
        assert client.post("/v1/records", json=safe).status_code == 200
        service = client.app.state.service
        for index, record in enumerate((protected, safe), start=100):
            batch = service.create_direct_batch(
                record_id=record["record_id"], network="signet"
            )
            service.storage.add_anchor(
                {
                    "txid": record["record_id"],
                    "vout": 0,
                    "batch_id": batch["batch_id"],
                    "network": "signet",
                    "status": "confirmed",
                    "anchored_at": index,
                    "block_hash": f"{index:064x}"[-64:],
                    "block_height": index,
                }
            )
            service.storage.add_scanned_block(index, f"{index:064x}"[-64:], index)
        feed = client.get("/v1/feed").json()
        ids = {item["record"]["record_id"] for item in feed}
        assert safe["record_id"] in ids
        assert protected["record_id"] not in ids
        exact = client.get(f"/v1/records/{protected['record_id']}").json()
        assert (
            exact["responsible_publication"]["discovery"]["exact_identifier_access"]
            is True
        )


def test_responsible_relay_requires_person_impact_declaration(tmp_path):
    settings = Settings(
        data_dir=str(tmp_path),
        role="relay",
        node_name="profile-relay",
        max_request_bytes=65536,
        max_record_bytes=49152,
        max_statement_chars=10000,
        write_requests_per_minute=50,
        relay_pow_bits=0,
        allow_mainnet=False,
        allow_snapshot_import=False,
        expose_docs=False,
    )
    wallet = generate_keypair()
    missing = create_signed_record(
        private_key=wallet.private_key,
        kind="claim",
        title="Missing declaration",
        statement="This claim omits the responsible-profile declaration.",
        created_at="2026-07-19T11:00:00Z",
    )
    with TestClient(create_app(settings)) as client:
        response = client.post("/v1/records", json=missing)
        assert response.status_code == 400
        assert "person-impact declaration" in response.text


def test_base_protocol_still_accepts_pseudonymous_claim_without_profile_tag(tmp_path):
    service = HistoryAnchorService(str(tmp_path))
    try:
        wallet = generate_keypair()
        record = create_signed_record(
            private_key=wallet.private_key,
            kind="claim",
            title="Base-valid claim",
            statement="Base validity remains permissionless and independent of the optional profile.",
            created_at="2026-07-19T11:01:00Z",
        )
        assert service.submit_record(record)["status"] == "accepted"
        view = service.responsible_publication_view(record["record_id"])
        assert view["discovery"]["state"] == "unpublished"
        assert view["base_protocol_validity_unchanged"] is True
    finally:
        service.close()
