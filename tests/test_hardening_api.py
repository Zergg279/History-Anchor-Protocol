from __future__ import annotations

from fastapi.testclient import TestClient

from hap.api import create_app
from hap.config import Settings
from hap.crypto import generate_keypair
from hap.records import create_signed_record
from hap.service import ServiceError


def api_settings(tmp_path, **overrides):
    values = dict(
        data_dir=str(tmp_path / "node"),
        role="relay",
        node_name="api-test",
        max_request_bytes=65536,
        max_record_bytes=49152,
        max_statement_chars=10000,
        write_requests_per_minute=100,
        relay_pow_bits=0,
        allow_mainnet=False,
        allow_snapshot_import=False,
        expose_docs=False,
        allow_snapshot_export=False,
        admin_token=None,
        bitcoin_expected_network="regtest",
        responsible_publication_profile=True,
    )
    values.update(overrides)
    return Settings(**values)


def make_record():
    key = generate_keypair()
    return create_signed_record(
        private_key=key.private_key,
        kind="claim",
        title="API record",
        statement="A public API test record.",
        tags=["hap:person-impact:none"],
        created_at="2026-07-19T12:00:00Z",
    )


def auth_headers():
    return {"Authorization": "Bearer admin"}


def test_basic_read_endpoints_and_disabled_feed(tmp_path):
    app = create_app(
        api_settings(tmp_path, responsible_publication_profile=False, expose_docs=True)
    )
    with TestClient(app) as client:
        assert "History Anchor Protocol" in client.get("/").text
        assert client.get("/healthz").json() == {
            "status": "ok",
            "version": "1.0.0",
            "role": "relay",
        }
        assert client.get("/readyz").status_code == 200
        assert (
            client.get("/v1/info").json()["has_independent_consensus_or_token"] is False
        )
        assert (
            client.get("/v1/funding")
            .json()["genesis_donation_address"]
            .startswith("bc1p")
        )
        manifest = client.get("/v1/view-manifest").json()
        assert manifest["profile_enabled"] is False
        assert client.get("/v1/feed").status_code == 404
        assert client.get("/docs").status_code == 200


def test_readiness_bitcoin_correct_wrong_and_unavailable(tmp_path, monkeypatch):
    class RPC:
        def network(self):
            return "regtest"

    monkeypatch.setattr("hap.api.BitcoinRPC.from_environment", lambda: RPC())
    app = create_app(api_settings(tmp_path, bitcoin_required_for_readiness=True))
    with TestClient(app) as client:
        response = client.get("/readyz")
        assert response.status_code == 200
        assert response.json()["checks"]["bitcoin"]["status"] == "ok"

    class WrongRPC:
        def network(self):
            return "signet"

    monkeypatch.setattr("hap.api.BitcoinRPC.from_environment", lambda: WrongRPC())
    app = create_app(
        api_settings(tmp_path / "wrong", bitcoin_required_for_readiness=True)
    )
    with TestClient(app) as client:
        response = client.get("/readyz")
        assert response.status_code == 503
        assert response.json()["checks"]["bitcoin"]["status"] == "wrong-network"

    def unavailable():
        raise RuntimeError("bitcoin offline")

    monkeypatch.setattr("hap.api.BitcoinRPC.from_environment", unavailable)
    app = create_app(
        api_settings(tmp_path / "off", bitcoin_required_for_readiness=True)
    )
    with TestClient(app) as client:
        response = client.get("/readyz")
        assert response.status_code == 503
        assert "offline" in response.json()["checks"]["bitcoin"]["detail"]


def test_record_batch_package_proof_and_sync_endpoints(tmp_path):
    app = create_app(api_settings(tmp_path, role="coordinator", admin_token="admin"))
    item = make_record()
    with TestClient(app) as client:
        created = client.post("/v1/records", json=item)
        assert created.status_code == 200
        assert (
            client.get("/v1/records?limit=500").json()[0]["record_id"]
            == item["record_id"]
        )
        assert client.get(f"/v1/records/{item['record_id']}").status_code == 200
        assert (
            client.get(f"/v1/records/{item['record_id']}/assessment").status_code == 200
        )
        assert (
            client.get(f"/v1/records/{item['record_id']}/provenance").status_code == 200
        )
        assert (
            client.get(
                f"/v1/records/{item['record_id']}/responsible-publication"
            ).status_code
            == 200
        )
        assert client.get(f"/v1/records/{item['record_id']}/proof").status_code == 404

        batch_response = client.post(
            "/v1/batches",
            json={"network": "regtest", "limit": 9999},
            headers=auth_headers(),
        )
        assert batch_response.status_code == 200
        batch = batch_response.json()
        batch_id = batch["batch_id"]
        assert client.get("/v1/batches?limit=999").status_code == 200
        assert client.get(f"/v1/batches/{batch_id}").status_code == 200
        package = client.get(f"/v1/packages/{batch_id}")
        assert package.status_code == 200
        proof = client.get(f"/v1/records/{item['record_id']}/proof")
        assert proof.status_code == 200
        bundle = client.get(f"/v1/records/{item['record_id']}/proof-bundle")
        assert bundle.status_code == 200

        assert client.post("/v1/verify", json={}).status_code == 400
        assert (
            client.post("/v1/verify", json={"record": item, "proof": []}).status_code
            == 400
        )
        verify = client.post("/v1/verify", json={"record": item, "proof": proof.json()})
        assert verify.status_code == 200
        verify_bundle = client.post("/v1/verify-proof-bundle", json=bundle.json())
        assert verify_bundle.status_code == 200
        assert client.post("/v1/verify-proof-bundle", json={}).status_code == 400

        records_page = client.get("/v1/sync/records?after_seq=0&limit=1").json()
        assert records_page["has_more"] is True
        batches_page = client.get("/v1/sync/batches?after_seq=0&limit=1").json()
        assert batches_page["has_more"] is True
        anchors_page = client.get("/v1/sync/anchors?after_seq=0&limit=1").json()
        assert anchors_page["has_more"] is False
        assert (
            client.get("/v1/commitments?limit=5000&unresolved_only=true").json() == []
        )


def test_missing_resource_endpoints(tmp_path):
    app = create_app(api_settings(tmp_path))
    missing = "11" * 32
    with TestClient(app) as client:
        for path in (
            f"/v1/records/{missing}",
            f"/v1/records/{missing}/assessment",
            f"/v1/records/{missing}/provenance",
            f"/v1/records/{missing}/responsible-publication",
            f"/v1/records/{missing}/proof",
            f"/v1/records/{missing}/proof-bundle",
            f"/v1/batches/{missing}",
            f"/v1/packages/{missing}",
        ):
            assert client.get(path).status_code == 404, path
        assert client.get(f"/v1/evidence/{missing}").status_code == 404


def test_coordinator_authorisation_network_and_service_routes(tmp_path, monkeypatch):
    app = create_app(api_settings(tmp_path, role="coordinator", admin_token="admin"))
    item = make_record()
    service = app.state.service
    with TestClient(app) as client:
        assert (
            client.post("/v1/batches", json={"network": "regtest"}).status_code == 401
        )
        assert (
            client.post(
                "/v1/batches", json={"network": "mainnet"}, headers=auth_headers()
            ).status_code
            == 403
        )
        assert (
            client.post(
                "/v1/batches", json={"network": "mars"}, headers=auth_headers()
            ).status_code
            == 400
        )
        client.post("/v1/records", json=item)
        batch = client.post(
            "/v1/batches", json={"network": "regtest"}, headers=auth_headers()
        ).json()

        monkeypatch.setattr(service, "anchor_batch", lambda *a, **k: {"anchored": True})
        monkeypatch.setattr(
            service, "direct_anchor_record", lambda *a, **k: {"direct": True}
        )
        monkeypatch.setattr(
            service, "verify_bitcoin_anchor", lambda *a, **k: {"verified": True}
        )
        assert client.post(
            f"/v1/batches/{batch['batch_id']}/anchor", headers=auth_headers()
        ).json()["anchored"]
        assert client.post(
            f"/v1/records/{item['record_id']}/anchor-direct?network=regtest",
            headers=auth_headers(),
        ).json()["direct"]
        assert (
            client.post(
                f"/v1/records/{item['record_id']}/anchor-direct?network=mainnet",
                headers=auth_headers(),
            ).status_code
            == 403
        )
        assert client.post(
            f"/v1/batches/{batch['batch_id']}/verify-anchor", headers=auth_headers()
        ).json()["verified"]


def test_non_coordinator_rejected_and_service_error_handler(tmp_path, monkeypatch):
    app = create_app(api_settings(tmp_path, role="relay"))
    with TestClient(app) as client:
        assert (
            client.post("/v1/batches", json={"network": "regtest"}).status_code == 403
        )
        monkeypatch.setattr(
            app.state.service,
            "submit_record",
            lambda *a, **k: (_ for _ in ()).throw(ServiceError("local rejection")),
        )
        response = client.post("/v1/records", json=make_record())
        assert response.status_code == 400
        assert response.json()["detail"] == "local rejection"


def test_admin_endpoints_and_snapshot_policy(tmp_path, monkeypatch):
    app = create_app(
        api_settings(
            tmp_path,
            role="relay",
            admin_token="admin",
            peers=("https://peer",),
            allow_snapshot_export=True,
            allow_snapshot_import=True,
        )
    )
    monkeypatch.setattr("hap.api.sync_all_peers", lambda *a, **k: [{"peer": "ok"}])
    monkeypatch.setattr("hap.api.scan_bitcoin", lambda *a, **k: {"scanned": 1})
    monkeypatch.setattr("hap.api.resolve_commitments", lambda *a, **k: {"resolved": 1})
    with TestClient(app) as client:
        assert client.post("/v1/admin/sync").status_code == 401
        assert client.post("/v1/admin/sync", headers=auth_headers()).json()[
            "results"
        ] == [{"peer": "ok"}]
        assert (
            client.post("/v1/admin/scan-bitcoin", headers=auth_headers()).json()[
                "scanned"
            ]
            == 1
        )
        assert (
            client.post("/v1/admin/resolve", headers=auth_headers()).json()["resolved"]
            == 1
        )
        snapshot = client.get("/v1/snapshot", headers=auth_headers())
        assert snapshot.status_code == 200
        imported = client.post(
            "/v1/snapshot/import", json=snapshot.json(), headers=auth_headers()
        )
        assert imported.status_code == 200

    disabled = create_app(api_settings(tmp_path / "disabled", admin_token="admin"))
    with TestClient(disabled) as client:
        assert client.get("/v1/snapshot", headers=auth_headers()).status_code == 403
        assert (
            client.post(
                "/v1/snapshot/import", json={}, headers=auth_headers()
            ).status_code
            == 403
        )
        # No peers means the admin sync endpoint returns an empty result without network calls.
        assert client.post("/v1/admin/sync", headers=auth_headers()).json() == {
            "results": []
        }


def test_archive_evidence_serving_and_bad_digest(tmp_path):
    app = create_app(api_settings(tmp_path, role="archive"))
    source = tmp_path / "evidence.bin"
    source.write_bytes(b"evidence bytes")
    stored = app.state.service.evidence_store.add_file(source)
    with TestClient(app) as client:
        response = client.get(f"/v1/evidence/{stored['sha256']}")
        assert response.status_code == 200
        assert response.content == b"evidence bytes"
        assert client.get("/v1/evidence/not-a-digest").status_code == 400
        missing = "ff" * 32
        assert client.get(f"/v1/evidence/{missing}").status_code == 404


def test_record_submission_validation_and_rate_limit(tmp_path):
    app = create_app(api_settings(tmp_path, write_requests_per_minute=1))
    with TestClient(app) as client:
        assert client.post("/v1/records", json={}).status_code == 400
        assert client.post("/v1/records", json=make_record()).status_code == 429
