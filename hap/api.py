from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager, suppress
from importlib.resources import files
from typing import Any

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from .auth import (
    require_admin_token,
    require_submission_token,
    token_rate_key,
    trusted_client_ip,
)
from .bitcoin import BitcoinRPC
from .config import Settings
from .discovery import resolve_commitments, scan_bitcoin
from .funding import funding_info
from .middleware import (
    BodyLimitMiddleware,
    FixedWindowRateLimiter,
    SecurityHeadersMiddleware,
)
from .policy import validate_safe_relay_record, verify_relay_pow
from .records import validate_record
from .service import HistoryAnchorService, ServiceError
from .sync import sync_all_peers
from .view_manifest import create_view_manifest

API_VERSION = "1.0.0"
LOGGER = logging.getLogger("hap.api")


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_environment()
    settings.validate()
    service = HistoryAnchorService(settings.data_dir)
    limiter = FixedWindowRateLimiter(settings.write_requests_per_minute)
    stop = asyncio.Event()

    async def periodic(name: str, interval: int, action: Any) -> None:
        while not stop.is_set():
            try:
                await asyncio.to_thread(action)
            except Exception:
                LOGGER.exception("background %s failed", name)
            try:
                await asyncio.wait_for(stop.wait(), timeout=interval)
            except TimeoutError:
                continue

    def run_sync() -> Any:
        return sync_all_peers(
            service,
            settings.peers,
            page_size=settings.sync_page_size,
            max_response_bytes=settings.max_sync_response_bytes,
            max_pages=settings.max_sync_pages,
        )

    def run_scan() -> Any:
        return scan_bitcoin(
            service,
            start_height=settings.bitcoin_scan_start_height,
            max_blocks=settings.bitcoin_scan_max_blocks,
        )

    def run_resolve() -> Any:
        return resolve_commitments(
            service,
            settings.peers,
            max_response_bytes=settings.max_sync_response_bytes,
        )

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        tasks: list[asyncio.Task[None]] = []
        if settings.peers and settings.sync_interval_seconds > 0:
            tasks.append(
                asyncio.create_task(
                    periodic("peer sync", settings.sync_interval_seconds, run_sync)
                )
            )
        if settings.bitcoin_scan_interval_seconds > 0:
            tasks.append(
                asyncio.create_task(
                    periodic(
                        "Bitcoin scan", settings.bitcoin_scan_interval_seconds, run_scan
                    )
                )
            )
        if settings.peers and settings.resolve_interval_seconds > 0:
            tasks.append(
                asyncio.create_task(
                    periodic(
                        "package resolution",
                        settings.resolve_interval_seconds,
                        run_resolve,
                    )
                )
            )
        try:
            yield
        finally:
            stop.set()
            for task in tasks:
                task.cancel()
            for task in tasks:
                with suppress(asyncio.CancelledError):
                    await task
            service.close()

    app = FastAPI(
        title="History Anchor Protocol",
        version=API_VERSION,
        description=(
            "Bitcoin-first open memory node. Bitcoin transactions define publication and ordering; "
            "this node retrieves, validates, preserves, and indexes the committed packages."
        ),
        docs_url="/docs" if settings.expose_docs else None,
        redoc_url="/redoc" if settings.expose_docs else None,
        openapi_url="/openapi.json" if settings.expose_docs else None,
        lifespan=lifespan,
    )
    app.state.settings = settings
    app.state.service = service
    app.mount("/static", StaticFiles(directory=str(files("hap.static"))), name="static")
    app.add_middleware(BodyLimitMiddleware, max_bytes=settings.max_request_bytes)
    app.add_middleware(SecurityHeadersMiddleware)

    def client_key(request: Request, submission_token: str | None = None) -> str:
        return token_rate_key(submission_token) or (
            "ip:" + trusted_client_ip(request, settings.trusted_proxy_cidrs)
        )

    def require_record_write(request: Request) -> None:
        if not settings.can_relay:
            raise HTTPException(403, "this node role does not accept records")
        submission_token = require_submission_token(
            request, settings.require_submission_token, settings.submission_tokens
        )
        if not limiter.allow(client_key(request, submission_token)):
            raise HTTPException(429, "write rate limit exceeded")

    def require_coordinator_admin(request: Request) -> None:
        if not settings.can_coordinate:
            raise HTTPException(403, "this node role does not coordinate batches")
        require_admin_token(request, settings.admin_token)
        if not limiter.allow(
            "admin:" + trusted_client_ip(request, settings.trusted_proxy_cidrs)
        ):
            raise HTTPException(429, "administrative rate limit exceeded")

    def require_node_admin(request: Request) -> None:
        require_admin_token(request, settings.admin_token)
        if not limiter.allow(
            "admin:" + trusted_client_ip(request, settings.trusted_proxy_cidrs)
        ):
            raise HTTPException(429, "administrative rate limit exceeded")

    @app.exception_handler(ServiceError)
    async def service_error_handler(_: Request, exc: ServiceError) -> JSONResponse:
        return JSONResponse(status_code=400, content={"detail": str(exc)})

    @app.get("/", response_class=HTMLResponse)
    def home() -> str:
        return files("hap.static").joinpath("index.html").read_text(encoding="utf-8")

    @app.get("/healthz")
    def health() -> dict[str, Any]:
        return {"status": "ok", "version": API_VERSION, "role": settings.role}

    @app.get("/readyz")
    def readiness() -> JSONResponse:
        checks: dict[str, Any] = {"storage": service.storage.check()}
        ready = checks["storage"]["database"] == "ok"
        if settings.bitcoin_required_for_readiness:
            try:
                rpc = BitcoinRPC.from_environment()
                network = rpc.network()
                checks["bitcoin"] = {
                    "status": "ok",
                    "network": network,
                    "expected_network": settings.bitcoin_expected_network,
                }
                if network != settings.bitcoin_expected_network:
                    ready = False
                    checks["bitcoin"]["status"] = "wrong-network"
            except Exception as exc:
                ready = False
                checks["bitcoin"] = {"status": "unavailable", "detail": str(exc)}
        return JSONResponse(
            status_code=200 if ready else 503,
            content={"status": "ready" if ready else "not-ready", "checks": checks},
        )

    @app.get("/v1/view-manifest")
    def view_manifest() -> dict[str, Any]:
        return create_view_manifest(
            node_name=settings.node_name,
            profile_enabled=settings.responsible_publication_profile,
            cooling_blocks=settings.responsible_cooling_blocks,
            notice_protection_blocks=settings.responsible_notice_protection_blocks,
            recognised_accountable_authors=settings.recognised_accountable_authors,
        )

    @app.get("/v1/funding")
    def funding() -> dict[str, Any]:
        return funding_info()

    @app.get("/v1/info")
    def info() -> dict[str, Any]:
        return {
            "name": "History Anchor Protocol",
            "version": API_VERSION,
            "architecture": "bitcoin-first-client-side-validation",
            "bitcoin_is_canonical_publication_layer": True,
            "has_independent_consensus_or_token": False,
            "network_profile": settings.deployment_profile,
            "node_name": settings.node_name,
            "role": settings.role,
            "counts": {
                **service.storage.counts(),
                "evidence_files": service.evidence_store.count(),
            },
            "relay_policy": {
                "accepts_records": settings.can_relay,
                "submission_token_required": settings.require_submission_token,
                "max_request_bytes": settings.max_request_bytes,
                "max_record_bytes": settings.max_record_bytes,
                "max_statement_chars": settings.max_statement_chars,
                "requests_per_minute": settings.write_requests_per_minute,
                "proof_of_work_bits": settings.relay_pow_bits,
                "evidence_uploads": False,
            },
            "bitcoin_discovery": {
                "enabled": settings.bitcoin_scan_interval_seconds > 0,
                "start_height": settings.bitcoin_scan_start_height,
                "expected_network": settings.bitcoin_expected_network,
                "last_scanned_block": service.storage.latest_scanned_block(),
            },
            "archive": {"serves_verified_evidence": settings.can_archive},
            "responsible_publication": {
                "enabled": settings.responsible_publication_profile,
                "profile": "hap-responsible-publication-v1",
                "cooling_blocks": settings.responsible_cooling_blocks,
                "notice_protection_blocks": settings.responsible_notice_protection_blocks,
                "recognised_accountable_authors": len(
                    settings.recognised_accountable_authors
                ),
                "base_protocol_validity_unchanged": True,
                "unilateral_emergency_override": False,
            },
            "sync_epoch": service.storage.node_instance_id,
            "peers": {"configured": len(settings.peers)},
        }

    @app.post("/v1/records")
    def submit_record(record: dict[str, Any], request: Request) -> dict[str, Any]:
        require_record_write(request)
        try:
            validate_record(record)
            validate_safe_relay_record(record, settings)
        except Exception as exc:
            raise HTTPException(400, str(exc)) from exc
        nonce = request.headers.get("x-hap-relay-nonce")
        if not verify_relay_pow(record["record_id"], nonce, settings.relay_pow_bits):
            raise HTTPException(
                400,
                f"relay proof-of-work does not meet this node's {settings.relay_pow_bits}-bit policy",
            )
        return service.submit_record(
            record,
            local_policy=lambda value: validate_safe_relay_record(value, settings),
        )

    @app.get("/v1/feed")
    def reference_feed(limit: int = 50) -> list[dict[str, Any]]:
        if not settings.responsible_publication_profile:
            raise HTTPException(
                404, "the responsible-publication reference feed is disabled"
            )
        return service.reference_feed(
            limit=max(1, min(limit, 100)),
            recognised_accountable_authors=settings.recognised_accountable_authors,
            cooling_blocks=settings.responsible_cooling_blocks,
            notice_protection_blocks=settings.responsible_notice_protection_blocks,
        )

    @app.get("/v1/records")
    def records(limit: int = 100) -> list[dict[str, Any]]:
        # Raw protocol objects. Public-facing clients should use /v1/feed and
        # exact-ID record views so linked context is not silently omitted.
        return service.storage.latest_records(limit=max(1, min(limit, 100)))

    @app.get("/v1/records/{record_id}")
    def record(record_id: str) -> dict[str, Any]:
        result = service.record_view(
            record_id,
            recognised_accountable_authors=settings.recognised_accountable_authors,
            cooling_blocks=settings.responsible_cooling_blocks,
            notice_protection_blocks=settings.responsible_notice_protection_blocks,
        )
        if not result:
            raise HTTPException(404, "record not found")
        return result

    @app.get("/v1/records/{record_id}/assessment")
    def record_assessment(record_id: str) -> dict[str, Any]:
        result = service.record_assessment(record_id)
        if not result:
            raise HTTPException(404, "record not found")
        return result

    @app.get("/v1/records/{record_id}/provenance")
    def provenance(record_id: str) -> dict[str, Any]:
        result = service.provenance_graph(record_id)
        if not result:
            raise HTTPException(404, "record not found")
        return result

    @app.get("/v1/records/{record_id}/responsible-publication")
    def responsible_publication(record_id: str) -> dict[str, Any]:
        result = service.responsible_publication_view(
            record_id,
            recognised_accountable_authors=settings.recognised_accountable_authors,
            cooling_blocks=settings.responsible_cooling_blocks,
            notice_protection_blocks=settings.responsible_notice_protection_blocks,
        )
        if not result:
            raise HTTPException(404, "record not found")
        return result

    @app.get("/v1/records/{record_id}/proof")
    def record_proof(record_id: str) -> dict[str, Any]:
        result = service.proof_for_record(record_id)
        if not result:
            raise HTTPException(404, "record has not been batched")
        return result

    @app.get("/v1/records/{record_id}/proof-bundle")
    def record_proof_bundle(record_id: str) -> dict[str, Any]:
        result = service.proof_bundle_for_record(record_id)
        if not result:
            raise HTTPException(404, "record not found")
        return result

    @app.post("/v1/verify")
    def verify_package(request_body: dict[str, Any]) -> dict[str, Any]:
        record_value = request_body.get("record")
        if not isinstance(record_value, dict):
            raise HTTPException(400, "record is required")
        proof = request_body.get("proof")
        if proof is not None and not isinstance(proof, dict):
            raise HTTPException(400, "proof must be an object")
        return service.verify_package(record=record_value, proof=proof)

    @app.post("/v1/verify-proof-bundle")
    def verify_proof_bundle(bundle: dict[str, Any]) -> dict[str, Any]:
        try:
            return service.verify_proof_bundle(bundle)
        except Exception as exc:
            raise HTTPException(400, str(exc)) from exc

    @app.post("/v1/batches")
    def create_batch(request_body: dict[str, Any], request: Request) -> dict[str, Any]:
        require_coordinator_admin(request)
        network = request_body.get("network", settings.bitcoin_expected_network)
        if network == "mainnet" and not settings.allow_mainnet:
            raise HTTPException(403, "mainnet anchoring is disabled")
        if network not in {"signet", "regtest", "mainnet"}:
            raise HTTPException(400, "network must be signet, regtest, or mainnet")
        requested = int(request_body.get("limit", settings.max_batch_records))
        return service.create_batch(
            network=network,
            limit=max(1, min(requested, settings.max_batch_records)),
            max_package_bytes=settings.max_package_bytes,
        )

    @app.get("/v1/batches")
    def batches(limit: int = 100) -> list[dict[str, Any]]:
        return service.storage.batches(limit=max(1, min(limit, 20)))

    @app.get("/v1/batches/{batch_id}")
    def batch(batch_id: str) -> dict[str, Any]:
        result = service.storage.batch(batch_id)
        if not result:
            raise HTTPException(404, "batch not found")
        return {**result, "anchors": service.storage.anchors(batch_id)}

    @app.get("/v1/packages/{batch_id}")
    def package(batch_id: str) -> dict[str, Any]:
        result = service.package_for_batch(batch_id)
        if not result:
            raise HTTPException(404, "package not found")
        return result

    @app.post("/v1/batches/{batch_id}/anchor")
    def anchor_batch(batch_id: str, request: Request) -> dict[str, Any]:
        require_coordinator_admin(request)
        batch_value = service.storage.batch(batch_id)
        if (
            batch_value
            and batch_value["network"] == "mainnet"
            and not settings.allow_mainnet
        ):
            raise HTTPException(403, "mainnet anchoring is disabled")
        return service.anchor_batch(batch_id, allow_mainnet=settings.allow_mainnet)

    @app.post("/v1/records/{record_id}/anchor-direct")
    def direct_anchor(
        record_id: str, request: Request, network: str | None = None
    ) -> dict[str, Any]:
        require_coordinator_admin(request)
        target_network = network or settings.bitcoin_expected_network
        if target_network == "mainnet" and not settings.allow_mainnet:
            raise HTTPException(403, "mainnet anchoring is disabled")
        return service.direct_anchor_record(
            record_id,
            network=target_network,
            allow_mainnet=settings.allow_mainnet,
        )

    @app.post("/v1/batches/{batch_id}/verify-anchor")
    def verify_anchor(batch_id: str, request: Request) -> dict[str, Any]:
        require_coordinator_admin(request)
        return service.verify_bitcoin_anchor(batch_id)

    @app.get("/v1/commitments")
    def commitments(
        limit: int = 100, unresolved_only: bool = False
    ) -> list[dict[str, Any]]:
        return service.storage.commitments(
            unresolved_only=unresolved_only, limit=max(1, min(limit, 1000))
        )

    @app.get("/v1/evidence/{digest}")
    def evidence(digest: str) -> FileResponse:
        if not settings.can_archive:
            raise HTTPException(404, "this node does not serve evidence")
        try:
            path = service.evidence_store.path_for(digest)
            if not service.evidence_store.verify(digest):
                raise HTTPException(404, "verified evidence is not available")
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        return FileResponse(
            path, media_type="application/octet-stream", filename=digest
        )

    @app.get("/v1/sync/records")
    def sync_records(
        after_seq: int = Query(0, ge=0), limit: int = Query(25, ge=1, le=25)
    ) -> dict[str, Any]:
        items, last_seq = service.storage.record_sync_page(after_seq, limit=limit)
        cursor = last_seq if last_seq is not None else after_seq
        return {
            "items": items,
            "cursor": {"seq": cursor},
            "has_more": len(items) == limit,
        }

    @app.get("/v1/sync/batches")
    def sync_batches(
        after_seq: int = Query(0, ge=0), limit: int = Query(1, ge=1, le=1)
    ) -> dict[str, Any]:
        items, last_seq = service.storage.batch_sync_page(after_seq, limit=limit)
        cursor = last_seq if last_seq is not None else after_seq
        return {
            "items": items,
            "cursor": {"seq": cursor},
            "has_more": len(items) == limit,
        }

    @app.get("/v1/sync/anchors")
    def sync_anchors(
        after_seq: int = Query(0, ge=0), limit: int = Query(100, ge=1, le=200)
    ) -> dict[str, Any]:
        items, last_seq = service.storage.anchor_sync_page(after_seq, limit=limit)
        cursor = last_seq if last_seq is not None else after_seq
        return {
            "items": items,
            "cursor": {"seq": cursor},
            "has_more": len(items) == limit,
        }

    @app.post("/v1/admin/sync")
    def run_sync_endpoint(request: Request) -> dict[str, Any]:
        require_node_admin(request)
        return {"results": run_sync() if settings.peers else []}

    @app.post("/v1/admin/scan-bitcoin")
    def scan_bitcoin_endpoint(request: Request) -> dict[str, Any]:
        require_node_admin(request)
        return run_scan()

    @app.post("/v1/admin/resolve")
    def resolve_endpoint(request: Request) -> dict[str, Any]:
        require_node_admin(request)
        return run_resolve()

    @app.get("/v1/snapshot")
    def export_snapshot(request: Request) -> dict[str, Any]:
        require_node_admin(request)
        if not settings.allow_snapshot_export:
            raise HTTPException(
                403, "remote snapshot export is disabled; use the local backup command"
            )
        return service.export_snapshot()

    @app.post("/v1/snapshot/import")
    def import_snapshot(snapshot: dict[str, Any], request: Request) -> dict[str, Any]:
        require_node_admin(request)
        if not settings.allow_snapshot_import:
            raise HTTPException(
                403, "remote snapshot import is disabled; use the local CLI"
            )
        return service.import_snapshot(snapshot)

    return app


app = create_app()
