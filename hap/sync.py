from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass
from typing import Any

import httpx

from .service import HistoryAnchorService, MissingDependencyError, ServiceError

LOGGER = logging.getLogger("hap.sync")


@dataclass
class SyncResult:
    peer: str
    records: int = 0
    batches: int = 0
    anchors: int = 0
    errors: int = 0
    reset: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "peer": self.peer,
            "records": self.records,
            "batches": self.batches,
            "anchors": self.anchors,
            "errors": self.errors,
            "reset": self.reset,
        }


def _peer_key(peer: str) -> str:
    normalized = peer.rstrip("/")
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:32]


def _get_json(
    client: httpx.Client,
    peer: str,
    path: str,
    params: dict[str, Any] | None,
    *,
    max_bytes: int,
) -> Any:
    clean_params = {
        key: value for key, value in (params or {}).items() if value is not None
    }
    with client.stream("GET", peer.rstrip("/") + path, params=clean_params) as response:
        response.raise_for_status()
        declared = response.headers.get("content-length")
        if declared is not None:
            try:
                if int(declared) > max_bytes:
                    raise ValueError(f"peer response exceeds {max_bytes} bytes")
            except ValueError as exc:
                if "exceeds" in str(exc):
                    raise
        chunks: list[bytes] = []
        total = 0
        for chunk in response.iter_bytes():
            total += len(chunk)
            if total > max_bytes:
                raise ValueError(f"peer response exceeds {max_bytes} bytes")
            chunks.append(chunk)
    return json.loads(b"".join(chunks))


def _get_page(
    client: httpx.Client,
    peer: str,
    path: str,
    params: dict[str, Any],
    *,
    max_bytes: int,
) -> dict[str, Any]:
    value = _get_json(client, peer, path, params, max_bytes=max_bytes)
    if not isinstance(value, dict) or not isinstance(value.get("items"), list):
        raise ValueError(f"peer returned an invalid sync response for {path}")
    cursor = value.get("cursor")
    if not isinstance(cursor, dict) or not isinstance(cursor.get("seq"), int):
        raise ValueError(f"peer returned an invalid cursor for {path}")
    if not isinstance(value.get("has_more"), bool):
        raise ValueError(f"peer returned an invalid has_more flag for {path}")
    return value


def _persist(service: HistoryAnchorService, key: str, state: dict[str, Any]) -> None:
    service.storage.set_peer_sync_state(key, state)


def sync_peer(
    service: HistoryAnchorService,
    peer: str,
    *,
    page_size: int = 100,
    max_response_bytes: int = 8_388_608,
    max_pages: int = 10_000,
) -> SyncResult:
    result = SyncResult(peer=peer)
    limits = httpx.Limits(max_connections=2, max_keepalive_connections=1)
    peer_key = _peer_key(peer)
    with httpx.Client(
        timeout=httpx.Timeout(20.0), follow_redirects=False, limits=limits
    ) as client:
        info = _get_json(
            client, peer, "/v1/info", None, max_bytes=min(max_response_bytes, 262_144)
        )
        if not isinstance(info, dict):
            raise ValueError("peer returned invalid node information")
        sync_epoch = info.get("sync_epoch")
        if not isinstance(sync_epoch, str) or not sync_epoch:
            raise ValueError("peer does not expose a sync epoch")

        state = service.storage.peer_sync_state(peer_key) or {
            "peer": peer.rstrip("/"),
            "sync_epoch": sync_epoch,
            "records_seq": 0,
            "batches_seq": 0,
            "anchors_seq": 0,
        }
        if state.get("sync_epoch") != sync_epoch or state.get("peer") != peer.rstrip(
            "/"
        ):
            state = {
                "peer": peer.rstrip("/"),
                "sync_epoch": sync_epoch,
                "records_seq": 0,
                "batches_seq": 0,
                "anchors_seq": 0,
            }
            result.reset = True
            _persist(service, peer_key, state)

        for kind, path, import_item, kind_page_size in (
            (
                "records",
                "/v1/sync/records",
                lambda item: service.submit_record(item, require_local_target=False),
                min(page_size, 25),
            ),
            ("batches", "/v1/sync/batches", service.import_batch, 1),
            (
                "anchors",
                "/v1/sync/anchors",
                service.import_anchor_reference,
                min(page_size, 200),
            ),
        ):
            cursor_key = f"{kind}_seq"
            current = int(state.get(cursor_key, 0))
            for _ in range(max_pages):
                page = _get_page(
                    client,
                    peer,
                    path,
                    {"after_seq": current, "limit": kind_page_size},
                    max_bytes=max_response_bytes,
                )
                items = page["items"]
                next_seq = int(page["cursor"]["seq"])
                if items and next_seq <= current:
                    raise ValueError(f"peer cursor failed to advance for {path}")

                dependency_missing = False
                for item in items:
                    try:
                        status = import_item(item)
                        if status.get("status") == "accepted":
                            setattr(result, kind, getattr(result, kind) + 1)
                    except MissingDependencyError:
                        dependency_missing = True
                        break
                    except ServiceError:
                        result.errors += 1

                if dependency_missing:
                    # Records or batches may have appeared on the peer during this cycle.
                    # Keep the old cursor and retry after the next records pass.
                    break

                current = next_seq
                state[cursor_key] = current
                _persist(service, peer_key, state)
                if not page["has_more"]:
                    break
            else:
                raise ValueError(
                    f"peer exceeded the {max_pages}-page sync ceiling for {path}"
                )
    return result


def sync_all_peers(
    service: HistoryAnchorService,
    peers: tuple[str, ...],
    *,
    page_size: int = 100,
    max_response_bytes: int = 8_388_608,
    max_pages: int = 10_000,
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for peer in peers:
        try:
            results.append(
                sync_peer(
                    service,
                    peer,
                    page_size=page_size,
                    max_response_bytes=max_response_bytes,
                    max_pages=max_pages,
                ).as_dict()
            )
        except Exception as exc:
            LOGGER.warning("peer sync failed for %s: %s", peer, exc)
            results.append(
                {
                    "peer": peer,
                    "records": 0,
                    "batches": 0,
                    "anchors": 0,
                    "errors": 1,
                    "reset": False,
                    "reason": str(exc),
                }
            )
    return results
