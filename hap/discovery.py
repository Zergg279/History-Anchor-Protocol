from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass
from typing import Any

import httpx

from .bitcoin import BitcoinRPC, decode_anchor_payload, extract_payload_from_script
from .packages import validate_package
from .service import HistoryAnchorService, ServiceError

LOGGER = logging.getLogger("hap.discovery")


@dataclass
class ScanResult:
    network: str
    start_height: int
    end_height: int
    blocks_scanned: int
    commitments_found: int
    reorg_rewind_height: int | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "network": self.network,
            "start_height": self.start_height,
            "end_height": self.end_height,
            "blocks_scanned": self.blocks_scanned,
            "commitments_found": self.commitments_found,
            "reorg_rewind_height": self.reorg_rewind_height,
        }


def _find_common_ancestor(
    service: HistoryAnchorService, rpc: BitcoinRPC, height: int
) -> int:
    candidate = height
    while candidate >= 0:
        stored = service.storage.scanned_block(candidate)
        if stored is None:
            candidate -= 1
            continue
        try:
            active_hash = rpc.block_hash(candidate)
        except Exception:
            candidate -= 1
            continue
        if active_hash == stored["block_hash"]:
            return candidate
        candidate -= 1
    return -1


def scan_bitcoin(
    service: HistoryAnchorService,
    *,
    rpc: BitcoinRPC | None = None,
    start_height: int = 0,
    max_blocks: int = 500,
) -> dict[str, Any]:
    rpc = rpc or BitcoinRPC.from_environment()
    network = rpc.network()
    tip = rpc.block_count()
    stored_tip = service.storage.latest_scanned_block()
    rewind_height: int | None = None

    if stored_tip is not None:
        stored_height = int(stored_tip["height"])
        if stored_height <= tip:
            try:
                active_hash = rpc.block_hash(stored_height)
            except Exception:
                active_hash = None
            if active_hash != stored_tip["block_hash"]:
                ancestor = _find_common_ancestor(service, rpc, stored_height)
                service.storage.rewind_bitcoin_scan(ancestor)
                rewind_height = ancestor
                next_height = max(start_height, ancestor + 1)
            else:
                next_height = stored_height + 1
        else:
            ancestor = _find_common_ancestor(service, rpc, tip)
            service.storage.rewind_bitcoin_scan(ancestor)
            rewind_height = ancestor
            next_height = max(start_height, ancestor + 1)
    else:
        next_height = max(0, start_height)

    if next_height > tip:
        result = ScanResult(network, next_height, tip, 0, 0, rewind_height)
        return result.as_dict()

    end_height = min(tip, next_height + max(1, max_blocks) - 1)
    commitments_found = 0
    for height in range(next_height, end_height + 1):
        block_hash = rpc.block_hash(height)
        block = rpc.block(block_hash, verbosity=2)
        block_time = int(block.get("time", 0) or 0)
        for tx in block.get("tx", []):
            txid = tx.get("txid")
            if not isinstance(txid, str):
                continue
            for vout_index, output in enumerate(tx.get("vout", [])):
                script = output.get("scriptPubKey", {})
                payload_hex = extract_payload_from_script(script.get("hex", ""))
                if not payload_hex:
                    continue
                try:
                    payload = decode_anchor_payload(payload_hex)
                except Exception:
                    continue
                service.storage.add_commitment(
                    {
                        "txid": txid,
                        "vout": int(output.get("n", vout_index)),
                        "batch_id": payload.manifest_hash,
                        "payload_hex": payload_hex,
                        "network": network,
                        "block_height": height,
                        "block_hash": block_hash,
                        "block_time": block_time,
                        "status": "confirmed",
                        "discovered_at": int(time.time()),
                    }
                )
                commitments_found += 1
                batch = service.storage.batch(payload.manifest_hash)
                if batch is not None and batch["payload_hex"] == payload_hex:
                    service.register_scanned_anchor(
                        payload.manifest_hash, txid, int(output.get("n", vout_index))
                    )
        service.storage.add_scanned_block(height, block_hash, block_time)

    result = ScanResult(
        network=network,
        start_height=next_height,
        end_height=end_height,
        blocks_scanned=end_height - next_height + 1,
        commitments_found=commitments_found,
        reorg_rewind_height=rewind_height,
    )
    return result.as_dict()


def _download_package(peer: str, batch_id: str, *, max_bytes: int) -> dict[str, Any]:
    url = f"{peer.rstrip('/')}/v1/packages/{batch_id}"
    with httpx.Client(timeout=30.0, follow_redirects=False) as client:
        with client.stream(
            "GET", url, headers={"Accept": "application/json"}
        ) as response:
            response.raise_for_status()
            chunks: list[bytes] = []
            total = 0
            for chunk in response.iter_bytes():
                total += len(chunk)
                if total > max_bytes:
                    raise ServiceError(
                        "peer package exceeds the configured response limit"
                    )
                chunks.append(chunk)
    value = json.loads(b"".join(chunks))
    if not isinstance(value, dict):
        raise ServiceError("peer package response is not a JSON object")
    validate_package(value)
    return value


def resolve_commitments(
    service: HistoryAnchorService,
    peers: tuple[str, ...] | list[str],
    *,
    max_response_bytes: int = 67_108_864,
    limit: int = 100,
) -> dict[str, Any]:
    unresolved = service.storage.commitments(unresolved_only=True, limit=limit)
    resolved = 0
    missing = 0
    errors: list[dict[str, str]] = []
    for commitment in unresolved:
        batch_id = commitment["batch_id"]
        package = None
        for peer in peers:
            try:
                candidate = _download_package(
                    peer, batch_id, max_bytes=max_response_bytes
                )
                if candidate["batch"]["batch_id"] != batch_id:
                    raise ServiceError(
                        "peer returned a package for the wrong Bitcoin commitment"
                    )
                package = candidate
                break
            except Exception as exc:
                errors.append({"batch_id": batch_id, "peer": peer, "error": str(exc)})
        if package is None:
            missing += 1
            continue
        service.import_package(package)
        service.register_scanned_anchor(
            batch_id, commitment["txid"], commitment["vout"]
        )
        service.storage.mark_commitment_resolved(commitment["txid"], commitment["vout"])
        resolved += 1
    return {
        "unresolved_examined": len(unresolved),
        "resolved": resolved,
        "still_missing": missing,
        "errors": errors,
    }
