from __future__ import annotations

import time
from copy import deepcopy
from typing import Any, Callable

from .anchors import validate_anchor_reference
from .archive import calculate_snapshot_id, validate_snapshot
from .assessment import assess_record
from .batches import BatchValidationError, create_batch_manifest, validate_batch
from .bitcoin import BitcoinRPC, decode_anchor_payload
from .codec import canonical_json_bytes
from .evidence_store import EvidenceStore
from .merkle import merkle_proof, verify_merkle_proof
from .packages import create_package, validate_package
from .proofs import create_proof_bundle, validate_proof_bundle_shape
from .provenance import build_provenance_graph
from .records import RecordValidationError, calculate_record_id, validate_record
from .responsible import assess_responsible_publication
from .storage import Storage


class ServiceError(ValueError):
    pass


class MissingDependencyError(ServiceError):
    pass


class HistoryAnchorService:
    def __init__(self, data_dir: str):
        self.storage = Storage(data_dir)
        self.evidence_store = EvidenceStore(data_dir)

    def close(self) -> None:
        self.storage.close()

    def __enter__(self) -> "HistoryAnchorService":
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()

    def submit_record(
        self,
        record: dict[str, Any],
        *,
        require_local_target: bool = True,
        local_policy: Callable[[dict[str, Any]], None] | None = None,
    ) -> dict[str, Any]:
        try:
            validate_record(record)
            if local_policy is not None:
                local_policy(record)
        except (RecordValidationError, ValueError) as exc:
            raise ServiceError(str(exc)) from exc
        if self.storage.record(record["record_id"]):
            return {"record_id": record["record_id"], "status": "already_exists"}
        target = record.get("target_record_id")
        if require_local_target and target and not self.storage.record(target):
            raise ServiceError("target_record_id does not exist in this index")
        self.storage.add_record(record)
        return {
            "record_id": record["record_id"],
            "status": "accepted",
            "classification": "unverified",
        }

    def record_assessment(self, record_id: str) -> dict[str, Any] | None:
        record = self.storage.record(record_id)
        if not record:
            return None
        linked = self.storage.linked_records(record_id)
        anchored_ids = self.storage.anchored_record_ids()
        available = {
            item["sha256"]
            for item in record.get("evidence", [])
            if self.evidence_store.has(item["sha256"])
            and self.evidence_store.verify(item["sha256"])
        }
        return assess_record(
            record=record,
            linked_records=linked,
            anchored_record_ids=anchored_ids,
            available_evidence=available,
        )

    def provenance_graph(self, record_id: str) -> dict[str, Any] | None:
        record = self.storage.record(record_id)
        if not record:
            return None
        return build_provenance_graph(
            record=record,
            all_records=self.storage.records(limit=10_000_000),
            linked_records=self.storage.linked_records(record_id),
            anchored_record_ids=self.storage.anchored_record_ids(),
        )

    def responsible_publication_view(
        self,
        record_id: str,
        *,
        recognised_accountable_authors: tuple[str, ...] = (),
        cooling_blocks: int = 6,
        notice_protection_blocks: int = 6,
    ) -> dict[str, Any] | None:
        record = self.storage.record(record_id)
        if not record:
            return None
        linked = self.storage.linked_records(record_id)
        anchored_ids = self.storage.anchored_record_ids()
        related_ids = [record_id, *[item["record_id"] for item in linked]]
        heights = self.storage.confirmed_anchor_heights(related_ids)
        latest_block = self.storage.latest_scanned_block()
        return assess_responsible_publication(
            record=record,
            linked_records=linked,
            anchored_record_ids=anchored_ids,
            anchor_heights=heights,
            chain_height=int(latest_block["height"]) if latest_block else None,
            recognised_accountable_authors=recognised_accountable_authors,
            cooling_blocks=cooling_blocks,
            notice_protection_blocks=notice_protection_blocks,
        )

    def record_view(
        self,
        record_id: str,
        *,
        recognised_accountable_authors: tuple[str, ...] = (),
        cooling_blocks: int = 6,
        notice_protection_blocks: int = 6,
    ) -> dict[str, Any] | None:
        record = self.storage.record(record_id)
        if not record:
            return None
        assessment = self.record_assessment(record_id)
        responsible = self.responsible_publication_view(
            record_id,
            recognised_accountable_authors=recognised_accountable_authors,
            cooling_blocks=cooling_blocks,
            notice_protection_blocks=notice_protection_blocks,
        )
        return {
            "record": record,
            "classification": assessment["classification"]
            if assessment
            else "unpublished",
            "assessment": assessment,
            "provenance": self.provenance_graph(record_id),
            "responsible_publication": responsible,
            "linked_records": self.storage.linked_records(record_id),
            "proofs": self.proofs_for_record(record_id),
        }

    def reference_feed(
        self,
        *,
        limit: int = 50,
        recognised_accountable_authors: tuple[str, ...] = (),
        cooling_blocks: int = 6,
        notice_protection_blocks: int = 6,
    ) -> list[dict[str, Any]]:
        output: list[dict[str, Any]] = []
        # Scan beyond the requested output limit because protected records are omitted.
        for record in self.storage.latest_records(limit=max(limit * 10, 100)):
            if record["kind"] != "claim":
                continue
            view = self.record_view(
                record["record_id"],
                recognised_accountable_authors=recognised_accountable_authors,
                cooling_blocks=cooling_blocks,
                notice_protection_blocks=notice_protection_blocks,
            )
            if not view:
                continue
            responsible = view.get("responsible_publication") or {}
            if responsible.get("discovery", {}).get("listed_in_reference_feed"):
                output.append(view)
            if len(output) >= limit:
                break
        return output

    def create_batch(
        self,
        *,
        network: str,
        limit: int = 1_000,
        max_package_bytes: int = 67_108_864,
    ) -> dict[str, Any]:
        candidates = self.storage.records(limit=limit, unbatched_only=True)
        if not candidates:
            raise ServiceError("there are no unbatched records")
        records: list[dict[str, Any]] = []
        estimated_bytes = 4_096
        for record in candidates:
            record_bytes = len(canonical_json_bytes(record)) + 96
            if records and estimated_bytes + record_bytes > max_package_bytes:
                break
            if not records and estimated_bytes + record_bytes > max_package_bytes:
                raise ServiceError(
                    "the next record cannot fit within the configured package limit"
                )
            records.append(record)
            estimated_bytes += record_bytes
        created_at = int(time.time())
        while records:
            record_ids = [record["record_id"] for record in records]
            batch = create_batch_manifest(
                record_ids=record_ids, network=network, created_at=created_at
            )
            package = create_package(batch, records)
            if len(canonical_json_bytes(package)) <= max_package_bytes:
                self.storage.add_batch(batch)
                return batch
            records.pop()
        raise ServiceError("no record can fit within the configured package limit")

    def create_direct_batch(self, *, record_id: str, network: str) -> dict[str, Any]:
        if not self.storage.record(record_id):
            raise ServiceError("record not found")
        batch = create_batch_manifest(
            record_ids=[record_id], network=network, created_at=int(time.time())
        )
        self.storage.add_batch(batch)
        return batch

    def package_for_batch(self, batch_id: str) -> dict[str, Any] | None:
        batch = self.storage.batch(batch_id)
        if not batch:
            return None
        records = self.storage.records_by_ids(batch["record_ids"])
        if len(records) != batch["record_count"]:
            raise MissingDependencyError(
                "local batch is missing one or more committed records"
            )
        return create_package(batch, records)

    def import_package(self, package: dict[str, Any]) -> dict[str, Any]:
        try:
            validate_package(package)
        except Exception as exc:
            raise ServiceError(str(exc)) from exc
        pending = {record["record_id"]: record for record in package["records"]}
        imported_records = 0
        while pending:
            progressed = False
            for record_id, record in list(pending.items()):
                target = record.get("target_record_id")
                if target and not self.storage.record(target) and target in pending:
                    continue
                result = self.submit_record(record, require_local_target=False)
                pending.pop(record_id)
                imported_records += int(result["status"] == "accepted")
                progressed = True
            if not progressed:
                raise ServiceError("package record graph contains unresolved targets")
        batch_result = self.import_batch(package["batch"])
        return {
            "package_id": package["package_id"],
            "batch_id": package["batch"]["batch_id"],
            "records": imported_records,
            "batch_status": batch_result["status"],
        }

    def proofs_for_record(self, record_id: str) -> list[dict[str, Any]]:
        proofs: list[dict[str, Any]] = []
        for batch in self.storage.batches_for_record(record_id):
            try:
                index = batch["record_ids"].index(record_id)
            except ValueError:
                continue
            proofs.append(
                {
                    "schema": "hap.proof",
                    "version": 3,
                    "record_id": record_id,
                    "batch": batch,
                    "index": index,
                    "path": merkle_proof(batch["record_ids"], index),
                    "anchors": self.storage.anchors(batch["batch_id"]),
                }
            )
        return proofs

    def proof_for_record(self, record_id: str) -> dict[str, Any] | None:
        proofs = self.proofs_for_record(record_id)
        return proofs[0] if proofs else None

    def proof_bundle_for_record(self, record_id: str) -> dict[str, Any] | None:
        record = self.storage.record(record_id)
        if not record:
            return None
        return create_proof_bundle(record, self.proofs_for_record(record_id))

    def verify_package(
        self, *, record: dict[str, Any], proof: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        checks: dict[str, Any] = {}
        try:
            validate_record(record)
            checks["record_signature"] = True
            checks["record_id"] = calculate_record_id(record) == record["record_id"]
        except RecordValidationError as exc:
            checks["record_signature"] = False
            checks["record_id"] = False
            checks["record_error"] = str(exc)

        if proof is None:
            checks["batch_manifest"] = None
            checks["merkle_membership"] = None
            checks["anchor_payload"] = None
        else:
            batch = proof.get("batch")
            try:
                if not isinstance(batch, dict):
                    raise BatchValidationError("proof batch is required")
                validate_batch(batch)
                checks["batch_manifest"] = True
                checks["merkle_membership"] = verify_merkle_proof(
                    record.get("record_id", ""),
                    proof.get("path", []),
                    batch["merkle_root"],
                )
                payload = decode_anchor_payload(batch["payload_hex"])
                checks["anchor_payload"] = payload.manifest_hash == batch["batch_id"]
            except Exception as exc:
                checks["batch_manifest"] = False
                checks["merkle_membership"] = False
                checks["anchor_payload"] = False
                checks["proof_error"] = str(exc)

        boolean_checks = [value for value in checks.values() if isinstance(value, bool)]
        return {
            "valid_structure": all(boolean_checks) if boolean_checks else False,
            "bitcoin_anchor_verified": False,
            "bitcoin_anchor_note": "Anchor transaction references require independent Bitcoin Core verification.",
            "checks": checks,
        }

    def verify_proof_bundle(self, bundle: dict[str, Any]) -> dict[str, Any]:
        validate_proof_bundle_shape(bundle)
        results = [
            self.verify_package(record=bundle["record"], proof=proof)
            for proof in bundle["proofs"]
        ]
        record_only = self.verify_package(record=bundle["record"], proof=None)
        return {
            "bundle_id": bundle["bundle_id"],
            "record_valid": record_only["valid_structure"],
            "proof_results": results,
            "all_proofs_valid": bool(results)
            and all(item["valid_structure"] for item in results),
        }

    def verify_proof_bundle_against_bitcoin(
        self, bundle: dict[str, Any], rpc: BitcoinRPC | None = None
    ) -> dict[str, Any]:
        validate_proof_bundle_shape(bundle)
        structural = self.verify_proof_bundle(bundle)
        rpc = rpc or BitcoinRPC.from_environment()
        anchor_results: list[dict[str, Any]] = []
        for proof in bundle["proofs"]:
            batch = proof.get("batch")
            try:
                if not isinstance(batch, dict):
                    raise ServiceError("proof batch is required")
                validate_batch(batch)
                if rpc.network() != batch["network"]:
                    raise ServiceError("Bitcoin RPC network does not match proof batch")
                for anchor in proof.get("anchors", []):
                    txid = anchor.get("txid")
                    if not isinstance(txid, str) or not txid:
                        anchor_results.append(
                            {"verified": False, "reason": "anchor txid is missing"}
                        )
                        continue
                    found = rpc.find_payload(
                        txid,
                        anchor.get("block_hash"),
                        batch["payload_hex"],
                        expected_vout=anchor.get("vout"),
                    )
                    if not found:
                        anchor_results.append(
                            {
                                "txid": txid,
                                "verified": False,
                                "reason": "payload not found",
                            }
                        )
                        continue
                    payload_hex, tx, found_vout = found
                    block_hash = tx.get("blockhash") or anchor.get("block_hash")
                    context = rpc.block_context(block_hash) if block_hash else None
                    confirmations = int(tx.get("confirmations", 0) or 0)
                    payload_matches = payload_hex == batch["payload_hex"]
                    in_active_chain = bool(context and context.get("in_active_chain"))
                    confirmed = (
                        payload_matches and confirmations > 0 and in_active_chain
                    )
                    anchor_results.append(
                        {
                            "txid": txid,
                            "vout": found_vout,
                            "verified": confirmed,
                            "payload_matches": payload_matches,
                            "confirmed_in_active_chain": confirmed,
                            "confirmations": confirmations,
                            "block_context": context,
                            "expected_payload_hex": batch["payload_hex"],
                            "payload_hex": payload_hex,
                        }
                    )
            except Exception as exc:
                anchor_results.append({"verified": False, "reason": str(exc)})
        return {
            **structural,
            "bitcoin_network": rpc.network(),
            "anchor_results": anchor_results,
            "any_bitcoin_payload_match": any(
                item.get("payload_matches") for item in anchor_results
            ),
            "any_bitcoin_anchor_verified": any(
                item.get("verified") for item in anchor_results
            ),
        }

    def anchor_batch(
        self,
        batch_id: str,
        rpc: BitcoinRPC | None = None,
        *,
        allow_mainnet: bool = False,
    ) -> dict[str, Any]:
        batch = self.storage.batch(batch_id)
        if not batch:
            raise ServiceError("batch not found")
        validate_batch(batch)
        if batch["network"] == "mainnet" and not allow_mainnet:
            raise ServiceError(
                "mainnet anchoring is disabled; explicitly enable it after commissioning"
            )
        rpc = rpc or BitcoinRPC.from_environment()
        rpc_network = rpc.network()
        if rpc_network != batch["network"]:
            raise ServiceError(
                f"Bitcoin RPC is on {rpc_network}, but this batch was prepared for {batch['network']}"
            )
        broadcast = rpc.broadcast_op_return(batch["payload_hex"])
        anchor = {
            "batch_id": batch_id,
            "txid": broadcast["txid"],
            "vout": broadcast["vout"],
            "network": rpc_network,
            "status": "broadcast",
            "anchored_at": int(time.time()),
            "block_hash": None,
            "block_height": None,
        }
        self.storage.add_anchor(anchor)
        return {**anchor, "fee_btc": broadcast["fee_btc"]}

    def direct_anchor_record(
        self,
        record_id: str,
        *,
        network: str,
        rpc: BitcoinRPC | None = None,
        allow_mainnet: bool = False,
    ) -> dict[str, Any]:
        batch = self.create_direct_batch(record_id=record_id, network=network)
        package = self.package_for_batch(batch["batch_id"])
        if package is None:
            raise ServiceError("could not construct the direct-publication package")
        anchor = self.anchor_batch(
            batch["batch_id"], rpc=rpc, allow_mainnet=allow_mainnet
        )
        return {
            "record_id": record_id,
            "batch": batch,
            "package": package,
            "anchor": anchor,
        }

    def register_scanned_anchor(
        self, batch_id: str, txid: str, vout: int = 0
    ) -> dict[str, Any]:
        batch = self.storage.batch(batch_id)
        if not batch:
            raise MissingDependencyError(
                "Bitcoin commitment package has not been retrieved yet"
            )
        matches = [
            item
            for item in self.storage.commitments(batch_id=batch_id, limit=10_000)
            if item["txid"] == txid and item["vout"] == vout
        ]
        if not matches:
            raise MissingDependencyError(
                "Bitcoin commitment is not present in the local chain scan"
            )
        commitment = matches[0]
        if commitment["payload_hex"] != batch["payload_hex"]:
            raise ServiceError(
                "scanned Bitcoin payload does not match the retrieved batch"
            )
        anchor = {
            "batch_id": batch_id,
            "txid": txid,
            "vout": commitment["vout"],
            "network": commitment["network"],
            "status": "confirmed",
            "anchored_at": commitment["block_time"],
            "block_hash": commitment["block_hash"],
            "block_height": commitment["block_height"],
        }
        self.storage.add_anchor(anchor)
        for item in matches:
            self.storage.mark_commitment_resolved(item["txid"], item["vout"])
        return anchor

    def verify_bitcoin_anchor(
        self, batch_id: str, txid: str | None = None, rpc: BitcoinRPC | None = None
    ) -> dict[str, Any]:
        batch = self.storage.batch(batch_id)
        if not batch:
            raise ServiceError("batch not found")
        anchors = self.storage.anchors(batch_id)
        if txid is None:
            if not anchors:
                raise ServiceError("no anchor found for batch")
            txid = anchors[-1]["txid"]
        rpc = rpc or BitcoinRPC.from_environment()
        if rpc.network() != batch["network"]:
            raise ServiceError("Bitcoin RPC network does not match batch network")
        existing_anchor = next((item for item in anchors if item["txid"] == txid), None)
        known_block_hash = (
            existing_anchor.get("block_hash") if existing_anchor else None
        )
        expected_vout = existing_anchor.get("vout") if existing_anchor else None
        found = rpc.find_payload(
            txid,
            known_block_hash,
            batch["payload_hex"],
            expected_vout=expected_vout,
        )
        if not found:
            return {
                "verified": False,
                "reason": "no OP_RETURN payload found",
                "txid": txid,
            }
        payload_hex, tx, found_vout = found
        confirmations = int(tx.get("confirmations", 0) or 0)
        payload_matches = payload_hex == batch["payload_hex"]
        block_hash = tx.get("blockhash")
        context = rpc.block_context(block_hash) if block_hash else None
        existing = next(
            (
                item
                for item in anchors
                if item["txid"] == txid and item["vout"] == found_vout
            ),
            None,
        )
        updated = deepcopy(
            existing
            or {
                "batch_id": batch_id,
                "txid": txid,
                "vout": found_vout,
                "network": rpc.network(),
                "anchored_at": int(time.time()),
            }
        )
        if (
            payload_matches
            and confirmations > 0
            and context
            and context["in_active_chain"]
        ):
            updated["status"] = "confirmed"
        elif payload_matches and context and not context["in_active_chain"]:
            updated["status"] = "reorganised"
        elif payload_matches:
            updated["status"] = "broadcast"
        else:
            updated["status"] = "invalid"
        updated["block_hash"] = block_hash
        updated["block_height"] = context.get("block_height") if context else None
        self.storage.add_anchor(updated)
        return {
            "verified": updated["status"] == "confirmed",
            "payload_matches": payload_matches,
            "confirmations": confirmations,
            "txid": txid,
            "vout": found_vout,
            "payload_hex": payload_hex,
            "expected_payload_hex": batch["payload_hex"],
            "block_context": context,
            "status": updated["status"],
        }

    def import_batch(self, batch: dict[str, Any]) -> dict[str, Any]:
        try:
            validate_batch(batch)
        except Exception as exc:
            raise ServiceError(str(exc)) from exc
        missing = [
            record_id
            for record_id in batch["record_ids"]
            if not self.storage.record(record_id)
        ]
        if missing:
            raise MissingDependencyError(
                f"batch references {len(missing)} records that are not present locally"
            )
        created = self.storage.add_batch(batch)
        return {
            "batch_id": batch["batch_id"],
            "status": "accepted" if created else "already_exists",
        }

    def import_anchor_reference(self, anchor: dict[str, Any]) -> dict[str, Any]:
        try:
            validate_anchor_reference(anchor)
        except Exception as exc:
            raise ServiceError(str(exc)) from exc
        batch = self.storage.batch(anchor["batch_id"])
        if not batch:
            raise MissingDependencyError("anchor batch is not present locally")
        if anchor["network"] != batch["network"]:
            raise ServiceError("anchor network does not match batch")
        existing = self.storage.anchor(anchor["txid"], anchor["vout"])
        if existing and existing["batch_id"] != anchor["batch_id"]:
            raise ServiceError(
                "anchor txid is already associated with a different batch"
            )
        locally_checked = bool(
            existing
            and existing["status"]
            in {"broadcast", "confirmed", "invalid", "reorganised"}
        )
        local_reference = {
            "txid": anchor["txid"],
            "vout": anchor["vout"],
            "batch_id": anchor["batch_id"],
            "network": anchor["network"],
            "status": existing["status"] if locally_checked else "unverified",
            "anchored_at": existing["anchored_at"]
            if locally_checked
            else anchor["anchored_at"],
            "block_hash": existing.get("block_hash")
            if locally_checked
            else anchor.get("block_hash"),
            "block_height": existing.get("block_height")
            if locally_checked
            else anchor.get("block_height"),
        }
        created = self.storage.add_anchor(local_reference)
        return {"txid": anchor["txid"], "status": "accepted" if created else "updated"}

    def export_snapshot(self) -> dict[str, Any]:
        snapshot: dict[str, Any] = {
            "schema": "hap.snapshot",
            "version": 1,
            "created_at": int(time.time()),
            "records": self.storage.records(limit=10_000_000),
            "batches": self.storage.batches(limit=10_000_000)[::-1],
            "anchors": self.storage.anchors(),
        }
        snapshot["snapshot_id"] = calculate_snapshot_id(snapshot)
        validate_snapshot(snapshot)
        return snapshot

    def import_snapshot(self, snapshot: dict[str, Any]) -> dict[str, int]:
        validate_snapshot(snapshot)
        pending = {record["record_id"]: record for record in snapshot["records"]}
        imported_records = 0
        while pending:
            progressed = False
            for record_id, record in list(pending.items()):
                target = record.get("target_record_id")
                if target and not self.storage.record(target) and target in pending:
                    continue
                result = self.submit_record(record, require_local_target=False)
                pending.pop(record_id)
                if result["status"] == "accepted":
                    imported_records += 1
                progressed = True
            if not progressed:
                raise ServiceError("snapshot record graph contains unresolved targets")

        imported_batches = 0
        for batch in snapshot["batches"]:
            result = self.import_batch(batch)
            if result["status"] == "accepted":
                imported_batches += 1
        imported_anchors = 0
        for anchor in snapshot["anchors"]:
            result = self.import_anchor_reference(anchor)
            if result["status"] == "accepted":
                imported_anchors += 1
        return {
            "records": imported_records,
            "batches": imported_batches,
            "anchors": imported_anchors,
        }
