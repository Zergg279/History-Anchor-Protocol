from __future__ import annotations

from copy import deepcopy
from typing import Any

from .anchors import validate_anchor_reference
from .batches import validate_batch
from .codec import canonical_json_bytes, sha256_hex
from .records import validate_record

PROOF_BUNDLE_SCHEMA = "hap.proof-bundle"
PROOF_BUNDLE_VERSION = 1
PROOF_BUNDLE_FIELDS = {"schema", "version", "record", "proofs", "bundle_id"}
PROOF_FIELDS = {"schema", "version", "record_id", "batch", "index", "path", "anchors"}
PROOF_STEP_FIELDS = {"sibling", "side"}


class ProofBundleError(ValueError):
    pass


def proof_bundle_body(bundle: dict[str, Any]) -> dict[str, Any]:
    body = deepcopy(bundle)
    body.pop("bundle_id", None)
    return body


def calculate_proof_bundle_id(bundle: dict[str, Any]) -> str:
    return sha256_hex(canonical_json_bytes(proof_bundle_body(bundle)))


def create_proof_bundle(
    record: dict[str, Any], proofs: list[dict[str, Any]]
) -> dict[str, Any]:
    bundle: dict[str, Any] = {
        "schema": PROOF_BUNDLE_SCHEMA,
        "version": PROOF_BUNDLE_VERSION,
        "record": record,
        "proofs": proofs,
    }
    bundle["bundle_id"] = calculate_proof_bundle_id(bundle)
    return bundle


def _validate_digest(value: Any, field: str) -> None:
    if not isinstance(value, str) or len(value) != 64:
        raise ProofBundleError(f"{field} must be a 32-byte hexadecimal digest")
    try:
        if len(bytes.fromhex(value)) != 32:
            raise ValueError
    except ValueError as exc:
        raise ProofBundleError(f"{field} must be a 32-byte hexadecimal digest") from exc


def validate_proof_bundle_shape(bundle: dict[str, Any]) -> None:
    if not isinstance(bundle, dict) or set(bundle) != PROOF_BUNDLE_FIELDS:
        raise ProofBundleError("proof bundle fields do not match the versioned schema")
    if (
        bundle.get("schema") != PROOF_BUNDLE_SCHEMA
        or bundle.get("version") != PROOF_BUNDLE_VERSION
    ):
        raise ProofBundleError("unsupported proof bundle schema or version")
    if not isinstance(bundle.get("record"), dict):
        raise ProofBundleError("proof bundle record is required")
    validate_record(bundle["record"])
    if not isinstance(bundle.get("proofs"), list):
        raise ProofBundleError("proofs must be a list")
    for proof in bundle["proofs"]:
        if not isinstance(proof, dict) or set(proof) != PROOF_FIELDS:
            raise ProofBundleError("proof fields do not match the versioned schema")
        if proof.get("schema") != "hap.proof" or proof.get("version") != 3:
            raise ProofBundleError("unsupported proof schema or version")
        if proof.get("record_id") != bundle["record"]["record_id"]:
            raise ProofBundleError("proof record_id does not match bundle record")
        validate_batch(proof.get("batch"))
        index = proof.get("index")
        if not isinstance(index, int) or isinstance(index, bool) or index < 0:
            raise ProofBundleError("proof index must be a non-negative integer")
        if index >= len(proof["batch"]["record_ids"]):
            raise ProofBundleError("proof index is outside the batch")
        path = proof.get("path")
        if not isinstance(path, list) or len(path) > 64:
            raise ProofBundleError("proof path is invalid")
        for step in path:
            if not isinstance(step, dict) or set(step) != PROOF_STEP_FIELDS:
                raise ProofBundleError("proof step fields do not match the schema")
            _validate_digest(step.get("sibling"), "proof sibling")
            if step.get("side") not in {"left", "right"}:
                raise ProofBundleError("proof side must be left or right")
        anchors = proof.get("anchors")
        if not isinstance(anchors, list):
            raise ProofBundleError("proof anchors must be a list")
        for anchor in anchors:
            validate_anchor_reference(anchor)
    if calculate_proof_bundle_id(bundle) != bundle.get("bundle_id"):
        raise ProofBundleError("bundle_id does not match proof bundle contents")
