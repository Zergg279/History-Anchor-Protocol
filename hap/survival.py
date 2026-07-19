from __future__ import annotations

import io
import json
import tarfile
from pathlib import Path
from typing import Any

from .codec import canonical_json_bytes, sha256_hex
from .evidence_store import EvidenceStore

SURVIVAL_SCHEMA = "hap.survival-manifest"
SURVIVAL_VERSION = 1


class SurvivalArchiveError(ValueError):
    pass


def export_survival_archive(
    *, snapshot: dict[str, Any], evidence_store: EvidenceStore, output: str | Path
) -> dict[str, Any]:
    output_path = Path(output).expanduser().resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    evidence_entries: list[dict[str, Any]] = []
    for digest, path in evidence_store.files():
        if not evidence_store.verify(digest):
            continue
        evidence_entries.append(
            {
                "sha256": digest,
                "size": path.stat().st_size,
                "member": f"evidence/{digest}",
            }
        )
    manifest: dict[str, Any] = {
        "schema": SURVIVAL_SCHEMA,
        "version": SURVIVAL_VERSION,
        "snapshot_id": snapshot["snapshot_id"],
        "snapshot_sha256": sha256_hex(canonical_json_bytes(snapshot)),
        "evidence": evidence_entries,
    }
    manifest["manifest_id"] = sha256_hex(canonical_json_bytes(manifest))
    with tarfile.open(output_path, "w:gz", format=tarfile.PAX_FORMAT) as archive:
        snapshot_bytes = canonical_json_bytes(snapshot)
        info = tarfile.TarInfo("snapshot.json")
        info.size = len(snapshot_bytes)
        info.mtime = 0
        info.mode = 0o600
        archive.addfile(info, io.BytesIO(snapshot_bytes))
        manifest_bytes = canonical_json_bytes(manifest)
        info = tarfile.TarInfo("manifest.json")
        info.size = len(manifest_bytes)
        info.mtime = 0
        info.mode = 0o600
        archive.addfile(info, io.BytesIO(manifest_bytes))
        for entry in evidence_entries:
            path = evidence_store.path_for(entry["sha256"])
            info = archive.gettarinfo(str(path), arcname=entry["member"])
            info.mtime = 0
            info.mode = 0o600
            with path.open("rb") as handle:
                archive.addfile(info, handle)
    return {"path": str(output_path), "manifest": manifest}


def import_survival_archive(
    *,
    archive_path: str | Path,
    service: Any,
    max_evidence_bytes: int,
    max_metadata_bytes: int = 1_073_741_824,
) -> dict[str, Any]:
    path = Path(archive_path).expanduser().resolve()
    if not path.is_file():
        raise SurvivalArchiveError("survival archive does not exist")
    with tarfile.open(path, "r:gz") as archive:
        member_list = archive.getmembers()
        names = [member.name for member in member_list]
        if len(names) != len(set(names)):
            raise SurvivalArchiveError(
                "survival archive contains duplicate member names"
            )
        members = {member.name: member for member in member_list}
        if any(member.issym() or member.islnk() for member in member_list):
            raise SurvivalArchiveError("survival archive must not contain links")
        if "manifest.json" not in members or "snapshot.json" not in members:
            raise SurvivalArchiveError(
                "survival archive is missing manifest.json or snapshot.json"
            )
        for metadata_name in ("manifest.json", "snapshot.json"):
            member = members[metadata_name]
            if (
                not member.isfile()
                or member.size < 0
                or member.size > max_metadata_bytes
            ):
                raise SurvivalArchiveError(
                    f"{metadata_name} exceeds the configured metadata limit"
                )
        manifest_file = archive.extractfile(members["manifest.json"])
        snapshot_file = archive.extractfile(members["snapshot.json"])
        if not manifest_file or not snapshot_file:
            raise SurvivalArchiveError("survival archive metadata cannot be read")
        manifest = json.loads(manifest_file.read())
        snapshot = json.loads(snapshot_file.read())
        if not isinstance(manifest, dict) or set(manifest) != {
            "schema",
            "version",
            "snapshot_id",
            "snapshot_sha256",
            "evidence",
            "manifest_id",
        }:
            raise SurvivalArchiveError(
                "survival manifest fields do not match the schema"
            )
        if (
            manifest.get("schema") != SURVIVAL_SCHEMA
            or manifest.get("version") != SURVIVAL_VERSION
        ):
            raise SurvivalArchiveError("unsupported survival archive version")
        if not isinstance(manifest.get("evidence"), list):
            raise SurvivalArchiveError("survival evidence manifest must be a list")
        claimed_manifest_id = manifest.get("manifest_id")
        body = dict(manifest)
        body.pop("manifest_id", None)
        if sha256_hex(canonical_json_bytes(body)) != claimed_manifest_id:
            raise SurvivalArchiveError("survival manifest integrity check failed")
        if sha256_hex(canonical_json_bytes(snapshot)) != manifest.get(
            "snapshot_sha256"
        ):
            raise SurvivalArchiveError(
                "snapshot bytes do not match the survival manifest"
            )
        evidence_store = service.evidence_store
        evidence_imported = 0
        seen_digests: set[str] = set()
        for entry in manifest.get("evidence", []):
            if not isinstance(entry, dict) or set(entry) != {
                "sha256",
                "size",
                "member",
            }:
                raise SurvivalArchiveError(
                    "survival evidence entry fields do not match the schema"
                )
            member_name = entry.get("member")
            digest = entry.get("sha256")
            size = entry.get("size")
            if digest in seen_digests:
                raise SurvivalArchiveError(
                    "survival manifest contains duplicate evidence"
                )
            seen_digests.add(digest)
            if not isinstance(member_name, str) or member_name not in members:
                raise SurvivalArchiveError("survival evidence member is missing")
            if member_name != f"evidence/{digest}":
                raise SurvivalArchiveError(
                    "survival evidence member path is not canonical"
                )
            if not isinstance(size, int) or size < 0 or size > max_evidence_bytes:
                raise SurvivalArchiveError("survival evidence size is invalid")
            member = members[member_name]
            if not member.isfile() or member.size != size:
                raise SurvivalArchiveError(
                    "survival evidence member metadata is invalid"
                )
            source = archive.extractfile(member)
            if not source:
                raise SurvivalArchiveError("survival evidence cannot be read")
            evidence_store.store_stream(
                digest, source, max_bytes=max_evidence_bytes, expected_size=size
            )
            evidence_imported += 1
        # Import protocol state only after the archive metadata and every evidence member
        # have passed byte-level validation. A failed evidence import cannot partially trust
        # the archive's claimed Bitcoin or record state.
        imported = service.import_snapshot(snapshot)
    return {**imported, "evidence": evidence_imported}
