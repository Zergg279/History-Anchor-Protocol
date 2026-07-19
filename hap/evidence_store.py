from __future__ import annotations

import hashlib
import os
import uuid
from pathlib import Path
from typing import BinaryIO, Iterator


class EvidenceStoreError(ValueError):
    pass


def _validate_digest(digest: str) -> str:
    if not isinstance(digest, str) or len(digest) != 64:
        raise EvidenceStoreError(
            "evidence digest must be a 32-byte hexadecimal SHA-256 value"
        )
    try:
        raw = bytes.fromhex(digest)
    except ValueError as exc:
        raise EvidenceStoreError("evidence digest must be hexadecimal") from exc
    if len(raw) != 32:
        raise EvidenceStoreError(
            "evidence digest must be a 32-byte hexadecimal SHA-256 value"
        )
    return digest.lower()


class EvidenceStore:
    def __init__(self, data_dir: str | Path):
        self.root = Path(data_dir).expanduser().resolve() / "evidence"
        self.root.mkdir(parents=True, exist_ok=True)

    def path_for(self, digest: str) -> Path:
        digest = _validate_digest(digest)
        return self.root / digest[:2] / digest

    def has(self, digest: str) -> bool:
        return self.path_for(digest).is_file()

    def verify(self, digest: str) -> bool:
        digest = _validate_digest(digest)
        path = self.path_for(digest)
        if not path.is_file():
            return False
        actual = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                actual.update(chunk)
        return actual.hexdigest() == digest

    def add_file(
        self, source: str | Path, *, max_bytes: int | None = None
    ) -> dict[str, int | str]:
        source_path = Path(source).expanduser().resolve()
        if not source_path.is_file():
            raise EvidenceStoreError("evidence source is not a regular file")
        size = source_path.stat().st_size
        if max_bytes is not None and size > max_bytes:
            raise EvidenceStoreError(
                f"evidence exceeds the configured {max_bytes}-byte limit"
            )
        digest = hashlib.sha256()
        with source_path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        hexdigest = digest.hexdigest()
        destination = self.path_for(hexdigest)
        destination.parent.mkdir(parents=True, exist_ok=True)
        if not destination.exists():
            temporary = destination.with_suffix(
                f".tmp-{os.getpid()}-{uuid.uuid4().hex}"
            )
            with (
                source_path.open("rb") as source_handle,
                temporary.open("xb") as output,
            ):
                for chunk in iter(lambda: source_handle.read(1024 * 1024), b""):
                    output.write(chunk)
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, destination)
        if not self.verify(hexdigest):
            raise EvidenceStoreError("stored evidence failed its SHA-256 verification")
        return {"sha256": hexdigest, "size": size, "path": str(destination)}

    def store_stream(
        self,
        digest: str,
        stream: BinaryIO,
        *,
        max_bytes: int,
        expected_size: int | None = None,
    ) -> dict[str, int | str]:
        digest = _validate_digest(digest)
        destination = self.path_for(digest)
        if destination.exists() and self.verify(digest):
            return {
                "sha256": digest,
                "size": destination.stat().st_size,
                "path": str(destination),
            }
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = destination.with_suffix(f".tmp-{os.getpid()}-{uuid.uuid4().hex}")
        total = 0
        actual = hashlib.sha256()
        try:
            with temporary.open("xb") as output:
                while True:
                    chunk = stream.read(1024 * 1024)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > max_bytes:
                        raise EvidenceStoreError(
                            "evidence download exceeds the configured size limit"
                        )
                    actual.update(chunk)
                    output.write(chunk)
                output.flush()
                os.fsync(output.fileno())
            if expected_size is not None and total != expected_size:
                raise EvidenceStoreError(
                    "evidence size does not match its signed metadata"
                )
            if actual.hexdigest() != digest:
                raise EvidenceStoreError(
                    "evidence bytes do not match the committed SHA-256 digest"
                )
            os.replace(temporary, destination)
        finally:
            if temporary.exists():
                temporary.unlink(missing_ok=True)
        return {"sha256": digest, "size": total, "path": str(destination)}

    def open(self, digest: str) -> BinaryIO:
        path = self.path_for(digest)
        if not path.is_file() or not self.verify(digest):
            raise EvidenceStoreError("verified evidence is not available locally")
        return path.open("rb")

    def files(self) -> Iterator[tuple[str, Path]]:
        for path in sorted(self.root.glob("[0-9a-f][0-9a-f]/*")):
            if path.is_file() and len(path.name) == 64:
                try:
                    digest = _validate_digest(path.name)
                except EvidenceStoreError:
                    continue
                yield digest, path

    def count(self) -> int:
        return sum(1 for _ in self.files())
