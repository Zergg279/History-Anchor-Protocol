#!/usr/bin/env python3
"""Create deterministic public-release assets from a finalised tagged repository."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import stat
import subprocess
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path


def run(*args: str, cwd: Path) -> str:
    result = subprocess.run(
        args,
        cwd=cwd,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return result.stdout.strip()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def tracked_files(root: Path) -> list[Path]:
    raw = subprocess.check_output(["git", "ls-files", "-z"], cwd=root)
    return [Path(value.decode("utf-8")) for value in raw.split(b"\0") if value]


def zip_datetime(commit_epoch: int) -> tuple[int, int, int, int, int, int]:
    value = datetime.fromtimestamp(commit_epoch, tz=timezone.utc)
    year = max(1980, value.year)
    return (
        year,
        value.month,
        value.day,
        value.hour,
        value.minute,
        value.second // 2 * 2,
    )


def write_deterministic_zip(
    source: Path, destination: Path, timestamp: tuple[int, ...]
) -> None:
    with zipfile.ZipFile(
        destination, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9
    ) as archive:
        for path in sorted(p for p in source.rglob("*") if p.is_file()):
            relative = path.relative_to(source).as_posix()
            info = zipfile.ZipInfo(relative, date_time=timestamp)
            mode = stat.S_IMODE(path.stat().st_mode)
            info.external_attr = (mode & 0xFFFF) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(
                info,
                path.read_bytes(),
                compress_type=zipfile.ZIP_DEFLATED,
                compresslevel=9,
            )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Package a finalised HAP public release."
    )
    parser.add_argument("--version", default="1.0.0")
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--out-dir", type=Path, default=Path("release-assets"))
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = args.root.resolve()
    out_dir = (
        (root / args.out_dir).resolve()
        if not args.out_dir.is_absolute()
        else args.out_dir
    )
    tag = f"v{args.version}"

    if run("git", "status", "--porcelain", cwd=root):
        raise SystemExit("repository must be clean before packaging")
    head = run("git", "rev-parse", "HEAD", cwd=root)
    tagged = run("git", "rev-parse", f"{tag}^{{}}", cwd=root)
    if head != tagged:
        raise SystemExit(f"{tag} must point to HEAD before packaging")

    wheel_candidates = sorted(
        (root / "dist").glob(f"history_anchor_protocol-{args.version}-*.whl")
    )
    if len(wheel_candidates) != 1:
        raise SystemExit("exactly one built wheel is required in dist/")
    wheel = wheel_candidates[0]

    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True)

    prefix = f"history-anchor-protocol-v{args.version}"
    with tempfile.TemporaryDirectory(prefix="hap-release-") as temporary:
        stage = Path(temporary) / prefix
        stage.mkdir()
        for relative in tracked_files(root):
            source = root / relative
            destination = stage / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)

        staged_wheel = stage / "dist" / wheel.name
        staged_wheel.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(wheel, staged_wheel)

        manifest_files = []
        for path in sorted(p for p in stage.rglob("*") if p.is_file()):
            relative = path.relative_to(stage).as_posix()
            manifest_files.append(
                {
                    "path": relative,
                    "sha256": sha256_file(path),
                    "size_bytes": path.stat().st_size,
                }
            )
        manifest = {
            "schema": "hap.release-manifest",
            "version": 1,
            "release_version": args.version,
            "git_commit": head,
            "files": manifest_files,
        }
        manifest_path = stage / "RELEASE_MANIFEST.json"
        manifest_path.write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )

        sum_lines = []
        for path in sorted(
            p for p in stage.rglob("*") if p.is_file() and p.name != "SHA256SUMS"
        ):
            relative = path.relative_to(stage).as_posix()
            sum_lines.append(f"{sha256_file(path)}  {relative}")
        (stage / "SHA256SUMS").write_text(
            "\n".join(sum_lines) + "\n", encoding="utf-8", newline="\n"
        )

        commit_epoch = int(run("git", "show", "-s", "--format=%ct", "HEAD", cwd=root))
        archive_path = out_dir / f"{prefix}-official-release.zip"
        write_deterministic_zip(stage.parent, archive_path, zip_datetime(commit_epoch))

    copied_wheel = out_dir / wheel.name
    shutil.copy2(wheel, copied_wheel)
    bundle = out_dir / f"{prefix}.git.bundle"
    # Advertise HEAD explicitly so a normal `git clone bundle destination` checks
    # out the release branch instead of producing an empty default branch.
    subprocess.run(
        [
            "git",
            "bundle",
            "create",
            str(bundle),
            "HEAD",
            "refs/heads/main",
            f"refs/tags/{tag}",
        ],
        cwd=root,
        check=True,
    )

    assets = (archive_path, copied_wheel, bundle)
    combined_lines = []
    for asset in assets:
        digest = sha256_file(asset)
        checksum_path = asset.with_name(asset.name + ".sha256")
        checksum_path.write_text(
            f"{digest}  {asset.name}\n", encoding="utf-8", newline="\n"
        )
        combined_lines.append(f"{digest}  {asset.name}")
    (out_dir / f"{prefix}-release-assets.sha256").write_text(
        "\n".join(combined_lines) + "\n", encoding="utf-8", newline="\n"
    )

    print(f"Public release assets created in {out_dir}")
    for asset in sorted(out_dir.iterdir()):
        print(f"  {asset.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
