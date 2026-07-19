from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import mimetypes
import os
import tempfile
from pathlib import Path
from typing import Any

import httpx
import uvicorn

from .discovery import resolve_commitments, scan_bitcoin
from .funding import funding_info
from .policy import mine_relay_pow
from .proofs import validate_proof_bundle_shape
from .records import create_signed_record
from .service import HistoryAnchorService
from .survival import export_survival_archive, import_survival_archive
from .sync import sync_peer
from .wallets import create_encrypted_wallet, decrypt_wallet

DEFAULT_URL = "http://127.0.0.1:8339"
VERSION = "1.0.0"


def print_json(value: Any) -> None:
    print(json.dumps(value, indent=2, ensure_ascii=False))


def atomic_write_json(path: str | Path, value: Any) -> Path:
    destination = Path(path).expanduser().resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.tmp-{os.getpid()}")
    payload = json.dumps(value, indent=2, ensure_ascii=False).encode("utf-8")
    try:
        with temporary.open("xb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)
    return destination


def load_json(path: str) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise SystemExit(f"{path}: expected a JSON object")
    return value


def env_secret(name: str | None) -> str | None:
    if not name:
        return None
    value = os.environ.get(name)
    if not value:
        raise SystemExit(f"environment variable {name} is empty or missing")
    return value


def auth_headers(
    *, submission_token: str | None = None, admin_token: str | None = None
) -> dict[str, str]:
    headers: dict[str, str] = {}
    if submission_token:
        headers["X-HAP-Submission-Token"] = submission_token
    if admin_token:
        headers["Authorization"] = f"Bearer {admin_token}"
    return headers


def request(
    method: str,
    url: str,
    path: str,
    value: Any | None = None,
    headers: dict[str, str] | None = None,
) -> Any:
    response = httpx.request(
        method,
        f"{url.rstrip('/')}{path}",
        json=value,
        headers=headers,
        timeout=60,
        follow_redirects=False,
    )
    if response.is_error:
        raise SystemExit(f"HTTP {response.status_code}: {response.text}")
    return response.json()


def post(url: str, path: str, value: Any, headers: dict[str, str] | None = None) -> Any:
    return request("POST", url, path, value, headers)


def get(url: str, path: str, headers: dict[str, str] | None = None) -> Any:
    return request("GET", url, path, headers=headers)


def wallet_password(env_name: str | None, *, confirm: bool = False) -> str:
    if env_name:
        value = os.environ.get(env_name)
        if not value:
            raise SystemExit(f"environment variable {env_name} is empty or missing")
        return value
    first = getpass.getpass("Wallet password: ")
    if not first:
        raise SystemExit("wallet password cannot be empty")
    if confirm and first != getpass.getpass("Confirm wallet password: "):
        raise SystemExit("wallet passwords do not match")
    return first


def hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def submit_signed_record(
    url: str, record: dict[str, Any], submission_token: str | None
) -> dict[str, Any]:
    info = get(url, "/v1/info")
    policy = info.get("relay_policy", {})
    if not policy.get("accepts_records"):
        raise SystemExit("this node is read-only and does not accept records")
    bits = int(policy.get("proof_of_work_bits", 0))
    headers = auth_headers(submission_token=submission_token)
    if bits > 0:
        print(f"Computing {bits}-bit relay proof-of-work locally…")
        headers["X-HAP-Relay-Nonce"] = mine_relay_pow(record["record_id"], bits)
    return post(url, "/v1/records", record, headers)


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="hap", description=f"History Anchor Protocol {VERSION}"
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    parser.add_argument("--url", default=DEFAULT_URL)
    parser.add_argument("--submission-token-env")
    parser.add_argument("--admin-token-env")
    sub = parser.add_subparsers(dest="command", required=True)

    serve = sub.add_parser("serve", help="run a Bitcoin-first HAP node")
    serve.add_argument("--data-dir", default=".history-anchor")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8339)
    serve.add_argument(
        "--role",
        choices=["observer", "relay", "coordinator", "archive"],
        default="observer",
    )
    serve.add_argument("--node-name", default="unnamed-hap-node")
    serve.add_argument("--relay-pow-bits", type=int, default=0)
    serve.add_argument("--write-rpm", type=int, default=10)
    serve.add_argument("--expose-docs", action="store_true")
    serve.add_argument("--require-submission-token", action="store_true")
    serve.add_argument("--peers", default="")
    serve.add_argument("--sync-interval", type=int, default=0)
    serve.add_argument("--scan-interval", type=int, default=0)
    serve.add_argument("--scan-start-height", type=int, default=0)
    serve.add_argument("--resolve-interval", type=int, default=0)
    serve.add_argument("--serve-evidence", action="store_true")
    serve.add_argument("--allow-mainnet", action="store_true")
    serve.add_argument("--disable-responsible-profile", action="store_true")
    serve.add_argument("--responsible-cooling-blocks", type=int, default=6)
    serve.add_argument("--responsible-notice-protection-blocks", type=int, default=6)
    serve.add_argument("--recognised-accountable-authors", default="")

    keygen = sub.add_parser("keygen")
    keygen.add_argument("--out", default="hap-wallet.json")
    keygen.add_argument("--password-env")
    keygen.add_argument("--force", action="store_true")

    create = sub.add_parser("create", help="create and sign a record locally")
    create.add_argument("--wallet", default="hap-wallet.json")
    create.add_argument("--password-env")
    create.add_argument(
        "--kind",
        choices=[
            "claim",
            "attestation",
            "dispute",
            "correction",
            "subject_response",
            "person_impact_notice",
            "restriction_notice",
            "withdrawal_notice",
            "legal_adjudication",
            "public_interest_justification",
            "view_decision",
            "provenance_assertion",
        ],
        default="claim",
    )
    create.add_argument("--title", required=True)
    create.add_argument("--statement", required=True)
    create.add_argument("--event-time")
    create.add_argument("--target")
    create.add_argument("--source", action="append", default=[])
    create.add_argument("--evidence", action="append", default=[])
    create.add_argument("--tag", action="append", default=[])
    create.add_argument(
        "--person-impact",
        choices=["none", "direct", "indirect-or-mosaic", "uncertain"],
        default="uncertain",
        help="responsible-publication declaration; conservative default is uncertain",
    )
    create.add_argument(
        "--view-action",
        choices=["enable-discovery", "restrict-discovery"],
        help="required for view_decision records",
    )
    create.add_argument("--out")
    create.add_argument("--no-submit", action="store_true")

    submit = sub.add_parser("submit")
    submit.add_argument("record_file")

    batch = sub.add_parser("batch")
    batch.add_argument(
        "--network", choices=["mainnet", "signet", "regtest"], default="signet"
    )
    batch.add_argument("--limit", type=int, default=10_000)

    anchor = sub.add_parser("anchor")
    anchor.add_argument("batch_id")
    verify_anchor = sub.add_parser("verify-anchor")
    verify_anchor.add_argument("batch_id")

    direct = sub.add_parser(
        "direct-anchor",
        help="publish one signed record directly through one Bitcoin transaction",
    )
    direct.add_argument("record_file")
    direct.add_argument("--data-dir", default=".history-anchor")
    direct.add_argument(
        "--network", choices=["mainnet", "signet", "regtest"], default="signet"
    )
    direct.add_argument(
        "--package-out",
        help="write the portable package before broadcasting (default: hap-package-<batch-id>.json)",
    )

    scan = sub.add_parser(
        "scan-bitcoin", help="discover canonical HAP commitments directly from Bitcoin"
    )
    scan.add_argument("--data-dir", default=".history-anchor")
    scan.add_argument("--start-height", type=int, default=0)
    scan.add_argument("--max-blocks", type=int, default=500)

    resolve = sub.add_parser(
        "resolve", help="retrieve Bitcoin-committed packages from any configured peer"
    )
    resolve.add_argument("--data-dir", default=".history-anchor")
    resolve.add_argument("--peers", required=True)

    package = sub.add_parser("package")
    package.add_argument("batch_id")
    package.add_argument("--data-dir", default=".history-anchor")
    package.add_argument("--out", required=True)

    import_package = sub.add_parser("import-package")
    import_package.add_argument("package_file")
    import_package.add_argument("--data-dir", default=".history-anchor")

    evidence_add = sub.add_parser(
        "evidence-add", help="store evidence locally by SHA-256 content address"
    )
    evidence_add.add_argument("file")
    evidence_add.add_argument("--data-dir", default=".history-anchor")
    evidence_add.add_argument("--max-bytes", type=int, default=2_147_483_648)

    evidence_fetch = sub.add_parser(
        "evidence-fetch", help="retrieve evidence from any archive peer and verify it"
    )
    evidence_fetch.add_argument("sha256")
    evidence_fetch.add_argument("--peer", required=True)
    evidence_fetch.add_argument("--data-dir", default=".history-anchor")
    evidence_fetch.add_argument("--expected-size", type=int)
    evidence_fetch.add_argument("--max-bytes", type=int, default=2_147_483_648)

    assessment = sub.add_parser("assessment")
    assessment.add_argument("record_id")
    responsible = sub.add_parser("responsible-view")
    responsible.add_argument("record_id")
    provenance = sub.add_parser("provenance")
    provenance.add_argument("record_id")

    sync = sub.add_parser("sync")
    sync.add_argument("--peer", required=True)
    sync.add_argument("--data-dir", default=".history-anchor")
    sync.add_argument("--page-size", type=int, default=100)

    show = sub.add_parser("show")
    show.add_argument("record_id")
    proof_bundle = sub.add_parser("proof-bundle")
    proof_bundle.add_argument("record_id")
    proof_bundle.add_argument("--out", required=True)
    verify = sub.add_parser("verify")
    verify.add_argument("file")
    verify.add_argument("--proof")
    verify_bitcoin = sub.add_parser("verify-bitcoin")
    verify_bitcoin.add_argument("proof_bundle")

    for name in (
        "info",
        "records",
        "batches",
        "ready",
        "commitments",
        "view-manifest",
        "funding",
    ):
        sub.add_parser(name)

    backup = sub.add_parser("backup")
    backup.add_argument("--data-dir", default=".history-anchor")
    backup.add_argument("--out-dir", default="backups")
    check = sub.add_parser("check")
    check.add_argument("--data-dir", default=".history-anchor")
    import_cmd = sub.add_parser("import")
    import_cmd.add_argument("snapshot_file")
    import_cmd.add_argument("--data-dir", default=".history-anchor-restored")
    survival_export = sub.add_parser("survival-export")
    survival_export.add_argument("--data-dir", default=".history-anchor")
    survival_export.add_argument("--out", default="hap-survival.tar.gz")
    survival_import = sub.add_parser("survival-import")
    survival_import.add_argument("archive")
    survival_import.add_argument("--data-dir", default=".history-anchor-restored")
    survival_import.add_argument(
        "--max-evidence-bytes", type=int, default=2_147_483_648
    )
    survival_import.add_argument(
        "--max-metadata-bytes", type=int, default=1_073_741_824
    )

    args = parser.parse_args()
    submission_token = env_secret(args.submission_token_env)
    admin_token = env_secret(args.admin_token_env)

    if args.command == "serve":
        os.environ.update(
            {
                "HAP_DATA_DIR": args.data_dir,
                "HAP_ROLE": args.role,
                "HAP_NODE_NAME": args.node_name,
                "HAP_RELAY_POW_BITS": str(args.relay_pow_bits),
                "HAP_WRITE_REQUESTS_PER_MINUTE": str(args.write_rpm),
                "HAP_EXPOSE_DOCS": "1" if args.expose_docs else "0",
                "HAP_REQUIRE_SUBMISSION_TOKEN": "1"
                if args.require_submission_token
                else "0",
                "HAP_PEERS": args.peers,
                "HAP_SYNC_INTERVAL_SECONDS": str(args.sync_interval),
                "HAP_BITCOIN_SCAN_INTERVAL_SECONDS": str(args.scan_interval),
                "HAP_BITCOIN_SCAN_START_HEIGHT": str(args.scan_start_height),
                "HAP_RESOLVE_INTERVAL_SECONDS": str(args.resolve_interval),
                "HAP_SERVE_EVIDENCE": "1" if args.serve_evidence else "0",
                "HAP_ALLOW_MAINNET": "1" if args.allow_mainnet else "0",
                "HAP_RESPONSIBLE_PUBLICATION_PROFILE": "0"
                if args.disable_responsible_profile
                else "1",
                "HAP_RESPONSIBLE_COOLING_BLOCKS": str(args.responsible_cooling_blocks),
                "HAP_RESPONSIBLE_NOTICE_PROTECTION_BLOCKS": str(
                    args.responsible_notice_protection_blocks
                ),
                "HAP_RECOGNISED_ACCOUNTABLE_AUTHORS": args.recognised_accountable_authors,
            }
        )
        uvicorn.run(
            "hap.api:app",
            host=args.host,
            port=args.port,
            reload=False,
            proxy_headers=False,
            workers=1,
        )
        return

    if args.command == "keygen":
        path = Path(args.out)
        if path.exists() and not args.force:
            raise SystemExit(f"refusing to overwrite {path}; use --force")
        wallet = create_encrypted_wallet(
            wallet_password(args.password_env, confirm=True)
        )
        path = atomic_write_json(path, wallet)
        try:
            path.chmod(0o600)
        except OSError:
            pass
        print_json(
            {
                "wallet": str(path.resolve()),
                "author_id": wallet["author_id"],
                "encrypted": True,
            }
        )
        return

    if args.command == "create":
        private_key = decrypt_wallet(
            load_json(args.wallet), wallet_password(args.password_env)
        )
        evidence = []
        for filename in args.evidence:
            path = Path(filename)
            if not path.is_file():
                raise SystemExit(f"evidence file not found: {path}")
            evidence.append(
                {
                    "filename": path.name,
                    "size": path.stat().st_size,
                    "mime_type": mimetypes.guess_type(path.name)[0],
                    "sha256": hash_file(path),
                    "cid": None,
                }
            )
        tags = list(args.tag)
        if not any(tag.startswith("hap:person-impact:") for tag in tags):
            tags.append(f"hap:person-impact:{args.person_impact}")
        if args.kind == "view_decision":
            if not args.view_action:
                raise SystemExit("view_decision requires --view-action")
            tags.append(f"hap:view:{args.view_action}")
        elif args.view_action:
            raise SystemExit("--view-action is only valid with --kind view_decision")
        record = create_signed_record(
            private_key=private_key,
            kind=args.kind,
            title=args.title,
            statement=args.statement,
            event_time=args.event_time,
            target_record_id=args.target,
            sources=[{"uri": uri, "label": None} for uri in args.source],
            evidence=evidence,
            tags=tags,
        )
        if args.out:
            atomic_write_json(args.out, record)
        result = (
            None
            if args.no_submit
            else submit_signed_record(args.url, record, submission_token)
        )
        print_json({"record": record, "submission": result})
        return
    if args.command == "submit":
        print_json(
            submit_signed_record(
                args.url, load_json(args.record_file), submission_token
            )
        )
        return
    if args.command == "batch":
        print_json(
            post(
                args.url,
                "/v1/batches",
                {"network": args.network, "limit": args.limit},
                auth_headers(admin_token=admin_token),
            )
        )
        return
    if args.command == "anchor":
        print_json(
            post(
                args.url,
                f"/v1/batches/{args.batch_id}/anchor",
                {},
                auth_headers(admin_token=admin_token),
            )
        )
        return
    if args.command == "verify-anchor":
        print_json(
            post(
                args.url,
                f"/v1/batches/{args.batch_id}/verify-anchor",
                {},
                auth_headers(admin_token=admin_token),
            )
        )
        return
    if args.command == "assessment":
        print_json(get(args.url, f"/v1/records/{args.record_id}/assessment"))
        return
    if args.command == "responsible-view":
        print_json(
            get(args.url, f"/v1/records/{args.record_id}/responsible-publication")
        )
        return
    if args.command == "provenance":
        print_json(get(args.url, f"/v1/records/{args.record_id}/provenance"))
        return
    if args.command == "show":
        print_json(get(args.url, f"/v1/records/{args.record_id}"))
        return
    if args.command == "info":
        print_json(get(args.url, "/v1/info"))
        return
    if args.command == "records":
        print_json(get(args.url, "/v1/records"))
        return
    if args.command == "batches":
        print_json(get(args.url, "/v1/batches"))
        return
    if args.command == "ready":
        print_json(get(args.url, "/readyz"))
        return
    if args.command == "commitments":
        print_json(get(args.url, "/v1/commitments"))
        return
    if args.command == "view-manifest":
        print_json(get(args.url, "/v1/view-manifest"))
        return
    if args.command == "funding":
        print_json(funding_info())
        return

    if args.command == "proof-bundle":
        bundle = get(args.url, f"/v1/records/{args.record_id}/proof-bundle")
        atomic_write_json(args.out, bundle)
        print_json(
            {
                "proof_bundle": str(Path(args.out).resolve()),
                "bundle_id": bundle["bundle_id"],
            }
        )
        return
    if args.command == "verify":
        value = load_json(args.file)
        with tempfile.TemporaryDirectory(prefix="hap-verify-") as directory:
            verifier = HistoryAnchorService(directory)
            try:
                if value.get("schema") == "hap.proof-bundle":
                    validate_proof_bundle_shape(value)
                    print_json(verifier.verify_proof_bundle(value))
                else:
                    print_json(
                        verifier.verify_package(
                            record=value,
                            proof=load_json(args.proof) if args.proof else None,
                        )
                    )
            finally:
                verifier.close()
        return
    if args.command == "verify-bitcoin":
        with tempfile.TemporaryDirectory(prefix="hap-bitcoin-verify-") as directory:
            verifier = HistoryAnchorService(directory)
            try:
                print_json(
                    verifier.verify_proof_bundle_against_bitcoin(
                        load_json(args.proof_bundle)
                    )
                )
            finally:
                verifier.close()
        return

    service = HistoryAnchorService(getattr(args, "data_dir", ".history-anchor"))
    try:
        if args.command == "sync":
            print_json(
                sync_peer(
                    service, args.peer, page_size=max(1, min(args.page_size, 1000))
                ).as_dict()
            )
        elif args.command == "direct-anchor":
            record = load_json(args.record_file)
            service.submit_record(record, require_local_target=False)
            batch = service.create_direct_batch(
                record_id=record["record_id"], network=args.network
            )
            package_value = service.package_for_batch(batch["batch_id"])
            if package_value is None:
                raise SystemExit("could not construct the direct-publication package")
            package_path = args.package_out or f"hap-package-{batch['batch_id']}.json"
            written = atomic_write_json(package_path, package_value)
            allow_mainnet = os.environ.get("HAP_ALLOW_MAINNET", "").strip().lower() in {
                "1",
                "true",
                "yes",
                "on",
            }
            anchor_value = service.anchor_batch(
                batch["batch_id"],
                allow_mainnet=allow_mainnet,
            )
            print_json(
                {
                    "record_id": record["record_id"],
                    "batch": batch,
                    "package": {
                        "path": str(written),
                        "package_id": package_value["package_id"],
                    },
                    "anchor": anchor_value,
                }
            )
        elif args.command == "scan-bitcoin":
            print_json(
                scan_bitcoin(
                    service, start_height=args.start_height, max_blocks=args.max_blocks
                )
            )
        elif args.command == "resolve":
            print_json(
                resolve_commitments(
                    service,
                    tuple(p.strip() for p in args.peers.split(",") if p.strip()),
                )
            )
        elif args.command == "package":
            value = service.package_for_batch(args.batch_id)
            if not value:
                raise SystemExit("batch not found")
            atomic_write_json(args.out, value)
            print_json(
                {
                    "package": str(Path(args.out).resolve()),
                    "package_id": value["package_id"],
                }
            )
        elif args.command == "import-package":
            print_json(service.import_package(load_json(args.package_file)))
        elif args.command == "evidence-add":
            print_json(
                service.evidence_store.add_file(args.file, max_bytes=args.max_bytes)
            )
        elif args.command == "evidence-fetch":
            temporary_path: Path | None = None
            try:
                with tempfile.NamedTemporaryFile(
                    prefix="hap-evidence-", delete=False
                ) as temporary:
                    temporary_path = Path(temporary.name)
                    with httpx.stream(
                        "GET",
                        f"{args.peer.rstrip('/')}/v1/evidence/{args.sha256}",
                        timeout=120,
                        follow_redirects=False,
                    ) as response:
                        response.raise_for_status()
                        total = 0
                        for chunk in response.iter_bytes():
                            total += len(chunk)
                            if total > args.max_bytes:
                                raise SystemExit(
                                    "evidence download exceeds --max-bytes"
                                )
                            temporary.write(chunk)
                with temporary_path.open("rb") as handle:
                    print_json(
                        service.evidence_store.store_stream(
                            args.sha256,
                            handle,
                            max_bytes=args.max_bytes,
                            expected_size=args.expected_size,
                        )
                    )
            finally:
                if temporary_path is not None:
                    temporary_path.unlink(missing_ok=True)
        elif args.command == "backup":
            out_dir = Path(args.out_dir).resolve()
            out_dir.mkdir(parents=True, exist_ok=True)
            snapshot = service.export_snapshot()
            snapshot_path = (
                out_dir / f"hap-snapshot-{snapshot['snapshot_id'][:16]}.json"
            )
            atomic_write_json(snapshot_path, snapshot)
            print_json(
                {
                    "snapshot": str(snapshot_path),
                    "database_backup": str(
                        service.storage.backup_database(
                            out_dir / "hap-database.sqlite3"
                        )
                    ),
                }
            )
        elif args.command == "check":
            print_json(
                {
                    "storage": service.storage.check(),
                    "counts": service.storage.counts(),
                    "evidence": service.evidence_store.count(),
                }
            )
        elif args.command == "import":
            print_json(
                {
                    "imported": service.import_snapshot(load_json(args.snapshot_file)),
                    "counts": service.storage.counts(),
                }
            )
        elif args.command == "survival-export":
            print_json(
                export_survival_archive(
                    snapshot=service.export_snapshot(),
                    evidence_store=service.evidence_store,
                    output=args.out,
                )
            )
        elif args.command == "survival-import":
            print_json(
                import_survival_archive(
                    archive_path=args.archive,
                    service=service,
                    max_evidence_bytes=args.max_evidence_bytes,
                    max_metadata_bytes=args.max_metadata_bytes,
                )
            )
    finally:
        service.close()


if __name__ == "__main__":
    main()
