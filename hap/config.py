from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

VALID_ROLES = {"observer", "relay", "coordinator", "archive"}


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int, minimum: int, maximum: int) -> int:
    value = int(os.environ.get(name, str(default)))
    return max(minimum, min(value, maximum))


def _read_secret(name: str, file_name: str) -> str | None:
    direct = os.environ.get(name)
    if direct is not None:
        value = direct.strip()
        return value or None
    path = os.environ.get(file_name)
    if not path:
        return None
    value = Path(path).read_text(encoding="utf-8").strip()
    return value or None


def _read_tokens(name: str, file_name: str) -> tuple[str, ...]:
    raw = _read_secret(name, file_name)
    if not raw:
        return ()
    values: list[str] = []
    for line in raw.replace(",", "\n").splitlines():
        value = line.strip()
        if value and value not in values:
            values.append(value)
    return tuple(values)


def _env_csv(name: str) -> tuple[str, ...]:
    raw = os.environ.get(name, "")
    return tuple(value.strip() for value in raw.split(",") if value.strip())


@dataclass(frozen=True)
class Settings:
    data_dir: str
    role: str
    node_name: str
    max_request_bytes: int
    max_record_bytes: int
    max_statement_chars: int
    write_requests_per_minute: int
    relay_pow_bits: int
    allow_mainnet: bool
    allow_snapshot_import: bool
    expose_docs: bool
    allow_snapshot_export: bool = False
    require_submission_token: bool = False
    submission_tokens: tuple[str, ...] = ()
    admin_token: str | None = None
    trusted_proxy_cidrs: tuple[str, ...] = ()
    peers: tuple[str, ...] = ()
    sync_interval_seconds: int = 0
    sync_page_size: int = 100
    max_sync_response_bytes: int = 67_108_864
    max_sync_pages: int = 10_000
    max_batch_records: int = 1_000
    max_package_bytes: int = 67_108_864
    bitcoin_required_for_readiness: bool = False
    bitcoin_expected_network: str = "signet"
    bitcoin_scan_interval_seconds: int = 0
    bitcoin_scan_start_height: int = 0
    bitcoin_scan_max_blocks: int = 500
    resolve_interval_seconds: int = 0
    serve_evidence: bool = False
    max_evidence_bytes: int = 2_147_483_648
    deployment_profile: str = "production"
    responsible_publication_profile: bool = True
    responsible_cooling_blocks: int = 6
    responsible_notice_protection_blocks: int = 6
    recognised_accountable_authors: tuple[str, ...] = ()

    @property
    def can_relay(self) -> bool:
        return self.role in {"relay", "coordinator"}

    @property
    def can_coordinate(self) -> bool:
        return self.role == "coordinator"

    @property
    def can_archive(self) -> bool:
        return self.role == "archive" or self.serve_evidence

    def validate(self) -> None:
        if self.role not in VALID_ROLES:
            raise ValueError(
                f"HAP_ROLE must be one of: {', '.join(sorted(VALID_ROLES))}"
            )
        if self.can_coordinate and not self.admin_token:
            raise ValueError(
                "coordinator nodes require HAP_ADMIN_TOKEN or HAP_ADMIN_TOKEN_FILE"
            )
        if self.require_submission_token and not self.submission_tokens:
            raise ValueError(
                "HAP_REQUIRE_SUBMISSION_TOKEN=1 requires HAP_SUBMISSION_TOKENS or HAP_SUBMISSION_TOKENS_FILE"
            )
        if self.bitcoin_expected_network not in {"signet", "regtest", "mainnet"}:
            raise ValueError(
                "HAP_BITCOIN_EXPECTED_NETWORK must be signet, regtest, or mainnet"
            )
        if self.bitcoin_expected_network == "mainnet" and not self.allow_mainnet:
            raise ValueError(
                "mainnet cannot be the expected Bitcoin network while HAP_ALLOW_MAINNET=0"
            )
        for peer in self.peers:
            if not peer.startswith(("http://", "https://")):
                raise ValueError(
                    "HAP_PEERS entries must begin with http:// or https://"
                )

    @classmethod
    def from_environment(cls) -> "Settings":
        role = os.environ.get("HAP_ROLE", "observer").strip().lower()
        settings = cls(
            data_dir=os.environ.get("HAP_DATA_DIR", ".history-anchor"),
            role=role,
            node_name=os.environ.get("HAP_NODE_NAME", "unnamed-hap-node")[:120],
            max_request_bytes=_env_int(
                "HAP_MAX_REQUEST_BYTES", 65_536, 16_384, 1_048_576
            ),
            max_record_bytes=_env_int("HAP_MAX_RECORD_BYTES", 49_152, 8_192, 262_144),
            max_statement_chars=_env_int(
                "HAP_MAX_STATEMENT_CHARS", 10_000, 256, 100_000
            ),
            write_requests_per_minute=_env_int(
                "HAP_WRITE_REQUESTS_PER_MINUTE", 10, 1, 10_000
            ),
            relay_pow_bits=_env_int("HAP_RELAY_POW_BITS", 0, 0, 30),
            allow_mainnet=_env_bool("HAP_ALLOW_MAINNET", False),
            allow_snapshot_import=_env_bool("HAP_ALLOW_SNAPSHOT_IMPORT", False),
            expose_docs=_env_bool("HAP_EXPOSE_DOCS", False),
            allow_snapshot_export=_env_bool("HAP_ALLOW_SNAPSHOT_EXPORT", False),
            require_submission_token=_env_bool("HAP_REQUIRE_SUBMISSION_TOKEN", False),
            submission_tokens=_read_tokens(
                "HAP_SUBMISSION_TOKENS", "HAP_SUBMISSION_TOKENS_FILE"
            ),
            admin_token=_read_secret("HAP_ADMIN_TOKEN", "HAP_ADMIN_TOKEN_FILE"),
            trusted_proxy_cidrs=_env_csv("HAP_TRUSTED_PROXY_CIDRS"),
            peers=_env_csv("HAP_PEERS"),
            sync_interval_seconds=_env_int("HAP_SYNC_INTERVAL_SECONDS", 0, 0, 86_400),
            sync_page_size=_env_int("HAP_SYNC_PAGE_SIZE", 100, 1, 5_000),
            max_sync_response_bytes=_env_int(
                "HAP_MAX_SYNC_RESPONSE_BYTES", 67_108_864, 65_536, 268_435_456
            ),
            max_sync_pages=_env_int("HAP_MAX_SYNC_PAGES", 10_000, 1, 1_000_000),
            max_batch_records=_env_int("HAP_MAX_BATCH_RECORDS", 1_000, 1, 50_000),
            max_package_bytes=_env_int(
                "HAP_MAX_PACKAGE_BYTES", 67_108_864, 65_536, 268_435_456
            ),
            bitcoin_required_for_readiness=_env_bool(
                "HAP_BITCOIN_REQUIRED_FOR_READINESS", False
            ),
            bitcoin_expected_network=os.environ.get(
                "HAP_BITCOIN_EXPECTED_NETWORK", "signet"
            )
            .strip()
            .lower(),
            bitcoin_scan_interval_seconds=_env_int(
                "HAP_BITCOIN_SCAN_INTERVAL_SECONDS", 0, 0, 86_400
            ),
            bitcoin_scan_start_height=_env_int(
                "HAP_BITCOIN_SCAN_START_HEIGHT", 0, 0, 10_000_000
            ),
            bitcoin_scan_max_blocks=_env_int(
                "HAP_BITCOIN_SCAN_MAX_BLOCKS", 500, 1, 100_000
            ),
            resolve_interval_seconds=_env_int(
                "HAP_RESOLVE_INTERVAL_SECONDS", 0, 0, 86_400
            ),
            serve_evidence=_env_bool("HAP_SERVE_EVIDENCE", False),
            max_evidence_bytes=_env_int(
                "HAP_MAX_EVIDENCE_BYTES", 2_147_483_648, 1_048_576, 1_099_511_627_776
            ),
            deployment_profile=os.environ.get("HAP_DEPLOYMENT_PROFILE", "production")[
                :80
            ],
            responsible_publication_profile=_env_bool(
                "HAP_RESPONSIBLE_PUBLICATION_PROFILE", True
            ),
            responsible_cooling_blocks=_env_int(
                "HAP_RESPONSIBLE_COOLING_BLOCKS", 6, 0, 100_000
            ),
            responsible_notice_protection_blocks=_env_int(
                "HAP_RESPONSIBLE_NOTICE_PROTECTION_BLOCKS", 6, 0, 100_000
            ),
            recognised_accountable_authors=_env_csv(
                "HAP_RECOGNISED_ACCOUNTABLE_AUTHORS"
            ),
        )
        settings.validate()
        return settings
