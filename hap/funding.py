"""Official-release funding metadata.

Funding metadata is deliberately outside HAP validity and Bitcoin consensus.  The
address is fixed in a particular signed source release so users can authenticate
that release's intended contribution destination.  Forks may change it, but must
not imply that their destination belongs to the original maintainers.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

GENESIS_DONATION_ADDRESS = (
    "bc1pughulyqcqtxjz7xsa3lgd7pmkfd3ptper3z55n7gh4ffjjk2xrxsj6lqds"
)
RELEASE_VERSION = "1.0.0"


def canonical_funding_manifest() -> dict[str, Any]:
    """Return the content covered by the funding-manifest identifier."""

    return {
        "schema": "hap.funding",
        "version": 1,
        "release_version": RELEASE_VERSION,
        "bitcoin_network": "mainnet",
        "genesis_donation_address": GENESIS_DONATION_ADDRESS,
        "purpose": "voluntary support for open-source HAP development",
        "consensus_effect": False,
        "governance_rights": False,
        "protocol_dependency": False,
    }


def funding_manifest_id() -> str:
    encoded = json.dumps(
        canonical_funding_manifest(),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def funding_info() -> dict[str, Any]:
    value = canonical_funding_manifest()
    value["manifest_id"] = funding_manifest_id()
    value["notice"] = (
        "Voluntary support only. This address has no role in protocol validity, "
        "governance, ranking, publication, or node operation."
    )
    return value
