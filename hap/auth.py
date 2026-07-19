from __future__ import annotations

import hashlib
import hmac
import ipaddress
from typing import Iterable

from fastapi import HTTPException, Request


def _constant_time_member(value: str, candidates: Iterable[str]) -> bool:
    return any(hmac.compare_digest(value, candidate) for candidate in candidates)


def require_submission_token(
    request: Request, required: bool, tokens: tuple[str, ...]
) -> str | None:
    supplied = request.headers.get("x-hap-submission-token")
    if not required:
        if supplied and _constant_time_member(supplied, tokens):
            return supplied
        return None
    if not supplied or not _constant_time_member(supplied, tokens):
        raise HTTPException(
            401,
            "valid submission token required",
            headers={"WWW-Authenticate": "HAP-Submission"},
        )
    return supplied


def require_admin_token(request: Request, expected: str | None) -> None:
    if not expected:
        raise HTTPException(503, "coordinator administration is not configured")
    authorization = request.headers.get("authorization", "")
    scheme, _, supplied = authorization.partition(" ")
    if (
        scheme.lower() != "bearer"
        or not supplied
        or not hmac.compare_digest(supplied, expected)
    ):
        raise HTTPException(
            401,
            "valid coordinator bearer token required",
            headers={"WWW-Authenticate": "Bearer"},
        )


def token_rate_key(token: str | None) -> str | None:
    if not token:
        return None
    return "token:" + hashlib.sha256(token.encode("utf-8")).hexdigest()[:24]


def trusted_client_ip(request: Request, trusted_proxy_cidrs: tuple[str, ...]) -> str:
    peer = request.client.host if request.client else "unknown"
    if not trusted_proxy_cidrs or peer == "unknown":
        return peer
    try:
        peer_ip = ipaddress.ip_address(peer)
        trusted = any(
            peer_ip in ipaddress.ip_network(cidr, strict=False)
            for cidr in trusted_proxy_cidrs
        )
    except ValueError:
        trusted = False
    if not trusted:
        return peer
    forwarded = request.headers.get("x-forwarded-for", "")
    candidate = forwarded.split(",", 1)[0].strip()
    if not candidate:
        return peer
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return peer
