from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import quote

import httpx

MAGIC = b"HIST"
VERSION = 3
COMMITMENT_TYPE_BATCH_MANIFEST = 1


class BitcoinRPCError(RuntimeError):
    pass


@dataclass(frozen=True)
class AnchorPayload:
    version: int
    commitment_type: int
    manifest_hash: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "magic": MAGIC.decode("ascii"),
            "version": self.version,
            "commitment_type": self.commitment_type,
            "manifest_hash": self.manifest_hash,
        }


def encode_anchor_payload(
    *, manifest_hash: str, commitment_type: int = COMMITMENT_TYPE_BATCH_MANIFEST
) -> str:
    try:
        digest = bytes.fromhex(manifest_hash)
    except ValueError as exc:
        raise ValueError("manifest_hash must be hexadecimal") from exc
    if len(digest) != 32:
        raise ValueError("manifest_hash must be a 32-byte hex digest")
    if not 0 <= commitment_type <= 255:
        raise ValueError("commitment_type must fit in one byte")
    return (MAGIC + bytes([VERSION, commitment_type]) + digest).hex()


def decode_anchor_payload(payload_hex: str) -> AnchorPayload:
    raw = bytes.fromhex(payload_hex)
    expected_length = 4 + 1 + 1 + 32
    if len(raw) != expected_length:
        raise ValueError(f"anchor payload must be {expected_length} bytes")
    if raw[:4] != MAGIC:
        raise ValueError("invalid anchor magic")
    if raw[4] != VERSION:
        raise ValueError("unsupported anchor version")
    return AnchorPayload(
        version=raw[4], commitment_type=raw[5], manifest_hash=raw[6:].hex()
    )


def build_op_return_script(payload_hex: str) -> str:
    payload = bytes.fromhex(payload_hex)
    if len(payload) > 75:
        raise ValueError(
            "payload requires PUSHDATA encoding not supported by this helper"
        )
    return (bytes([0x6A, len(payload)]) + payload).hex()


def extract_payload_from_script(script_hex: str) -> str | None:
    try:
        raw = bytes.fromhex(script_hex)
    except (TypeError, ValueError):
        return None
    if len(raw) < 2 or raw[0] != 0x6A:
        return None
    size = raw[1]
    if size > 75 or len(raw) != size + 2:
        return None
    return raw[2:].hex()


class BitcoinRPC:
    def __init__(
        self,
        *,
        url: str,
        username: str | None = None,
        password: str | None = None,
        wallet: str | None = None,
        timeout: float = 30.0,
        max_anchor_fee_btc: float = 0.001,
    ):
        base = url.rstrip("/")
        self.url = f"{base}/wallet/{quote(wallet, safe='')}" if wallet else base
        self.auth = (
            (username, password)
            if username is not None and password is not None
            else None
        )
        self.timeout = timeout
        self.max_anchor_fee_btc = max_anchor_fee_btc
        self._counter = 0

    @classmethod
    def from_environment(cls) -> "BitcoinRPC":
        url = os.environ.get("HAP_BITCOIN_RPC_URL")
        if not url:
            raise BitcoinRPCError("HAP_BITCOIN_RPC_URL is not configured")
        username = os.environ.get("HAP_BITCOIN_RPC_USER")
        password = os.environ.get("HAP_BITCOIN_RPC_PASSWORD")
        user_file = os.environ.get("HAP_BITCOIN_RPC_USER_FILE")
        password_file = os.environ.get("HAP_BITCOIN_RPC_PASSWORD_FILE")
        if user_file:
            try:
                username = (
                    Path(user_file).expanduser().read_text(encoding="utf-8").strip()
                )
            except Exception as exc:
                raise BitcoinRPCError(
                    "could not read Bitcoin Core RPC username file"
                ) from exc
        if password_file:
            try:
                password = (
                    Path(password_file).expanduser().read_text(encoding="utf-8").strip()
                )
            except Exception as exc:
                raise BitcoinRPCError(
                    "could not read Bitcoin Core RPC password file"
                ) from exc
        cookie_file = os.environ.get("HAP_BITCOIN_COOKIE_FILE")
        if cookie_file:
            try:
                username, password = (
                    Path(cookie_file)
                    .expanduser()
                    .read_text(encoding="utf-8")
                    .strip()
                    .split(":", 1)
                )
            except Exception as exc:
                raise BitcoinRPCError(
                    "could not read Bitcoin Core cookie file"
                ) from exc
        return cls(
            url=url,
            username=username,
            password=password,
            wallet=os.environ.get("HAP_BITCOIN_RPC_WALLET"),
            max_anchor_fee_btc=float(os.environ.get("HAP_MAX_ANCHOR_FEE_BTC", "0.001")),
        )

    def call(self, method: str, *params: Any) -> Any:
        self._counter += 1
        try:
            response = httpx.post(
                self.url,
                auth=self.auth,
                timeout=self.timeout,
                json={
                    "jsonrpc": "2.0",
                    "id": self._counter,
                    "method": method,
                    "params": list(params),
                },
            )
            response.raise_for_status()
            data = response.json()
        except Exception as exc:
            raise BitcoinRPCError(f"{method}: Bitcoin Core RPC request failed") from exc
        if data.get("error"):
            raise BitcoinRPCError(f"{method}: {data['error']}")
        return data.get("result")

    def network(self) -> str:
        chain = self.call("getblockchaininfo")["chain"]
        return {"main": "mainnet", "signet": "signet", "regtest": "regtest"}.get(
            chain, chain
        )

    def block_count(self) -> int:
        return int(self.call("getblockcount"))

    def block_hash(self, height: int) -> str:
        if height < 0:
            raise BitcoinRPCError("block height cannot be negative")
        return str(self.call("getblockhash", height))

    def block(self, block_hash: str, *, verbosity: int = 2) -> dict[str, Any]:
        result = self.call("getblock", block_hash, verbosity)
        if not isinstance(result, dict):
            raise BitcoinRPCError("getblock did not return a decoded block")
        return result

    def broadcast_op_return(self, payload_hex: str) -> dict[str, Any]:
        raw = self.call("createrawtransaction", [], [{"data": payload_hex}], 0, True)
        funded = self.call("fundrawtransaction", raw, {"changePosition": 1})
        fee = float(funded.get("fee", 0))
        if fee <= 0 or fee > self.max_anchor_fee_btc:
            raise BitcoinRPCError(
                f"anchor fee {fee:.8f} BTC is outside allowed range (max {self.max_anchor_fee_btc:.8f} BTC)"
            )
        signed = self.call("signrawtransactionwithwallet", funded["hex"])
        if not signed.get("complete"):
            raise BitcoinRPCError("wallet could not fully sign the anchor transaction")
        acceptance = self.call("testmempoolaccept", [signed["hex"]])
        if not acceptance or not acceptance[0].get("allowed"):
            reason = (
                acceptance[0].get("reject-reason", "unknown rejection")
                if acceptance
                else "no result"
            )
            raise BitcoinRPCError(
                f"anchor transaction rejected by mempool policy: {reason}"
            )
        decoded = self.call("decoderawtransaction", signed["hex"])
        matching_vouts: list[int] = []
        for output in decoded.get("vout", []):
            script = output.get("scriptPubKey", {})
            if extract_payload_from_script(script.get("hex", "")) == payload_hex:
                matching_vouts.append(int(output.get("n", 0)))
        if len(matching_vouts) != 1:
            raise BitcoinRPCError(
                "signed anchor transaction does not contain exactly one expected commitment"
            )
        txid = self.call("sendrawtransaction", signed["hex"])
        return {
            "txid": txid,
            "vout": matching_vouts[0],
            "fee_btc": fee,
            "raw_transaction": signed["hex"],
        }

    def transaction(self, txid: str, block_hash: str | None = None) -> dict[str, Any]:
        try:
            wallet_tx = self.call("gettransaction", txid, False, True)
            decoded = wallet_tx.get("decoded") or {}
            decoded.update(
                {
                    "confirmations": wallet_tx.get("confirmations", 0),
                    "blockhash": wallet_tx.get("blockhash"),
                    "blockheight": wallet_tx.get("blockheight"),
                    "blocktime": wallet_tx.get("blocktime"),
                }
            )
            return decoded
        except BitcoinRPCError:
            params: list[Any] = [txid, True]
            if block_hash:
                params.append(block_hash)
            return self.call("getrawtransaction", *params)

    def find_payload(
        self,
        txid: str,
        block_hash: str | None = None,
        expected_payload_hex: str | None = None,
        expected_vout: int | None = None,
    ) -> tuple[str, dict[str, Any], int] | None:
        """Find a valid HAP payload, optionally requiring an exact expected commitment.

        A Bitcoin transaction may contain more than one OP_RETURN output. Verifiers must
        inspect every output rather than accepting or rejecting solely on the first HAP-like
        payload they encounter.
        """
        tx = self.transaction(txid, block_hash)
        first_valid: tuple[str, dict[str, Any], int] | None = None
        for output_index, output in enumerate(tx.get("vout", [])):
            output_number = int(output.get("n", output_index))
            if expected_vout is not None and output_number != expected_vout:
                continue
            script = output.get("scriptPubKey", {})
            payload = extract_payload_from_script(script.get("hex", ""))
            if not payload:
                continue
            try:
                decode_anchor_payload(payload)
            except Exception:
                continue
            candidate = (payload, tx, output_number)
            if expected_payload_hex is None or payload == expected_payload_hex:
                return candidate
            if first_valid is None:
                first_valid = candidate
        return first_valid if expected_payload_hex is None else None

    def block_context(self, block_hash: str) -> dict[str, Any]:
        header = self.call("getblockheader", block_hash, True)
        return {
            "block_hash": block_hash,
            "block_height": header.get("height"),
            "block_time": header.get("time"),
            "median_time": header.get("mediantime"),
            "block_confirmations": header.get("confirmations"),
            "in_active_chain": int(header.get("confirmations", -1)) >= 0,
        }
