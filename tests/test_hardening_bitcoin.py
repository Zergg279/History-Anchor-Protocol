from __future__ import annotations


import pytest

from hap.bitcoin import (
    MAGIC,
    VERSION,
    AnchorPayload,
    BitcoinRPC,
    BitcoinRPCError,
    build_op_return_script,
    decode_anchor_payload,
    encode_anchor_payload,
    extract_payload_from_script,
)


class FakeResponse:
    def __init__(self, payload=None, *, error: Exception | None = None):
        self.payload = payload
        self.error = error

    def raise_for_status(self):
        if self.error:
            raise self.error

    def json(self):
        if isinstance(self.payload, Exception):
            raise self.payload
        return self.payload


def test_anchor_payload_round_trip_and_dict():
    digest = "ab" * 32
    encoded = encode_anchor_payload(manifest_hash=digest, commitment_type=7)
    decoded = decode_anchor_payload(encoded)
    assert decoded == AnchorPayload(
        version=VERSION, commitment_type=7, manifest_hash=digest
    )
    assert decoded.as_dict() == {
        "magic": MAGIC.decode("ascii"),
        "version": VERSION,
        "commitment_type": 7,
        "manifest_hash": digest,
    }


@pytest.mark.parametrize(
    "value,message",
    [
        ("zz", "hexadecimal"),
        ("aa", "32-byte"),
    ],
)
def test_encode_anchor_payload_rejects_bad_digest(value, message):
    with pytest.raises(ValueError, match=message):
        encode_anchor_payload(manifest_hash=value)


@pytest.mark.parametrize("commitment_type", [-1, 256])
def test_encode_anchor_payload_rejects_bad_type(commitment_type):
    with pytest.raises(ValueError, match="one byte"):
        encode_anchor_payload(manifest_hash="00" * 32, commitment_type=commitment_type)


def test_decode_anchor_payload_rejects_shape_magic_and_version():
    with pytest.raises(ValueError, match="38 bytes"):
        decode_anchor_payload("00")
    valid = bytearray.fromhex(encode_anchor_payload(manifest_hash="00" * 32))
    invalid_magic = valid.copy()
    invalid_magic[0] ^= 1
    with pytest.raises(ValueError, match="magic"):
        decode_anchor_payload(invalid_magic.hex())
    invalid_version = valid.copy()
    invalid_version[4] = (VERSION + 1) % 256
    with pytest.raises(ValueError, match="version"):
        decode_anchor_payload(invalid_version.hex())


def test_op_return_helpers_cover_invalid_scripts():
    payload = encode_anchor_payload(manifest_hash="11" * 32)
    script = build_op_return_script(payload)
    assert extract_payload_from_script(script) == payload
    assert extract_payload_from_script("not-hex") is None
    assert extract_payload_from_script(None) is None
    assert extract_payload_from_script("") is None
    assert extract_payload_from_script("51") is None
    assert extract_payload_from_script("6a4c") is None
    assert extract_payload_from_script("6a02aa") is None
    with pytest.raises(ValueError, match="PUSHDATA"):
        build_op_return_script((b"x" * 76).hex())


def test_rpc_init_encodes_wallet_and_auth():
    rpc = BitcoinRPC(
        url="http://127.0.0.1:8332/",
        username="alice",
        password="secret",
        wallet="wallet name/one",
        timeout=4.5,
    )
    assert rpc.url.endswith("/wallet/wallet%20name%2Fone")
    assert rpc.auth == ("alice", "secret")
    assert rpc.timeout == 4.5
    assert BitcoinRPC(url="http://x", username="only").auth is None


def clear_rpc_env(monkeypatch):
    for key in (
        "HAP_BITCOIN_RPC_URL",
        "HAP_BITCOIN_RPC_USER",
        "HAP_BITCOIN_RPC_PASSWORD",
        "HAP_BITCOIN_RPC_USER_FILE",
        "HAP_BITCOIN_RPC_PASSWORD_FILE",
        "HAP_BITCOIN_COOKIE_FILE",
        "HAP_BITCOIN_RPC_WALLET",
        "HAP_MAX_ANCHOR_FEE_BTC",
    ):
        monkeypatch.delenv(key, raising=False)


def test_rpc_from_environment_direct_and_files(tmp_path, monkeypatch):
    clear_rpc_env(monkeypatch)
    with pytest.raises(BitcoinRPCError, match="URL"):
        BitcoinRPC.from_environment()

    monkeypatch.setenv("HAP_BITCOIN_RPC_URL", "http://node")
    monkeypatch.setenv("HAP_BITCOIN_RPC_USER", "direct-user")
    monkeypatch.setenv("HAP_BITCOIN_RPC_PASSWORD", "direct-pass")
    monkeypatch.setenv("HAP_BITCOIN_RPC_WALLET", "w")
    monkeypatch.setenv("HAP_MAX_ANCHOR_FEE_BTC", "0.002")
    rpc = BitcoinRPC.from_environment()
    assert rpc.auth == ("direct-user", "direct-pass")
    assert rpc.url == "http://node/wallet/w"
    assert rpc.max_anchor_fee_btc == 0.002

    user_file = tmp_path / "user"
    pass_file = tmp_path / "pass"
    user_file.write_text(" file-user \n")
    pass_file.write_text(" file-pass \n")
    monkeypatch.setenv("HAP_BITCOIN_RPC_USER_FILE", str(user_file))
    monkeypatch.setenv("HAP_BITCOIN_RPC_PASSWORD_FILE", str(pass_file))
    rpc = BitcoinRPC.from_environment()
    assert rpc.auth == ("file-user", "file-pass")

    cookie = tmp_path / "cookie"
    cookie.write_text("cookie-user:cookie-pass\n")
    monkeypatch.setenv("HAP_BITCOIN_COOKIE_FILE", str(cookie))
    rpc = BitcoinRPC.from_environment()
    assert rpc.auth == ("cookie-user", "cookie-pass")


@pytest.mark.parametrize(
    "env_key,error_message",
    [
        ("HAP_BITCOIN_RPC_USER_FILE", "username file"),
        ("HAP_BITCOIN_RPC_PASSWORD_FILE", "password file"),
        ("HAP_BITCOIN_COOKIE_FILE", "cookie file"),
    ],
)
def test_rpc_from_environment_file_errors(
    tmp_path, monkeypatch, env_key, error_message
):
    clear_rpc_env(monkeypatch)
    monkeypatch.setenv("HAP_BITCOIN_RPC_URL", "http://node")
    monkeypatch.setenv(env_key, str(tmp_path / "missing"))
    with pytest.raises(BitcoinRPCError, match=error_message):
        BitcoinRPC.from_environment()


def test_rpc_call_success_rpc_error_and_transport_error(monkeypatch):
    captured = []

    def post_success(*args, **kwargs):
        captured.append((args, kwargs))
        return FakeResponse({"result": {"ok": True}, "error": None})

    monkeypatch.setattr("hap.bitcoin.httpx.post", post_success)
    rpc = BitcoinRPC(url="http://node", username="u", password="p")
    assert rpc.call("method", 1, "x") == {"ok": True}
    assert captured[0][1]["json"]["id"] == 1
    assert captured[0][1]["json"]["params"] == [1, "x"]

    monkeypatch.setattr(
        "hap.bitcoin.httpx.post",
        lambda *a, **k: FakeResponse({"result": None, "error": {"code": -1}}),
    )
    with pytest.raises(BitcoinRPCError, match="method"):
        rpc.call("method")

    monkeypatch.setattr(
        "hap.bitcoin.httpx.post",
        lambda *a, **k: FakeResponse(error=RuntimeError("offline")),
    )
    with pytest.raises(BitcoinRPCError, match="request failed"):
        rpc.call("method")


def test_network_block_helpers_and_context(monkeypatch):
    rpc = BitcoinRPC(url="http://node")
    responses = {
        "getblockchaininfo": {"chain": "main"},
        "getblockcount": "12",
        "getblockhash": "ab" * 32,
        "getblock": {"height": 12},
        "getblockheader": {
            "height": 12,
            "time": 100,
            "mediantime": 90,
            "confirmations": 3,
        },
    }
    monkeypatch.setattr(rpc, "call", lambda method, *params: responses[method])
    assert rpc.network() == "mainnet"
    assert rpc.block_count() == 12
    assert rpc.block_hash(12) == "ab" * 32
    assert rpc.block("ab" * 32) == {"height": 12}
    assert rpc.block_context("ab" * 32)["in_active_chain"] is True

    responses["getblockchaininfo"] = {"chain": "custom"}
    assert rpc.network() == "custom"
    with pytest.raises(BitcoinRPCError, match="negative"):
        rpc.block_hash(-1)
    responses["getblock"] = "raw"
    with pytest.raises(BitcoinRPCError, match="decoded block"):
        rpc.block("ab" * 32)
    responses["getblockheader"] = {"confirmations": -1}
    assert rpc.block_context("ab" * 32)["in_active_chain"] is False


def test_broadcast_op_return_success(monkeypatch):
    payload = encode_anchor_payload(manifest_hash="22" * 32)
    script = build_op_return_script(payload)
    rpc = BitcoinRPC(url="http://node", max_anchor_fee_btc=0.01)
    calls = []

    def fake_call(method, *params):
        calls.append((method, params))
        return {
            "createrawtransaction": "raw",
            "fundrawtransaction": {"hex": "funded", "fee": 0.00001},
            "signrawtransactionwithwallet": {"hex": "signed", "complete": True},
            "testmempoolaccept": [{"allowed": True}],
            "decoderawtransaction": {
                "vout": [
                    {"n": 1, "scriptPubKey": {"hex": "51"}},
                    {"n": 3, "scriptPubKey": {"hex": script}},
                ]
            },
            "sendrawtransaction": "33" * 32,
        }[method]

    monkeypatch.setattr(rpc, "call", fake_call)
    result = rpc.broadcast_op_return(payload)
    assert result == {
        "txid": "33" * 32,
        "vout": 3,
        "fee_btc": 0.00001,
        "raw_transaction": "signed",
    }
    assert [name for name, _ in calls] == [
        "createrawtransaction",
        "fundrawtransaction",
        "signrawtransactionwithwallet",
        "testmempoolaccept",
        "decoderawtransaction",
        "sendrawtransaction",
    ]


@pytest.mark.parametrize(
    "responses,message",
    [
        ({"fundrawtransaction": {"hex": "funded", "fee": 0}}, "outside allowed"),
        (
            {
                "fundrawtransaction": {"hex": "funded", "fee": 0.02},
            },
            "outside allowed",
        ),
        (
            {
                "fundrawtransaction": {"hex": "funded", "fee": 0.00001},
                "signrawtransactionwithwallet": {"hex": "signed", "complete": False},
            },
            "fully sign",
        ),
        (
            {
                "fundrawtransaction": {"hex": "funded", "fee": 0.00001},
                "signrawtransactionwithwallet": {"hex": "signed", "complete": True},
                "testmempoolaccept": [],
            },
            "no result",
        ),
        (
            {
                "fundrawtransaction": {"hex": "funded", "fee": 0.00001},
                "signrawtransactionwithwallet": {"hex": "signed", "complete": True},
                "testmempoolaccept": [{"allowed": False, "reject-reason": "policy"}],
            },
            "policy",
        ),
    ],
)
def test_broadcast_op_return_failure_paths(monkeypatch, responses, message):
    payload = encode_anchor_payload(manifest_hash="22" * 32)
    rpc = BitcoinRPC(url="http://node", max_anchor_fee_btc=0.01)

    def fake_call(method, *params):
        defaults = {
            "createrawtransaction": "raw",
            "fundrawtransaction": {"hex": "funded", "fee": 0.00001},
            "signrawtransactionwithwallet": {"hex": "signed", "complete": True},
            "testmempoolaccept": [{"allowed": True}],
            "decoderawtransaction": {"vout": []},
        }
        return responses.get(method, defaults[method])

    monkeypatch.setattr(rpc, "call", fake_call)
    with pytest.raises(BitcoinRPCError, match=message):
        rpc.broadcast_op_return(payload)


def test_broadcast_requires_exactly_one_commitment(monkeypatch):
    payload = encode_anchor_payload(manifest_hash="22" * 32)
    script = build_op_return_script(payload)
    rpc = BitcoinRPC(url="http://node")

    def run(vouts):
        def fake_call(method, *params):
            return {
                "createrawtransaction": "raw",
                "fundrawtransaction": {"hex": "funded", "fee": 0.00001},
                "signrawtransactionwithwallet": {"hex": "signed", "complete": True},
                "testmempoolaccept": [{"allowed": True}],
                "decoderawtransaction": {"vout": vouts},
            }[method]

        monkeypatch.setattr(rpc, "call", fake_call)
        with pytest.raises(BitcoinRPCError, match="exactly one"):
            rpc.broadcast_op_return(payload)

    run([])
    run(
        [
            {"n": 0, "scriptPubKey": {"hex": script}},
            {"n": 1, "scriptPubKey": {"hex": script}},
        ]
    )


def test_transaction_wallet_and_fallback(monkeypatch):
    rpc = BitcoinRPC(url="http://node")
    monkeypatch.setattr(
        rpc,
        "call",
        lambda method, *params: {
            "decoded": {"txid": "aa" * 32},
            "confirmations": 2,
            "blockhash": "bb" * 32,
            "blockheight": 9,
            "blocktime": 10,
        },
    )
    tx = rpc.transaction("aa" * 32)
    assert tx["confirmations"] == 2
    assert tx["blockheight"] == 9

    calls = []

    def fallback(method, *params):
        calls.append((method, params))
        if method == "gettransaction":
            raise BitcoinRPCError("not wallet")
        return {"txid": params[0]}

    monkeypatch.setattr(rpc, "call", fallback)
    assert rpc.transaction("cc" * 32, "dd" * 32)["txid"] == "cc" * 32
    assert calls[-1] == ("getrawtransaction", ("cc" * 32, True, "dd" * 32))


def test_find_payload_exact_vout_and_first_valid(monkeypatch):
    rpc = BitcoinRPC(url="http://node")
    first = encode_anchor_payload(manifest_hash="11" * 32)
    second = encode_anchor_payload(manifest_hash="22" * 32)
    tx = {
        "vout": [
            {"n": 0, "scriptPubKey": {"hex": "51"}},
            {"n": 2, "scriptPubKey": {"hex": "6a01ff"}},
            {"n": 4, "scriptPubKey": {"hex": build_op_return_script(first)}},
            {"n": 7, "scriptPubKey": {"hex": build_op_return_script(second)}},
        ]
    }
    monkeypatch.setattr(rpc, "transaction", lambda *a, **k: tx)
    assert rpc.find_payload("aa" * 32)[0] == first
    assert rpc.find_payload("aa" * 32, expected_payload_hex=second)[2] == 7
    assert rpc.find_payload("aa" * 32, expected_vout=7)[0] == second
    assert rpc.find_payload("aa" * 32, expected_vout=99) is None
    assert rpc.find_payload("aa" * 32, expected_payload_hex="ff") is None
