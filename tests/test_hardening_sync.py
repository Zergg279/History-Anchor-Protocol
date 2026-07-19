from __future__ import annotations

import json

import pytest

from hap.service import MissingDependencyError, ServiceError
from hap.sync import (
    SyncResult,
    _get_json,
    _get_page,
    _peer_key,
    sync_all_peers,
    sync_peer,
)


class StreamResponse:
    def __init__(self, value, *, headers=None, status_error=None, chunks=None):
        self.value = value
        self.headers = headers or {}
        self.status_error = status_error
        self._chunks = chunks

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def raise_for_status(self):
        if self.status_error:
            raise self.status_error

    def iter_bytes(self):
        if self._chunks is not None:
            yield from self._chunks
        else:
            yield json.dumps(self.value).encode()


class OneResponseClient:
    def __init__(self, response):
        self.response = response
        self.calls = []

    def stream(self, method, url, params=None):
        self.calls.append((method, url, params))
        return self.response


class StorageStub:
    def __init__(self, state=None):
        self.state = state
        self.persisted = []

    def peer_sync_state(self, key):
        return self.state

    def set_peer_sync_state(self, key, state):
        self.state = dict(state)
        self.persisted.append((key, dict(state)))


class ServiceStub:
    def __init__(self, state=None):
        self.storage = StorageStub(state)
        self.records = []
        self.batches = []
        self.anchors = []
        self.record_error = None
        self.batch_error = None
        self.anchor_error = None

    def submit_record(self, item, require_local_target=False):
        if self.record_error:
            raise self.record_error
        self.records.append(item)
        return {"status": "accepted"}

    def import_batch(self, item):
        if self.batch_error:
            raise self.batch_error
        self.batches.append(item)
        return {"status": "accepted"}

    def import_anchor_reference(self, item):
        if self.anchor_error:
            raise self.anchor_error
        self.anchors.append(item)
        return {"status": "accepted"}


class RouteClient:
    routes = {}

    def __init__(self, *args, **kwargs):
        self.args = args
        self.kwargs = kwargs

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def stream(self, method, url, params=None):
        path = "/" + url.split("/", 3)[-1] if "/" in url[8:] else "/"
        # More robustly retain the API path.
        marker = url.find("/v1/")
        path = url[marker:] if marker >= 0 else "/v1/info"
        key = (path, (params or {}).get("after_seq"))
        value = self.routes.get(key, self.routes.get(path))
        if isinstance(value, Exception):
            return StreamResponse({}, status_error=value)
        if value is None:
            raise AssertionError(f"missing fake route {key}")
        return StreamResponse(value)


def test_sync_result_and_peer_key_are_stable():
    result = SyncResult(
        peer="https://peer", records=1, batches=2, anchors=3, errors=4, reset=True
    )
    assert result.as_dict() == {
        "peer": "https://peer",
        "records": 1,
        "batches": 2,
        "anchors": 3,
        "errors": 4,
        "reset": True,
    }
    assert _peer_key("https://peer/") == _peer_key("https://peer")
    assert len(_peer_key("https://peer")) == 32


def test_get_json_filters_none_and_accepts_invalid_content_length():
    response = StreamResponse({"ok": True}, headers={"content-length": "unknown"})
    client = OneResponseClient(response)
    assert _get_json(
        client,
        "https://peer/",
        "/v1/info",
        {"a": 1, "unused": None},
        max_bytes=1024,
    ) == {"ok": True}
    assert client.calls == [("GET", "https://peer/v1/info", {"a": 1})]


def test_get_json_rejects_declared_and_streamed_size():
    client = OneResponseClient(StreamResponse({}, headers={"content-length": "1001"}))
    with pytest.raises(ValueError, match="exceeds"):
        _get_json(client, "https://peer", "/x", None, max_bytes=1000)

    client = OneResponseClient(StreamResponse({}, chunks=[b"x" * 600, b"x" * 500]))
    with pytest.raises(ValueError, match="exceeds"):
        _get_json(client, "https://peer", "/x", None, max_bytes=1000)


def test_get_page_validates_shape_cursor_and_has_more(monkeypatch):
    client = object()
    valid = {"items": [], "cursor": {"seq": 0}, "has_more": False}
    monkeypatch.setattr("hap.sync._get_json", lambda *a, **k: valid)
    assert _get_page(client, "p", "/x", {}, max_bytes=1) == valid

    for value, message in (
        ([], "invalid sync response"),
        (
            {"items": "bad", "cursor": {"seq": 0}, "has_more": False},
            "invalid sync response",
        ),
        ({"items": [], "cursor": {}, "has_more": False}, "invalid cursor"),
        ({"items": [], "cursor": {"seq": "0"}, "has_more": False}, "invalid cursor"),
        ({"items": [], "cursor": {"seq": 0}, "has_more": 1}, "invalid has_more"),
    ):
        monkeypatch.setattr("hap.sync._get_json", lambda *a, value=value, **k: value)
        with pytest.raises(ValueError, match=message):
            _get_page(client, "p", "/x", {}, max_bytes=1)


def set_happy_routes(epoch="epoch-1"):
    RouteClient.routes = {
        "/v1/info": {"sync_epoch": epoch},
        ("/v1/sync/records", 0): {
            "items": [{"record_id": "r"}],
            "cursor": {"seq": 1},
            "has_more": False,
        },
        ("/v1/sync/batches", 0): {
            "items": [{"batch_id": "b"}],
            "cursor": {"seq": 1},
            "has_more": False,
        },
        ("/v1/sync/anchors", 0): {
            "items": [{"txid": "a"}],
            "cursor": {"seq": 1},
            "has_more": False,
        },
    }


def test_sync_peer_happy_path_and_reset(monkeypatch):
    set_happy_routes()
    monkeypatch.setattr("hap.sync.httpx.Client", RouteClient)
    stale = {
        "peer": "https://different",
        "sync_epoch": "old",
        "records_seq": 99,
        "batches_seq": 99,
        "anchors_seq": 99,
    }
    service = ServiceStub(stale)
    result = sync_peer(service, "https://peer/", page_size=999)
    assert result.as_dict() == {
        "peer": "https://peer/",
        "records": 1,
        "batches": 1,
        "anchors": 1,
        "errors": 0,
        "reset": True,
    }
    assert service.records == [{"record_id": "r"}]
    assert service.batches == [{"batch_id": "b"}]
    assert service.anchors == [{"txid": "a"}]
    assert service.storage.state["records_seq"] == 1
    assert service.storage.state["batches_seq"] == 1
    assert service.storage.state["anchors_seq"] == 1


def test_sync_peer_rejects_invalid_info(monkeypatch):
    monkeypatch.setattr("hap.sync.httpx.Client", RouteClient)
    for value, message in (
        ([], "invalid node information"),
        ({}, "sync epoch"),
        ({"sync_epoch": ""}, "sync epoch"),
    ):
        RouteClient.routes = {"/v1/info": value}
        with pytest.raises(ValueError, match=message):
            sync_peer(ServiceStub(), "https://peer")


def test_sync_peer_counts_service_errors_and_stops_on_dependency(monkeypatch):
    set_happy_routes()
    monkeypatch.setattr("hap.sync.httpx.Client", RouteClient)
    service = ServiceStub()
    service.record_error = ServiceError("bad record")
    service.batch_error = MissingDependencyError("missing record")
    result = sync_peer(service, "https://peer")
    assert result.errors == 1
    assert result.records == 0
    assert result.batches == 0
    # Batch cursor remains unchanged after the missing dependency.
    assert service.storage.state["batches_seq"] == 0
    # Anchors are still attempted in the next kind pass.
    assert result.anchors == 1


def test_sync_peer_rejects_non_advancing_cursor(monkeypatch):
    set_happy_routes()
    RouteClient.routes[("/v1/sync/records", 0)] = {
        "items": [{"record_id": "r"}],
        "cursor": {"seq": 0},
        "has_more": False,
    }
    monkeypatch.setattr("hap.sync.httpx.Client", RouteClient)
    with pytest.raises(ValueError, match="failed to advance"):
        sync_peer(ServiceStub(), "https://peer")


def test_sync_peer_enforces_page_ceiling(monkeypatch):
    RouteClient.routes = {
        "/v1/info": {"sync_epoch": "e"},
        ("/v1/sync/records", 0): {
            "items": [],
            "cursor": {"seq": 0},
            "has_more": True,
        },
    }
    monkeypatch.setattr("hap.sync.httpx.Client", RouteClient)
    with pytest.raises(ValueError, match="page sync ceiling"):
        sync_peer(ServiceStub(), "https://peer", max_pages=1)


def test_sync_all_peers_returns_success_and_failure(monkeypatch):
    calls = []

    def fake(service, peer, **kwargs):
        calls.append((peer, kwargs))
        if peer == "bad":
            raise RuntimeError("offline")
        return SyncResult(peer=peer, records=2)

    monkeypatch.setattr("hap.sync.sync_peer", fake)
    results = sync_all_peers(
        object(), ("good", "bad"), page_size=3, max_response_bytes=4, max_pages=5
    )
    assert results[0]["records"] == 2
    assert results[1]["errors"] == 1
    assert results[1]["reason"] == "offline"
    assert calls[0][1] == {
        "page_size": 3,
        "max_response_bytes": 4,
        "max_pages": 5,
    }
