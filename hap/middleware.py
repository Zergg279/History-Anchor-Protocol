from __future__ import annotations

import json
import time
from collections import defaultdict, deque
from threading import Lock

from starlette.types import ASGIApp, Message, Receive, Scope, Send


class BodyLimitMiddleware:
    def __init__(self, app: ASGIApp, max_bytes: int):
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        length = next(
            (
                value
                for key, value in scope.get("headers", [])
                if key == b"content-length"
            ),
            None,
        )
        if length is not None:
            try:
                if int(length) > self.max_bytes:
                    await self._reject(send)
                    return
            except ValueError:
                await self._reject(send, "invalid Content-Length")
                return

        total = 0

        async def limited_receive() -> Message:
            nonlocal total
            message = await receive()
            if message["type"] == "http.request":
                total += len(message.get("body", b""))
                if total > self.max_bytes:
                    raise RequestTooLarge
            return message

        try:
            await self.app(scope, limited_receive, send)
        except RequestTooLarge:
            await self._reject(send)

    @staticmethod
    async def _reject(send: Send, detail: str = "request body is too large") -> None:
        body = json.dumps({"detail": detail}).encode("utf-8")
        await send(
            {
                "type": "http.response.start",
                "status": 413,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode()),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})


class RequestTooLarge(Exception):
    pass


class SecurityHeadersMiddleware:
    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        async def secure_send(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                headers.extend(
                    [
                        (b"x-content-type-options", b"nosniff"),
                        (b"x-frame-options", b"DENY"),
                        (b"referrer-policy", b"no-referrer"),
                        (
                            b"permissions-policy",
                            b"camera=(), microphone=(), geolocation=()",
                        ),
                        (
                            b"content-security-policy",
                            b"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
                        ),
                    ]
                )
                message["headers"] = headers
            await send(message)

        await self.app(scope, receive, secure_send)


class FixedWindowRateLimiter:
    def __init__(
        self, requests: int, window_seconds: float = 60.0, max_keys: int = 100_000
    ):
        self.requests = requests
        self.window_seconds = window_seconds
        self.max_keys = max_keys
        self.events: dict[str, deque[float]] = defaultdict(deque)
        self.lock = Lock()
        self._operations = 0

    def _prune(self, cutoff: float) -> None:
        expired: list[str] = []
        for key, queue in self.events.items():
            while queue and queue[0] <= cutoff:
                queue.popleft()
            if not queue:
                expired.append(key)
        for key in expired:
            self.events.pop(key, None)

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        cutoff = now - self.window_seconds
        with self.lock:
            self._operations += 1
            if self._operations % 1_000 == 0:
                self._prune(cutoff)
            queue = self.events.get(key)
            if queue is None:
                if len(self.events) >= self.max_keys:
                    self._prune(cutoff)
                    if len(self.events) >= self.max_keys:
                        return False
                queue = self.events[key]
            while queue and queue[0] <= cutoff:
                queue.popleft()
            if len(queue) >= self.requests:
                return False
            queue.append(now)
            return True
