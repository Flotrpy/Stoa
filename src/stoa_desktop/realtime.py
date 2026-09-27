"""Reconnectable authenticated WebSocket client for central events."""

import asyncio
import json
from collections.abc import Awaitable, Callable
from typing import Any

from websockets.asyncio.client import connect
from websockets.exceptions import ConnectionClosed, WebSocketException

EventHandler = Callable[[dict[str, Any]], Awaitable[None]]
StateHandler = Callable[[bool], Awaitable[None]]


class RealtimeClient:
    """Receive metadata events with bounded exponential reconnection delay."""

    def __init__(self, api_url: str, token: str) -> None:
        scheme = "wss" if api_url.startswith("https://") else "ws"
        host = api_url.split("://", maxsplit=1)[-1].rstrip("/")
        self.url = f"{scheme}://{host}/api/v1/events/ws"
        self.token = token
        self._stop = asyncio.Event()

    async def run(
        self,
        on_event: EventHandler,
        on_state: StateHandler,
        *,
        maximum_delay: float = 30.0,
    ) -> None:
        delay = 1.0
        while not self._stop.is_set():
            try:
                async with connect(
                    self.url,
                    additional_headers={"Authorization": f"Bearer {self.token}"},
                    open_timeout=10,
                ) as websocket:
                    await on_state(True)
                    delay = 1.0
                    async for raw_message in websocket:
                        event = json.loads(raw_message)
                        if isinstance(event, dict):
                            await on_event(event)
            except (OSError, ConnectionClosed, WebSocketException, json.JSONDecodeError):
                await on_state(False)
                try:
                    await asyncio.wait_for(self._stop.wait(), timeout=delay)
                except TimeoutError:
                    delay = min(delay * 2, maximum_delay)

    def stop(self) -> None:
        self._stop.set()
