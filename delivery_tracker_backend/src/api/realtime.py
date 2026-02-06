from __future__ import annotations

import asyncio
import json
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from fastapi import WebSocket


@dataclass(frozen=True)
class Subscription:
    delivery_id: UUID


class RealtimeHub:
    """
    In-memory pub/sub hub for WebSocket connections.

    Notes:
    - This is per-process; if you scale horizontally, use Redis/pubsub.
    - Consumers subscribe to delivery_ids and receive JSON messages.
    """

    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        # IMPORTANT: must be a real runtime defaultdict, not typing.DefaultDict (type-only).
        self._delivery_subscribers: dict[UUID, set[WebSocket]] = defaultdict(set)

    async def subscribe(self, websocket: WebSocket, delivery_id: UUID) -> None:
        async with self._lock:
            self._delivery_subscribers[delivery_id].add(websocket)

    async def unsubscribe_all(self, websocket: WebSocket) -> None:
        async with self._lock:
            for delivery_id in list(self._delivery_subscribers.keys()):
                if websocket in self._delivery_subscribers[delivery_id]:
                    self._delivery_subscribers[delivery_id].remove(websocket)
                if not self._delivery_subscribers[delivery_id]:
                    del self._delivery_subscribers[delivery_id]

    async def publish(self, delivery_id: UUID, message_type: str, payload: dict[str, Any]) -> None:
        emitted = datetime.now(timezone.utc).isoformat()
        msg = {
            "type": message_type,
            "delivery_id": str(delivery_id),
            "payload": payload,
            "emitted_at": emitted,
        }
        data = json.dumps(msg)

        async with self._lock:
            subscribers = list(self._delivery_subscribers.get(delivery_id, set()))

        # Send outside lock; ignore broken connections (cleanup handled on disconnect).
        for ws in subscribers:
            try:
                await ws.send_text(data)
            except Exception:
                # Best-effort; will be removed on disconnect.
                pass


realtime_hub = RealtimeHub()
