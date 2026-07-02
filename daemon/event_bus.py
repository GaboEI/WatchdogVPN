from __future__ import annotations

import queue
import threading
from dataclasses import dataclass

from daemon.protocol import Event


@dataclass(frozen=True, slots=True)
class EventSubscription:
    _bus: "EventBus"
    _queue: "queue.Queue[Event]"
    _closed: threading.Event

    def get(self, timeout: float | None = None) -> Event:
        return self._queue.get(timeout=timeout)

    def close(self) -> None:
        if self._closed.is_set():
            return
        self._closed.set()
        self._bus.unsubscribe(self)


class EventBus:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._subscribers: set[EventSubscription] = set()

    def subscribe(self) -> EventSubscription:
        subscription = EventSubscription(
            _bus=self,
            _queue=queue.Queue(),
            _closed=threading.Event(),
        )
        with self._lock:
            self._subscribers.add(subscription)
        return subscription

    def unsubscribe(self, subscription: EventSubscription) -> None:
        with self._lock:
            self._subscribers.discard(subscription)

    def broadcast(self, event: Event) -> None:
        with self._lock:
            subscribers = list(self._subscribers)
        for subscription in subscribers:
            if not subscription._closed.is_set():
                subscription._queue.put(event)

    def subscriber_count(self) -> int:
        with self._lock:
            return len(self._subscribers)
