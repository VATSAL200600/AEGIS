"""AEGIS Reconnaissance Engine — Real-Time SSE Event Bus

Publishes asynchronous scan progress, asset discoveries, and vulnerability alerts
to connected frontend clients via Server-Sent Events (SSE).
"""
import asyncio
import json
import logging
from typing import Dict, Set, Any, AsyncGenerator, List

logger = logging.getLogger("aegis.recon.event_bus")


class ScanEventBus:
    """In-memory pub/sub event bus supporting multiple SSE subscribers per scan."""

    def __init__(self, max_history: int = 150):
        self._subscribers: Dict[str, Set[asyncio.Queue]] = {}
        self._history: Dict[str, List[Dict[str, Any]]] = {}
        self._max_history = max_history

    async def publish(self, scan_id: str, event_type: str, data: Dict[str, Any]):
        """
        Publish an event to all subscribers listening to scan_id.
        Appends event to in-memory history buffer.
        """
        event_payload = {
            "event": event_type,
            "data": data
        }

        # Save to replay buffer
        if scan_id not in self._history:
            self._history[scan_id] = []
        self._history[scan_id].append(event_payload)
        if len(self._history[scan_id]) > self._max_history:
            self._history[scan_id].pop(0)

        # Distribute to active queues
        queues = self._subscribers.get(scan_id, set())
        for q in list(queues):
            try:
                q.put_nowait(event_payload)
            except asyncio.QueueFull:
                logger.warning(f"Subscriber queue full for scan {scan_id}")
            except Exception as e:
                logger.debug(f"Error publishing to subscriber queue: {e}")

    async def subscribe(self, scan_id: str) -> AsyncGenerator[str, None]:
        """
        Subscribes to live events for a scan_id.
        Yields RFC-8895 Server-Sent Events (SSE) formatted text.
        Replays prior events before streaming live events.
        """
        queue: asyncio.Queue = asyncio.Queue(maxsize=100)

        if scan_id not in self._subscribers:
            self._subscribers[scan_id] = set()
        self._subscribers[scan_id].add(queue)

        try:
            # 1. Replay recent history
            history_events = self._history.get(scan_id, [])
            for event_obj in history_events:
                yield self._format_sse(event_obj["event"], event_obj["data"])
                if event_obj["event"] in ["scan_completed", "scan_failed"]:
                    return  # Scan already finished

            # 2. Stream live events
            while True:
                event_obj = await queue.get()
                yield self._format_sse(event_obj["event"], event_obj["data"])

                # If terminal event received, close stream
                if event_obj["event"] in ["scan_completed", "scan_failed"]:
                    break
        except asyncio.CancelledError:
            pass
        finally:
            if scan_id in self._subscribers and queue in self._subscribers[scan_id]:
                self._subscribers[scan_id].remove(queue)
                if not self._subscribers[scan_id]:
                    del self._subscribers[scan_id]

    @staticmethod
    def _format_sse(event: str, data: Dict[str, Any]) -> str:
        """Format event type and dictionary payload into standard SSE wire format."""
        if isinstance(data, dict):
            enriched = {**data, "event": event, "type": event}
        else:
            enriched = {"data": data, "event": event, "type": event}
        json_data = json.dumps(enriched)
        return f"event: {event}\ndata: {json_data}\n\n"

    def clear_scan(self, scan_id: str):
        """Purge history and clean up memory when scan is deleted."""
        self._history.pop(scan_id, None)
        self._subscribers.pop(scan_id, None)


# Global singleton instance
event_bus = ScanEventBus()
