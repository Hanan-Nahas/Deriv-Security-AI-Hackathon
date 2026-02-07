"""Behavior monitoring for session anomaly detection and risk scoring."""

from __future__ import annotations

import logging
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Dict, List

logger = logging.getLogger(__name__)


@dataclass
class SessionEvent:
    """Represents one observed user interaction event."""

    timestamp: datetime
    attack_type: str
    risk_score: float


class BehaviorMonitor:
    """Monitor activity patterns and estimate session-level threat score."""

    def __init__(self) -> None:
        self._events: Dict[str, List[SessionEvent]] = defaultdict(list)

    def add_event(self, session_id: str, attack_type: str, risk_score: float) -> None:
        """Append an event to a tracked session with basic bounds checking."""
        try:
            bounded_score = max(0.0, min(1.0, risk_score))
            self._events[session_id].append(
                SessionEvent(timestamp=datetime.utcnow(), attack_type=attack_type, risk_score=bounded_score)
            )
            logger.debug("Event added to session=%s attack=%s score=%.2f", session_id, attack_type, bounded_score)
        except Exception as exc:  # pragma: no cover
            logger.exception("Failed to add behavior event: %s", exc)

    def get_session_summary(self, session_id: str) -> dict:
        """Return aggregate behavior metrics for a session."""
        try:
            events = self._events.get(session_id, [])
            if not events:
                return {
                    "session_id": session_id,
                    "event_count": 0,
                    "threat_score": 0.0,
                    "anomaly_detected": False,
                    "top_attack_types": {},
                }

            recent_window = datetime.utcnow() - timedelta(minutes=3)
            recent_events = [event for event in events if event.timestamp >= recent_window]

            avg_risk = sum(event.risk_score for event in events) / len(events)
            burst_factor = min(1.0, len(recent_events) / 10)
            threat_score = min(1.0, (avg_risk * 0.7) + (burst_factor * 0.3))
            attack_counter = Counter(event.attack_type for event in events)

            return {
                "session_id": session_id,
                "event_count": len(events),
                "recent_event_count": len(recent_events),
                "threat_score": round(threat_score, 3),
                "anomaly_detected": threat_score >= 0.6,
                "top_attack_types": dict(attack_counter.most_common(5)),
            }
        except Exception as exc:  # pragma: no cover
            logger.exception("Failed to summarize behavior for session %s: %s", session_id, exc)
            return {
                "session_id": session_id,
                "event_count": 0,
                "threat_score": 1.0,
                "anomaly_detected": True,
                "top_attack_types": {"monitor_error": 1},
            }

    def export_all_summaries(self) -> List[dict]:
        """Export summaries for all observed sessions."""
        return [self.get_session_summary(session_id) for session_id in self._events]

