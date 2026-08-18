from __future__ import annotations

"""Alert Correlation, Aggregation, and Anti-Alert Storm Engine for MiniSOAR."""

import logging
import time
from typing import Any

logger = logging.getLogger(__name__)


class CorrelationEngine:
    """Manages time-sliding aggregation, anti-storm throttling, and campaign correlation."""

    def __init__(self, redis_conn: Any = None, default_window: int = 60, campaign_threshold: int = 5):
        self.r = redis_conn
        self.default_window = default_window
        self.campaign_threshold = campaign_threshold

    def aggregate_event(
        self,
        ip: str,
        website: str,
        detector_type: str,
        top_paths: list[str] | None = None,
        hits: int = 1,
        window_seconds: int | None = None,
    ) -> dict[str, Any]:
        """Aggregates alert hits within a sliding time window in Redis.

        Returns aggregated statistics including total hit count and unique target paths.
        """
        window = window_seconds or self.default_window
        if not self.r or not ip or ip == "(unknown)":
            return {
                "total_hits": hits or 1,
                "unique_paths": top_paths or [],
                "is_first": True,
                "window_seconds": window,
            }

        norm_site = website.strip().lower() if website else "unknown"
        norm_detector = detector_type.strip().lower() if detector_type else "generic"
        base_key = f"minisoar:corr:{ip}:{norm_site}:{norm_detector}"
        hits_key = f"{base_key}:hits"
        paths_key = f"{base_key}:paths"

        try:
            # Increment hit counter
            total_hits = self.r.incrby(hits_key, hits or 1)
            if total_hits == (hits or 1):
                self.r.expire(hits_key, window)
                is_first = True
            else:
                is_first = False

            # Track unique paths
            if top_paths:
                self.r.sadd(paths_key, *top_paths)
                self.r.expire(paths_key, window)
                unique_paths = [p.decode("utf-8") if isinstance(p, bytes) else str(p) for p in self.r.smembers(paths_key)]
            else:
                unique_paths = []

            return {
                "total_hits": int(total_hits),
                "unique_paths": unique_paths,
                "is_first": is_first,
                "window_seconds": window,
            }
        except Exception as e:
            logger.warning("[CORRELATION] Redis aggregation failed: %s", e)
            return {
                "total_hits": hits or 1,
                "unique_paths": top_paths or [],
                "is_first": True,
                "window_seconds": window,
            }

    def should_throttle(
        self,
        ip: str,
        website: str,
        detector_type: str,
        throttle_seconds: int = 60,
    ) -> tuple[bool, int]:
        """Checks if an alert for (ip, website, detector) was recently sent to prevent Telegram alert storms.

        Returns (is_throttled: bool, hit_count_in_window: int).
        """
        if not self.r or not ip or ip == "(unknown)":
            return False, 1

        norm_site = website.strip().lower() if website else "unknown"
        norm_detector = detector_type.strip().lower() if detector_type else "generic"
        throttle_key = f"minisoar:throttle:{ip}:{norm_site}:{norm_detector}"
        hits_key = f"minisoar:corr:{ip}:{norm_site}:{norm_detector}:hits"

        try:
            already_notified = bool(self.r.exists(throttle_key))
            hits_val = self.r.get(hits_key)
            total_hits = int(hits_val) if hits_val else 1

            if already_notified:
                return True, total_hits

            # Set throttle marker with expiration
            self.r.setex(throttle_key, throttle_seconds, "1")
            return False, total_hits
        except Exception as e:
            logger.warning("[CORRELATION] Redis throttle check failed: %s", e)
            return False, 1

    def detect_campaign(
        self,
        website: str,
        detector_type: str,
        src_ip: str,
        window_seconds: int = 180,
    ) -> dict[str, Any]:
        """Detects distributed attack campaigns where multiple distinct IPs attack the same target asset."""
        if not self.r or not website or not src_ip or src_ip == "(unknown)":
            return {"is_campaign": False, "attacker_count": 1, "attackers": [src_ip] if src_ip else []}

        norm_site = website.strip().lower()
        norm_detector = detector_type.strip().lower() if detector_type else "generic"
        campaign_key = f"minisoar:campaign:{norm_site}:{norm_detector}"

        try:
            self.r.sadd(campaign_key, src_ip)
            self.r.expire(campaign_key, window_seconds)

            members = self.r.smembers(campaign_key)
            attackers = [m.decode("utf-8") if isinstance(m, bytes) else str(m) for m in members]
            attacker_count = len(attackers)

            is_campaign = attacker_count >= self.campaign_threshold
            return {
                "is_campaign": is_campaign,
                "attacker_count": attacker_count,
                "attackers": attackers,
                "target_website": website,
                "detector_type": detector_type,
            }
        except Exception as e:
            logger.warning("[CORRELATION] Campaign detection failed: %s", e)
            return {"is_campaign": False, "attacker_count": 1, "attackers": [src_ip]}
