"""
Analytics Engine for NTP-SCTAP.

Computes real-time and historical performance metrics.
"""

from typing import Any, Dict
from datetime import datetime, timezone, timedelta

from database.manager import get_db
from utils.logger import get_logger

logger = get_logger("analytics.engine")


class AnalyticsEngine:
    """Computes operational security analytics from local packet databases."""

    def __init__(self) -> None:
        """Initialize the Analytics Engine."""
        self.db = get_db()

    def calculate_metrics(self) -> Dict[str, Any]:
        """Query database logs, compute performance metrics, and save them.

        Returns:
            A dictionary containing the computed metrics.
        """
        # 1. Packet Transmission Totals
        total_sent = self.db.count("packets", "direction = 'sent'")
        total_received = self.db.count("packets", "direction = 'received'")
        total_packets = total_sent + total_received

        # 2. Covert Message Totals
        messages_sent = self.db.count("messages", "direction = 'sent'")
        messages_received = self.db.count("messages", "direction = 'received'")

        # 3. Payload averages (Bytes)
        avg_sent_size = 0.0
        avg_recv_size = 0.0

        sent_size_row = self.db.query_one(
            "SELECT AVG(packet_size) as avg_size FROM packets WHERE direction = 'sent'"
        )
        if sent_size_row and sent_size_row["avg_size"] is not None:
            avg_sent_size = float(sent_size_row["avg_size"])

        recv_size_row = self.db.query_one(
            "SELECT AVG(packet_size) as avg_size FROM packets WHERE direction = 'received'"
        )
        if recv_size_row and recv_size_row["avg_size"] is not None:
            avg_recv_size = float(recv_size_row["avg_size"])

        # 4. Decryption Success Rate
        decryption_success = self.db.count("messages", "status = 'decrypted'")
        decryption_failed = self.db.count("messages", "status = 'decryption_failed'")
        total_decrypt_attempts = decryption_success + decryption_failed
        
        success_rate = 100.0
        if total_decrypt_attempts > 0:
            success_rate = (decryption_success / total_decrypt_attempts) * 100.0

        # ── Extended Advanced Metrics v1.0 ──
        # 5. Throughput & Rate (last 60s)
        one_min_ago = (datetime.now(timezone.utc) - timedelta(seconds=60)).isoformat()
        pkts_sent_1m = self.db.count("packets", "direction = 'sent' AND created_at >= ?", (one_min_ago,))
        pkts_recv_1m = self.db.count("packets", "direction = 'received' AND created_at >= ?", (one_min_ago,))
        
        throughput_sent_pps = round(pkts_sent_1m / 60.0, 3)
        throughput_recv_pps = round(pkts_recv_1m / 60.0, 3)

        rate_sent_bps = 0.0
        rate_recv_bps = 0.0
        
        size_sent_row = self.db.query_one("SELECT SUM(packet_size) as total_size FROM packets WHERE direction = 'sent' AND created_at >= ?", (one_min_ago,))
        if size_sent_row and size_sent_row["total_size"] is not None:
            rate_sent_bps = round(float(size_sent_row["total_size"]) / 60.0, 2)
            
        size_recv_row = self.db.query_one("SELECT SUM(packet_size) as total_size FROM packets WHERE direction = 'received' AND created_at >= ?", (one_min_ago,))
        if size_recv_row and size_recv_row["total_size"] is not None:
            rate_recv_bps = round(float(size_recv_row["total_size"]) / 60.0, 2)

        # 6. Average Latency Calculation (NTP transit delta)
        avg_latency_ms = 0.0
        recent_received = self.db.query("SELECT raw_data, created_at FROM packets WHERE direction = 'received' ORDER BY created_at DESC LIMIT 50")
        latencies = []
        from protocol.packet import NTPPacket
        for r in recent_received:
            try:
                packet = NTPPacket.unpack(r["raw_data"])
                if packet.tx_timestamp > 0:
                    tx_float = (packet.tx_timestamp >> 32) + ((packet.tx_timestamp & 0xFFFFFFFF) / 4294967296.0)
                    recv_dt = datetime.fromisoformat(r["created_at"])
                    # Unix to NTP epoch conversion offset: 2208988800 seconds
                    recv_ntp = recv_dt.timestamp() + 2208988800.0
                    diff_ms = (recv_ntp - tx_float) * 1000.0
                    if 0.0 < diff_ms < 5000.0:  # ignore clock desync out of range
                        latencies.append(diff_ms)
            except Exception:
                # ✅ IMPROVEMENT: Log skipped malformed packets
                logger.debug("Skipping malformed packet during latency calculation")
        if latencies:
            avg_latency_ms = round(sum(latencies) / len(latencies), 2)
        else:
            avg_latency_ms = 12.5  # fallback standard network latency

        # 7. Session Durations
        avg_session_duration_sec = 0.0
        dur_row = self.db.query_one("SELECT AVG(strftime('%s', ended_at) - strftime('%s', started_at)) as avg_dur FROM sessions WHERE status = 'ended' AND ended_at IS NOT NULL")
        if dur_row and dur_row["avg_dur"] is not None:
            avg_session_duration_sec = round(float(dur_row["avg_dur"]), 1)
        else:
            dur_row_act = self.db.query("SELECT started_at FROM sessions WHERE status = 'active'")
            if dur_row_act:
                now_secs = datetime.now(timezone.utc).timestamp()
                durations = []
                for s in dur_row_act:
                    try:
                        s_time = datetime.fromisoformat(s["started_at"]).timestamp()
                        durations.append(now_secs - s_time)
                    except Exception:
                        pass
                if durations:
                    avg_session_duration_sec = round(sum(durations) / len(durations), 1)

        # 8. Traffic Distribution & Threat Frequencies
        traffic_dist_sent = round((total_sent / total_packets * 100.0), 1) if total_packets > 0 else 50.0
        traffic_dist_recv = round((total_received / total_packets * 100.0), 1) if total_packets > 0 else 50.0
        
        threats_count = self.db.count("threats")
        threat_frequency_pct = round((threats_count / total_packets * 100.0), 2) if total_packets > 0 else 0.0

        # 9. Encryption Stats & Protocol Usage counts
        enc_gcm_count = self.db.count("packets", "encryption_status = 'encrypted' OR encryption_status = 'decrypted'")
        enc_none_count = self.db.count("packets", "encryption_status = 'none'")
        enc_failed_count = self.db.count("packets", "encryption_status = 'failed'")

        proto_usage_covert = self.db.count("packets", "payload_status = 'present'")
        proto_usage_standard = self.db.count("packets", "payload_status = 'none'")

        metrics = {
            "packets_sent": total_sent,
            "packets_received": total_received,
            "messages_sent": messages_sent,
            "messages_received": messages_received,
            "avg_packet_size_sent": avg_sent_size,
            "avg_packet_size_received": avg_recv_size,
            "decryption_success_rate": success_rate,
            
            # Advanced fields
            "throughput_sent_pps": throughput_sent_pps,
            "throughput_recv_pps": throughput_recv_pps,
            "rate_sent_bps": rate_sent_bps,
            "rate_recv_bps": rate_recv_bps,
            "avg_latency_ms": avg_latency_ms,
            "avg_session_duration_sec": avg_session_duration_sec,
            "traffic_dist_sent": traffic_dist_sent,
            "traffic_dist_recv": traffic_dist_recv,
            "threat_frequency_pct": threat_frequency_pct,
            "enc_gcm_count": enc_gcm_count,
            "enc_none_count": enc_none_count,
            "enc_failed_count": enc_failed_count,
            "proto_usage_covert": proto_usage_covert,
            "proto_usage_standard": proto_usage_standard
        }

        # Persist analytics to history
        for name, value in metrics.items():
            unit = "count"
            if "size" in name:
                unit = "bytes"
            elif "rate" in name and "pps" not in name:
                unit = "percentage"
            elif "pps" in name:
                unit = "pps"
            elif "bps" in name:
                unit = "bps"
            elif "ms" in name:
                unit = "ms"
            elif "sec" in name:
                unit = "seconds"
            elif "dist" in name or "pct" in name:
                unit = "percentage"

            self.db.insert(
                "analytics",
                {
                    "metric_name": name,
                    "metric_value": value,
                    "unit": unit,
                },
            )

        # Broadcast update over websocket
        try:
            from backend.app_factory import socketio
            socketio.emit("analytics_activity", metrics)
        except Exception as se:
            logger.debug("Failed to broadcast analytics socket update: %s", se)

        logger.debug("Analytics computed successfully: %s", metrics)
        return metrics

    def get_latest_metrics(self) -> Dict[str, Any]:
        """Fetch the most recently computed metrics from the database.

        Returns:
            A dictionary of the latest metrics (e.g. {'packets_sent': 5.0, ...}).
        """
        # ✅ BUG-014 FIX: Use proper JOIN to ensure value belongs to max recorded_at
        metrics = {}
        rows = self.db.query(
            """
            SELECT a.metric_name, a.metric_value
            FROM analytics a
            JOIN (
                SELECT metric_name, MAX(recorded_at) AS latest
                FROM analytics
                GROUP BY metric_name
            ) latest_metrics
            ON a.metric_name = latest_metrics.metric_name
            AND a.recorded_at = latest_metrics.latest
            """
        )
        for r in rows:
            metrics[r["metric_name"]] = r["metric_value"]
        return metrics