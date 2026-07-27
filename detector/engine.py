"""
Threat Detection Engine for NTP-SCTAP.

Analyzes raw NTP packets and transmission patterns to flag anomalies,
covert channels, and timing signatures.
"""

import json
from datetime import datetime
from typing import Dict, Any, List, Optional

from config.settings import get_config
from database.manager import get_db
from protocol.packet import NTPPacket
from utils.logger import get_logger
from utils.helpers import generate_id, iso_timestamp
from detector.exceptions import AnalysisError

logger = get_logger("detector.engine")


class ThreatDetector:
    """Analyzes network packet logs and timing data to detect covert channels."""

    def __init__(self) -> None:
        """Initialize the Threat Detector."""
        self.db = get_db()
        self.cfg = get_config()

    def analyze_packet(self, packet_id: str) -> Optional[Dict[str, Any]]:
        """Perform static and dynamic anomaly detection on a logged packet.

        Queries the packet from the database, runs detection rules,
        logs any threats discovered, and updates the packet validation status.

        Args:
            packet_id: Database identifier of the packet.

        Returns:
            A dictionary containing the highest-priority threat if detected, else None.
            Note: All detected threats are recorded in the database.

        Raises:
            AnalysisError: If the packet record is missing or corrupted.
        """
        # Fetch packet record
        pkt_record = self.db.query_one("SELECT * FROM packets WHERE id = ?", (packet_id,))
        if not pkt_record:
            raise AnalysisError(f"Packet with ID {packet_id} not found in database")

        raw_data = pkt_record.get("raw_data")
        if not raw_data:
            logger.debug("Packet %s has no raw data; skipping deep inspection", packet_id)
            return None

        # 1. Parse packet header and payload
        try:
            packet = NTPPacket.unpack(raw_data)
        except Exception as e:
            logger.warning("Failed to parse packet %s: %s", packet_id, e)
            return self._record_threat(
                packet_id=packet_id,
                session_id=pkt_record.get("session_id"),
                threat_level="high",
                confidence=0.95,
                alert_reason=f"Failed to parse standard NTP header: {e}",
                severity="critical",
                recommendation="Block source IP; packet is severely malformed.",
                details={
                    "category": "Malformed Packet",
                    "evidence": f"Failed to parse standard NTP header: {e}",
                    "affected_fields": ["raw_data"],
                    "error": str(e)
                },
                validation_status="malicious"
            )

        threats_found: List[Dict[str, Any]] = []

        # ── Rule 1: Covert Extension Field Detection ──
        covert_payload = packet.extract_extension()
        if covert_payload:
            threats_found.append({
                "rule": "covert_extension_present",
                "threat_level": "critical" if pkt_record.get("encryption_status") == "failed" else "medium",
                "confidence": 0.99,
                "severity": "critical" if pkt_record.get("encryption_status") == "failed" else "warning",
                "alert_reason": "Secure covert extension field (type 0x7363) detected in NTP packet.",
                "recommendation": "Decryption failed or unauthorized key used. Inspect for active data exfiltration." 
                if pkt_record.get("encryption_status") == "failed" else "Monitor session; covert channel active.",
                "details": {
                    "category": "Covert Channel",
                    "evidence": f"Custom extension field (type 0x7363) detected with payload size {len(covert_payload)} bytes.",
                    "affected_fields": ["extension_data"],
                    "extension_size": len(packet.extension_data),
                    "payload_size": len(covert_payload),
                    "encryption_status": pkt_record.get("encryption_status")
                }
            })
        elif len(packet.extension_data) > 0:
            threats_found.append({
                "rule": "unknown_extension_present",
                "threat_level": "medium",
                "confidence": 0.80,
                "severity": "warning",
                "alert_reason": "Non-standard extension field detected in NTP packet.",
                "recommendation": "Validate client configuration. Standard NTP clients rarely append extension fields.",
                "details": {
                    "category": "Protocol Anomaly",
                    "evidence": f"Non-standard extension field detected of size {len(packet.extension_data)} bytes.",
                    "affected_fields": ["extension_data"],
                    "extension_size": len(packet.extension_data)
                }
            })

        # ── Rule 2: Protocol Header Integrity ──
        if packet.version != 4:
            threats_found.append({
                "rule": "ntp_version_anomaly",
                "threat_level": "low",
                "confidence": 0.85,
                "severity": "info",
                "alert_reason": f"Non-standard NTP version ({packet.version}) in use.",
                "recommendation": "Verify if old NTPv3 clients are authorized on the network.",
                "details": {
                    "category": "Protocol Anomaly",
                    "evidence": f"NTP version {packet.version} detected (standard is 4).",
                    "affected_fields": ["version"],
                    "version": packet.version
                }
            })

        if packet.mode not in (3, 4):  # Client and Server are standard
            threats_found.append({
                "rule": "ntp_mode_anomaly",
                "threat_level": "medium",
                "confidence": 0.90,
                "severity": "warning",
                "alert_reason": f"Abnormal NTP Mode ({packet.mode}) detected.",
                "recommendation": "Inspect host for NTP amplification attacks or custom tunnel protocols.",
                "details": {
                    "category": "Protocol Anomaly",
                    "evidence": f"NTP mode {packet.mode} detected (standard is 3 or 4).",
                    "affected_fields": ["mode"],
                    "mode": packet.mode
                }
            })

        # ── Rule 3: Size Anomaly ──
        # Standard NTP header is exactly 48 bytes
        if len(raw_data) != 48 and not packet.extension_data:
            threats_found.append({
                "rule": "packet_size_anomaly",
                "threat_level": "low",
                "confidence": 0.70,
                "severity": "info",
                "alert_reason": f"Abnormal packet size ({len(raw_data)} bytes) with no formal NTP extension header.",
                "recommendation": "Investigate network transmission layers for invalid padding or ethernet frame fragmentation.",
                "details": {
                    "category": "Protocol Anomaly",
                    "evidence": f"Abnormal packet size ({len(raw_data)} bytes) with no extension fields.",
                    "affected_fields": ["packet_size"],
                    "packet_size": len(raw_data)
                }
            })

        # ── Rule 4: Timing Anomaly (Dynamic burst pattern check) ──
        timing_threat = self._check_timing_anomalies(pkt_record)
        if timing_threat:
            threats_found.append(timing_threat)

        # 2. ✅ BUG-035 FIX: Prioritize covert channel detection above timing anomalies
        # Collect all threats, then evaluate using smart priority rules
        if threats_found:
            # Custom priority: covert channel detection is highest priority
            # then critical/high level, then medium, then low
            priority_mapping = {
                "covert_extension_present": 100,  # Highest: actual covert channel
                "unknown_extension_present": 99,  # Second: unknown extension
                "critical": 10,
                "high": 8,
                "medium": 5,
                "low": 1
            }
            
            def threat_priority(threat: Dict[str, Any]) -> int:
                # Check rule first (covert channel rules have highest priority)
                rule = threat.get("rule", "")
                if rule in priority_mapping:
                    return priority_mapping[rule]
                # Fall back to threat level
                level = threat.get("threat_level", "low")
                return priority_mapping.get(level, 1)
            
            sorted_threats = sorted(threats_found, key=threat_priority, reverse=True)
            
            selected_threat = sorted_threats[0]
            validation_status = "suspicious"
            if selected_threat["threat_level"] in ("high", "critical"):
                validation_status = "malicious"

            # Record all threats, not just the top one
            threat_records = []
            for threat in sorted_threats:
                record = self._record_threat(
                    packet_id=packet_id,
                    session_id=pkt_record.get("session_id"),
                    threat_level=threat["threat_level"],
                    confidence=threat["confidence"],
                    alert_reason=threat["alert_reason"],
                    severity=threat["severity"],
                    recommendation=threat["recommendation"],
                    details=threat["details"],
                    validation_status=validation_status
                )
                threat_records.append(record)

            # Return the highest-priority threat record
            return threat_records[0]

        # If clean, mark packet as valid
        self.db.update("packets", packet_id, {"validation": "valid"})
        return None

    def _check_timing_anomalies(self, pkt: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Analyze temporal patterns of packets from the same source host."""
        source_host = pkt.get("source_host")
        if not source_host:
            return None

        # Fetch recent packets from same source
        window_limit = self.cfg.THREAT_PATTERN_WINDOW
        recent_pkts = self.db.query(
            "SELECT created_at FROM packets WHERE source_host = ? AND id != ? "
            "ORDER BY created_at DESC LIMIT ?",
            (source_host, pkt["id"], window_limit)
        )

        if len(recent_pkts) < 5:
            return None  # Insufficient traffic to calculate statistics

        # ✅ BUG-013 FIX: Parse timestamps and sort in memory for deterministic calculation
        timestamps: List[datetime] = []
        for r in recent_pkts:
            try:
                t = datetime.fromisoformat(r["created_at"])
                timestamps.append(t)
            except ValueError:
                continue

        if len(timestamps) < 2:
            return None

        # Sort timestamps in ascending order (oldest first) for consistent delta calculation
        timestamps.sort()

        # Compute deltas between consecutive timestamps
        deltas: List[float] = []
        for i in range(1, len(timestamps)):
            delta_ms = abs((timestamps[i] - timestamps[i-1]).total_seconds() * 1000.0)
            deltas.append(delta_ms)

        if not deltas:
            return None

        # Check for rapid packet burst
        threshold = self.cfg.THREAT_TIMING_THRESHOLD_MS
        short_intervals = [d for d in deltas if d < threshold]
        ratio = len(short_intervals) / len(deltas)

        if ratio >= 0.6:  # Over 60% of packets arrive within threshold window
            avg_delta = sum(deltas) / len(deltas)
            return {
                "rule": "timing_burst_anomaly",
                "threat_level": "high" if avg_delta < (threshold / 2) else "medium",
                "confidence": 0.85,
                "severity": "warning",
                "alert_reason": f"Timing burst signature: {len(short_intervals)} of last {len(deltas)} packets arrived with < {threshold}ms latency.",
                "recommendation": "Review host for unauthorized automation script or high-bandwidth communication tunnels.",
                "details": {
                    "category": "Timing Signature",
                    "evidence": f"Timing burst signature: {len(short_intervals)} of last {len(deltas)} packets arrived with < {threshold}ms latency.",
                    "affected_fields": ["tx_timestamp"],
                    "avg_delta_ms": round(avg_delta, 2),
                    "burst_ratio": round(ratio, 2),
                    "threshold_ms": threshold
                }
            }

        return None

    def _record_threat(
        self,
        packet_id: str,
        session_id: Optional[str],
        threat_level: str,
        confidence: float,
        alert_reason: str,
        severity: str,
        recommendation: str,
        details: Dict[str, Any],
        validation_status: str
    ) -> Dict[str, Any]:
        """Insert a threat log into the database and update packet validation."""
        threat_id = generate_id()
        threat_record = {
            "id": threat_id,
            "packet_id": packet_id,
            "session_id": session_id,
            "threat_level": threat_level,
            "confidence": confidence,
            "alert_reason": alert_reason,
            "severity": severity,
            "recommendation": recommendation,
            # ✅ DEFENSIVE JSON SERIALIZATION: Use default=str for non-serializable types
            "details_json": json.dumps(details, default=str),
            "detected_at": iso_timestamp()
        }

        self.db.insert("threats", threat_record)
        self.db.update("packets", packet_id, {"validation": validation_status})

        logger.warning(
            "Threat detected! ID=%s, Level=%s, Reason=%s",
            threat_id, threat_level, alert_reason
        )

        return threat_record