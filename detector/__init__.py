"""
NTP-SCTAP Threat Detection Engine package.
"""

from detector.engine import ThreatDetector
from detector.exceptions import DetectionError, AnalysisError

__all__ = ["ThreatDetector", "DetectionError", "AnalysisError"]
