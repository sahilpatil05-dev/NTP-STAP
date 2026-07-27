"""
NTP-SCTAP Threat Detection Exceptions.
"""

class DetectionError(Exception):
    """Base exception for threat detection operations."""
    pass


class AnalysisError(DetectionError):
    """Raised when parsing or analysis of a packet fails."""
    pass
