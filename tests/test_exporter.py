"""
Unit tests for the NTP-SCTAP Data Exporter.
"""

import json
from utils.exporter import (
    MinimalPDFWriter,
    export_to_json,
    export_to_csv,
    generate_pdf_report,
)


def test_minimal_pdf_writer_structure():
    """Test that MinimalPDFWriter compiles to a valid minimal PDF structure."""
    writer = MinimalPDFWriter(title="Test Document Title")
    writer.add_section_header("Section 1: Setup")
    writer.add_spacer(10)
    writer.add_row([(50, "ID"), (150, "Name"), (250, "Status")])
    writer.add_row([(50, "1"), (150, "Covert Packet"), (250, "Transmitted")])

    pdf_bytes = writer.compile()
    
    assert isinstance(pdf_bytes, bytes)
    assert pdf_bytes.startswith(b"%PDF-1.4")
    assert b"startxref" in pdf_bytes
    assert pdf_bytes.endswith(b"%%EOF\n")


def test_export_to_json():
    """Test JSON exporting utility handles datasets and handles dates/types properly."""
    data = [
        {"id": "abc-123", "size": 48, "status": "valid"},
        {"id": "xyz-987", "size": 64, "status": "pending"},
    ]
    json_str = export_to_json(data)
    parsed = json.loads(json_str)
    
    assert len(parsed) == 2
    assert parsed[0]["id"] == "abc-123"
    assert parsed[1]["status"] == "pending"


def test_export_to_csv():
    """Test CSV exporting utility handles headers and rows properly."""
    headers = ["id", "size", "status"]
    data = [
        {"id": "abc-123", "size": 48, "status": "valid"},
        {"id": "xyz-987", "size": 64, "status": "pending"},
    ]
    csv_str = export_to_csv(headers, data)
    lines = csv_str.strip().split("\n")
    
    assert len(lines) == 3
    assert lines[0] == "id,size,status"
    assert lines[1] == "abc-123,48,valid"
    assert lines[2] == "xyz-987,64,pending"


def test_generate_pdf_report_domains():
    """Test PDF generation logic across all support data domains."""
    # 1. Packets domain
    packets_data = [{
        "id": "p-1",
        "direction": "received",
        "source_host": "127.0.0.1",
        "source_port": 123,
        "dest_host": "127.0.0.1",
        "dest_port": 9123,
        "packet_size": 48,
        "payload_status": "present",
        "created_at": "2026-06-29T07:00:00Z"
    }]
    pdf = generate_pdf_report("packets", packets_data)
    assert pdf.startswith(b"%PDF-1.4")
    assert b"Packet ID" in pdf

    # 2. Threats domain
    threats_data = [{
        "id": "t-1",
        "threat_level": "high",
        "severity": "critical",
        "alert_reason": "Timing anomaly signature detected in burst interval checks.",
        "detected_at": "2026-06-29T07:00:00Z"
    }]
    pdf = generate_pdf_report("threats", threats_data)
    assert pdf.startswith(b"%PDF-1.4")
    assert b"Alert ID" in pdf

    # 3. Sessions domain
    sessions_data = [{
        "id": "s-1",
        "status": "active",
        "sender_host": "127.0.0.1",
        "receiver_host": "127.0.0.1",
        "packets_sent": 5,
        "packets_received": 4,
        "started_at": "2026-06-29T07:00:00Z"
    }]
    pdf = generate_pdf_report("sessions", sessions_data)
    assert pdf.startswith(b"%PDF-1.4")
    assert b"Session ID" in pdf

    # 4. Analytics domain
    analytics_data = [{
        "metric_name": "packets_sent",
        "metric_value": 15.0,
        "unit": "count",
        "recorded_at": "2026-06-29T07:00:00Z"
    }]
    pdf = generate_pdf_report("analytics", analytics_data)
    assert pdf.startswith(b"%PDF-1.4")
    assert b"Metric Name" in pdf

    # 5. Config domain
    config_data = [{
        "key": "NTP_PORT",
        "value": "123",
        "description": "Port used to run server listener.",
        "updated_at": "2026-06-29T07:00:00Z"
    }]
    pdf = generate_pdf_report("config", config_data)
    assert pdf.startswith(b"%PDF-1.4")
    assert b"Parameter Key" in pdf

    # 6. Empty domain fallback
    pdf = generate_pdf_report("packets", [])
    assert pdf.startswith(b"%PDF-1.4")
    assert b"No records found" in pdf
