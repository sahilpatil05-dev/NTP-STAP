"""
NTP-SCTAP Data Exporter.

Provides functions to export tables (Packets, Threats, Sessions, Analytics, Config)
into JSON, CSV, and PDF formats. Implements a lightweight, zero-dependency PDF
generator in pure Python.
"""

import io
import csv
import json
from typing import Any, Dict, List, Tuple
from utils.logger import get_logger

logger = get_logger("utils.exporter")


class MinimalPDFWriter:
    """A zero-dependency pure-Python PDF writer.

    Generates valid multi-page PDF files containing tables and text reports.
    """

    def __init__(self, title: str) -> None:
        self.title = title
        self.pages: List[List[str]] = []
        self.current_page: List[str] = []
        self.y_position = 750  # Start below title/header
        self.page_height = 842  # A4 Height in points
        self.page_width = 595   # A4 Width in points
        self.margin = 50
        
        # Start the first page with header
        self._add_page_header()

    def _add_page_header(self) -> None:
        """Create a consistent page header."""
        self.y_position = 780
        self.current_page.append("BT /F1 16 Tf 50 780 Td (NTP-SCTAP SECURE REPORT) Tj ET")
        self.current_page.append(f"BT /F1 12 Tf 50 758 Td ({self._escape_text(self.title)}) Tj ET")
        # Draw a horizontal separation line
        self.current_page.append(f"0.5 w 50 745 m {self.page_width - self.margin} 745 l S")
        self.y_position = 720

    def _escape_text(self, text: Any) -> str:
        """Escape text parenthesis and backslashes for PDF string syntax."""
        val = str(text) if text is not None else ""
        return val.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")

    def add_row(self, fields: List[Tuple[int, str]]) -> None:
        """Add a table row with column coordinate positions.

        Args:
            fields: A list of tuples containing (x_coordinate, text_val).
        """
        if self.y_position < 60:
            # Page limit reached, start a new page
            self.pages.append(self.current_page)
            self.current_page = []
            self._add_page_header()

        # Render row
        for x_pos, text in fields:
            escaped = self._escape_text(text)
            self.current_page.append(f"BT /F1 9 Tf {x_pos} {self.y_position} Td ({escaped}) Tj ET")

        self.y_position -= 15

    def add_section_header(self, text: str) -> None:
        """Add a section title."""
        if self.y_position < 80:
            self.pages.append(self.current_page)
            self.current_page = []
            self._add_page_header()

        self.y_position -= 10
        escaped = self._escape_text(text)
        self.current_page.append(f"BT /F1 11 Tf 50 {self.y_position} Td ({escaped}) Tj ET")
        self.y_position -= 18

    def add_spacer(self, points: int = 15) -> None:
        """Adjust vertical cursor layout position."""
        self.y_position -= points

    def compile(self) -> bytes:
        """Compile the PDF structures into a binary byte string."""
        # Append the final page in progress
        if self.current_page:
            self.pages.append(self.current_page)

        # PDF Object collection
        objects: List[bytes] = []
        offsets: List[int] = []

        def write_obj(body: bytes) -> int:
            obj_id = len(objects) + 1
            objects.append(body)
            return obj_id

        # Setup standard layout references
        # Catalog obj (1)
        # Pages structure (2)
        # Font descriptor (3)
        
        catalog_id = 1
        pages_id = 2
        font_id = 3
        
        # Calculate other object indexes sequentially
        total_pages = len(self.pages)
        page_obj_ids = []
        content_obj_ids = []
        
        current_obj_index = 4
        for _ in range(total_pages):
            page_obj_ids.append(current_obj_index)
            content_obj_ids.append(current_obj_index + 1)
            current_obj_index += 2

        # Placeholder list for PDF objects list
        pdf_objs: List[bytes] = [b""] * (current_obj_index)

        # Build Catalog and Font
        pdf_objs[catalog_id] = f"{catalog_id} 0 obj\n<< /Type /Catalog /Pages {pages_id} 0 R >>\nendobj".encode("ascii")
        pdf_objs[font_id] = f"{font_id} 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj".encode("ascii")

        # Build Pages index list
        kids_str = " ".join(f"{pid} 0 R" for pid in page_obj_ids)
        pdf_objs[pages_id] = f"{pages_id} 0 obj\n<< /Type /Pages /Kids [ {kids_str} ] /Count {total_pages} >>\nendobj".encode("ascii")

        # Generate each Page and its Contents stream
        for idx, page_lines in enumerate(self.pages):
            p_id = page_obj_ids[idx]
            c_id = content_obj_ids[idx]

            # Generate drawing contents stream
            contents_body = "\n".join(page_lines).encode("utf-8")
            pdf_objs[c_id] = f"{c_id} 0 obj\n<< /Length {len(contents_body)} >>\nstream\n".encode("ascii") + contents_body + b"\nendstream\nendobj"

            # Create Page object
            pdf_objs[p_id] = f"{p_id} 0 obj\n<< /Type /Page /Parent {pages_id} 0 R /MediaBox [0 0 595 842] /Contents {c_id} 0 R /Resources << /Font << /F1 {font_id} 0 R >> >> >>\nendobj".encode("ascii")

        # Assemble PDF file structure with offset calculations
        output = io.BytesIO()
        output.write(b"%PDF-1.4\n")

        # Record absolute byte offsets of objects for the XRef table
        for obj_idx in range(1, len(pdf_objs)):
            offsets.append(output.tell())
            output.write(pdf_objs[obj_idx])
            output.write(b"\n")

        # Write XRef table
        xref_offset = output.tell()
        output.write(b"xref\n")
        output.write(f"0 {len(pdf_objs)}\n".encode("ascii"))
        output.write(b"0000000000 65535 f \n")
        for off in offsets:
            output.write(f"{off:010d} 00000 n \n".encode("ascii"))

        # Write trailer
        output.write(b"trailer\n")
        output.write(f"<< /Size {len(pdf_objs)} /Root {catalog_id} 0 R >>\n".encode("ascii"))
        output.write(b"startxref\n")
        output.write(f"{xref_offset}\n".encode("ascii"))
        output.write(b"%%EOF\n")

        return output.getvalue()


def export_to_json(data: List[Dict[str, Any]]) -> str:
    """Format dataset as pretty-printed JSON.
    
    ✅ BUG-030 FIX: Preserves Unicode characters (ensure_ascii=False)
    """
    return json.dumps(
        data,
        indent=2,
        default=str,
        ensure_ascii=False  # Preserve UTF-8 text readability
    )


def export_to_csv(headers: List[str], data: List[Dict[str, Any]]) -> str:
    """Format dataset as standard comma-separated text."""
    output = io.StringIO()
    writer = csv.writer(output, lineterminator="\n")
    
    # Write Header row
    writer.writerow(headers)
    
    # Write Rows
    for row in data:
        writer.writerow([row.get(h, "") for h in headers])
        
    return output.getvalue()


def generate_pdf_report(domain: str, data: List[Dict[str, Any]]) -> bytes:
    """Generate a structured PDF report for the requested data domain."""
    logger.info("Generating PDF report for domain: %s (rows=%d)", domain, len(data))
    
    title = f"{domain.capitalize()} Export Report"
    writer = MinimalPDFWriter(title=title)
    
    if not data:
        writer.add_section_header("No records found in this domain.")
        return writer.compile()

    if domain == "packets":
        # Draw columns: ID, Dir, Source, Destination, Size, Payload, Time
        writer.add_section_header("Recent Network Packet Activity Log")
        headers = [(50, "Packet ID"), (120, "Dir"), (160, "Source"), (260, "Destination"), (360, "Size"), (400, "Payload"), (460, "Timestamp")]
        writer.add_row(headers)
        writer.add_spacer(5)
        
        for row in data:
            fields = [
                (50, str(row.get("id"))[:10]),
                (120, str(row.get("direction"))),
                (160, f"{row.get('source_host')}:{row.get('source_port')}"),
                (260, f"{row.get('dest_host')}:{row.get('dest_port')}"),
                (360, f"{row.get('packet_size')} B"),
                (400, str(row.get("payload_status"))),
                (460, str(row.get("created_at"))[:19].replace("T", " "))
            ]
            writer.add_row(fields)

    elif domain == "threats":
        # Draw columns: ID, Level, Severity, Reason, Detected At
        writer.add_section_header("Threat Analytics & Intrusion Alert Log")
        headers = [(50, "Alert ID"), (120, "Level"), (180, "Severity"), (240, "Reason Summary"), (460, "Timestamp")]
        writer.add_row(headers)
        writer.add_spacer(5)
        
        for row in data:
            reason = str(row.get("alert_reason"))
            if len(reason) > 40:
                reason = reason[:37] + "..."
            fields = [
                (50, str(row.get("id"))[:10]),
                (120, str(row.get("threat_level")).upper()),
                (180, str(row.get("severity")).upper()),
                (240, reason),
                (460, str(row.get("detected_at"))[:19].replace("T", " "))
            ]
            writer.add_row(fields)

    elif domain == "sessions":
        # Draw columns: ID, Status, Sender, Receiver, Packets Sent, Packets Recv, Started
        writer.add_section_header("Communication Session History Log")
        headers = [(50, "Session ID"), (130, "Status"), (190, "Sender Host"), (280, "Receiver Host"), (370, "Pkt Tx"), (420, "Pkt Rx"), (470, "Started At")]
        writer.add_row(headers)
        writer.add_spacer(5)
        
        for row in data:
            fields = [
                (50, str(row.get("id"))[:12]),
                (130, str(row.get("status")).upper()),
                (190, str(row.get("sender_host"))),
                (280, str(row.get("receiver_host"))),
                (370, str(row.get("packets_sent", 0))),
                (420, str(row.get("packets_received", 0))),
                (470, str(row.get("started_at"))[:16].replace("T", " "))
            ]
            writer.add_row(fields)

    elif domain == "analytics":
        # Draw columns: Name, Value, Unit, Recorded At
        writer.add_section_header("System Performance Metrics History")
        headers = [(50, "Metric Name"), (250, "Value"), (320, "Unit"), (400, "Recorded At")]
        writer.add_row(headers)
        writer.add_spacer(5)
        
        for row in data:
            # ✅ BUG-029 FIX: Safely handle non-numeric metric_value
            value = row.get("metric_value")
            try:
                value_text = f"{float(value):.2f}"
            except (TypeError, ValueError):
                value_text = str(value) if value is not None else "N/A"
            
            fields = [
                (50, str(row.get("metric_name"))),
                (250, value_text),
                (320, str(row.get("unit"))),
                (400, str(row.get("recorded_at"))[:19].replace("T", " "))
            ]
            writer.add_row(fields)

    elif domain == "config":
        # Draw columns: Key, Value, Description, Updated At
        writer.add_section_header("Runtime Platform Configuration Settings")
        headers = [(50, "Parameter Key"), (200, "Value"), (320, "Description"), (480, "Updated At")]
        writer.add_row(headers)
        writer.add_spacer(5)
        
        for row in data:
            desc = str(row.get("description", ""))
            if len(desc) > 30:
                desc = desc[:27] + "..."
            fields = [
                (50, str(row.get("key"))),
                (200, str(row.get("value"))),
                (320, desc),
                (480, str(row.get("updated_at"))[:19].replace("T", " "))
            ]
            writer.add_row(fields)
            
    else:
        writer.add_section_header("Generic Data Export")
        for idx, row in enumerate(data[:100]):
            fields = [(50, f"Row {idx + 1}:"), (120, str(row)[:90])]
            writer.add_row(fields)

    return writer.compile()