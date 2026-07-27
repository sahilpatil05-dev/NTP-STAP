# NTP-SCTAP Research Notes

> NTP protocol research and covert channel analysis.  
> Last updated: 2026-06-29 | Version: 0.5.0

---

## NTP Packet Structure (RFC 5905, 48 bytes)

| Field | Bits | Description |
|---|---|---|
| LI | 2 | Leap Indicator |
| VN | 3 | Version Number (4) |
| Mode | 3 | Client(3) / Server(4) |
| Stratum | 8 | Distance from reference |
| Poll | 8 | Polling interval |
| Precision | 8 | Clock precision |
| Root Delay | 32 | RTT to reference |
| Root Dispersion | 32 | Dispersion |
| Reference ID | 32 | Reference identifier |
| Reference TS | 64 | Last update |
| Origin TS | 64 | Request departure |
| Receive TS | 64 | Request arrival |
| Transmit TS | 64 | Reply departure |

## Covert Channel Opportunities

1. Timestamp fractional parts (multiple 64-bit fields)
2. Extension fields after 48-byte header
3. Reference ID manipulation (stratum > 1)

## Detection Indicators

- Unusual fractional precision
- Non-standard timing intervals
- Repetitive patterns in pseudo-random fields
- Non-conformant NTP mode sequences

## References

- RFC 5905, RFC 5116, NIST SP 800-38D
