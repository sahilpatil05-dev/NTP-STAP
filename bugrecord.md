


packet monitor 

messages and threat detection  are errors showing still loading packets 



| Bug ID  | Module            | Severity | Status  |
| ------- | ----------------- | -------- | ------- |
| BUG-001 | Sender UI         | Medium   | Pending |
| BUG-002 | Sender Validation | Medium   | Pending |




Root Cause Analysis
Bug #003 — Packet Inspector API Crash

The traceback clearly shows:

TypeError:
Object of type bytes is not JSON serializable

This is not a frontend bug.

The API:

GET /api/packets/<packet_id>/inspect

returns something like

return jsonify(packet)

where one of the fields is

raw_packet = b'...'

Flask cannot convert Python bytes directly into JSON.

Correct implementation

Before calling jsonify, convert the bytes to something JSON-safe, for example:

hexadecimal string (recommended for packet inspection)
Base64 string
UTF-8 (only if appropriate)

Example:

packet["raw_packet"] = packet["raw_packet"].hex()

or

import base64
packet["raw_packet"] = base64.b64encode(packet["raw_packet"]).decode()
Bug #004 — Packet Inspector Never Opens

Because the API returns:

500 Internal Server Error

your JavaScript receives nothing.

Therefore

Inspector

↓

No data

↓

Doesn't open

This isn't a UI problem—the frontend is waiting for valid JSON, but the backend crashes first.

Bug #005 — Everything After Inspector Fails

This explains why:

Raw Packet
Hex Dump
Timeline
Learning Mode

all fail.

They're all dependent on the packet inspector endpoint.

Bug #006 — Packet Filters

You mentioned:

All / Sent / Received filter isn't working

This is a separate bug.

Likely causes:

Filter buttons don't have event listeners.
JavaScript never filters the data.
Backend ignores the filter parameter.
Wrong DOM selector.

We'll inspect that after finishing the overall QA pass.

Updated Bug Tracker
Bug ID	Module	Severity	Status
BUG-001	Sender UI Error Messages	Medium	Pending
BUG-002	SQL Injection Handling / Error Display	Medium	Pending
BUG-003	Packet Inspector API (bytes not JSON serializable)	🔴 Critical	Pending
BUG-004	Packet Inspector UI	High	Pending
BUG-005	Packet Detail Components	High	Pending
BUG-006	Packet Filter Buttons	High	Pending



Updated Bug Tracker
ID	Severity	Module
BUG-001	Medium	Sender UI
BUG-002	Medium	SQL Error Display
BUG-003	🔴 Critical	Packet Inspector API
BUG-004	High	Packet Inspector UI
BUG-005	High	Packet Details
BUG-006	High	Packet Filters
BUG-007	Medium	Message Auto Refresh
BUG-008	Medium	Message Sort
BUG-009	Medium	Message Refresh
BUG-010	High	Message Status
BUG-011	🔴 Critical	Threat Detection Logic
BUG-012	High	Threat Inspector
BUG-013	High	Threat Detail API
BUG-014	High	Threat Charts
BUG-015	Medium	Threat Refresh
BUG-016	Medium	Threat Filters
BUG-017	🔴 Critical	Data Lost After Browser Refresh



New Bugs Found
🔴 BUG-018 — Refresh Button Does Nothing

Severity: Medium

The Refresh button exists but clicking it has no effect.

This usually means one of these:

The button has no event listener.
It calls a function that doesn't refresh the analytics.
The refresh function returns without updating the UI.
🔴 BUG-019 — Analytics Not Persistent After F5

This is a high-priority architectural issue.

You observed:

Graphs remain.

Metric cards reset.

That means the application is using two different data sources.

Probably something like:

Charts
↓
GET /api/analytics/history

while the cards use:

In-memory variables

instead of querying:

GET /api/analytics

or the database.

This explains why charts survive a browser refresh but summary cards do not.

This Also Explains Earlier Bugs

Remember the issues we found with:

Dashboard
Packet Monitor
Threat Detection
Messages

where data disappeared after pressing F5?

Now we have a consistent pattern:

Real-time updates work, but persistence after a page reload is incomplete.

That points to a single architectural weakness rather than many unrelated bugs.