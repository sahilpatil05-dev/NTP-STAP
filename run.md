# Running NTP-SCTAP

Quick reference for running, testing and verifying the platform.

---

# 1. Activate Virtual Environment

## Windows

```cmd
.venv\Scripts\activate
```

Activates the Python virtual environment.

---

## Linux

```bash
source .venv/bin/activate
```

Activates the Python virtual environment.

---

# 2. Start the Dashboard (Receiver)

```bash
python run.py
```

Starts:

- Flask Dashboard
- UDP Receiver
- Threat Detection
- Analytics Engine

Dashboard:

```
http://<Kali-IP>:5000
```

---

# 3. Find Receiver IP (Linux)

```bash
hostname -I
```

Displays the receiver IP.

Example

```
10.205.211.212
```

---

# 4. Send Message (Windows)

```bash
python sender_client.py
```

Example

```
Receiver IP   : 10.205.211.212
Receiver Port : 9124
Password      : admin@123
Message        : Hello from Windows
```

Sends an encrypted NTP packet.

---

# 5. Verify Receiver

Expected output

```
Threat detected
Message recovered
```

Confirms successful reception and processing.

---

# 6. Verify with tcpdump

```bash
sudo tcpdump -i any udp port 9124
```

Checks whether UDP packets reach the receiver.

Expected

```
UDP
Port 9124
```

---

# 7. Verify with Wireshark

Start Wireshark

```bash
sudo wireshark
```

Capture Filter

```
udp
```

Display Filter

```
udp.port == 9124
```

Verify

- UDP Packet
- Port 9124
- Encrypted Payload
- Source IP
- Destination IP

---

# 8. Run Tests

```bash
pytest -v
```

Runs all automated tests.

---

# Useful Commands

### Find Linux IP

```bash
hostname -I
```

---

### Find Windows IP

```cmd
ipconfig
```

---

### Check UDP Receiver

```bash
sudo ss -lun
```

Confirms receiver is listening on UDP port 9124.

---

### Monitor Python Process

```bash
ps -ef | grep python
```

Shows running Python processes.

---

### Check Network Connectivity

From Windows

```cmd
ping <Kali-IP>
```

Verifies Windows can reach the Kali machine.

---

### Monitor Incoming Packets

```bash
sudo tcpdump -i any udp port 9124
```

Shows live UDP traffic.

---

## Current Test Flow

```
Activate Environment
        ↓
python run.py
        ↓
hostname -I
        ↓
python sender_client.py
        ↓
tcpdump
        ↓
Wireshark
        ↓
Dashboard Verification
```

---

**Version:** 1.2.0