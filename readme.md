# BabyWireshark
> A network packet analyser that takes you from request to packet.

Enter a URL. BabyWireshark resolves it, captures every packet involved in that request, and displays them organised by OSI layer in real time.

---

## Stack
- **Backend** — Python, FastAPI, Scapy
- **Frontend** — Vanilla JS, HTML, CSS

---

## Setup

### Backend
```bash
cd backend
pip install -r requirements.txt
sudo python -m uvicorn main:app --reload
```
> `sudo` is required — Scapy needs root access for raw packet capture.

### Frontend
Open `frontend/index.html` directly in your browser, or serve it:
```bash
cd frontend
python -m http.server 3000
```
Then visit `http://localhost:3000`.

---

## How it works
1. You enter a URL
2. Backend resolves the hostname to an IP via DNS
3. Scapy starts a capture filtered to that IP and port
4. Backend fires the HTTP request itself
5. Captured packets stream to the frontend via WebSocket
6. Each packet is displayed with its L2–L7 fields broken out by OSI layer

---

## Notes
- Requires root/admin to run (pcap needs raw socket access)
- HTTPS traffic at L7 will show TLS-encrypted payload — L4 and below are always visible in plaintext
- Tested on Linux/macOS; Windows requires Npcap installed