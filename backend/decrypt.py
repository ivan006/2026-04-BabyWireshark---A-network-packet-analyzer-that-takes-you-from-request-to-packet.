import os
import tempfile
import subprocess
import json


def find_tshark() -> str | None:
    candidates = [
        r"C:\Program Files\Wireshark\tshark.exe",
        r"C:\Program Files (x86)\Wireshark\tshark.exe",
        "tshark",
    ]
    for c in candidates:
        try:
            subprocess.run([c, "--version"], capture_output=True, timeout=5)
            return c
        except Exception:
            continue
    return None


def decrypt_packets_with_tshark(packets: list, keylog_path: str) -> dict:
    if not os.path.exists(keylog_path):
        return {}

    tshark = find_tshark()
    if not tshark:
        return {}

    try:
        from scapy.all import wrpcap
        pcap_path = os.path.join(tempfile.gettempdir(), "babywireshark_capture.pcap")
        wrpcap(pcap_path, packets)

        # Extract full reassembled HTTP response body
        result = subprocess.run([
            tshark,
            "-r", pcap_path,
            "-o", f"tls.keylog_file:{keylog_path}",
            "-T", "json",
            "-e", "frame.number",
            "-e", "http.response.code",
            "-e", "http.response_for.uri",
            "-e", "http.file_data",
            "-e", "http2.data.data",
            "-e", "http.response",
            "-Y", "http.file_data or http2.data.data",
        ], capture_output=True, timeout=30, encoding="utf-8", errors="replace")

        output = result.stdout.strip()
        if not output:
            print("tshark returned no HTTP data")
            return {}

        data = json.loads(output)
        full_response = ""

        for entry in data:
            layers = entry.get("_source", {}).get("layers", {})
            for key in ["http.file_data", "http2.data.data"]:
                if key in layers:
                    vals = layers[key]
                    if not isinstance(vals, list):
                        vals = [vals]
                    for val in vals:
                        try:
                            chunk = bytes.fromhex(val.replace(":", "").replace(" ", "")).decode("utf-8", errors="replace")
                            full_response += chunk
                        except Exception:
                            pass

        if not full_response:
            print("No HTTP body found in tshark output")
            return {}

        print(f"Total decrypted: {len(full_response)} chars")
        return {len(packets) - 1: full_response}

    except Exception as e:
        import traceback
        print(f"tshark error: {traceback.format_exc()}")
        return {}