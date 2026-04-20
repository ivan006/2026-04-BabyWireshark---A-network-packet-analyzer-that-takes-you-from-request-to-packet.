import os
import tempfile
import subprocess
import json


def find_tshark() -> str | None:
    """Find tshark executable."""
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
    """
    Write captured packets to a temp pcap, run tshark with the keylog,
    return a dict of {packet_index: decrypted_http_payload}.
    """
    if not os.path.exists(keylog_path):
        return {}

    tshark = find_tshark()
    if not tshark:
        return {}

    try:
        from scapy.all import wrpcap, Ether, IP, TCP, Raw
        import struct

        # Write raw packets to temp pcap
        pcap_path = os.path.join(tempfile.gettempdir(), "babywireshark_capture.pcap")
        wrpcap(pcap_path, packets)

        # Run tshark to decrypt and extract HTTP2/HTTP data
        result = subprocess.run([
            tshark,
            "-r", pcap_path,
            "-o", f"tls.keylog_file:{keylog_path}",
            "-T", "json",
            "-Y", "http2 or http",
            "-e", "frame.number",
            "-e", "http2.data.data",
            "-e", "http.file_data",
            "-e", "http2.headers",
            "-e", "http.request.full_uri",
            "-e", "http.response.code",
        ], capture_output=True, text=True, timeout=30)

        print(f"tshark stderr: {result.stderr[:500]}")
        print(f"tshark stdout length: {len(result.stdout)}")
        print(f"tshark stdout preview: {result.stdout[:500]}")
        if not result.stdout.strip():
            return {}

        data = json.loads(result.stdout)
        decrypted = {}

        for entry in data:
            # frame.number is 1-based index in the pcap
            frame_num = int(entry.get("_source", {}).get("layers", {}).get("frame.number", [0])[0]) - 1
            layers = entry.get("_source", {}).get("layers", {})

            content = ""
            if "http2.data.data" in layers:
                hex_data = layers["http2.data.data"]
                if isinstance(hex_data, list):
                    hex_data = hex_data[0]
                try:
                    content = bytes.fromhex(hex_data.replace(":", "")).decode("utf-8", errors="replace")
                except Exception:
                    content = hex_data
            elif "http.file_data" in layers:
                hex_data = layers["http.file_data"]
                if isinstance(hex_data, list):
                    hex_data = hex_data[0]
                try:
                    content = bytes.fromhex(hex_data.replace(":", "")).decode("utf-8", errors="replace")
                except Exception:
                    content = str(hex_data)

            if content:
                decrypted[frame_num] = content[:2000]
                print(f"Decrypted frame {frame_num+1}: {content[:100]}")

        return decrypted

    except Exception as e:
        print(f"tshark decryption error: {e}")
        return {}