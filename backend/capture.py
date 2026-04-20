import threading
import time
import requests
from scapy.all import sniff, IP, TCP, UDP, Ether, Raw
from scapy.layers.tls.record import TLS

from scapy.all import conf as _scapy_conf
IFACE = _scapy_conf.iface

import tempfile
import os
_current_stop_event = None
_current_sniffer = None
_keylog_path = os.path.join(tempfile.gettempdir(), "babywireshark_keylog.txt")


def parse_packet(pkt):
    if not pkt.haslayer(IP):
        return None

    layers = {}

    if pkt.haslayer(Ether):
        eth = pkt[Ether]
        layers["L2_DataLink"] = {
            "frame_type": "Ethernet II",
            "src_mac": eth.src,
            "dst_mac": eth.dst,
            "ethertype": hex(eth.type),
        }

    ip = pkt[IP]
    layers["L3_Network"] = {
        "protocol": "IPv4",
        "src_ip": ip.src,
        "dst_ip": ip.dst,
        "ttl": ip.ttl,
        "length": ip.len,
        "checksum": hex(ip.chksum),
        "flags": str(ip.flags),
        "fragment_offset": ip.frag,
    }

    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        layers["L4_Transport"] = {
            "protocol": "TCP",
            "src_port": tcp.sport,
            "dst_port": tcp.dport,
            "seq": tcp.seq,
            "ack": tcp.ack,
            "flags": str(tcp.flags),
            "window": tcp.window,
            "checksum": hex(tcp.chksum),
            "data_offset": tcp.dataofs,
        }
    elif pkt.haslayer(UDP):
        udp = pkt[UDP]
        layers["L4_Transport"] = {
            "protocol": "UDP",
            "src_port": udp.sport,
            "dst_port": udp.dport,
            "length": udp.len,
            "checksum": hex(udp.chksum),
        }

    if pkt.haslayer(TLS):
        tls = pkt[TLS]
        tls_info = {
            "protocol": "TLS",
            "type": tls.type,
            "version": hex(tls.version) if hasattr(tls, "version") else "unknown",
        }

        layers["L5_L6_Session_Presentation"] = tls_info

    if pkt.haslayer(Raw):
        import gzip, re as _re
        raw = pkt[Raw].load
        is_http = (layers.get("L4_Transport", {}).get("dst_port") == 80
                   or layers.get("L4_Transport", {}).get("src_port") == 80)

        decoded = None

        # Try to parse as HTTP (headers + body)
        try:
            text = raw.decode("latin-1")
            if "\r\n\r\n" in text:
                header_part, body_part = text.split("\r\n\r\n", 1)
                is_gzip = "Content-Encoding: gzip" in header_part
                is_chunked = "Transfer-Encoding: chunked" in header_part

                body_bytes = body_part.encode("latin-1")

                # Strip chunked encoding
                if is_chunked:
                    unchunked = b""
                    remaining = body_bytes
                    while remaining:
                        # Find chunk size line
                        crlf = remaining.find(b"\r\n")
                        if crlf == -1:
                            break
                        size_str = remaining[:crlf].split(b";")[0].strip()
                        if not size_str:
                            break
                        try:
                            chunk_size = int(size_str, 16)
                        except Exception:
                            break
                        if chunk_size == 0:
                            break
                        chunk_data = remaining[crlf + 2: crlf + 2 + chunk_size]
                        unchunked += chunk_data
                        remaining = remaining[crlf + 2 + chunk_size + 2:]
                    body_bytes = unchunked

                # Decompress gzip body
                if is_gzip and body_bytes:
                    try:
                        body_bytes = gzip.decompress(body_bytes)
                    except Exception:
                        pass

                body_text = body_bytes.decode("utf-8", errors="replace")
                decoded = header_part + "\r\n\r\n" + body_text
            else:
                decoded = text
        except Exception:
            pass

        # Fallback to hex
        if not decoded:
            decoded = raw.hex()

        layers["L7_Application"] = {
            "protocol": "HTTP" if is_http else "HTTPS/TLS encrypted",
            "payload_bytes": len(raw),
            "payload_preview": decoded[:2000],
        }

    return {
        "timestamp": float(pkt.time),
        "size_bytes": len(pkt),
        "layers": layers,
    }


def capture_and_request(resolved: dict, on_packet, on_done):
    global _current_stop_event, _current_sniffer

    # Kill any previous sniffer
    if _current_stop_event is not None:
        _current_stop_event.set()
    if _current_sniffer is not None and _current_sniffer.is_alive():
        _current_sniffer.join(timeout=5)

    ip = resolved["ip"]
    port = resolved["port"]
    hostname = resolved["hostname"]
    scheme = resolved["scheme"]

    captured = []
    stop_event = threading.Event()
    _current_stop_event = stop_event

    def packet_handler(pkt):
        # Python-level filter — match exact resolved IP
        if not (IP in pkt and (pkt[IP].dst == ip or pkt[IP].src == ip)):
            return
        parsed = parse_packet(pkt)
        if parsed:
            captured.append(parsed)
            on_packet(parsed)

    def do_sniff():
        sniff(
            iface=IFACE,
            prn=packet_handler,
            store=False,
            stop_filter=lambda _: stop_event.is_set(),
            timeout=15,
        )

    sniffer = threading.Thread(target=do_sniff, daemon=True)
    _current_sniffer = sniffer
    sniffer.start()

    # Wait for sniffer to be ready
    time.sleep(1.0)

    # Set SSLKEYLOGFILE so Python's ssl module logs session keys
    os.environ["SSLKEYLOGFILE"] = _keylog_path
    if os.path.exists(_keylog_path):
        os.remove(_keylog_path)

    try:
        import socket
        from urllib3.util.connection import create_connection as _orig

        # Force requests to connect to our resolved IP but keep SNI hostname for TLS
        _resolved_ip = ip
        _resolved_host = hostname

        def patched_create_connection(address, *args, **kwargs):
            host, port = address
            if host == _resolved_host:
                host = _resolved_ip
            return _orig((host, port), *args, **kwargs)

        import urllib3.util.connection as _conn_mod
        _orig_fn = _conn_mod.create_connection
        _conn_mod.create_connection = patched_create_connection

        url = f"{scheme}://{hostname}{resolved['path'] or '/'}"
        if resolved.get('query'):
            url += f"?{resolved['query']}"
        requests.get(url, timeout=10)

        _conn_mod.create_connection = _orig_fn
    except Exception:
        pass

    # Wait for trailing packets
    time.sleep(1.5)
    stop_event.set()
    sniffer.join(timeout=5)
    # Run tshark decryption on all captured packets
    try:
        from decrypt import decrypt_packets_with_tshark
        decrypted_map = decrypt_packets_with_tshark(raw_packets, _keylog_path)
        for idx, content in decrypted_map.items():
            if idx < len(captured):
                if "L5_L6_Session_Presentation" not in captured[idx]["layers"]:
                    captured[idx]["layers"]["L5_L6_Session_Presentation"] = {}
                captured[idx]["layers"]["L5_L6_Session_Presentation"]["decrypted_preview"] = content
    except Exception as e:
        print(f"Decryption failed: {e}")

    on_done(captured)