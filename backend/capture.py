import threading
import time
import requests
from scapy.all import sniff, IP, TCP, UDP, Ether, Raw
from scapy.layers.tls.record import TLS

from scapy.all import conf as _scapy_conf
IFACE = _scapy_conf.iface

_current_stop_event = None
_current_sniffer = None


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
        layers["L5_L6_Session_Presentation"] = {
            "protocol": "TLS",
            "type": tls.type,
            "version": hex(tls.version) if hasattr(tls, "version") else "unknown",
        }

    if pkt.haslayer(Raw):
        raw = pkt[Raw].load
        try:
            decoded = raw.decode("utf-8", errors="replace")
        except Exception:
            decoded = raw.hex()
        layers["L7_Application"] = {
            "protocol": "HTTP" if layers.get("L4_Transport", {}).get("dst_port") == 80
                        or layers.get("L4_Transport", {}).get("src_port") == 80
                        else "HTTPS/TLS encrypted",
            "payload_bytes": len(raw),
            "payload_preview": decoded[:300],
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

    try:
        # Fix 1: force request to exact resolved IP to avoid DNS mismatch
        url = f"{scheme}://{ip}{resolved['path'] or '/'}"
        if resolved.get('query'):
            url += f"?{resolved['query']}"
        requests.get(
            url,
            headers={"Host": hostname},
            timeout=10,
            verify=(scheme == "https"),
        )
    except Exception:
        pass

    # Wait for trailing packets
    time.sleep(1.5)
    stop_event.set()
    sniffer.join(timeout=5)
    on_done(captured)