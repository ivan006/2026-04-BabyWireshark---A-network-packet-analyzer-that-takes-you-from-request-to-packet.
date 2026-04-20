import threading
import requests
from scapy.all import sniff, IP, TCP, UDP, Ether, Raw
from scapy.layers.tls.record import TLS


def parse_packet(pkt) -> dict | None:
    if not pkt.haslayer(IP):
        return None

    layers = {}

    # L2 - Data Link
    if pkt.haslayer(Ether):
        eth = pkt[Ether]
        layers["L2_DataLink"] = {
            "frame_type": "Ethernet II",
            "src_mac": eth.src,
            "dst_mac": eth.dst,
            "ethertype": hex(eth.type),
        }

    # L3 - Network
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

    # L4 - Transport
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

    # L5/L6 - Session / Presentation (TLS)
    if pkt.haslayer(TLS):
        tls = pkt[TLS]
        layers["L5_L6_Session_Presentation"] = {
            "protocol": "TLS",
            "type": tls.type,
            "version": hex(tls.version) if hasattr(tls, "version") else "unknown",
        }

    # L7 - Application (raw payload)
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
    ip = resolved["ip"]
    port = resolved["port"]
    url = resolved["url"]

    captured = []
    stop_event = threading.Event()

    def packet_handler(pkt):
        parsed = parse_packet(pkt)
        if parsed:
            captured.append(parsed)
            on_packet(parsed)

    def do_sniff():
        sniff(
            iface=r'\Device\NPF_{DA5D51D8-74CD-4BF3-98E0-09575A6465CB}',
            filter=f"host {ip} and port {port}",
            prn=packet_handler,
            store=False,
            stop_filter=lambda _: stop_event.is_set(),
            timeout=15,
        )

    sniffer = threading.Thread(target=do_sniff, daemon=True)
    sniffer.start()

    # Small delay to let sniffer initialise before request fires
    import time
    time.sleep(0.3)

    try:
        requests.get(url, timeout=10, verify=(port == 443))
    except Exception as e:
        pass

    time.sleep(1)
    stop_event.set()
    sniffer.join(timeout=5)
    on_done(captured)