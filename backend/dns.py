import socket
from urllib.parse import urlparse


def resolve(url: str) -> dict:
    parsed = urlparse(url if url.startswith("http") else "https://" + url)
    hostname = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    ip = socket.gethostbyname(hostname)
    return {
        "url": url,
        "hostname": hostname,
        "ip": ip,
        "port": port,
        "scheme": parsed.scheme,
        "path": parsed.path or "/",
        "query": parsed.query,
    }