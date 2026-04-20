"""
TLS decryption using SSLKEYLOGFILE session keys.
Parses the key log and decrypts TLS application data packets.
"""
import os
import re
import struct
from pathlib import Path


def parse_keylog(keylog_path: str) -> dict:
    """Parse NSS key log file into a dict keyed by client_random."""
    keys = {}
    try:
        with open(keylog_path, "r") as f:
            for line in f:
                line = line.strip()
                if line.startswith("#") or not line:
                    continue
                parts = line.split()
                if len(parts) == 3:
                    label, client_random, secret = parts
                    if client_random not in keys:
                        keys[client_random] = {}
                    keys[client_random][label] = bytes.fromhex(secret)
    except Exception:
        pass
    return keys


def try_decrypt_packet(raw_payload: bytes, keylog_path: str) -> str | None:
    """
    Attempt to decrypt a TLS application data record.
    Returns decrypted string or None if decryption fails.
    Uses Python's ssl module via a loopback approach.
    """
    if not keylog_path or not os.path.exists(keylog_path):
        return None

    keys = parse_keylog(keylog_path)
    if not keys:
        return None

    # TLS record header: type(1) + version(2) + length(2)
    if len(raw_payload) < 5:
        return None
    record_type = raw_payload[0]
    if record_type != 23:  # ApplicationData
        return None

    try:
        import ssl
        import cryptography
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        # Minimal TLS 1.3 decryption attempt using CLIENT_TRAFFIC_SECRET_0
        for client_random, secrets in keys.items():
            secret = secrets.get("CLIENT_TRAFFIC_SECRET_0") or secrets.get("SERVER_TRAFFIC_SECRET_0")
            if not secret:
                continue
            # Derive key + iv from secret using HKDF (simplified)
            from cryptography.hazmat.primitives.hashes import SHA256
            from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
            from cryptography.hazmat.backends import default_backend

            def hkdf_expand_label(secret, label, context, length):
                full_label = b"tls13 " + label.encode()
                hkdf_label = (
                    struct.pack(">H", length)
                    + bytes([len(full_label)]) + full_label
                    + bytes([len(context)]) + context
                )
                return HKDFExpand(SHA256(), length, hkdf_label, default_backend()).derive(secret)

            key = hkdf_expand_label(secret, "key", b"", 16)
            iv = hkdf_expand_label(secret, "iv", b"", 12)
            ciphertext = raw_payload[5:]
            aesgcm = AESGCM(key)
            # Try seq numbers 0-10
            for seq in range(11):
                nonce = bytearray(iv)
                for i in range(8):
                    nonce[11 - i] ^= (seq >> (8 * i)) & 0xFF
                try:
                    plaintext = aesgcm.decrypt(bytes(nonce), ciphertext, None)
                    return plaintext.decode("utf-8", errors="replace")
                except Exception:
                    continue
    except ImportError:
        pass
    except Exception:
        pass

    return None