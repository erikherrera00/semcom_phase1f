# telemetry.py
import struct, hmac, hashlib
from dataclasses import dataclass

@dataclass
class Telemetry:
    lost_pkts: int = 0
    repaired: int = 0
    dup_used: int = 0
    interleave: int = 1

def pack_signed_telemetry(t: Telemetry, key: bytes) -> bytes:
    # unclassified counters + HMAC-SHA256 (trim to 16 bytes)
    body = struct.pack(">IIII", t.lost_pkts & 0xFFFFFFFF, t.repaired & 0xFFFFFFFF,
                       t.dup_used & 0xFFFFFFFF, t.interleave & 0xFFFFFFFF)
    tag = hmac.new(key, body, hashlib.sha256).digest()[:16]
    return body + tag

def verify_signed_telemetry(blob: bytes, key: bytes) -> tuple[Telemetry, bool]:
    if len(blob) < 32: return Telemetry(), False
    body, tag = blob[:-16], blob[-16:]
    ok = hmac.compare_digest(hmac.new(key, body, hashlib.sha256).digest()[:16], tag)
    lost, repaired, dup_used, interleave = struct.unpack(">IIII", body[:16])
    return Telemetry(lost, repaired, dup_used, interleave), ok

