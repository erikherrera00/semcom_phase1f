# semdev_common.py
import os, struct, hmac, hashlib
from typing import Optional, Tuple, List
from zfec.easyfec import Encoder, Decoder
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from pack_aad import pack_aad
from session import PSKSession
from ecdh_session import (
    start_handshake_initiator, respond_handshake_responder,
    finish_handshake_initiator, finish_handshake_responder
)

# Frame types
TYPE_DATA    = 1
TYPE_BEACON  = 2
TYPE_ACK     = 3
TYPE_TELEM   = 4
TYPE_HELLO   = 10
TYPE_HS_ACK  = 11

# Small readable header for early ACKs:
# [u32 msg_id][u16 part_id][u16 total_parts][u16 chunk_len]
HDR_FMT = ">IHHH"
HDR_LEN = struct.calcsize(HDR_FMT)

def fec_encode_bytes(data: bytes, k: int, n: int) -> list[bytes]:
    shares = Encoder(k, n).encode(data)
    return [bytes(s) for s in shares]

def fec_decode_bytes(shares: list[bytes], idxs: list[int], k: int, n: int) -> bytes:
    joined = Decoder(k, n).decode(shares, idxs, padlen=None)
    return bytes(joined)

def z_crc32(b:bytes) -> int:
    import zlib
    return zlib.crc32(b) & 0xFFFFFFFF

def pack_share(idx:int, k:int, n:int, payload:bytes) -> bytes:
    # TYPE_DATA + [u16 idx][u16 k][u16 n][u32 crc] + payload
    return struct.pack(">BHHHI", TYPE_DATA, idx, k, n, z_crc32(payload)) + payload

def unpack_share(pkt:bytes):
    if len(pkt) < 11: return None
    if pkt[0] != TYPE_DATA: return None
    idx,k,n,c = struct.unpack(">BHHHI", pkt[:11])[1:]
    pl = pkt[11:]
    ok = (z_crc32(pl) == c)
    return idx,k,n,pl,ok

def make_data_envelope(msg_id:int, part_id:int, total:int, chunk_len:int,
                       nonce:bytes, ct:bytes) -> bytes:
    hdr = struct.pack(HDR_FMT, msg_id & 0xFFFFFFFF, part_id & 0xFFFF, total & 0xFFFF, chunk_len & 0xFFFF)
    return bytes([TYPE_DATA]) + hdr + nonce + ct

def parse_data_envelope(pkt:bytes) -> Optional[tuple[int,int,int,int,bytes,bytes]]:
    if len(pkt) < 1+HDR_LEN+12+16:  # type + hdr + nonce + min tag
        return None
    if pkt[0] != TYPE_DATA:
        return None
    hdr = pkt[1:1+HDR_LEN]
    msg_id, part_id, total, chunk_len = struct.unpack(HDR_FMT, hdr)
    nonce = pkt[1+HDR_LEN:1+HDR_LEN+12]
    ct    = pkt[1+HDR_LEN+12:]
    return (msg_id, part_id, total, chunk_len, nonce, ct)

def make_beacon(session, session_id:int) -> bytes:
    aad = pack_aad(ver=1, suite=1, session_id=session_id,
                   msg_id=0, part_id=0, total_parts=0,
                   n=0, k=0, interleave=0, dup=0, chunk_len=16)
    if session:
        nonce, ct = session.encrypt(aad, b"")
    else:
        nonce = os.urandom(12); ct = AESGCM(os.urandom(32)).encrypt(nonce, b"", aad)
    return bytes([TYPE_BEACON]) + nonce + ct

def make_ack(msg_id:int, part_id:int) -> bytes:
    return bytes([TYPE_ACK]) + struct.pack(">IH", msg_id & 0xFFFFFFFF, part_id & 0xFFFF)

def parse_ack(pkt:bytes) -> Optional[tuple[int,int]]:
    if len(pkt) != 1+6 or pkt[0] != TYPE_ACK: return None
    return struct.unpack(">IH", pkt[1:])

# --- Telemetry (signed) ---
# struct: >IIII  (lost_pkts, repaired, dup_used, interleave)  + HMAC-SHA256 tag[:16]
def pack_signed_telemetry(lost:int, repaired:int, dup_used:int, interleave:int, key:bytes) -> bytes:
    body = struct.pack(">IIII", lost & 0xFFFFFFFF, repaired & 0xFFFFFFFF,
                       dup_used & 0xFFFFFFFF, interleave & 0xFFFFFFFF)
    tag = hmac.new(key, body, hashlib.sha256).digest()[:16]
    return bytes([TYPE_TELEM]) + body + tag

def parse_signed_telemetry(pkt:bytes, key:bytes) -> Optional[tuple[int,int,int,int,bool]]:
    if len(pkt) != 1+16+16 or pkt[0] != TYPE_TELEM: return None
    body, tag = pkt[1:17], pkt[17:]
    ok = hmac.compare_digest(hmac.new(key, body, hashlib.sha256).digest()[:16], tag)
    lost, repaired, dup_used, interleave = struct.unpack(">IIII", body)
    return (lost, repaired, dup_used, interleave, ok)

# --- ECDH handshake frames ---
def make_hello_frame(hello_bytes:bytes) -> bytes:
    return bytes([TYPE_HELLO]) + hello_bytes

def parse_hello_frame(pkt:bytes) -> Optional[bytes]:
    if len(pkt) != 1+36 or pkt[0] != TYPE_HELLO: return None
    return pkt[1:]

def make_hs_ack_frame(ack_bytes:bytes) -> bytes:
    return bytes([TYPE_HS_ACK]) + ack_bytes

def parse_hs_ack_frame(pkt:bytes) -> Optional[bytes]:
    if len(pkt) != 1+36 or pkt[0] != TYPE_HS_ACK: return None
    return pkt[1:]

# --- Replay LRU ---
from collections import OrderedDict
class ReplayLRU:
    def __init__(self, cap=4096):
        self.cap = cap; self._d = OrderedDict()
    def seen(self, key:tuple) -> bool:
        if key in self._d:
            self._d.move_to_end(key, last=True); return True
        self._d[key] = True
        if len(self._d) > self.cap: self._d.popitem(last=False)
        return False

# --- Sessions ---
def derive_psk_session(psk_hex:str|None, session_id:int):
    if psk_hex:
        return PSKSession.from_psk(session_id, bytes.fromhex(psk_hex))
    return None

