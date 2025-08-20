# ecdh_session.py
import os, struct
from dataclasses import dataclass
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def hkdf_bytes(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    hk = HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info)
    return hk.derive(ikm)

def hkdf_salt_from_transcript(session_id: int, a_pub_bytes: bytes, b_pub_bytes: bytes) -> bytes:
    # Deterministic salt = SHA256("SC1-salt" || sid || A_pub || B_pub)[:16]
    h = hashes.Hash(hashes.SHA256())
    h.update(b"SC1-salt")
    h.update(struct.pack(">I", session_id & 0xFFFFFFFF))
    h.update(a_pub_bytes)
    h.update(b_pub_bytes)
    return h.finalize()[:16]

@dataclass
class ECDHSession:
    session_id: int
    aes: AESGCM
    nonce_salt: bytes
    counter: int
    _exporter_secret: bytes  # base material for exporter keys

    def next_nonce(self) -> bytes:
        c = self.counter & 0xFFFFFFFFFFFFFFFF
        self.counter += 1
        return self.nonce_salt + struct.pack(">Q", c)

    def encrypt(self, aad: bytes, pt: bytes) -> tuple[bytes, bytes]:
        n = self.next_nonce()
        return n, self.aes.encrypt(n, pt, aad)

    def decrypt(self, aad: bytes, n: bytes, ct: bytes) -> bytes:
        return self.aes.decrypt(n, ct, aad)

    def export_key(self, label: bytes, length: int = 32) -> bytes:
        """
        Derive a session-bound, context-separated key (e.g., telemetry MAC key).
        Label must be unique per purpose, e.g. b"SC1-TELEMETRY".
        """
        hk = HKDF(algorithm=hashes.SHA256(), length=length, salt=None, info=label)
        return hk.derive(self._exporter_secret)

def start_handshake_initiator(session_id:int):
    priv = X25519PrivateKey.generate()
    pub  = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    # HELLO: [u32 session_id][32B A_pub]
    hello = struct.pack(">I", session_id) + pub
    return hello, priv

def respond_handshake_responder(hello:bytes):
    session_id = struct.unpack(">I", hello[:4])[0]
    a_pub_bytes = hello[4:4+32]
    priv_b = X25519PrivateKey.generate()
    b_pub_bytes  = priv_b.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    # ACK: [u32 session_id][32B B_pub]
    ack = struct.pack(">I", session_id) + b_pub_bytes
    return ack, a_pub_bytes, priv_b, session_id

def finish_handshake_initiator(ack:bytes, priv_a:X25519PrivateKey, hello:bytes)->ECDHSession:
    session_id = struct.unpack(">I", ack[:4])[0]
    b_pub_bytes = ack[4:4+32]
    a_pub_bytes = hello[4:4+32]
    b_pub = X25519PublicKey.from_public_bytes(b_pub_bytes)
    shared = priv_a.exchange(b_pub)

    # Transcript-bound salt & info (ORDER: A_pub then B_pub)
    salt = hkdf_salt_from_transcript(session_id, a_pub_bytes, b_pub_bytes)
    info_common = b"SC1-AES-256-GCM" + struct.pack(">I", session_id) + a_pub_bytes + b_pub_bytes

    # Traffic key
    traffic_key = hkdf_bytes(shared, salt, info_common, 32)
    # Exporter base (distinct label, same transcript)
    exporter_secret = hkdf_bytes(shared, salt, b"SC1-EXPORT" + info_common, 32)

    return ECDHSession(session_id, AESGCM(traffic_key), os.urandom(4), 0, exporter_secret)

def finish_handshake_responder(priv_b:X25519PrivateKey, a_pub_bytes:bytes, ack:bytes)->ECDHSession:
    session_id = struct.unpack(">I", ack[:4])[0]
    b_pub_bytes = ack[4:4+32]
    a_pub = X25519PublicKey.from_public_bytes(a_pub_bytes)
    shared = priv_b.exchange(a_pub)

    salt = hkdf_salt_from_transcript(session_id, a_pub_bytes, b_pub_bytes)
    info_common = b"SC1-AES-256-GCM" + struct.pack(">I", session_id) + a_pub_bytes + b_pub_bytes

    traffic_key = hkdf_bytes(shared, salt, info_common, 32)
    exporter_secret = hkdf_bytes(shared, salt, b"SC1-EXPORT" + info_common, 32)

    return ECDHSession(session_id, AESGCM(traffic_key), os.urandom(4), 0, exporter_secret)

