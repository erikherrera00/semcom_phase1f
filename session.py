# session.py
import os, struct
from dataclasses import dataclass
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def hkdf_bytes(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    hk = HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info)
    return hk.derive(ikm)

def salt_for_psk(session_id: int) -> bytes:
    # Deterministic per-session salt: SHA256("SC1-psk-salt" || sid)[:16]
    h = hashes.Hash(hashes.SHA256())
    h.update(b"SC1-psk-salt")
    h.update(struct.pack(">I", session_id & 0xFFFFFFFF))
    return h.finalize()[:16]

@dataclass
class PSKSession:
    session_id: int
    aes: AESGCM
    nonce_salt: bytes
    counter: int
    _exporter_secret: bytes  # base material for exporter keys

    @classmethod
    def from_psk(cls, session_id: int, psk: bytes) -> "PSKSession":
        s = salt_for_psk(session_id)
        info_traffic = b"SC1-AES-256-GCM-PSK" + struct.pack(">I", session_id & 0xFFFFFFFF)
        info_export  = b"SC1-EXPORT-PSK"      + struct.pack(">I", session_id & 0xFFFFFFFF)
        traffic_key = hkdf_bytes(psk, s, info_traffic, 32)
        exporter_secret = hkdf_bytes(psk, s, info_export, 32)
        return cls(session_id=session_id, aes=AESGCM(traffic_key),
                   nonce_salt=os.urandom(4), counter=0,
                   _exporter_secret=exporter_secret)

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
        """Derive a context-specific key (e.g., telemetry) separated from traffic key."""
        hk = HKDF(algorithm=hashes.SHA256(), length=length, salt=None, info=label)
        return hk.derive(self._exporter_secret)

