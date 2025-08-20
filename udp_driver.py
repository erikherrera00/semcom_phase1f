# udp_driver.py
import socket, threading, time, random
from dataclasses import dataclass

@dataclass
class UDPConfig:
    bind_host: str = "0.0.0.0"
    bind_port: int = 9000
    peer_host: str = "127.0.0.1"
    peer_port: int = 9001
    drop: float = 0.0    # iid drop probability
    jitter_ms: int = 0   # +/- jitter per send in ms
    max_len: int = 4096

class UDPLink:
    def __init__(self, cfg: UDPConfig):
        self.cfg = cfg
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((cfg.bind_host, cfg.bind_port))
        self.sock.settimeout(0.2)
        self._rng = random.Random(0xD15EA5E)

    def send(self, blob: bytes):
        if self.cfg.drop and self._rng.random() < self.cfg.drop:
            return
        if self.cfg.jitter_ms:
            time.sleep(max(0, (self._rng.randint(-self.cfg.jitter_ms, self.cfg.jitter_ms))/1000.0))
        self.sock.sendto(blob, (self.cfg.peer_host, self.cfg.peer_port))

    def recv(self) -> bytes | None:
        try:
            data, _ = self.sock.recvfrom(self.cfg.max_len)
            return data
        except socket.timeout:
            return None

