# arq.py
import random, time
from dataclasses import dataclass
from typing import Callable, Optional

@dataclass
class ARQConfig:
    max_retries: int = 3
    base_rto_ms: int = 120     # base retransmission timeout
    jitter_ms: int = 40        # ± jitter
    ack_timeout_ms: int = 200  # wait for ack before deciding to retry

class SelectiveARQ:
    """
    Critical-only ARQ wrapper. You provide two callbacks:
      send_once(seq: int, payload: bytes) -> None
      got_ack(seq: int) -> bool
    """
    def __init__(self, cfg: ARQConfig):
        self.cfg = cfg
        self.rng = random.Random(0xC0FFEE)

    def _sleep_ms(self, ms: int):
        time.sleep(ms/1000.0)

    def send_with_retries(self, seq: int, payload: bytes,
                          send_once: Callable[[int, bytes], None],
                          got_ack: Callable[[int], bool]) -> bool:
        # first attempt
        send_once(seq, payload)
        # quick wait for ack
        self._sleep_ms(self.cfg.ack_timeout_ms)
        if got_ack(seq): return True
        # bounded retries with jittered RTO
        for attempt in range(1, self.cfg.max_retries+1):
            rto = self.cfg.base_rto_ms + self.rng.randint(-self.cfg.jitter_ms, self.cfg.jitter_ms)
            self._sleep_ms(max(10, rto))
            send_once(seq, payload)
            self._sleep_ms(self.cfg.ack_timeout_ms)
            if got_ack(seq): return True
        return False

