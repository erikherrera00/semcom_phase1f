# traffic.py
import os, time, random, threading
from dataclasses import dataclass

@dataclass
class ShapingConfig:
    beacon_interval_ms: int = 250      # base period
    beacon_jitter_ms: int = 60         # ± jitter
    pad_targets: tuple = (64, 128, 256, 512)  # canonical payload sizes
    size_jitter: int = 8               # ± small jitter

def pick_canonical(targets, raw_len, jitter):
    # pick the smallest >= raw_len, then add ± jitter (bounded >= raw_len)
    t = next((t for t in targets if t >= raw_len), targets[-1])
    delta = random.randint(-jitter, jitter)
    out = max(raw_len, t + delta)
    return out

def pad_to_canonical(data: bytes, cfg: ShapingConfig) -> bytes:
    target = pick_canonical(cfg.pad_targets, len(data), cfg.size_jitter)
    if target <= len(data):
        return data
    return data + os.urandom(target - len(data))

class BeaconLoop:
    """
    Calls the provided send_dummy() at randomized intervals to emit cover beacons.
    Start/stop are idempotent.
    """
    def __init__(self, cfg: ShapingConfig, send_dummy):
        self.cfg = cfg
        self._send_dummy = send_dummy
        self._thr = None
        self._stop = threading.Event()

    def _run(self):
        rnd = random.Random(0xBEEFCAFE)
        while not self._stop.is_set():
            base = self.cfg.beacon_interval_ms
            jitter = rnd.randint(-self.cfg.beacon_jitter_ms, self.cfg.beacon_jitter_ms)
            time.sleep(max(1, base + jitter) / 1000.0)
            try:
                self._send_dummy()
            except Exception:
                # best-effort; never crash the loop
                pass

    def start(self):
        if self._thr and self._thr.is_alive():
            return
        self._stop.clear()
        self._thr = threading.Thread(target=self._run, daemon=True)
        self._thr.start()

    def stop(self):
        if not self._thr: return
        self._stop.set()
        self._thr.join(timeout=1.0)


