#!/usr/bin/env python3
# battle_outer_fec_sim.py
# AES-256-GCM -> ZFEC(n/k) -> Interleave -> Dup -> Channel
# Per-share CRC; decode requires >=k unique shares.
# Sessions: --psk_hex (HKDF->AES-GCM) or --ecdh (X25519->HKDF->AES-GCM)
# Fragmentation + selective ARQ for --priority critical
# Phase-4 hardening: traffic shaping (padding + beacons) and signed telemetry.

import os, random, struct, argparse, zlib, csv, time, json, hmac, hashlib, threading, sys
from typing import List, Optional, Tuple, Dict
from collections import OrderedDict
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from zfec.easyfec import Encoder, Decoder

from pack_aad import pack_aad
from session import PSKSession
from ecdh_session import (
    start_handshake_initiator, respond_handshake_responder,
    finish_handshake_initiator
)

# ==========================
# Replay LRU (per-link)
# ==========================
class ReplayLRU:
    def __init__(self, cap=4096):
        self.cap = cap
        self._d = OrderedDict()
    def seen(self, key):
        if key in self._d:
            self._d.move_to_end(key, last=True)
            return True
        self._d[key] = True
        if len(self._d) > self.cap:
            self._d.popitem(last=False)
        return False

REPLAY = ReplayLRU(4096)

# ==========================
# Traffic shaping (padding + beacons)
# ==========================
@dataclass
class ShapingConfig:
    beacon_interval_ms: int = 250
    beacon_jitter_ms: int = 60
    pad_targets: tuple = (64, 128, 256, 512)
    size_jitter: int = 8

def _pick_canonical(targets, raw_len, jitter, rng: random.Random):
    t = next((t for t in targets if t >= raw_len), targets[-1])
    delta = rng.randint(-jitter, jitter)
    out = max(raw_len, t + delta)
    return out

def pad_to_canonical(data: bytes, cfg: ShapingConfig, rng: random.Random) -> bytes:
    target = _pick_canonical(cfg.pad_targets, len(data), cfg.size_jitter, rng)
    if target <= len(data):
        return data
    return data + os.urandom(target - len(data))

class BeaconLoop:
    def __init__(self, cfg: ShapingConfig, send_dummy):
        self.cfg = cfg
        self._send_dummy = send_dummy
        self._thr = None
        self._stop = threading.Event()
        self._rng = random.Random(0xBEEFCAFE)
    def _run(self):
        while not self._stop.is_set():
            base = self.cfg.beacon_interval_ms
            jitter = self._rng.randint(-self.cfg.beacon_jitter_ms, self.cfg.beacon_jitter_ms)
            time.sleep(max(1, base + jitter) / 1000.0)
            try:
                self._send_dummy()
            except Exception:
                pass
    def start(self):
        if self._thr and self._thr.is_alive(): return
        self._stop.clear()
        self._thr = threading.Thread(target=self._run, daemon=True)
        self._thr.start()
    def stop(self):
        if not self._thr: return
        self._stop.set()
        self._thr.join(timeout=1.0)

# ==========================
# Fragmentation
# ==========================
@dataclass(frozen=True)
class Part:
    msg_id: int
    part_id: int
    total_parts: int
    payload: bytes

def fragment(msg_id: int, data: bytes, max_part: int) -> List[Part]:
    assert max_part > 0
    total = max(1, (len(data) + max_part - 1) // max_part)
    return [Part(msg_id, i, total, data[i*max_part:(i+1)*max_part]) for i in range(total)]

class Reassembler:
    def __init__(self, cap_msgs: int = 1024):
        self._msgs: Dict[int, Dict[int, bytes]] = {}
        self._totals: Dict[int, int] = {}
        self._cap = cap_msgs
    def offer(self, msg_id: int, part_id: int, total_parts: int, payload: bytes) -> Optional[bytes]:
        if msg_id not in self._msgs:
            if len(self._msgs) >= self._cap:
                old_id, _ = next(iter(self._msgs.items()))
                self._msgs.pop(old_id, None); self._totals.pop(old_id, None)
            self._msgs[msg_id] = {}; self._totals[msg_id] = total_parts
        if self._totals.get(msg_id) != total_parts: return None
        if part_id in self._msgs[msg_id]: return None
        self._msgs[msg_id][part_id] = payload
        if len(self._msgs[msg_id]) == total_parts:
            data = b"".join(self._msgs[msg_id][i] for i in range(total_parts))
            del self._msgs[msg_id]; del self._totals[msg_id]
            return data
        return None

# ==========================
# Selective ARQ (critical)
# ==========================
@dataclass
class ARQConfig:
    max_retries: int = 2

class SelectiveARQ:
    def __init__(self, cfg: ARQConfig):
        self.cfg = cfg
    def send_until_k(self, attempt_fn) -> Tuple[bool, int, int, int]:
        last = (False, 0, 0, 0)
        for _ in range(1 + self.cfg.max_retries):
            last = attempt_fn()
            if last[0]:
                return last
        return last

# ==========================
# Telemetry (signed)
# ==========================
@dataclass
class Telemetry:
    lost_pkts: int = 0
    repaired: int = 0
    dup_used: int = 0
    interleave: int = 1

def pack_signed_telemetry(t: Telemetry, key: bytes) -> bytes:
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

# ==========================
# CRC + share packetization
# ==========================
def crc32(b: bytes) -> int: return zlib.crc32(b) & 0xFFFFFFFF
def pack_share(idx:int, k:int, n:int, payload:bytes) -> bytes:
    return struct.pack(">HHHI", idx, k, n, crc32(payload)) + payload
def unpack_share(pkt:bytes):
    if len(pkt) < 10: return -1,0,0,b"",False
    idx,k,n,c = struct.unpack(">HHHI", pkt[:10])
    pl = pkt[10:]
    return idx,k,n,pl,(crc32(pl)==c)

# ==========================
# Interleave / Duplication
# ==========================
def interleave_packets(packets: List[bytes], depth:int) -> List[bytes]:
    if depth <= 1:
        return packets[:]
    stripes=[[] for _ in range(depth)]
    for i,p in enumerate(packets):
        stripes[i%depth].append(p)
    out, idx, rem, s = [], [0]*depth, len(packets), 0
    while rem:
        if idx[s] < len(stripes[s]):
            out.append(stripes[s][idx[s]])
            idx[s]+=1; rem-=1
        s = (s+1) % depth
    return out

def duplicate_packets(packets: List[bytes], dup:int) -> List[bytes]:
    if dup<=1: return packets[:]
    out=[]
    for p in packets:
        for _ in range(dup): out.append(p)
    return out

# ==========================
# Channel models
# ==========================
def ch_iid(packets, loss, rng):
    return [p for p in packets if rng.random() >= loss]
def ch_burst(packets, loss, rng):
    p_bad = min(0.15 + 0.7*loss, 0.95)
    drop_g, drop_b = loss*0.3, min(0.9, loss*1.8)
    bad = rng.random() < p_bad
    keep=[]
    for p in packets:
        if rng.random() < 0.1: bad = not bad
        d = drop_b if bad else drop_g
        if rng.random() >= d: keep.append(p)
    return keep
def ch_fade(packets, loss, rng):
    good_len, bad_len = rng.randint(5,15), rng.randint(3,10)
    drop_g, drop_b = loss*0.4, min(0.95, loss*1.7)
    keep=[]; good=True; left=good_len
    for p in packets:
        if rng.random() >= (drop_g if good else drop_b): keep.append(p)
        left -= 1
        if left==0: good = not good; left = (good_len if good else bad_len)
    return keep
PROFILE = {"iid": ch_iid, "fade": ch_fade, "burst": ch_burst}

# ==========================
# FEC (zfec bytes-in/bytes-out)
# ==========================
def fec_encode_bytes(data: bytes, k: int, n: int) -> list[bytes]:
    shares = Encoder(k, n).encode(data)
    return [bytes(s) for s in shares]
def fec_decode_bytes(shares: list[bytes], idxs: list[int], k: int, n: int) -> bytes:
    joined = Decoder(k, n).decode(shares, idxs, padlen=None)
    return bytes(joined)

# ==========================
# Single message trial (fragmentation, ARQ, shaping, telemetry)
# ==========================
def run_trial(plaintext: bytes, n:int,k:int, inter:int, dup:int, loss:float, prof:str,
              rng:random.Random, mode:str, session_obj:Optional[object], aad_base_no_parts:dict,
              max_part:int, critical:bool, shape_cfg:ShapingConfig, telemetry_key:Optional[bytes]) -> Dict[str, float]:
    msg_id = rng.getrandbits(64)
    parts = fragment(msg_id, plaintext, max_part=max_part)
    rx = Reassembler()
    arq = SelectiveARQ(ARQConfig(max_retries=2)) if critical else None

    per_unique = per_kept = per_dups = 0.0
    tel_lost = tel_repaired = tel_dup_used = 0

    for part in parts:
        pt_part_raw = part.payload
        pt_part = pad_to_canonical(pt_part_raw, shape_cfg, rng)
        ct_len = len(pt_part) + 16
        aad = pack_aad(**aad_base_no_parts, msg_id=msg_id,
                       part_id=part.part_id, total_parts=part.total_parts,
                       chunk_len=ct_len)

        if mode in ("psk","ecdh"):
            nonce, ct = session_obj.encrypt(aad, pt_part)
            key_ephem = None
        else:
            key_ephem = AESGCM.generate_key(256)
            aes = AESGCM(key_ephem)
            nonce = os.urandom(12)
            ct = aes.encrypt(nonce, pt_part, aad)

        shares = fec_encode_bytes(ct, k=k, n=n)
        packets = [pack_share(i, k, n, payload) for i, payload in enumerate(shares)]
        packets = interleave_packets(packets, inter)
        packets = duplicate_packets(packets, dup)

        def attempt_once():
            kept = PROFILE[prof](packets, loss, rng)
            good_by_idx = {}; dup_supp = 0
            for pkt in kept:
                idx,k_rx,n_rx,payload,ok = unpack_share(pkt)
                if not ok or k_rx!=k or n_rx!=n or not (0<=idx<n): continue
                if idx in good_by_idx:
                    dup_supp += 1; continue
                good_by_idx[idx]=payload
            unique = len(good_by_idx)
            if unique < k:
                return (False, unique, len(kept), dup_supp)

            chosen = sorted(good_by_idx.keys())[:k]
            ct_rec = fec_decode_bytes([good_by_idx[i] for i in chosen], chosen, k, n)[:ct_len]
            try:
                if mode in ("psk","ecdh"):
                    pt = session_obj.decrypt(aad, nonce, ct_rec)
                else:
                    pt = AESGCM(key_ephem).decrypt(nonce, ct_rec, aad)
            except Exception:
                return (False, unique, len(kept), dup_supp)

            rx.offer(msg_id, part.part_id, part.total_parts, pt)
            return (True, unique, len(kept), dup_supp)

        if critical and arq:
            ok, u, kp, ds = arq.send_until_k(attempt_once)
        else:
            ok, u, kp, ds = attempt_once()

        tel_lost     += max(0, kp - u)
        tel_repaired += max(0, u - k)
        tel_dup_used += ds

        per_unique += u; per_kept += kp; per_dups += ds

        if not ok:
            if telemetry_key:
                _ = pack_signed_telemetry(Telemetry(tel_lost, tel_repaired, tel_dup_used, inter), telemetry_key)
            return dict(success=False,
                        unique_good=per_unique/len(parts),
                        kept_pkts=per_kept/len(parts),
                        dup_supp=per_dups/len(parts))

    if telemetry_key:
        _ = pack_signed_telemetry(Telemetry(tel_lost, tel_repaired, tel_dup_used, inter), telemetry_key)
    return dict(success=True,
                unique_good=per_unique/len(parts),
                kept_pkts=per_kept/len(parts),
                dup_supp=per_dups/len(parts))

# ==========================
# CLI
# ==========================
def main():
    p = argparse.ArgumentParser(description="Battle-grade FEC sim with PSK/ECDH, fragmentation, ARQ, shaping, telemetry")
    p.add_argument("--batch", type=int, default=1000)
    p.add_argument("--msg_size", type=int, default=256)
    p.add_argument("--profiles", nargs="+", default=["light","medium","heavy"])
    p.add_argument("--losses", nargs="+", type=float, default=None)
    p.add_argument("--n", type=int, default=None)
    p.add_argument("--k", type=int, default=None)
    p.add_argument("--interleave", type=int, default=None)
    p.add_argument("--dup", type=int, default=1)
    p.add_argument("--seed", type=int, default=1337)
    p.add_argument("--csv", type=str, default=None)
    p.add_argument("--sanity", action="store_true")
    # Sessions
    p.add_argument("--psk_hex", type=str, default=None, help="hex PSK for HKDF->AES-256-GCM")
    p.add_argument("--ecdh", action="store_true", help="Use X25519 ECDH-derived session")
    p.add_argument("--session_id", type=int, default=1)
    # Fragmentation & priority
    p.add_argument("--max_part", type=int, default=256, help="max cleartext bytes per fragment before AEAD")
    p.add_argument("--no_fragment", action="store_true", help="force single-part messages")
    p.add_argument("--priority", choices=["normal","critical"], default="normal")
    # Shaping
    p.add_argument("--beacons", action="store_true", help="enable cover beacons in sim")
    p.add_argument("--beacon_ms", type=int, default=250)
    # Telemetry
    p.add_argument("--telemetry", action="store_true", help="enable signed telemetry generation")
    p.add_argument("--telemetry_key_hex", type=str, default=None, help="HMAC key for telemetry (hex)")
    p.add_argument("--telemetry_from_session", action="store_true",
                   help="derive telemetry HMAC key from the active session via exporter")
    # JSON profile
    p.add_argument("--profile_json", type=str, help="path to JSON profile with defaults")

    args = p.parse_args()
    rng = random.Random(args.seed)

    # Load profile JSON (optional)
    if args.profile_json:
        with open(args.profile_json, "r") as f:
            prof = json.load(f)
        for k in ["n","k","interleave","dup","max_part"]:
            if getattr(args, k) is None and k in prof:
                setattr(args, k, prof[k])
        if "priority" in prof and args.priority == "normal":
            args.priority = prof["priority"]
        if "beacons" in prof and not args.beacons:
            args.beacons = prof["beacons"]
        if "beacon_ms" in prof and args.beacon_ms == 250:
            args.beacon_ms = prof["beacon_ms"]

    # Defaults per profile
    profile_map = {
        "light":  ("iid",   [0.05,0.10], dict(n=22,k=17, interleave=1,  dup=args.dup)),
        "medium": ("fade",  [0.10],      dict(n=26,k=20, interleave=6,  dup=args.dup)),
        "heavy":  ("burst", [0.20],      dict(n=30,k=20, interleave=12, dup=max(args.dup,2))),
        "iid":    ("iid",   [0.05,0.10], dict(n=22,k=17, interleave=1,  dup=args.dup)),
        "fade":   ("fade",  [0.10],      dict(n=26,k=20, interleave=6,  dup=args.dup)),
        "burst":  ("burst", [0.20],      dict(n=30,k=20, interleave=12, dup=max(args.dup,2))),
    }

    # Choose session
    if args.ecdh and args.psk_hex:
        raise SystemExit("Choose either --ecdh or --psk_hex, not both.")
    mode = "none"
    session_obj: Optional[object] = None
    if args.ecdh:
        hello, a_priv = start_handshake_initiator(args.session_id)
        ack, a_pub_bytes, b_priv, sid = respond_handshake_responder(hello)
        session_obj = finish_handshake_initiator(ack, a_priv, hello)
        mode = "ecdh"
    elif args.psk_hex:
        try:
            psk = bytes.fromhex(args.psk_hex)
        except ValueError:
            raise SystemExit("Invalid --psk_hex (must be even-length hex).")
        session_obj = PSKSession.from_psk(session_id=args.session_id, psk=psk)
        mode = "psk"

    # Fragmentation policy
    max_part = (10**9) if args.no_fragment else max(1, args.max_part)
    critical = (args.priority == "critical")

    # Shaping config + beacons
    shape = ShapingConfig(beacon_interval_ms=args.beacon_ms)
    beacons = None
    beacon_counter = {"n": 0}
    if args.beacons:
        def send_dummy():
            beacon_counter["n"] += 1
        beacons = BeaconLoop(shape, send_dummy)
        beacons.start()

    # Telemetry key selection
    telemetry_key = None
    if args.telemetry:
        if args.telemetry_from_session:
            if session_obj is None:
                raise SystemExit("--telemetry_from_session requires --psk_hex or --ecdh")
            telemetry_key = session_obj.export_key(b"SC1-TELEMETRY", 32)
        elif args.telemetry_key_hex:
            hx = args.telemetry_key_hex.strip()
            if len(hx) % 2 != 0:
                raise SystemExit("Invalid --telemetry_key_hex (must be even-length hex).")
            try:
                telemetry_key = bytes.fromhex(hx)
            except ValueError:
                raise SystemExit("Invalid --telemetry_key_hex (contains non-hex characters).")
        else:
            telemetry_key = b"\x00" * 32  # demo fallback

    # Build plan
    plan=[]
    for pf in args.profiles:
        if pf not in profile_map:
            raise SystemExit(f"Unknown profile: {pf}")
        base, default_losses, defaults = profile_map[pf]
        n = args.n or defaults["n"]
        k = args.k or defaults["k"]
        inter = args.interleave or defaults["interleave"]
        dup = defaults["dup"]
        if k <= 0 or n <= 0 or k > n: raise SystemExit("Invalid n/k")
        if inter <= 0: raise SystemExit("interleave must be >=1")
        losses = args.losses or default_losses
        plan.append((pf, base, n, k, inter, dup, losses))

    # Optional sanity
    if args.sanity:
        print("\n[SANITY] loss=0 check (should be 100%):")
        for pf, base, n, k, inter, dup, _ in plan:
            ok=0
            aad_base_no_parts=dict(ver=1, suite=1, session_id=args.session_id,
                                   n=n,k=k,interleave=inter,dup=dup)
            for _i in range(200):
                msg = os.urandom(args.msg_size)
                m = run_trial(msg, n,k, inter,dup, 0.0, base, rng, mode, session_obj,
                              aad_base_no_parts, max_part, False, shape, telemetry_key)
                ok += 1 if m["success"] else 0
            print(f"  profile={pf:<6} n/k={n}/{k} inter={inter:<2} dup={dup} -> {100.0*ok/200.0:.1f}%")
        print("[SANITY] Done.\n")
        if beacons: beacons.stop()
        return

    writer=None
    if args.csv:
        csvf=open(args.csv,"w",newline="")
        writer=csv.writer(csvf)
        writer.writerow(["profile","loss","n","k","interleave","dup","batch",
                         "success_rate","avg_unique","avg_kept","avg_dup_supp",
                         "mode","priority","max_part","beacons","beacon_sent","telemetry_from_session"])

    # Execute runs
    for pf, base, n, k, inter, dup, losses in plan:
        for loss in losses:
            succ=uniq=kept=dups=0.0
            aad_base_no_parts=dict(ver=1, suite=1, session_id=args.session_id,
                                   n=n,k=k,interleave=inter,dup=dup)
            for _i in range(args.batch):
                msg=os.urandom(args.msg_size)
                m=run_trial(msg, n,k, inter,dup, loss, base, rng, mode, session_obj,
                            aad_base_no_parts, max_part, critical, shape, telemetry_key)
                succ += 1 if m["success"] else 0
                uniq += m["unique_good"]; kept += m["kept_pkts"]; dups += m["dup_supp"]
            rate=100.0*succ/args.batch
            print(f"[REPORT] prof={pf:<6} loss={loss:<4.2f}  n/k={n}/{k} inter={inter:<2} dup={dup} "
                  f"-> {rate:.1f}%  (avg unique {uniq/args.batch:.1f}, kept {kept/args.batch:.1f}, dup_supp {dups/args.batch:.1f}) "
                  f"[mode={mode}, priority={'crit' if critical else 'norm'}, max_part={max_part}, beacons={args.beacons}]")
            if writer:
                writer.writerow([pf,loss,n,k,inter,dup,args.batch,
                                 f"{rate:.2f}",f"{uniq/args.batch:.2f}",f"{kept/args.batch:.2f}",f"{dups/args.batch:.2f}",
                                 mode, ("critical" if critical else "normal"), max_part, args.beacons, beacon_counter["n"],
                                 args.telemetry_from_session])
    if args.csv:
        csvf.close(); print(f"[INFO] Wrote {args.csv}")
    if beacons: beacons.stop()

if __name__=="__main__":
    main()

