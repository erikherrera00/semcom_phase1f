# semdev_send.py
import os, time, json, random, threading, sys
from dataclasses import dataclass
from typing import Dict, List

from udp_driver import UDPConfig, UDPLink
from semdev_common import *
from pack_aad import pack_aad
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

@dataclass
class TxProfile:
    n:int; k:int; interleave:int; dup:int; max_part:int; priority:str
    beacons:bool; beacon_ms:int

def interleave_packets(packets: List[bytes], depth:int) -> List[bytes]:
    if depth <= 1: return packets[:]
    stripes=[[] for _ in range(depth)]
    for i,p in enumerate(packets): stripes[i%depth].append(p)
    out, idx, rem, s = [], [0]*depth, len(packets), 0
    while rem:
        if idx[s] < len(stripes[s]): out.append(stripes[s][idx[s]]); idx[s]+=1; rem-=1
        s=(s+1)%depth
    return out

def duplicate_packets(packets: List[bytes], dup:int) -> List[bytes]:
    if dup<=1: return packets[:]
    out=[]; [out.extend([p]*dup) for p in packets]; return out

def fragment(msg_id:int, data:bytes, max_part:int):
    total = max(1, (len(data)+max_part-1)//max_part)
    return [(i, total, data[i*max_part:(i+1)*max_part]) for i in range(total)]

def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--peer_port", type=int, default=9001)
    ap.add_argument("--bind_port", type=int, default=9000)
    ap.add_argument("--peer_host", type=str, default="127.0.0.1")
    ap.add_argument("--bind_host", type=str, default="0.0.0.0")
    ap.add_argument("--drop", type=float, default=0.0)
    ap.add_argument("--jitter_ms", type=int, default=0)
    ap.add_argument("--psk_hex", type=str, default=None)
    ap.add_argument("--ecdh", action="store_true")
    ap.add_argument("--session_id", type=int, default=7)
    ap.add_argument("--profile_json", type=str, required=True)
    ap.add_argument("--msg", type=str, default="DEMO: hello DARPA")
    args = ap.parse_args()

    prof = json.load(open(args.profile_json))
    P = TxProfile(n=prof["n"], k=prof["k"], interleave=prof["interleave"], dup=prof["dup"],
                  max_part=prof.get("max_part",256), priority=prof.get("priority","normal"),
                  beacons=prof.get("beacons",True), beacon_ms=prof.get("beacon_ms",250))

    link = UDPLink(UDPConfig(bind_host=args.bind_host, bind_port=args.bind_port,
                             peer_host=args.peer_host, peer_port=args.peer_port,
                             drop=args.drop, jitter_ms=args.jitter_ms))
    sess = None

    # --- Session bring-up ---
    if args.ecdh and args.psk_hex:
        print("Error: use either --ecdh OR --psk_hex, not both."); sys.exit(2)

    if args.psk_hex:
        sess = derive_psk_session(args.psk_hex, args.session_id)
        print("[TX] PSK session ready.")
    elif args.ecdh:
        # Sender is initiator: send HELLO, wait HS_ACK
        hello, a_priv = start_handshake_initiator(args.session_id)
        hello_frame = make_hello_frame(hello)
        print("[TX] Sending ECDH HELLO...")
        got_ack = False; ack_bytes = None
        for attempt in range(10):
            link.send(hello_frame)
            t0=time.time()
            while time.time()-t0 < 0.5:
                pkt = link.recv()
                if not pkt: continue
                ab = parse_hs_ack_frame(pkt)
                if ab:
                    ack_bytes = ab; got_ack=True; break
            if got_ack: break
            print("[TX] HELLO retry", attempt+1)
        if not got_ack:
            print("[TX] ECDH handshake failed (no HS_ACK)."); sys.exit(1)
        sess = finish_handshake_initiator(ack_bytes, a_priv, hello)
        print("[TX] ECDH session established.")
    else:
        print("[TX] WARNING: no session; using ephemeral AES (demo only).")

    # Telemetry exporter
    tel_key = sess.export_key(b"SC1-TELEMETRY", 32) if sess else b"\x00"*32

    # Heartbeats
    stop = False
    def beacon_loop():
        while not stop and P.beacons:
            link.send(make_beacon(sess, args.session_id))
            time.sleep(P.beacon_ms/1000.0)
    thr = threading.Thread(target=beacon_loop, daemon=True); thr.start()

    payload = args.msg.encode()
    msg_id = random.getrandbits(32)  # fits header
    parts = fragment(msg_id, payload, P.max_part)

    # critical-only ARQ
    max_retries = 2 if P.priority=="critical" else 0

    # Telemetry counters
    lost_parts = 0
    dup_used   = 0  # retransmits count
    repaired   = 0  # (not meaningful in 1-part demo; kept for parity)

    for (part_id, total_parts, pt) in parts:
        ct_len = len(pt)+16
        aad = pack_aad(ver=1, suite=1, session_id=args.session_id,
                       msg_id=msg_id, part_id=part_id, total_parts=total_parts,
                       n=P.n,k=P.k,interleave=P.interleave,dup=P.dup, chunk_len=ct_len)
        if sess:
            nonce, ct = sess.encrypt(aad, pt)
        else:
            nonce = os.urandom(12); ct = AESGCM(os.urandom(32)).encrypt(nonce, pt, aad)

        frame = make_data_envelope(msg_id, part_id, total_parts, ct_len, nonce, ct)
        print(f"[TX] part {part_id+1}/{total_parts} bytes={len(pt)} ct_len={ct_len}")
        link.send(frame)

        got = (max_retries == 0)  # if not critical, don't wait for ACK
        if max_retries>0:
            for attempt in range(max_retries+1):
                if attempt>0:
                    dup_used += 1
                    print(f"[TX] retransmitting part {part_id} (attempt {attempt+1}/{max_retries+1})")
                    link.send(frame)
                t0=time.time()
                while time.time()-t0 < 0.4:
                    rx = link.recv()
                    if not rx: continue
                    ack = parse_ack(rx)
                    if ack and ack==(msg_id, part_id):
                        print(f"[TX] got ACK for part {part_id}")
                        got=True; break
                if got: break
        if not got:
            print(f"[TX] part {part_id} presumed lost (no ACK).")
            lost_parts += 1

    # Send signed telemetry
    tel = pack_signed_telemetry(lost_parts, repaired, dup_used, P.interleave, tel_key)
    link.send(tel)
    print(f"[TX] telemetry sent (lost={lost_parts}, dup_used={dup_used}, interleave={P.interleave})")

    stop = True; thr.join(timeout=0.5)
    print("TX done.")

if __name__ == "__main__":
    main()

