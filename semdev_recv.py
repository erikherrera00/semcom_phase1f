#!/usr/bin/env python3
# semdev_recv.py — Device-mode receiver with:
# - ECDH-over-UDP or PSK sessions
# - Signed telemetry verification
# - Replay LRU
# - Loss/jitter knobs (via UDPLink)
# - --once flag to exit after first complete message
# - Clean Ctrl-C handling

import json
import signal
import sys
from dataclasses import dataclass
from typing import Dict

from udp_driver import UDPConfig, UDPLink
from semdev_common import *  # imports frame types, helpers, telemetry, ECDH helpers, replay LRU
from pack_aad import pack_aad
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


@dataclass
class RxProfile:
    n: int
    k: int
    interleave: int
    dup: int
    max_part: int
    priority: str


class Reassembler:
    def __init__(self):
        self.parts: Dict[int, Dict[int, bytes]] = {}
        self.total: Dict[int, int] = {}

    def offer(self, msg_id: int, part_id: int, total_parts: int, payload: bytes):
        if msg_id not in self.parts:
            self.parts[msg_id] = {}
            self.total[msg_id] = total_parts
        if self.total[msg_id] != total_parts:
            return None
        if part_id in self.parts[msg_id]:
            return None
        self.parts[msg_id][part_id] = payload
        if len(self.parts[msg_id]) == total_parts:
            data = b"".join(self.parts[msg_id][i] for i in range(total_parts))
            del self.parts[msg_id]
            del self.total[msg_id]
            return data
        return None


def main():
    import argparse

    ap = argparse.ArgumentParser()
    ap.add_argument("--peer_port", type=int, default=9000)
    ap.add_argument("--bind_port", type=int, default=9001)
    ap.add_argument("--peer_host", type=str, default="127.0.0.1")
    ap.add_argument("--bind_host", type=str, default="0.0.0.0")
    ap.add_argument("--drop", type=float, default=0.0, help="simulate iid loss on send path")
    ap.add_argument("--jitter_ms", type=int, default=0, help="+/- jitter per send (ms)")
    ap.add_argument("--psk_hex", type=str, default=None)
    ap.add_argument("--ecdh", action="store_true")
    ap.add_argument("--session_id", type=int, default=7)
    ap.add_argument("--profile_json", type=str, required=True)
    ap.add_argument("--once", action="store_true", help="exit after first complete message")
    args = ap.parse_args()

    # graceful Ctrl-C
    stop = False

    def _sigint(*_):
        nonlocal stop
        stop = True

    signal.signal(signal.SIGINT, _sigint)

    # load profile
    prof = json.load(open(args.profile_json))
    P = RxProfile(
        n=prof["n"],
        k=prof["k"],
        interleave=prof["interleave"],
        dup=prof["dup"],
        max_part=prof.get("max_part", 256),
        priority=prof.get("priority", "normal"),
    )

    # link
    link = UDPLink(
        UDPConfig(
            bind_host=args.bind_host,
            bind_port=args.bind_port,
            peer_host=args.peer_host,
            peer_port=args.peer_port,
            drop=args.drop,
            jitter_ms=args.jitter_ms,
        )
    )

    # session bring-up
    if args.ecdh and args.psk_hex:
        print("Error: use either --ecdh OR --psk_hex, not both.")
        sys.exit(2)

    sess = None
    tel_key = None

    print("RX ready.")

    if args.psk_hex:
        sess = derive_psk_session(args.psk_hex, args.session_id)
        tel_key = sess.export_key(b"SC1-TELEMETRY", 32)
        print("[RX] PSK session ready.")

    # If ECDH, wait for HELLO, reply with HS_ACK, derive session
    while not stop and args.ecdh and sess is None:
        pkt = link.recv()
        if not pkt:
            continue
        hb = parse_hello_frame(pkt)
        if hb:
            ack, a_pub_bytes, b_priv, sid = respond_handshake_responder(hb)
            link.send(make_hs_ack_frame(ack))
            sess = finish_handshake_responder(b_priv, a_pub_bytes, ack)
            tel_key = sess.export_key(b"SC1-TELEMETRY", 32)
            print("[RX] ECDH session established.")
            break
        # ignore other traffic until session exists

    rx = Reassembler()
    replay = ReplayLRU(4096)

    try:
        while not stop:
            pkt = link.recv()
            if not pkt:
                continue

            t = pkt[0]

            if t == TYPE_BEACON:
                # optional: count beacons for link health
                continue

            if t == TYPE_ACK:
                # RX doesn't expect ACKs; ignore
                continue

            if t == TYPE_TELEM:
                if tel_key is None:
                    # can't verify without a session-derived key
                    continue
                parsed = parse_signed_telemetry(pkt, tel_key)
                if not parsed:
                    continue
                lost, repaired, dup_used, interleave, ok = parsed
                print(
                    f"[RX] TELEMETRY {'OK' if ok else 'BAD'}: "
                    f"lost={lost}, repaired={repaired}, dup_used={dup_used}, interleave={interleave}"
                )
                continue

            env = parse_data_envelope(pkt)
            if not env:
                # unknown or malformed
                continue

            msg_id, part_id, total, chunk_len, nonce, ct = env

            # replay defense
            if replay.seen((msg_id, part_id, nonce)):
                if P.priority == "critical":
                    link.send(make_ack(msg_id, part_id))
                continue

            # AAD must match sender side
            aad = pack_aad(
                ver=1,
                suite=1,
                session_id=args.session_id,
                msg_id=msg_id,
                part_id=part_id,
                total_parts=total,
                n=P.n,
                k=P.k,
                interleave=P.interleave,
                dup=P.dup,
                chunk_len=chunk_len,
            )

            try:
                if sess:
                    pt = sess.decrypt(aad, nonce, ct)
                else:
                    # demo-only fallback
                    pt = AESGCM(os.urandom(32)).decrypt(nonce, ct, aad)  # type: ignore[name-defined]
            except Exception:
                # auth/decrypt failure; drop
                continue

            # ACK immediately for critical
            if P.priority == "critical":
                link.send(make_ack(msg_id, part_id))

            done = rx.offer(msg_id, part_id, total, pt)
            if done is not None:
                print("==== RX COMPLETE ====")
                try:
                    print(done.decode(errors="replace"))
                except Exception:
                    print(f"<{len(done)} bytes binary>")
                print("=====================")
                if args.once:
                    break

    except KeyboardInterrupt:
        # handled by --once or Ctrl-C gracefully
        pass

    print("[RX] Stopped cleanly.")


if __name__ == "__main__":
    main()

