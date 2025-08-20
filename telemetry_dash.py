#!/usr/bin/env python3
# telemetry_dash.py - live, simple dashboard reading receiver JSONL logs (robust tailer)

import argparse, json, os, time, glob
from datetime import datetime

def latest_rx_log():
    files = sorted(glob.glob("logs/receiver_*.jsonl"))
    return files[-1] if files else None

def fmt(ts): 
    try:
        return datetime.fromtimestamp(ts).strftime("%H:%M:%S")
    except Exception:
        return "-"

def tail_jsonl(path, start_pos=0):
    """
    Robust tail generator:
    - opens in binary mode
    - maintains byte position
    - handles partial lines across reads
    """
    pos = start_pos
    buf = b""
    while True:
        try:
            with open(path, "rb") as f:
                f.seek(pos, os.SEEK_SET)
                chunk = f.read()
                if chunk:
                    buf += chunk
                    # splitlines(True) keeps line endings
                    lines = buf.splitlines(True)
                    # if last line doesn't end with \n, keep it in buffer
                    if lines and not lines[-1].endswith(b"\n"):
                        buf = lines[-1]
                        lines = lines[:-1]
                    else:
                        buf = b""
                    for raw in lines:
                        pos += len(raw)
                        try:
                            line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
                            if not line:
                                continue
                            ev = json.loads(line)
                            yield ev, pos
                        except json.JSONDecodeError:
                            # skip malformed/incomplete json (should be rare)
                            continue
                else:
                    # no new data; yield nothing this cycle
                    yield None, pos
        except FileNotFoundError:
            yield None, pos
        time.sleep(0.2)  # poll interval for new data

def main():
    ap = argparse.ArgumentParser(description="Live Telemetry Dashboard")
    ap.add_argument("--file", help="receiver JSONL log; default=latest logs/receiver_*.jsonl")
    ap.add_argument("--interval", type=float, default=0.5, help="refresh seconds")
    args = ap.parse_args()

    path = args.file or latest_rx_log()
    if not path or not os.path.exists(path):
        print("No receiver JSONL found. Start securecomms receiver first.")
        return

    stats = {
        "link": "init",
        "msgs": 0,
        "acks": 0,
        "replays": 0,
        "auth_fail": 0,
        "last_bytes": 0,
        "telemetry": None,
        "last_ts": None,
        "log_path": path,
    }

    print(f"[dash] tailing {path}")
    last_draw = 0.0

    for ev, _pos in tail_jsonl(path, start_pos=0):
        if ev is not None:
            stats["last_ts"] = ev.get("ts", stats["last_ts"])
            et = ev.get("event","")
            if et == "ecdh_ok":
                stats["link"] = "ECDH"
            elif et == "psk_ready":
                stats["link"] = "PSK"
            elif et == "rx_complete":
                stats["msgs"] += 1
                stats["last_bytes"] = ev.get("bytes", 0)
            elif et == "rx_ack":
                stats["acks"] += 1
            elif et == "rx_replay_drop":
                stats["replays"] += 1
            elif et == "rx_auth_fail":
                stats["auth_fail"] += 1
            elif et == "rx_telem":
                stats["telemetry"] = {
                    "ok": ev.get("ok"),
                    "lost": ev.get("lost"),
                    "repaired": ev.get("repaired"),
                    "dup_used": ev.get("dup_used"),
                    "interleave": ev.get("interleave"),
                }

        now = time.time()
        if now - last_draw >= args.interval:
            os.system("clear")
            print("=== SemanticComms: Live RX Dashboard ===")
            print(f"Log: {stats['log_path']}")
            print(f"Link: {stats['link']}")
            print(f"Msgs Received: {stats['msgs']}  (last_bytes={stats['last_bytes']})")
            print(f"ACKs Sent: {stats['acks']}   Replays Dropped: {stats['replays']}   AuthFail: {stats['auth_fail']}")
            if stats["telemetry"]:
                t = stats["telemetry"]
                ok = "OK" if t.get("ok") else "BAD"
                print(f"Telemetry: {ok} | lost={t.get('lost')} repaired={t.get('repaired')} dup_used={t.get('dup_used')} interleave={t.get('interleave')}")
            else:
                print("Telemetry: (none yet)")
            if stats["last_ts"]:
                print(f"Last event: {fmt(stats['last_ts'])}")
            print("\n(CTRL-C to exit)")
            last_draw = now

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass

