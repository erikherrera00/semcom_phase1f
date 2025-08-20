#!/usr/bin/env python3
"""
securecomms.py — Orchestrator wrapper for Phase 3/4/6 flows with Phase‑5 polish:
- delegates to semdev_recv.py / semdev_send.py
- adds signed profile enforcement (--enforce_signed/--pubkey)
- creates a --ready_file marker when RX is ready (healthcheck for compose)
- preserves all flags you’ve been using
"""
import os
import sys
import json
import shlex
import time
import argparse
import subprocess
from typing import List, Optional

# Ensure we can import sibling modules regardless of CWD
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

# Optional semantics (Phase 6) — not required to run
try:
    from semcodec import encode_from_json, decode_to_dict, SEM_VER  # noqa: F401
    HAVE_SEMANTICS = True
except Exception as e:
    print(f"[init] semantics import failed: {e}")
    HAVE_SEMANTICS = False
    SEM_VER = 0


# ---------- Utility: signed profile verification ----------

def _verify_profile_signature(profile_path: str, pubkey_path: Optional[str]) -> None:
    """
    Verify profile JSON signature using repo tool: profsign.py verify --pubkey <pem> <profile.json>
    Raises SystemExit on failure with a clear message.
    """
    if not pubkey_path:
        raise SystemExit("[profile] --enforce_signed was set but --pubkey is missing.")
    if not os.path.exists(pubkey_path):
        raise SystemExit(f"[profile] public key not found: {pubkey_path}")
    if not os.path.exists(profile_path):
        raise SystemExit(f"[profile] profile file not found: {profile_path}")

    cmd = [sys.executable, "profsign.py", "verify", "--pubkey", pubkey_path, profile_path]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        msg = r.stderr.strip() or r.stdout.strip() or "unknown verification error"
        raise SystemExit(f"[profile] signature verification FAILED: {msg}")
    print("[profile] signature OK.")


def _resolve_profile_json(args: argparse.Namespace) -> str:
    """
    Resolve the profile JSON path from --profile_json or --profile name.
    Does not open/validate JSON; only path resolution.
    """
    if args.profile_json:
        return args.profile_json
    # default to profiles/<name>.json
    name = args.profile or "heavy"
    path = os.path.join("profiles", f"{name}.json")
    return path


# ---------- Subprocess driver wrappers ----------

def run_receiver(args: argparse.Namespace) -> int:
    """
    Launch semdev_recv.py as a subprocess, mirror output to our stdout,
    and when we see 'RX ready.' print, touch --ready_file (if provided).
    Returns the subprocess return code.
    """
    profile_path = _resolve_profile_json(args)
    if args.enforce_signed:
        _verify_profile_signature(profile_path, args.pubkey)

    recv_cmd: List[str] = [
        sys.executable, "semdev_recv.py",
        "--profile_json", profile_path,
        "--bind_port", str(args.bind_port),
        "--peer_port", str(args.peer_port),
    ]

    # optional hosts
    if args.bind_host:
        recv_cmd += ["--bind_host", args.bind_host]
    if args.peer_host:
        recv_cmd += ["--peer_host", args.peer_host]

    # channel impairments
    if args.drop is not None:
        recv_cmd += ["--drop", str(args.drop)]
    if args.jitter_ms is not None:
        recv_cmd += ["--jitter_ms", str(args.jitter_ms)]

    # session / crypto
    if args.ecdh:
        recv_cmd += ["--ecdh", "--session_id", str(args.session_id)]
    elif args.psk_hex:
        recv_cmd += ["--psk_hex", args.psk_hex, "--session_id", str(args.session_id)]

    # single-shot mode (stop after one complete message)
    if args.once:
        recv_cmd += ["--once"]

    print(f"[rx/wrap] exec: {shlex.join(recv_cmd)}")
    # Start child; stream stdout line by line
    with subprocess.Popen(
        recv_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        bufsize=1,
        text=True,
    ) as proc:
        try:
            ready_written = False
            for line in proc.stdout:
                # Mirror child's output
                print(line, end="")
                # Detect readiness and create health marker if asked
                if (not ready_written) and ("RX ready." in line):
                    if args.ready_file:
                        try:
                            open(args.ready_file, "w").close()
                            print(f"[rx/wrap] wrote ready_file: {args.ready_file}")
                        except Exception as e:
                            print(f"[rx/wrap] warn: cannot write ready_file {args.ready_file}: {e}")
                    ready_written = True
        except KeyboardInterrupt:
            try:
                proc.terminate()
            except Exception:
                pass
        finally:
            # If child still running, wait briefly then kill
            try:
                rc = proc.wait(timeout=1.0)
            except subprocess.TimeoutExpired:
                proc.kill()
                rc = proc.wait()
    return rc


def run_sender(args: argparse.Namespace) -> int:
    """
    Launch semdev_send.py as a subprocess; mirror output.
    Supports plaintext (--msg/--msg_file) and semantic (--semantic/--sem_json) modes.
    """
    profile_path = _resolve_profile_json(args)
    if args.enforce_signed:
        _verify_profile_signature(profile_path, args.pubkey)

    send_cmd: List[str] = [
        sys.executable, "semdev_send.py",
        "--profile_json", profile_path,
        "--bind_port", str(args.bind_port),
        "--peer_port", str(args.peer_port),
    ]

    # optional hosts
    if args.bind_host:
        send_cmd += ["--bind_host", args.bind_host]
    if args.peer_host:
        send_cmd += ["--peer_host", args.peer_host]

    # session / crypto
    if args.ecdh:
        send_cmd += ["--ecdh", "--session_id", str(args.session_id)]
    elif args.psk_hex:
        send_cmd += ["--psk_hex", args.psk_hex, "--session_id", str(args.session_id)]

    # payload mode: semantic vs plain
    if args.semantic:
        send_cmd += ["--semantic", args.semantic]
        if not args.sem_json:
            raise SystemExit("semantic mode requires --sem_json <file.json>")
        send_cmd += ["--sem_json", args.sem_json]
    else:
        # plaintext
        if args.msg:
            send_cmd += ["--msg", args.msg]
        elif args.msg_file:
            send_cmd += ["--msg_file", args.msg_file]
        else:
            # default text so you don't get a no-op
            send_cmd += ["--msg", "Hello from securecomms.py"]

    # optional beacons passthrough if your semdev_send supports them
    if args.beacons is True:
        send_cmd += ["--beacons"]
    elif args.beacons is False:
        send_cmd += ["--no-beacons"]
    if args.beacon_ms is not None:
        send_cmd += ["--beacon_ms", str(args.beacon_ms)]

    print(f"[tx/wrap] exec: {shlex.join(send_cmd)}")
    with subprocess.Popen(
        send_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        bufsize=1,
        text=True,
    ) as proc:
        try:
            for line in proc.stdout:
                print(line, end="")
        except KeyboardInterrupt:
            try:
                proc.terminate()
            except Exception:
                pass
        finally:
            try:
                rc = proc.wait(timeout=1.0)
            except subprocess.TimeoutExpired:
                proc.kill()
                rc = proc.wait()
    return rc


# ---------- CLI ----------

def build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Secure Semantic Comms — TX/RX wrapper with signed profiles + readiness."
    )
    p.add_argument("--role", required=True, choices=["send", "recv"], help="send or recv")

    # Profiles (either name or explicit path)
    p.add_argument("--profile", choices=["light", "medium", "heavy"], default="heavy",
                   help="profile name (uses profiles/<name>.json) unless --profile_json is given")
    p.add_argument("--profile_json", type=str, default=None,
                   help="explicit profile JSON path (overrides --profile)")

    # Signed profile enforcement
    p.add_argument("--enforce_signed", action="store_true",
                   help="require profile JSON to be Ed25519-signed (verified with --pubkey)")
    p.add_argument("--pubkey", type=str, default=None,
                   help="Ed25519 public key PEM for profile verification")

    # Session/crypto
    p.add_argument("--ecdh", action="store_true", help="use X25519 ECDH session")
    p.add_argument("--psk_hex", type=str, default=None, help="pre-shared 32-byte key (hex)")
    p.add_argument("--session_id", type=int, default=7, help="session id (nonce domain separation)")

    # UDP endpoints
    p.add_argument("--bind_host", type=str, default="0.0.0.0")
    p.add_argument("--peer_host", type=str, default=None)
    p.add_argument("--bind_port", type=int, required=True)
    p.add_argument("--peer_port", type=int, required=True)

    # Impairments (semdev scripts already implement drop/jitter)
    p.add_argument("--drop", type=float, default=None, help="loss probability (0..1)")
    p.add_argument("--jitter_ms", type=int, default=None, help="jitter in ms")

    # Receiver control
    p.add_argument("--once", action="store_true", help="receiver: exit after one complete message")
    p.add_argument("--ready_file", type=str, default=None,
                   help="receiver: touch this file when RX is ready (compose healthcheck)")

    # Sender payload control
    p.add_argument("--msg", type=str, default=None, help="plaintext message")
    p.add_argument("--msg_file", type=str, default=None, help="plaintext file")
    p.add_argument("--semantic", type=str, choices=["status", "command", "alert", "ack"], default=None,
                   help="semantic message type")
    p.add_argument("--sem_json", type=str, default=None, help="semantic body json path")

    # Beacons passthrough (if your semdev_send implements them)
    p.add_argument("--beacons", dest="beacons", action="store_true", help="enable cover beacons")
    p.add_argument("--no-beacons", dest="beacons", action="store_false", help="disable cover beacons")
    p.set_defaults(beacons=None)
    p.add_argument("--beacon_ms", type=int, default=None, help="beacon interval (ms)")

    return p


def main():
    args = build_argparser().parse_args()

    # Sanity: crypto mode
    if not args.ecdh and not args.psk_hex:
        print("[warn] no --ecdh or --psk_hex provided; proceeding without a session (OK if semdev handles defaults)")

    # Sanity: semantic mode requires sem_json
    if args.role == "send" and args.semantic and not args.sem_json:
        raise SystemExit("semantic mode requires --sem_json <file>")

    try:
        if args.role == "recv":
            rc = run_receiver(args)
        else:
            rc = run_sender(args)
    except KeyboardInterrupt:
        print("[wrap] interrupted")
        rc = 130

    sys.exit(rc)


if __name__ == "__main__":
    main()

