#!/usr/bin/env python3
# profsign.py - Generate keys, sign/verify profile JSONs (Ed25519)

import argparse, json, base64, os, sys
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey
)
from cryptography.hazmat.primitives import serialization

def canon_json_bytes(p: Path) -> bytes:
    obj = json.load(open(p, "r"))
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()

def cmd_gen(args):
    outdir = Path(args.outdir); outdir.mkdir(parents=True, exist_ok=True)
    priv = Ed25519PrivateKey.generate()
    pub  = priv.public_key()
    priv_pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption())
    pub_pem  = pub.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo)
    (outdir/"ed25519_priv.pem").write_bytes(priv_pem)
    (outdir/"ed25519_pub.pem").write_bytes(pub_pem)
    print(f"[OK] wrote {outdir/'ed25519_priv.pem'} and {outdir/'ed25519_pub.pem'}")

def cmd_sign(args):
    prof = Path(args.profile)
    priv = serialization.load_pem_private_key(Path(args.priv).read_bytes(), password=None)
    msg = canon_json_bytes(prof)
    sig = priv.sign(msg)
    Path(args.out).write_text(base64.b64encode(sig).decode()+"\n")
    print(f"[OK] signed {prof} -> {args.out}")

def cmd_verify(args):
    prof = Path(args.profile)
    pub  = serialization.load_pem_public_key(Path(args.pub).read_bytes())
    sig  = base64.b64decode(Path(args.sig).read_text().strip())
    try:
        pub.verify(sig, canon_json_bytes(prof))
        print("[OK] signature valid")
        sys.exit(0)
    except Exception:
        print("[FAIL] signature invalid")
        sys.exit(2)

def main():
    ap = argparse.ArgumentParser(description="Profile signing (Ed25519)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("gen");  g.add_argument("--outdir", default="keys")
    s = sub.add_parser("sign"); s.add_argument("--profile", required=True); s.add_argument("--priv", required=True); s.add_argument("--out", required=False)
    v = sub.add_parser("verify"); v.add_argument("--profile", required=True); v.add_argument("--sig", required=True); v.add_argument("--pub", required=True)

    args = ap.parse_args()
    if args.cmd=="gen": cmd_gen(args)
    elif args.cmd=="sign":
        if not args.out: args.out = args.profile + ".sig"
        cmd_sign(args)
    else: cmd_verify(args)

if __name__ == "__main__":
    main()

