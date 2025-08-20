# profile_secure.py - verify & load profiles; fallback to named defaults
import json, os, sys, base64
from pathlib import Path
from dataclasses import dataclass
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives import serialization

DEFAULTS = {
    "light":  {"n":20,"k":17,"interleave":2,"dup":1,"max_part":128,"priority":"normal","beacons":True,"beacon_ms":500},
    "medium": {"n":24,"k":18,"interleave":4,"dup":1,"max_part":192,"priority":"normal","beacons":True,"beacon_ms":400},
    "heavy":  {"n":30,"k":20,"interleave":12,"dup":2,"max_part":256,"priority":"critical","beacons":True,"beacon_ms":200},
}

@dataclass
class Profile: n:int; k:int; interleave:int; dup:int; max_part:int; priority:str; beacons:bool; beacon_ms:int

def _canon_bytes(path:Path)->bytes:
    obj = json.load(open(path,"r"))
    return json.dumps(obj, sort_keys=True, separators=(",",":")).encode()

def _verify_sig(profile_path:str, pubkey_path:str, sig_path:str)->bool:
    pub = serialization.load_pem_public_key(Path(pubkey_path).read_bytes())
    sig = base64.b64decode(Path(sig_path).read_text().strip())
    try:
        pub.verify(sig, _canon_bytes(Path(profile_path)))
        return True
    except Exception:
        return False

def _dict_to_profile(d:dict)->Profile:
    return Profile(
        n=int(d["n"]), k=int(d["k"]),
        interleave=int(d["interleave"]), dup=int(d["dup"]),
        max_part=int(d.get("max_part",256)),
        priority=str(d.get("priority","normal")),
        beacons=bool(d.get("beacons",True)),
        beacon_ms=int(d.get("beacon_ms",250)),
    )

def load_profile(args)->Profile:
    # if JSON path is given, optionally enforce signatures
    if getattr(args, "profile_json", None):
        d = json.load(open(args.profile_json,"r"))
        # if enforcement requested, require .sig + pubkey
        if getattr(args,"enforce_signed",False):
            sig_path = args.profile_sig or (args.profile_json + ".sig")
            if not (args.pubkey and os.path.exists(sig_path)):
                sys.exit("Profile signature required: provide --pubkey and a .sig (or --profile_sig).")
            if not _verify_sig(args.profile_json, args.pubkey, sig_path):
                sys.exit("Profile signature INVALID. Refusing to start.")
        # allow CLI beacon overrides
        if args.beacons is not None: d["beacons"]=bool(args.beacons)
        if args.beacon_ms is not None: d["beacon_ms"]=int(args.beacon_ms)
        return _dict_to_profile(d)

    # otherwise use built-in profile by name
    name = (args.profile or "heavy").lower()
    if name not in DEFAULTS: sys.exit(f"Unknown profile '{name}'")
    d = DEFAULTS[name]
    if args.beacons is not None: d = {**d, "beacons": bool(args.beacons)}
    if args.beacon_ms is not None: d = {**d, "beacon_ms": int(args.beacon_ms)}
    return _dict_to_profile(d)

