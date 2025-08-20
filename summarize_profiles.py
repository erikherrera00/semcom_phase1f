#!/usr/bin/env python3
import json, os, glob

OUT = "reports/phase2/profiles_table.md"
os.makedirs(os.path.dirname(OUT), exist_ok=True)

def overhead(n,k): return (n/k - 1.0)*100.0

rows = []
for path in sorted(glob.glob("profiles/*.json")):
    with open(path,"r") as f:
        d = json.load(f)
    n = d["n"]; k = d["k"]
    rows.append({
        "name": os.path.basename(path),
        "n": n, "k": k,
        "overhead%": round(overhead(n,k),1),
        "interleave": d.get("interleave"),
        "dup": d.get("dup"),
        "max_part": d.get("max_part"),
        "priority": d.get("priority","normal"),
        "beacon_ms": d.get("beacon_ms", None)
    })

lines = ["# Config Profiles\n",
         "| profile | n | k | overhead | interleave | dup | max_part | priority | beacon_ms |",
         "|---------|---|---|----------|------------|-----|----------|----------|-----------|"]
for r in rows:
    lines.append(f"| {r['name']} | {r['n']} | {r['k']} | {r['overhead%']}% | {r['interleave']} | {r['dup']} | {r['max_part']} | {r['priority']} | {r['beacon_ms']} |")

with open(OUT,"w") as f:
    f.write("\n".join(lines) + "\n")

print(f"[OK] wrote {OUT}")

