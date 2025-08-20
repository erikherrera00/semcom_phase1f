#!/usr/bin/env python3
import pandas as pd
import matplotlib.pyplot as plt
import os, math, sys

OUTDIR = "reports/phase2"
os.makedirs(OUTDIR, exist_ok=True)

def load_csvs(paths):
    frames = []
    for p in paths:
        if not os.path.exists(p):
            print(f"[WARN] missing CSV: {p}")
            continue
        df = pd.read_csv(p)
        frames.append(df)
    if not frames:
        raise SystemExit("No CSVs found. Run the simulator first.")
    df = pd.concat(frames, ignore_index=True)
    # Normalize dtypes
    if "profile" in df: df["profile"] = df["profile"].astype(str)
    if "loss" in df: df["loss"] = df["loss"].astype(float)
    if "success_rate" in df: df["success_rate"] = df["success_rate"].astype(float)
    return df

def annotate_overhead(row):
    n, k = int(row["n"]), int(row["k"])
    oh = (n / k) - 1.0
    return f"{n}/{k} ({oh*100:.0f}% OH)"

def plot_success(df):
    # One figure: success vs loss for each profile (lines with markers)
    plt.figure(figsize=(7.5, 5.0))
    for prof, g in df.groupby("profile"):
        g = g.sort_values("loss")
        label_extra = ""
        # derive a single (n/k) label per profile from the first row
        if {"n","k"} <= set(g.columns):
            label_extra = " " + annotate_overhead(g.iloc[0])
        plt.plot(g["loss"]*100.0, g["success_rate"], marker="o", label=f"{prof}{label_extra}")
    # thresholds
    plt.axhline(95.0, linestyle="--")
    plt.text(df["loss"].max()*100.0, 95.2, "95% threshold", ha="right", va="bottom")
    plt.axhline(90.0, linestyle="--")
    plt.text(df["loss"].max()*100.0, 90.2, "90% threshold", ha="right", va="bottom")

    plt.xlabel("Loss (%)")
    plt.ylabel("Success rate (%)")
    plt.title("SemanticComms: success vs. loss (simulated)")
    plt.legend()
    out = os.path.join(OUTDIR, "success_by_profile.png")
    plt.tight_layout(); plt.savefig(out, dpi=160)
    print(f"[OK] wrote {out}")

def write_summary_md(df):
    # Summarize each profile at each loss
    out_md = os.path.join(OUTDIR, "sim_summary.md")
    lines = ["# Simulator Summary\n"]
    for prof, g in df.groupby("profile"):
        lines.append(f"## {prof}")
        lines.append("")
        lines.append("| loss | n/k | interleave | dup | batch | success |")
        lines.append("|------|-----|------------|-----|-------|---------|")
        for _, r in g.sort_values(["loss"]).iterrows():
            lines.append("| {loss:.2f} | {nk} | {inter} | {dup} | {batch} | {sr:.1f}% |".format(
                loss=r["loss"], nk=annotate_overhead(r), inter=int(r["interleave"]),
                dup=int(r["dup"]), batch=int(r["batch"]), sr=r["success_rate"]))
        lines.append("")
    with open(out_md, "w") as f:
        f.write("\n".join(lines))
    print(f"[OK] wrote {out_md}")

if __name__ == "__main__":
    # default CSVs (override by args)
    csvs = sys.argv[1:] if len(sys.argv)>1 else ["war_light.csv","war_medium.csv","war_heavy.csv"]
    df = load_csvs(csvs)
    plot_success(df)
    write_summary_md(df)

