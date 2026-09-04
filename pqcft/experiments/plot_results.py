#!/usr/bin/env python3
"""
Analysis + figures (Weeks 9-10 of the plan).

Produces:
    fig1_retransmission.png   retransmission overhead vs disruption count
    fig2_goodput.png          goodput vs disruption count
    fig3_recovery.png         recovery time, proposed vs baseline
    fig4_kem_cost.png         ML-KEM vs X25519: handshake wire bytes + CPU
    fig5_checkpoint_interval.png  interval sweep (overhead vs write cost)
    summary.md                the numbers to paste into the report

Usage:
    python3 experiments/plot_results.py --csv results/results.csv --outdir results/figs
"""

from __future__ import annotations

import argparse
import csv
import os
import statistics
from collections import defaultdict

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

ARM_ORDER = ["baseline-tls", "pq-nockpt", "classical-ckpt", "proposed"]
ARM_LABEL = {
    "baseline-tls": "Baseline (X25519, no ckpt)",
    "pq-nockpt": "ML-KEM, no ckpt",
    "classical-ckpt": "X25519 + checkpoint",
    "proposed": "Proposed (ML-KEM + ckpt)",
}
ARM_COLOR = {
    "baseline-tls": "#b0413e",
    "pq-nockpt": "#d98032",
    "classical-ckpt": "#4a7fb5",
    "proposed": "#2e7d4f",
}


def load(path):
    with open(path) as f:
        rows = list(csv.DictReader(f))
    for r in rows:
        for k in ("total_time_s", "goodput_mbps", "retransmission_overhead_pct",
                  "mean_recovery_s", "max_recovery_s", "kex_cpu_ms",
                  "handshake_time_s", "disruption_duration_s",
                  "checkpoint_overhead_ms"):
            r[k] = float(r[k] or 0)
        for k in ("file_size", "disruptions_configured", "attempts",
                  "payload_bytes_sent", "kex_wire_bytes", "wasted_bytes",
                  "checkpoint_writes", "total_chunks"):
            r[k] = int(r[k] or 0)
        for k in ("integrity_ok", "completed"):
            r[k] = str(r.get(k, "")).lower() == "true"
    return rows


def delivered(rows):
    """
    Only runs that actually delivered the file.

    Performance means must be computed over these alone. A run that ran out of
    retry budget is a censored observation: its goodput and retransmission
    figures describe an aborted prefix, not a transfer, and averaging them in
    would flatter whichever arm failed most often. Non-completion is reported
    separately as a completion rate.
    """
    return [r for r in rows if r["completed"] and r["integrity_ok"]]


def agg(rows, key_fn, val_fn):
    """Mean + stdev of val_fn grouped by key_fn."""
    buckets = defaultdict(list)
    for r in rows:
        v = val_fn(r)
        if v is not None:
            buckets[key_fn(r)].append(v)
    return {
        k: (statistics.fmean(v), statistics.stdev(v) if len(v) > 1 else 0.0, len(v))
        for k, v in buckets.items()
    }


def _style(ax, title, xlabel, ylabel):
    ax.set_title(title, fontsize=12, fontweight="bold", pad=12)
    ax.set_xlabel(xlabel, fontsize=10)
    ax.set_ylabel(ylabel, fontsize=10)
    ax.grid(axis="y", alpha=0.25, linestyle="--")
    ax.set_axisbelow(True)
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)


def grouped_bar(rows, outdir, fname, metric, title, ylabel, dur=None):
    rows = delivered(rows)
    sel = [r for r in rows if dur is None or r["disruption_duration_s"] in (0.0, dur)]
    counts = sorted({r["disruptions_configured"] for r in sel})
    fig, ax = plt.subplots(figsize=(8, 4.5))
    width = 0.8 / len(ARM_ORDER)

    for i, arm in enumerate(ARM_ORDER):
        means, errs = [], []
        for c in counts:
            sub = [r for r in sel if r["protocol"] == arm
                   and r["disruptions_configured"] == c]
            if sub:
                vals = [r[metric] for r in sub]
                means.append(statistics.fmean(vals))
                errs.append(statistics.stdev(vals) if len(vals) > 1 else 0.0)
            else:
                means.append(0.0)
                errs.append(0.0)
        xs = [c_i + (i - len(ARM_ORDER) / 2 + 0.5) * width for c_i in range(len(counts))]
        ax.bar(xs, means, width, yerr=errs, capsize=3, label=ARM_LABEL[arm],
               color=ARM_COLOR[arm], edgecolor="white", linewidth=0.6)

    ax.set_xticks(range(len(counts)))
    ax.set_xticklabels([str(c) for c in counts])
    _style(ax, title, "Disruption events during transfer", ylabel)
    ax.legend(fontsize=8, frameon=False)
    fig.tight_layout()
    fig.savefig(os.path.join(outdir, fname), dpi=160)
    plt.close(fig)


def fig_recovery(rows, outdir):
    sel = [r for r in delivered(rows) if r["disruptions_configured"] > 0]
    durs = sorted({r["disruption_duration_s"] for r in sel})
    fig, ax = plt.subplots(figsize=(8, 4.5))
    width = 0.8 / len(ARM_ORDER)

    for i, arm in enumerate(ARM_ORDER):
        means, errs = [], []
        for d in durs:
            sub = [r["mean_recovery_s"] for r in sel
                   if r["protocol"] == arm and r["disruption_duration_s"] == d
                   and r["mean_recovery_s"] > 0]
            means.append(statistics.fmean(sub) if sub else 0.0)
            errs.append(statistics.stdev(sub) if len(sub) > 1 else 0.0)
        xs = [j + (i - len(ARM_ORDER) / 2 + 0.5) * width for j in range(len(durs))]
        ax.bar(xs, means, width, yerr=errs, capsize=3, label=ARM_LABEL[arm],
               color=ARM_COLOR[arm], edgecolor="white", linewidth=0.6)

    for j, d in enumerate(durs):
        ax.hlines(d, j - 0.45, j + 0.45, colors="#333", linestyles=":", linewidth=1.4,
                  label="Outage duration (floor)" if j == 0 else None)

    ax.set_xticks(range(len(durs)))
    ax.set_xticklabels([f"{d}s outage" for d in durs])
    _style(ax, "Time to resume transmission after a disruption",
           "Outage duration", "Mean recovery time (s)")
    ax.legend(fontsize=8, frameon=False)
    fig.tight_layout()
    fig.savefig(os.path.join(outdir, "fig3_recovery.png"), dpi=160)
    plt.close(fig)


def fig_kem(rows, outdir):
    """Isolate KEM cost: only clean runs, one handshake, no confounds."""
    clean = [r for r in delivered(rows) if r["disruptions_configured"] == 0]
    schemes = ["x25519-ecdhe", "ml-kem-768"]
    labels = ["X25519 ECDHE\n(classical)", "ML-KEM-768\n(post-quantum)"]

    wire = [statistics.fmean([r["kex_wire_bytes"] for r in clean
                              if r["scheme"] == s] or [0]) for s in schemes]
    cpu = [statistics.fmean([r["kex_cpu_ms"] for r in clean
                             if r["scheme"] == s] or [0]) for s in schemes]

    fig, (a1, a2) = plt.subplots(1, 2, figsize=(9, 4.2))
    c = ["#4a7fb5", "#2e7d4f"]
    a1.bar(labels, wire, color=c, width=0.55, edgecolor="white")
    for i, v in enumerate(wire):
        a1.text(i, v, f"{v:.0f} B", ha="center", va="bottom", fontsize=9)
    _style(a1, "Handshake bytes on the wire", "", "Bytes per session")

    a2.bar(labels, cpu, color=c, width=0.55, edgecolor="white")
    for i, v in enumerate(cpu):
        a2.text(i, v, f"{v:.2f} ms", ha="center", va="bottom", fontsize=9)
    _style(a2, "Initiator KEM CPU time", "", "Milliseconds per session")

    fig.suptitle("Cost of post-quantum key establishment (undisrupted transfers)",
                 fontsize=12, fontweight="bold")
    fig.tight_layout()
    fig.savefig(os.path.join(outdir, "fig4_kem_cost.png"), dpi=160)
    plt.close(fig)


def fig_completion(rows, outdir):
    """Completion rate under disruption -- the arm that never finishes."""
    sel = [r for r in rows if r["disruptions_configured"] > 0]
    conds = sorted({(r["disruptions_configured"], r["disruption_duration_s"])
                    for r in sel})
    fig, ax = plt.subplots(figsize=(9, 4.5))
    width = 0.8 / len(ARM_ORDER)
    for i, arm in enumerate(ARM_ORDER):
        rates = []
        for c, d in conds:
            sub = [r for r in sel if r["protocol"] == arm
                   and r["disruptions_configured"] == c
                   and r["disruption_duration_s"] == d]
            ok = [r for r in sub if r["completed"] and r["integrity_ok"]]
            rates.append(100.0 * len(ok) / len(sub) if sub else 0.0)
        xs = [j + (i - len(ARM_ORDER) / 2 + 0.5) * width for j in range(len(conds))]
        ax.bar(xs, rates, width, label=ARM_LABEL[arm], color=ARM_COLOR[arm],
               edgecolor="white", linewidth=0.6)
    ax.set_xticks(range(len(conds)))
    ax.set_xticklabels([f"{c}x{d}s" for c, d in conds], fontsize=8)
    ax.set_ylim(0, 105)
    _style(ax, "Transfers that completed within the retry budget",
           "Disruption schedule (count x outage duration)", "Completion rate (%)")
    ax.legend(fontsize=8, frameon=False, loc="lower left")
    fig.tight_layout()
    fig.savefig(os.path.join(outdir, "fig5_completion.png"), dpi=160)
    plt.close(fig)


def summary(rows, outdir):
    ok = delivered(rows)
    corrupt = [r for r in rows if r["completed"] and not r["integrity_ok"]]
    unfinished = [r for r in rows if not r["completed"]]

    lines = ["# Results summary", ""]
    lines.append(f"Total runs: {len(rows)}  |  delivered: {len(ok)}  |  "
                 f"did not finish in budget: {len(unfinished)}  |  "
                 f"**corrupted deliveries: {len(corrupt)}**")
    lines.append("")
    lines.append("Performance means below are over *delivered* runs only. A run that "
                 "exhausted its retry budget is a censored observation -- its goodput "
                 "describes an aborted prefix, not a transfer -- so it is reported as "
                 "a completion rate instead of averaged in.")
    lines.append("")

    clean = [r for r in ok if r["disruptions_configured"] == 0]
    dis = [r for r in ok if r["disruptions_configured"] > 0]

    lines.append("## Steady state (no disruptions)")
    lines.append("")
    lines.append("| Arm | Goodput (Mbps) | Handshake (ms) | KEX wire (B) |")
    lines.append("|---|---|---|---|")
    for arm in ARM_ORDER:
        s = [r for r in clean if r["protocol"] == arm]
        if not s:
            continue
        lines.append(
            f"| {ARM_LABEL[arm]} | {statistics.fmean([r['goodput_mbps'] for r in s]):.2f} "
            f"| {statistics.fmean([r['handshake_time_s'] for r in s])*1e3:.1f} "
            f"| {statistics.fmean([r['kex_wire_bytes'] for r in s]):.0f} |"
        )

    lines += ["", "## Under disruption", ""]
    lines.append("| Arm | Goodput (Mbps) | Retransmission overhead | Mean recovery (s) | Wasted MB |")
    lines.append("|---|---|---|---|---|")
    for arm in ARM_ORDER:
        s = [r for r in dis if r["protocol"] == arm]
        if not s:
            continue
        lines.append(
            f"| {ARM_LABEL[arm]} "
            f"| {statistics.fmean([r['goodput_mbps'] for r in s]):.2f} "
            f"| {statistics.fmean([r['retransmission_overhead_pct'] for r in s]):.1f}% "
            f"| {statistics.fmean([r['mean_recovery_s'] for r in s]):.2f} "
            f"| {statistics.fmean([r['wasted_bytes'] for r in s])/1e6:.2f} |"
        )

    lines += ["", "## Completion rate under disruption", ""]
    lines.append("| Arm | Completed | Rate |")
    lines.append("|---|---|---|")
    dis_all = [r for r in rows if r["disruptions_configured"] > 0]
    for arm in ARM_ORDER:
        s_all = [r for r in dis_all if r["protocol"] == arm]
        s_ok = [r for r in s_all if r["completed"] and r["integrity_ok"]]
        if s_all:
            lines.append(f"| {ARM_LABEL[arm]} | {len(s_ok)}/{len(s_all)} | "
                         f"{100*len(s_ok)/len(s_all):.0f}% |")

    base = [r for r in dis if r["protocol"] == "baseline-tls"]
    prop = [r for r in dis if r["protocol"] == "proposed"]
    if base and prop:
        b_rtx = statistics.fmean([r["retransmission_overhead_pct"] for r in base])
        p_rtx = statistics.fmean([r["retransmission_overhead_pct"] for r in prop])
        b_gp = statistics.fmean([r["goodput_mbps"] for r in base])
        p_gp = statistics.fmean([r["goodput_mbps"] for r in prop])
        lines += ["", "## Headline", ""]
        lines.append(f"- Retransmission overhead: {b_rtx:.1f}% -> {p_rtx:.1f}% "
                     f"({(1 - p_rtx/b_rtx)*100:.0f}% reduction)" if b_rtx else "")
        lines.append(f"- Goodput under disruption: {b_gp:.2f} -> {p_gp:.2f} Mbps "
                     f"({(p_gp/b_gp - 1)*100:+.0f}%)")

    pq = [r for r in clean if r["scheme"] == "ml-kem-768"]
    cl = [r for r in clean if r["scheme"] == "x25519-ecdhe"]
    if pq and cl:
        pw = statistics.fmean([r["kex_wire_bytes"] for r in pq])
        cw = statistics.fmean([r["kex_wire_bytes"] for r in cl])
        pc = statistics.fmean([r["kex_cpu_ms"] for r in pq])
        cc = statistics.fmean([r["kex_cpu_ms"] for r in cl])
        lines.append(f"- ML-KEM handshake cost: {pw:.0f} B vs {cw:.0f} B "
                     f"({pw/cw:.1f}x wire), {pc:.2f} ms vs {cc:.2f} ms CPU")
        gp_pq = statistics.fmean([r["goodput_mbps"] for r in pq])
        gp_cl = statistics.fmean([r["goodput_mbps"] for r in cl])
        lines.append(f"- Steady-state goodput impact of ML-KEM: "
                     f"{gp_cl:.2f} -> {gp_pq:.2f} Mbps ({(gp_pq/gp_cl-1)*100:+.1f}%)")

    out = os.path.join(outdir, "summary.md")
    with open(out, "w") as f:
        f.write("\n".join(l for l in lines if l is not None) + "\n")
    print("\n".join(l for l in lines if l))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", default="results/results.csv")
    ap.add_argument("--outdir", default="results/figs")
    args = ap.parse_args()

    os.makedirs(args.outdir, exist_ok=True)
    rows = load(args.csv)

    grouped_bar(rows, args.outdir, "fig1_retransmission.png",
                "retransmission_overhead_pct",
                "Bandwidth wasted re-sending already-delivered data",
                "Retransmission overhead (%)")
    grouped_bar(rows, args.outdir, "fig2_goodput.png", "goodput_mbps",
                "End-to-end goodput under 6G disruption",
                "Goodput (Mbps)")
    fig_recovery(rows, args.outdir)
    fig_kem(rows, args.outdir)
    fig_completion(rows, args.outdir)
    summary(rows, args.outdir)
    print(f"\nFigures -> {args.outdir}")


if __name__ == "__main__":
    main()
