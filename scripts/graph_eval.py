#!/usr/bin/env python3
"""Generate research-ready graphs from the clean evaluation database.

Reads ONLY data/eval.sqlite3 (the coherent dataset from collect_eval.py). Every
value plotted is a real Argus measurement; nothing is synthesised. Writes PNGs
to graphs/ and prints, per figure, how many real data points it used.
"""

from __future__ import annotations

import os
import sqlite3

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

ROOT = os.path.join(os.path.dirname(__file__), "..")
DB = os.path.join(ROOT, "data", "eval.sqlite3")
OUT = os.path.join(ROOT, "graphs")
os.makedirs(OUT, exist_ok=True)

plt.rcParams.update({"figure.dpi": 130, "font.size": 10, "axes.grid": True,
                     "grid.alpha": 0.3, "figure.autolayout": True})
COLORS = {"google": "#4285F4", "cloudflare": "#F38020", "quad9": "#7B2D8B"}


def color(name, i):
    return COLORS.get(name, plt.cm.tab10(i % 10))


c = sqlite3.connect(DB)
c.row_factory = sqlite3.Row
resolvers = [r["name"] for r in c.execute(
    "SELECT DISTINCT resolver AS name FROM health_metrics ORDER BY resolver")]
t0 = c.execute("SELECT min(computed_at) m FROM health_metrics").fetchone()["m"]


def save(fig, name):
    path = os.path.join(OUT, name)
    fig.savefig(path, bbox_inches="tight")
    plt.close(fig)
    print(f"  wrote {name}")


# 1. Latency over time --------------------------------------------------------
fig, ax = plt.subplots(figsize=(7, 4))
n = 0
for i, r in enumerate(resolvers):
    rows = c.execute("SELECT computed_at, avg_latency_ms FROM health_metrics "
                     "WHERE resolver=? AND avg_latency_ms IS NOT NULL ORDER BY computed_at",
                     (r,)).fetchall()
    if not rows:
        continue
    xs = [(x["computed_at"] - t0) / 60 for x in rows]
    ys = [x["avg_latency_ms"] for x in rows]
    ax.plot(xs, ys, marker="o", color=color(r, i), label=r)
    n += len(rows)
ax.set_xlabel("Time (minutes from start of experiment)")
ax.set_ylabel("Mean DNS response latency (ms)")
ax.set_title("Figure 1. DNS response latency over time, per resolver")
ax.legend(title="Resolver")
save(fig, "01_latency_over_time.png"); print(f"    (points={n})")

# 2. Availability -------------------------------------------------------------
avail = {r: c.execute("SELECT avg(availability_pct) a FROM health_metrics WHERE resolver=?",
                      (r,)).fetchone()["a"] for r in resolvers}
fig, ax = plt.subplots(figsize=(6, 4))
bars = ax.bar(list(avail), [avail[r] for r in avail],
              color=[color(r, i) for i, r in enumerate(avail)])
for b, r in zip(bars, avail):
    ax.text(b.get_x() + b.get_width() / 2, b.get_height() + 0.5, f"{avail[r]:.1f}%",
            ha="center", fontsize=9)
ax.set_ylim(0, 105)
ax.set_ylabel("Availability (%)")
ax.set_xlabel("Resolver")
ax.set_title("Figure 2. Mean resolver availability (responded / total queries)")
save(fig, "02_availability.png")

# 3. Query success rate -------------------------------------------------------
fig, ax = plt.subplots(figsize=(6, 4))
succ = {}
for r in resolvers:
    row = c.execute("SELECT sum(rcode='NOERROR') ok, count(*) n FROM query_results "
                    "WHERE resolver=?", (r,)).fetchone()
    succ[r] = 100.0 * row["ok"] / row["n"] if row["n"] else 0
bars = ax.bar(list(succ), [succ[r] for r in succ],
              color=[color(r, i) for i, r in enumerate(succ)])
for b, r in zip(bars, succ):
    ax.text(b.get_x() + b.get_width() / 2, b.get_height() + 0.5, f"{succ[r]:.1f}%",
            ha="center", fontsize=9)
ax.set_ylim(0, 105)
ax.set_ylabel("Query success rate (% NOERROR)")
ax.set_xlabel("Resolver")
ax.set_title("Figure 3. Query success rate per resolver")
save(fig, "03_success_rate.png")

# 4. Correctness --------------------------------------------------------------
corr = {r: c.execute("SELECT avg(correctness_rate) a FROM health_metrics "
                     "WHERE resolver=? AND correctness_rate IS NOT NULL",
                     (r,)).fetchone()["a"] for r in resolvers}
fig, ax = plt.subplots(figsize=(6, 4))
bars = ax.bar(list(corr), [(corr[r] or 0) * 100 for r in corr],
              color=[color(r, i) for i, r in enumerate(corr)])
for b, r in zip(bars, corr):
    ax.text(b.get_x() + b.get_width() / 2, b.get_height() + 0.5,
            f"{(corr[r] or 0)*100:.1f}%", ha="center", fontsize=9)
ax.set_ylim(0, 105)
ax.set_ylabel("Correctness (%) — verified vs authoritative")
ax.set_xlabel("Resolver")
ax.set_title("Figure 4. DNS response correctness per resolver (after verification)")
save(fig, "04_correctness.png")

# 5. TTL / freshness ----------------------------------------------------------
ratios = [x["ttl_ratio"] for x in c.execute(
    "SELECT ttl_ratio FROM comparisons WHERE ttl_ratio IS NOT NULL")]
fig, ax = plt.subplots(figsize=(6, 4))
if ratios:
    ax.hist(ratios, bins=20, color="#3a7", edgecolor="white")
ax.axvline(1.0, color="crimson", linestyle="--", label="authoritative TTL (ratio = 1.0)")
ax.set_xlabel("Observed TTL / Authoritative TTL")
ax.set_ylabel("Number of responses")
ax.set_title("Figure 5. Cache freshness: cached TTL relative to authoritative TTL")
ax.legend()
save(fig, "05_ttl_freshness.png"); print(f"    (points={len(ratios)})")

# 6. Anomalies per sweep ------------------------------------------------------
# Cluster query timestamps into sweeps (gap > 5s => new sweep).
times = sorted(x["observed_at"] for x in c.execute("SELECT observed_at FROM query_results"))
bounds = []
if times:
    start = times[0]
    for a, b in zip(times, times[1:]):
        if b - a > 5:
            bounds.append((start, a)); start = b
    bounds.append((start, times[-1] + 0.001))
anoms = [x["observed_at"] for x in c.execute("SELECT observed_at FROM anomalies")]
counts = [sum(1 for t in anoms if lo <= t <= hi) for lo, hi in bounds]
fig, ax = plt.subplots(figsize=(7, 4))
ax.bar(range(1, len(counts) + 1), counts, color="#c0392b")
ax.set_xlabel("Sweep number")
ax.set_ylabel("Number of DNS anomalies (verified)")
ax.set_title("Figure 6. Verified DNS integrity anomalies per monitoring sweep")
ax.set_xticks(range(1, len(counts) + 1))
if counts:
    ax.set_ylim(0, max(3, max(counts) + 1))
save(fig, "06_anomalies_per_sweep.png"); print(f"    (sweeps={len(counts)}, total_anomalies={sum(counts)})")

# 7. Resolver health over time (availability + correctness) -------------------
fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(7, 6), sharex=True)
for i, r in enumerate(resolvers):
    rows = c.execute("SELECT computed_at, availability_pct, correctness_rate FROM health_metrics "
                     "WHERE resolver=? ORDER BY computed_at", (r,)).fetchall()
    xs = [(x["computed_at"] - t0) / 60 for x in rows]
    ax1.plot(xs, [x["availability_pct"] for x in rows], marker="o", color=color(r, i), label=r)
    ax2.plot(xs, [(x["correctness_rate"] or 0) * 100 for x in rows], marker="s", color=color(r, i), label=r)
ax1.set_ylabel("Availability (%)"); ax1.set_ylim(0, 105); ax1.legend(title="Resolver", fontsize=8)
ax2.set_ylabel("Correctness (%)"); ax2.set_ylim(0, 105)
ax2.set_xlabel("Time (minutes from start of experiment)")
ax1.set_title("Figure 7. Resolver health over time (availability and correctness)")
save(fig, "07_health_over_time.png")

# 8. Resolver comparison ------------------------------------------------------
metrics = {}
for r in resolvers:
    row = c.execute("SELECT avg(availability_pct) av, avg(correctness_rate) co, "
                    "avg(freshness_ok_rate) fr, avg(avg_latency_ms) lat "
                    "FROM health_metrics WHERE resolver=?", (r,)).fetchone()
    metrics[r] = row
import numpy as np
labels = ["Availability", "Correctness", "Freshness"]
x = np.arange(len(resolvers)); w = 0.25
fig, ax = plt.subplots(figsize=(7, 4.5))
ax.bar(x - w, [metrics[r]["av"] for r in resolvers], w, label="Availability %", color="#4285F4")
ax.bar(x, [(metrics[r]["co"] or 0) * 100 for r in resolvers], w, label="Correctness %", color="#34A853")
ax.bar(x + w, [(metrics[r]["fr"] or 0) * 100 for r in resolvers], w, label="Freshness OK %", color="#FBBC05")
ax.set_xticks(x); ax.set_xticklabels(resolvers)
ax.set_ylim(0, 115); ax.set_ylabel("Percentage (%)"); ax.set_xlabel("Resolver")
lat = ", ".join(f"{r}={metrics[r]['lat']:.0f}ms" for r in resolvers)
ax.set_title("Figure 8. Resolver comparison across health dimensions\n(mean latency: " + lat + ")")
ax.legend(fontsize=8)
save(fig, "08_resolver_comparison.png")

c.close()
print("\nAll graphs written to:", OUT)
