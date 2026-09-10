"""
Reproduces Table 4 (main comparison, H1/H2) from the paper.

IMPORTANT: RPLSim's class defaults (theta_threat=0.25) do NOT reproduce
Table 4. The main results use theta_threat=0.15, cooldown=30, and the
default theta_energy=500.0 — this script pins those values explicitly so
the paper's headline numbers are reproducible without guessing.

Usage:
    python simulator/run_table4.py
"""
import numpy as np
from rpl_sim import run_condition

SEEDS = list(range(30))          # 30 seeds per condition, as in the paper
NETWORK_SIZES = [20, 50, 100]

# Parameters used for the adaptive controller in Table 4 (NOT the class defaults).
ADAPTIVE_PARAMS = dict(theta_threat=0.15, theta_energy=500.0, cooldown=30)

# Static baselines: fixed routing-cost weight w, no mode-switching.
STATIC_BASELINES = {
    "Static-MRHOF": dict(controller="static", w_fixed=1.0),
    "Fixed-Weight": dict(controller="static", w_fixed=0.5),
    "Static-Trust": dict(controller="static", w_fixed=0.2),
}


def mean_sem(values):
    values = np.array(values)
    return values.mean(), values.std(ddof=1) / np.sqrt(len(values))


def run_all():
    rows = []

    for n in NETWORK_SIZES:
        results = [run_condition(n, s, "adaptive", **ADAPTIVE_PARAMS) for s in SEEDS]
        pdr_mean, pdr_sem = mean_sem([r["pdr_attack"] for r in results])
        oh_mean, oh_sem = mean_sem([r["overhead_ratio"] for r in results])
        rows.append(("Proposed (Adaptive)", n, pdr_mean, pdr_sem, oh_mean, oh_sem))

    for name, kwargs in STATIC_BASELINES.items():
        for n in NETWORK_SIZES:
            results = [run_condition(n, s, **kwargs) for s in SEEDS]
            pdr_mean, pdr_sem = mean_sem([r["pdr_attack"] for r in results])
            rows.append((name, n, pdr_mean, pdr_sem, None, None))

    return rows


if __name__ == "__main__":
    print(f"{'Controller':<22}{'N':>5}{'PDR (attack)':>18}{'Overhead (N=100)':>20}")
    for name, n, pdr_mean, pdr_sem, oh_mean, oh_sem in run_all():
        pdr_str = f"{pdr_mean:.3f} \u00b1 {pdr_sem:.3f}"
        oh_str = f"{oh_mean:.3f} \u00b1 {oh_sem:.3f}" if oh_mean is not None else "\u2014"
        print(f"{name:<22}{n:>5}{pdr_str:>18}{oh_str:>20}")
