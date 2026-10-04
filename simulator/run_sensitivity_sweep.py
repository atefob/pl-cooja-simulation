"""
Reproduces the theta_threat x cooldown sensitivity sweep of Section 3.3 (Figs. 3-4) and the
Section 3.2 numbers: 5 theta_threat values x 4 cooldown values, N = 50, 30 seeds per configuration.
Prints mean overhead ratio and mean attack-window PDR for every configuration.

Usage:   python run_sensitivity_sweep.py          (about 2-3 minutes)
"""
import os, sys
import numpy as np
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rpl_sim
from rpl_sim import run_condition

SEEDS = list(range(30))
N = 50
THETAS = [0.20, 0.28, 0.35, 0.45, 0.55]
COOLDOWNS = [5, 15, 30, 60]

if __name__ == "__main__":
    rpl_sim.reset_defaults()
    oh, pdr = {}, {}
    for th in THETAS:
        for c in COOLDOWNS:
            res = [run_condition(N, s, "adaptive", theta_threat=th, theta_energy=500.0, cooldown=c) for s in SEEDS]
            oh[(th, c)] = float(np.mean([r["overhead_ratio"] for r in res]))
            pdr[(th, c)] = float(np.mean([r["pdr_attack"] for r in res]))

    for title, grid in (("Mean overhead ratio", oh), ("Mean attack-window PDR", pdr)):
        print(f"\n{title} (rows: theta_threat, columns: cooldown)")
        print(f"{'':>8}" + "".join(f"{'c=' + str(c):>9}" for c in COOLDOWNS))
        for th in THETAS:
            print(f"{th:>8.2f}" + "".join(f"{grid[(th, c)]:>9.3f}" for c in COOLDOWNS))

    print(f"\nSection 3.2: cooldown alone (theta=0.35): overhead {oh[(0.35, 5)]:.3f} (c=5) -> {oh[(0.35, 60)]:.3f} (c=60)")
    print(f"             theta alone (cooldown=30):   overhead {oh[(0.20, 30)]:.3f} (theta=0.20) -> {oh[(0.55, 30)]:.3f} (theta=0.55)")
    print("""
EXPECTED (paper, Section 3.2): cooldown alone 0.688 (c=5) -> 0.680 (c=60);
theta alone 1.358 (theta=0.20) -> 0.276 (theta=0.55).""")
