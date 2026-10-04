"""
Reproduces the Section 3.2 robustness check of the H3 finding (theta_threat dominates cooldown)
at four additional attacker configurations (N = 50): weaker/stronger malicious drop probability
and lower/higher compromised-node fraction. For each configuration it prints
    ratio = (overhead range when varying theta_threat alone, cooldown fixed at 30)
          / (overhead range when varying cooldown alone, theta_threat fixed at 0.35).

Usage:   python run_attacker_sensitivity.py          (about 5-8 minutes)
"""
import os, sys
import numpy as np
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rpl_sim
from rpl_sim import run_condition

SEEDS = list(range(30))
N = 50
CONFIGS = [("Baseline (drop 0.55, frac 0.18)", 0.55, 0.18),
           ("Weak attacker (drop 0.35)",       0.35, 0.18),
           ("Strong attacker (drop 0.75)",     0.75, 0.18),
           ("Low compromised frac (0.10)",     0.55, 0.10),
           ("High compromised frac (0.30)",    0.55, 0.30)]

def mean_overhead(**kw):
    return float(np.mean([run_condition(N, s, "adaptive", **kw)["overhead_ratio"] for s in SEEDS]))

if __name__ == "__main__":
    print(f"{'Configuration':<34}{'cooldown range':>16}{'theta range':>14}{'ratio':>9}")
    for label, drop, frac in CONFIGS:
        rpl_sim.reset_defaults()
        rpl_sim.ATTACK_DROP_PROB = drop
        rpl_sim.MALICIOUS_FRACTION = frac
        c5 = mean_overhead(theta_threat=0.35, theta_energy=500.0, cooldown=5)
        c60 = mean_overhead(theta_threat=0.35, theta_energy=500.0, cooldown=60)
        t20 = mean_overhead(theta_threat=0.20, theta_energy=500.0, cooldown=30)
        t55 = mean_overhead(theta_threat=0.55, theta_energy=500.0, cooldown=30)
        cr, tr = abs(c5 - c60), abs(t20 - t55)
        print(f"{label:<34}{cr:>16.4f}{tr:>14.4f}{tr / cr:>8.0f}x")
    print("""
EXPECTED (paper, Section 3.2): ratio ~133x at the baseline, and between ~199x and ~1219x at the four
additional configurations (about 1219x, 373x, 199x, 410x in the order listed above).""")
