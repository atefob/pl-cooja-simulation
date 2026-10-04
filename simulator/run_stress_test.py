"""
Reproduces the Section 3.6 stress test of the missing RESILIENT->ENERGY energy-triggered exit:
INIT_ENERGY = 1000 (twice theta_energy = 500) with a sustained attack covering all 1000 ticks.
Reports the share of node-ticks in which a node is simultaneously in RESILIENT mode AND below
theta_energy ("trapped"), and how many seeds reach battery depletion.

Usage:   python run_stress_test.py          (about 2-3 minutes)
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rpl_sim
from rpl_sim import run_condition, MAIN_ADAPTIVE
from stats_utils import mean_sem

SEEDS = list(range(30))
SIZES = [20, 50, 100]

if __name__ == "__main__":
    rpl_sim.reset_defaults()
    rpl_sim.INIT_ENERGY = 1000.0
    rpl_sim.ATTACK_START = 0
    rpl_sim.ATTACK_DURATION = rpl_sim.SIM_TICKS

    print("SECTION 3.6 stress test (adaptive controller)")
    print(f"{'N':>5}{'trapped node-ticks':>22}{'share of all node-ticks':>26}{'lifetime':>18}{'seeds depleted':>16}")
    for n in SIZES:
        res = [run_condition(n, s, "adaptive", **MAIN_ADAPTIVE) for s in SEEDS]
        tm, te = mean_sem([r["trapped_node_ticks"] for r in res])
        lm, le = mean_sem([r["lifetime"] for r in res])
        dep = sum(1 for r in res if r["lifetime"] < rpl_sim.SIM_TICKS)
        print(f"{n:>5}{tm:>14.1f}+/-{te:<5.1f}{100 * tm / (n * rpl_sim.SIM_TICKS):>25.1f}%{lm:>11.1f}+/-{le:<5.1f}{dep:>10}/30")
    print("""
EXPECTED (paper, Section 3.6)
  N=20   share 1.6%   seeds depleted 11/30
  N=50   share 6.9%   seeds depleted 30/30
  N=100  share 14.8%  seeds depleted 30/30""")
