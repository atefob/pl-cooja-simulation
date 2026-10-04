"""
Reproduces Table 6 (H4: network lifetime, NO attack) of the paper.

Uses a dedicated configuration: INIT_ENERGY = 600 and MALICIOUS_FRACTION = 0.
At the main-comparison INIT_ENERGY (4000) no node depletes within SIM_TICKS, so the
lifetime metric is degenerate there (see Section 3.4 of the paper).

Usage:   python run_h4.py          (about 1 minute)
"""
import os, sys
import numpy as np
from scipy import stats
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rpl_sim
from rpl_sim import MAIN_ADAPTIVE
from stats_utils import mean_sem, cohens_dz, tost_paired, fmt_p

SEEDS = list(range(30))
SIZES = [20, 50, 100]
TOST_MARGIN_FRAC = 0.05     # +/-5% of the Static-Energy mean lifetime

if __name__ == "__main__":
    rpl_sim.reset_defaults()
    rpl_sim.MALICIOUS_FRACTION = 0.0
    rpl_sim.INIT_ENERGY = 600.0

    print("TABLE 6 -- network lifetime (ticks, mean +/- SEM, 30 seeds), no attack, INIT_ENERGY=600")
    print(f"{'N':>5}{'Adaptive':>18}{'Static-Energy':>18}{'paired p':>11}{'TOST p':>10}{'Cohen dz':>10}")
    for n in SIZES:
        a = np.array([rpl_sim.run_condition(n, s, "adaptive", **MAIN_ADAPTIVE)["lifetime"] for s in SEEDS], dtype=float)
        e = np.array([rpl_sim.run_condition(n, s, "static", w_fixed=1.0)["lifetime"] for s in SEEDS], dtype=float)
        am, ase = mean_sem(a); em, ese = mean_sem(e)
        p = stats.ttest_rel(a, e).pvalue
        pt = tost_paired(a, e, TOST_MARGIN_FRAC * e.mean())
        print(f"{n:>5}{am:>11.1f}+/-{ase:<5.1f}{em:>11.1f}+/-{ese:<5.1f}{p:>11.4f}{fmt_p(pt):>10}{cohens_dz(a, e):>10.2f}")

    print("""
EXPECTED (paper, Table 6 and Section 3.4)
   20   712.0+/-23.6   715.7+/-23.6   0.0181   <0.0001   -0.46
   50   379.1+/-13.4   379.3+/-13.5   0.7652   <0.0001   -0.06
  100   220.2+/-8.1    219.2+/-8.1    0.1559   <0.0001   +0.27""")
