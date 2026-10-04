"""
Reproduces Table 4 (main comparison) and the H1/H2 statistics of the paper.

All adaptive-controller results in the paper use
    theta_threat = 0.35, theta_energy = 500, cooldown = 30
(rpl_sim.MAIN_ADAPTIVE) -- NOT the RPLSim constructor defaults.

Usage:   python run_table4.py          (about 1-2 minutes)
"""
import os, sys
import numpy as np
from scipy import stats
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rpl_sim
from rpl_sim import run_condition, MAIN_ADAPTIVE
from stats_utils import mean_sem, cohens_dz, tost_paired, fmt_p

SEEDS = list(range(30))
SIZES = [20, 50, 100]
TOST_MARGIN = 0.03          # +/-3 percentage points of attack-window PDR (H1)

rpl_sim.reset_defaults()

CONDITIONS = {
    "Static-Energy":            dict(controller="static", w_fixed=1.0),
    "Static-MRHOF (ETX+Hyst.)": dict(controller="static_mrhof_etx"),
    "Fixed-Weight":             dict(controller="static", w_fixed=0.5),
    "Static-Trust":             dict(controller="static", w_fixed=0.2),
}

if __name__ == "__main__":
    data = {}
    for n in SIZES:
        data[("Proposed (Adaptive)", n)] = [run_condition(n, s, "adaptive", **MAIN_ADAPTIVE) for s in SEEDS]
        for name, kw in CONDITIONS.items():
            data[(name, n)] = [run_condition(n, s, **kw) for s in SEEDS]

    print("TABLE 4 -- attack-window PDR (mean +/- SEM, 30 seeds); overhead ratio for the adaptive controller")
    print(f"{'Controller':<28}{'N=20 PDR':>16}{'N=50 PDR':>16}{'N=100 PDR':>16}")
    order = ["Static-Energy", "Static-MRHOF (ETX+Hyst.)", "Fixed-Weight", "Proposed (Adaptive)", "Static-Trust"]
    for name in order:
        cells = []
        for n in SIZES:
            m, e = mean_sem([r["pdr_attack"] for r in data[(name, n)]])
            cells.append(f"{m:.3f}+/-{e:.3f}")
        print(f"{name:<28}{cells[0]:>16}{cells[1]:>16}{cells[2]:>16}")
    cells = []
    for n in SIZES:
        m, e = mean_sem([r["overhead_ratio"] for r in data[("Proposed (Adaptive)", n)]])
        cells.append(f"{m:.3f}+/-{e:.3f}")
    print(f"{'Adaptive overhead ratio':<28}{cells[0]:>16}{cells[1]:>16}{cells[2]:>16}")

    print("\nH1 (adaptive vs Static-Trust, attack-window PDR) and H2 (overhead ratio vs 1.0)")
    print(f"{'N':>5}{'paired p':>11}{'TOST p':>11}{'Cohen dz':>10}{'H2 p':>11}{'adaptive vs MRHOF-ETX p':>26}")
    for n in SIZES:
        a = np.array([r["pdr_attack"] for r in data[("Proposed (Adaptive)", n)]])
        t = np.array([r["pdr_attack"] for r in data[("Static-Trust", n)]])
        mr = np.array([r["pdr_attack"] for r in data[("Static-MRHOF (ETX+Hyst.)", n)]])
        oh = [r["overhead_ratio"] for r in data[("Proposed (Adaptive)", n)]]
        p_h1 = stats.ttest_rel(a, t).pvalue
        p_h2 = stats.ttest_1samp(oh, 1.0).pvalue
        p_mr = stats.ttest_rel(a, mr).pvalue
        print(f"{n:>5}{fmt_p(p_h1):>11}{fmt_p(tost_paired(a, t, TOST_MARGIN)):>11}"
              f"{cohens_dz(a, t):>10.2f}{fmt_p(p_h2):>11}{fmt_p(p_mr):>26}")

    print("""
EXPECTED (paper, Table 4 and Section 3.1)
  Static-Energy            0.882+/-0.007  0.806+/-0.006  0.769+/-0.007
  Static-MRHOF (ETX+Hyst.) 0.928+/-0.003  0.908+/-0.001  0.898+/-0.001
  Fixed-Weight             0.922+/-0.003  0.898+/-0.002  0.883+/-0.002
  Proposed (Adaptive)      0.920+/-0.004  0.884+/-0.003  0.866+/-0.003
  Static-Trust             0.922+/-0.003  0.901+/-0.002  0.888+/-0.002
  Adaptive overhead ratio  0.428+/-0.035  0.681+/-0.027  0.830+/-0.021
  H1: paired p 0.063 / <0.0001 / <0.0001;  TOST p <0.0001 / <0.0001 / 0.0004;  dz -0.35 / -1.41 / -1.99
  H2: p < 0.001 at every N;  adaptive vs MRHOF-ETX: p < 0.0001 at every N""")
