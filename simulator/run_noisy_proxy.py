"""
Reproduces Table 5: the adaptive controller under a noisy local failure-detection proxy.

p_fn = probability a genuine drop is misreported to the controller as a success
       (models a MAC-ACK-then-drop attacker evading a next-hop-ACK-only proxy);
p_fp = probability a genuine success is misreported as a failure (MAC-layer noise).
True packet outcomes used for PDR accounting are never affected.

Usage:   python run_noisy_proxy.py          (about 3-5 minutes)
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rpl_sim
from rpl_sim import run_condition, MAIN_ADAPTIVE
from stats_utils import mean_sem

SEEDS = list(range(30))
SIZES = [20, 50, 100]
REGIMES = [("Clean (0, 0)", 0.0, 0.0), ("Moderate (0.2, 0.05)", 0.2, 0.05), ("Severe (0.5, 0.05)", 0.5, 0.05)]

if __name__ == "__main__":
    rpl_sim.reset_defaults()
    print("TABLE 5 -- adaptive controller under a noisy local detection proxy (mean +/- SEM, 30 seeds)")
    print(f"{'Regime':<24}{'Metric':<10}{'N=20':>16}{'N=50':>16}{'N=100':>16}")
    for name, fn, fp in REGIMES:
        res = {n: [run_condition(n, s, "adaptive", proxy_fn_rate=fn, proxy_fp_rate=fp, **MAIN_ADAPTIVE) for s in SEEDS] for n in SIZES}
        for metric, key in (("PDR", "pdr_attack"), ("Overhead", "overhead_ratio")):
            cells = []
            for n in SIZES:
                m, e = mean_sem([r[key] for r in res[n]])
                cells.append(f"{m:.3f}+/-{e:.3f}")
            print(f"{name:<24}{metric:<10}{cells[0]:>16}{cells[1]:>16}{cells[2]:>16}")
    print("""
EXPECTED (paper, Table 5)
  Clean (0, 0)          PDR       0.920+/-0.004  0.884+/-0.003  0.866+/-0.003
  Clean (0, 0)          Overhead  0.428+/-0.035  0.681+/-0.027  0.830+/-0.021
  Moderate (0.2, 0.05)  PDR       0.921+/-0.004  0.890+/-0.003  0.869+/-0.003
  Moderate (0.2, 0.05)  Overhead  0.788+/-0.038  0.990+/-0.017  1.094+/-0.019
  Severe (0.5, 0.05)    PDR       0.913+/-0.004  0.867+/-0.003  0.842+/-0.004
  Severe (0.5, 0.05)    Overhead  0.656+/-0.030  0.805+/-0.019  0.880+/-0.017""")
