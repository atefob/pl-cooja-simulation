"""
Reproduces Tables 7 and 8 and the H3 check of Section 3.4: the COMBINED attack-and-depletion
regime (INIT_ENERGY = 1000, standard 400-tick attack window).

Usage:   python run_combined_regime.py          (about 4-6 minutes)
"""
import os, sys
import numpy as np
from scipy import stats
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rpl_sim
from rpl_sim import run_condition, MAIN_ADAPTIVE
from stats_utils import mean_sem, fmt_p

SEEDS = list(range(30))
SIZES = [20, 50, 100]

def mean_overhead(n, **kw):
    return float(np.mean([run_condition(n, s, "adaptive", **kw)["overhead_ratio"] for s in SEEDS]))

if __name__ == "__main__":
    rpl_sim.reset_defaults()
    rpl_sim.INIT_ENERGY = 1000.0

    print("TABLE 7 -- combined regime: attack-window PDR (mean +/- SEM) and adaptive overhead ratio")
    print(f"{'N':>5}{'Static-Energy':>16}{'Adaptive':>16}{'Static-Trust':>16}{'Overhead':>10}{'p (Adp vs Trust)':>18}")
    life = {}
    for n in SIZES:
        ad = [run_condition(n, s, "adaptive", **MAIN_ADAPTIVE) for s in SEEDS]
        tr = [run_condition(n, s, "static", w_fixed=0.2) for s in SEEDS]
        en = [run_condition(n, s, "static", w_fixed=1.0) for s in SEEDS]
        life[n] = ([r["lifetime"] for r in ad], [r["lifetime"] for r in en])
        cells = [mean_sem([r["pdr_attack"] for r in x]) for x in (en, ad, tr)]
        oh = np.mean([r["overhead_ratio"] for r in ad])
        p = stats.ttest_rel([r["pdr_attack"] for r in ad], [r["pdr_attack"] for r in tr]).pvalue
        print(f"{n:>5}" + "".join(f"{m:>9.3f}+/-{e:.3f}" for m, e in cells) + f"{oh:>10.3f}{fmt_p(p):>18}")

    print("\nTABLE 8 -- combined regime: network lifetime under ACTIVE attack (ticks, mean +/- SEM)")
    print(f"{'N':>5}{'Adaptive':>18}{'Static-Energy':>18}{'paired p':>11}")
    for n in SIZES:
        a, e = life[n]
        (am, ase), (em, ese) = mean_sem(a), mean_sem(e)
        print(f"{n:>5}{am:>11.1f}+/-{ase:<5.1f}{em:>11.1f}+/-{ese:<5.1f}{fmt_p(stats.ttest_rel(a, e).pvalue):>11}")

    c5 = mean_overhead(50, theta_threat=0.35, theta_energy=500.0, cooldown=5)
    c60 = mean_overhead(50, theta_threat=0.35, theta_energy=500.0, cooldown=60)
    t20 = mean_overhead(50, theta_threat=0.20, theta_energy=500.0, cooldown=30)
    t55 = mean_overhead(50, theta_threat=0.55, theta_energy=500.0, cooldown=30)
    print(f"\nH3 under this regime (N=50): theta-effect / cooldown-effect = {abs(t20 - t55) / abs(c5 - c60):.0f}x")

    print("""
EXPECTED (paper, Tables 7-8, Section 3.4)
  N=20   0.882+/-0.007  0.906+/-0.005  0.921+/-0.004  overhead 0.355
  N=50   0.779+/-0.015  0.814+/-0.016  0.792+/-0.017  overhead 0.752   (adaptive > trust, p = 0.0036)
  N=100  0.489+/-0.020  0.537+/-0.019  0.501+/-0.018  overhead 1.125   (adaptive > trust, p < 0.0001)
  Lifetime  N=20 941.6+/-20.2 vs 985.0+/-8.6 (p 0.0076);  N=50 569.9+/-21.1 vs 669.2+/-22.9 (p <0.0001);
            N=100 365.1+/-11.5 vs 397.3+/-14.8 (p <0.0001)
  H3 ratio ~ 137x""")
