"""
Reproduces Table 6 (H4: network lifetime under no-attack conditions) from the paper.

IMPORTANT: this uses a DIFFERENT INIT_ENERGY (600) than Table 4/run_table4.py (4000).
At INIT_ENERGY=4000 (the main-comparison configuration), no node ever depletes within
SIM_TICKS=1000 under no-attack conditions — not even over a 50x longer horizon — because
the controller's own energy-aware routing load-balances traffic away from low-energy
nodes. That makes the lifetime metric degenerate (zero variance) at the Table 4
configuration, so H4 uses this dedicated, separately-tuned configuration instead.
Reducing INIT_ENERGY (or raising the packet rate) does induce depletion, but both also
change the attack-window routing dynamics behind Table 4 and the Section 13.2/13.3
sensitivity sweep — so this script deliberately does NOT touch those results.

Usage:
    python simulator/run_h4.py
"""
import numpy as np
from scipy import stats
import rpl_sim

SEEDS = list(range(30))
NETWORK_SIZES = [20, 50, 100]

# H4-specific configuration: same controller/threshold logic as the main comparison,
# but a smaller energy budget so depletion is actually observable, and no attack.
rpl_sim.MALICIOUS_FRACTION = 0.0
rpl_sim.INIT_ENERGY = 600
ADAPTIVE_PARAMS = dict(theta_threat=0.15, theta_energy=500.0, cooldown=30)


def mean_sem(values):
    values = np.array(values, dtype=float)
    return values.mean(), values.std(ddof=1) / np.sqrt(len(values))


if __name__ == "__main__":
    print(f"{'N':>5}{'Adaptive lifetime':>22}{'Static-MRHOF lifetime':>25}{'paired t-test p':>18}")
    for n in NETWORK_SIZES:
        adaptive = [rpl_sim.run_condition(n, s, "adaptive", **ADAPTIVE_PARAMS)["lifetime"] for s in SEEDS]
        mrhof = [rpl_sim.run_condition(n, s, "static", w_fixed=1.0)["lifetime"] for s in SEEDS]
        a_mean, a_sem = mean_sem(adaptive)
        m_mean, m_sem = mean_sem(mrhof)
        _, p = stats.ttest_rel(adaptive, mrhof)
        a_str = f"{a_mean:.1f} \u00b1 {a_sem:.1f}"
        m_str = f"{m_mean:.1f} \u00b1 {m_sem:.1f}"
        print(f"{n:>5}{a_str:>22}{m_str:>25}{p:>18.3f}")
