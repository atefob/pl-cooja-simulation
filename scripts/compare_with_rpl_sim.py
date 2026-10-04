"""
Compares the confirmatory Cooja simulation results (data/real_cooja_results.csv) with the
attack-window PDR of the Static-Energy baseline of the companion rpl_sim.py simulator
(Table 4 of the paper). This produces Table 9 / Fig. 5 of Section 3.5.

Note: the Cooja runs use the real, unmodified RPL-lite/MRHOF (ETX-based); rpl_sim.py's
Static-Energy is a pure energy-cost baseline, so only the qualitative network-size trend is
comparable, not the absolute PDR values.

Usage (from the repository root):   python scripts/compare_with_rpl_sim.py
"""
import pandas as pd

# rpl_sim.py Static-Energy attack-window PDR (Table 4) -- hard-coded because it comes from the
# companion Python simulator (simulator/run_table4.py), not from this folder's data.
RPL_SIM_STATIC_ENERGY = {
    20: (0.882, 0.007),
    50: (0.806, 0.006),
    100: (0.769, 0.007),
}

df = pd.read_csv("data/real_cooja_results.csv")

# Extract network size (N) from the scenario name, e.g. "attack_n50_s5_d90" -> 50
df["n"] = df["scenario"].str.extract(r"_n(\d+)_").astype(int)

print("=== Cooja confirmatory simulation: PDR by network size and drop_pct ===\n")
for n in sorted(df["n"].unique()):
    baseline = df[(df["n"] == n) & (df["kind"] == "baseline")]["pdr"]
    print(f"N={n:3d}  baseline: mean={baseline.mean():.4f}  std={baseline.std():.4f}  (n={len(baseline)})")
    for drop in sorted(df[df["kind"] == "attack"]["drop_pct"].unique()):
        attack = df[(df["n"] == n) & (df["kind"] == "attack") & (df["drop_pct"] == drop)]["pdr"]
        if len(attack):
            print(f"       attack d={drop}: mean={attack.mean():.4f}  std={attack.std():.4f}  (n={len(attack)})")
    print()

print("=== rpl_sim.py Static-Energy (attack-window PDR), for comparison ===")
for n, (mean, sem) in RPL_SIM_STATIC_ENERGY.items():
    print(f"N={n:3d} : {mean:.3f} \u00b1 {sem:.3f}")
