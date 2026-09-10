"""
Compares confirmatory Cooja simulation results (data/real_cooja_results.csv)
against the companion rpl_sim.py discrete-time simulator's Static-MRHOF
attack-window PDR values (Table 4 of the paper), to check whether the
simplified simulator's attack-model assumptions hold up against a full-stack
Contiki-NG/Cooja simulation. This produced Table 5 / Fig. 5 (Section 14).
"""
import pandas as pd

# rpl_sim.py's Static-MRHOF attack-window PDR (Table 4 of the paper) — hardcoded
# here since it comes from the companion Python simulator, not this repo's data.
RPL_SIM_STATIC_MRHOF = {
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

print("=== rpl_sim.py Static-MRHOF (attack-window PDR), for comparison ===")
for n, (mean, sem) in RPL_SIM_STATIC_MRHOF.items():
    print(f"N={n:3d} : {mean:.3f} \u00b1 {sem:.3f}")
