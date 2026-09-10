 # RPL Threat-Aware Routing: Simulator, Confirmatory Cooja Simulation, and Dataset

This repository accompanies the paper *"Threat-Aware Objective Function for
RPL: A Lightweight Dynamic-Weight Routing Controller for Energy–Security
Trade-offs in IoT Sensor Networks."* It contains:

- `simulator/` — the primary discrete-time Python simulator (`rpl_sim.py`)
  that produced all of the paper's headline results (Table 4, hypotheses
  H1–H4), plus a runner script that reproduces Table 4 exactly.
- `scripts/` and `ml/` — a confirmatory Contiki-NG/Cooja simulation (real
  full-stack RPL, not the simplified Python model) used to validate the
  attack-model assumptions (Section 14 of the paper), plus a baseline
  classifier on the resulting per-node dataset.
- `data/` — the confirmatory Cooja simulation's output.

## Primary simulator (`simulator/`)

`rpl_sim.py` models a single-sink RPL DODAG of N energy-constrained nodes
choosing routes via `Cost(cand) = w * E_norm(cand) + (1 - w) * R_norm(cand)`,
where `w` is set either by fixed baselines (Static-MRHOF, Static-Trust,
Fixed-Weight) or by the paper's adaptive threat-aware controller
(`θ_threat`, `θ_energy`, cooldown `c`, hysteresis exit band).

**Reproducing Table 4:**

```bash
cd simulator
python run_table4.py
```

This prints attack-window PDR (mean ± SEM over 30 seeds) for all four
controllers at N ∈ {20, 50, 100}, matching Table 4 exactly.

> **Note:** `RPLSim`'s constructor defaults to `theta_threat=0.25`, which
> does **not** reproduce Table 4. The paper's main results use
> `theta_threat=0.15, cooldown=30, theta_energy=500.0` — `run_table4.py`
> pins these explicitly. If you use `RPLSim`/`run_condition` directly for
> your own experiments, set these parameters yourself rather than relying
> on the class defaults.

---

## What this does

- Clones Contiki-NG and its Cooja submodule, and patches:
  - `os/net/mac/csma/csma.c` — adds a compile-time `IS_MALICIOUS` selective-forwarding
    behavior (configurable drop percentage) plus per-node send/drop counters.
  - `os/net/routing/rpl-lite/rpl-icmp6.c` — per-node DIO/DAO receive counters.
  - `os/net/routing/rpl-lite/rpl-neighbor.c` — per-node RPL parent-switch counter.
- Generates `.csc` Cooja scenarios across a sweep of network sizes, seeds, and
  attack drop intensities (baseline + attack, paired by seed).
- Runs each scenario headlessly via Gradle/Cooja and captures logs.
- Parses results into two CSVs:
  - `results/real_cooja_results.csv` — aggregate sent/received/PDR per scenario.
  - `results/per_node_dataset.csv` — per-node ground truth (packet counters, RPL
    control-plane counters, and the true `malicious` label) for every node in
    every scenario — suitable as IDS training data.

## Data

`data/` contains the actual output of a full 60-scenario run (3 network sizes ×
5 seeds × {baseline, drop=30%, drop=60%, drop=90%}), checked in so the analysis
scripts below are reproducible without re-running the full Cooja pipeline:

- `data/real_cooja_results.csv` — 60 rows, aggregate PDR per scenario.
- `data/per_node_dataset.csv` — 3,460 rows, per-node ground truth.

Regenerating them from scratch takes on the order of an hour on Kaggle (Cooja
build + 60 headless simulation runs); see Usage below.

## Requirements

- Kaggle notebook (or any environment with internet access, Java 21, and enough
  disk/CPU headroom to build Cooja and run Gradle). Developed and tested on Kaggle.
- No GPU needed — everything here is CPU/Java/bash.

## Usage (Kaggle)

1. Upload `scripts/one_shot_kaggle_rpl.sh` as a Kaggle Dataset (or `%%writefile` it
   directly into a notebook cell).
2. Run it:
   ```python
   !bash /kaggle/input/<your-dataset-slug>/one_shot_kaggle_rpl.sh
   ```
3. Edit the sweep parameters near the top of Stage 5 in the script to widen/narrow
   the experiment:
   ```bash
   NETWORK_SIZES="20 50 100"
   SEEDS="1 2 3 4 5"
   DROP_PCTS="30 60 90"
   ```

The working directory persists for the life of the Kaggle session — the script
resets any previously-patched source files via `git checkout` at the start of each
patch stage, so re-running it mid-session is safe.

## Random Forest baseline (`ml/train_rf_baseline.py`)

A baseline classifier on `per_node_dataset.csv`.

**Important caveat:** `dropped`/`drop_rate` are computed from a counter that only
increments inside the attacker's own malicious code path, so they are a
near-perfect predictor by construction (oracle leakage) — this baseline is a
pipeline sanity check, not a claim of realistic IDS performance. A real detector
should use externally-observable features instead (see `dio_rx`, `dao_rx`,
`parent_switches` in the same CSV, and Section 14 of the paper for discussion of
what was/wasn't found to discriminate malicious nodes with this attack model).

```bash
pip install -r requirements.txt
python ml/train_rf_baseline.py   # reads data/per_node_dataset.csv
```

## Realism-validation script (`scripts/compare_with_rpl_sim.py`)

Aggregates `real_cooja_results.csv` by (network size, drop_pct) and compares
against the companion `rpl_sim.py` discrete-time simulator's Static-MRHOF
attack-window PDR values, to check whether the simplified simulator's attack-model
assumptions hold up against a full-stack Cooja simulation. This is what produced
Table 5 / Fig. 5 in the paper's Section 14.

```bash
python scripts/compare_with_rpl_sim.py   # reads data/real_cooja_results.csv
```

## Known limitations

- This pipeline simulates the **attack model only** (a static selective-forwarding
  drop rate). It does **not** implement the paper's proposed adaptive
  threat-aware mode-switching controller itself — that would require rewriting
  RPL-lite's objective function (`rpl-mrhof.c`) to blend an energy-normalized and
  a threat-resilience-normalized routing cost. See the paper's Future Work
  section.
- `rpl_parent_switches` instrumentation targets a specific line in
  `rpl-neighbor.c` (`rpl_neighbor_set_preferred_parent`) confirmed against the
  Contiki-NG source at the time of writing; it may need re-verifying (via `grep`)
  against a different Contiki-NG revision.

## License

MIT (or replace with whatever license suits your submission).
