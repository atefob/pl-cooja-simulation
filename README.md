# RPL Selective-Forwarding: Contiki-NG/Cooja Confirmatory Simulation

Real Contiki-NG/Cooja simulation of an RPL selective-forwarding attack, built to
generate per-node ground-truth data and to validate the attack-model assumptions
used in a companion discrete-time Python simulator (`rpl_sim.py`) for a
threat-aware adaptive RPL routing controller.

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
