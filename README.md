# RPL Threat-Aware Routing: Simulator, Confirmatory Cooja Simulation, and Dataset

This repository accompanies the paper *"Threat-Aware Objective Function for
RPL: A Lightweight Dynamic-Weight Routing Controller for Energy-Security
Trade-offs in IoT Sensor Networks."* It contains:

- `simulator/` - the primary discrete-time Python simulator (`rpl_sim.py`) and one
  script per table/result of the paper (see the table below).
- `scripts/` and `ml/` - a confirmatory Contiki-NG/Cooja simulation (real full-stack RPL,
  not the simplified Python model) used to validate the attack-model assumptions
  (Section 3.5 of the paper), plus a sanity-check classifier on the resulting per-node dataset.
- `data/` - the confirmatory Cooja simulation's output.

## Primary simulator (`simulator/`)

`rpl_sim.py` models a single-sink RPL DODAG of N energy-constrained nodes choosing routes via
`Cost(cand) = w * E_norm(cand) + (1 - w) * R_norm(cand)`. The `controller` argument of
`run_condition(n, seed, controller, **kwargs)` selects:

| `controller` | Meaning in the paper |
|---|---|
| `"adaptive"` | the proposed threat-aware controller (`theta_threat`, `theta_energy`, `cooldown`, hysteresis band) |
| `"static"`, `w_fixed=1.0` | Static-Energy (energy-only cost; *not* MRHOF) |
| `"static"`, `w_fixed=0.5` | Fixed-Weight |
| `"static"`, `w_fixed=0.2` | Static-Trust |
| `"static_mrhof_etx"` | Static-MRHOF (ETX + hysteresis), an RFC 6719-style reimplementation |

Mode switching is fully local: each node tracks its own threat indicator (from its own
candidate-link failure history) and its own residual energy, with no network-wide aggregation.
The optional arguments `proxy_fn_rate` / `proxy_fp_rate` add noise to the failure signal the
controller observes (false negatives / false positives); true packet outcomes used for PDR and
lifetime are never affected.

**Parameters.** All adaptive-controller results use
`theta_threat=0.35, theta_energy=500, cooldown=30` (`rpl_sim.MAIN_ADAPTIVE`), *not* the
constructor defaults. If you use `run_condition` for your own experiments, pass these explicitly.

### Reproducing the paper's results

```bash
pip install -r requirements.txt
cd simulator
python run_all.py          # runs everything below, saves outputs to ../results/ (about 5-10 min)
```

Each script can also be run alone; each prints its results followed by an `EXPECTED` block with
the values reported in the paper (same 30 seeds, so they match to the printed precision).

| Script | Reproduces |
|---|---|
| `run_table4.py` | Table 4 (all five conditions, overhead ratio), H1/H2 statistics (paired t-test, TOST, Cohen's d_z), comparison with Static-MRHOF (ETX+Hysteresis) |
| `run_h4.py` | Table 6 (H4, network lifetime, no attack, `INIT_ENERGY=600`) |
| `run_noisy_proxy.py` | Table 5 (noisy local detection proxy) |
| `run_sensitivity_sweep.py` | Section 3.2-3.3 sensitivity sweep (theta_threat x cooldown grid, N=50; Figs. 3-4) |
| `run_combined_regime.py` | Tables 7 and 8 and the H3 check (combined attack-and-depletion regime, `INIT_ENERGY=1000`) |
| `run_stress_test.py` | Section 3.6 stress test (sustained attack, share of node-ticks "trapped" in RESILIENT mode below `theta_energy`) |
| `run_attacker_sensitivity.py` | Section 3.2 robustness of the theta_threat-vs-cooldown finding to attacker strength and compromised fraction |

Notes:
- Experiments change a few module-level constants (e.g. `INIT_ENERGY`); every script calls
  `rpl_sim.reset_defaults()` first, so they do not interfere with each other.
- `run_h4.py` uses `INIT_ENERGY=600` because at the main-comparison value (4000) no node
  depletes in the no-attack horizon and the lifetime metric is degenerate (Section 3.4).

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
`parent_switches` in the same CSV, and Section 3.5 of the paper for discussion of
what was/wasn't found to discriminate malicious nodes with this attack model).

```bash
pip install -r requirements.txt
python ml/train_rf_baseline.py   # reads data/per_node_dataset.csv
```

## Realism-validation script (`scripts/compare_with_rpl_sim.py`)

Aggregates `real_cooja_results.csv` by (network size, drop_pct) and compares
against the companion `rpl_sim.py` discrete-time simulator's Static-Energy
attack-window PDR values, to check whether the simplified simulator's attack-model
assumptions hold up against a full-stack Cooja simulation. This is what produced
Table 9 / Fig. 5 in the paper's Section 3.5.

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

MIT License (see `LICENSE`).
