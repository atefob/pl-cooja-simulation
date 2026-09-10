"""
COMBINED VERIFICATION SCRIPT — merges rpl_sim.py + run_table4.py + run_h4.py
into a single file so you can run it directly and check it reproduces the
paper's Table 4 and Table 6 numbers exactly.

Usage:
    pip install numpy scipy statsmodels
    python combined_verify.py

Expected output: two tables. Compare them against Table 4 and Table 6 in
the paper — they should match to 3 decimal places (same 30 seeds, same
parameters).
"""

import numpy as np
from scipy import stats
from statsmodels.stats.weightstats import ttost_paired

# ============================================================================
# PART 1: rpl_sim.py — the simulator itself
# ============================================================================

ENERGY, RESILIENT = "ENERGY", "RESILIENT"

BASE_LINK_RELIABILITY = 0.985      # non-malicious hop success prob
ATTACK_DROP_PROB = 0.55            # malicious node drop prob for forwarded pkts
TX_ENERGY = 1.0                    # energy units per forwarded packet
RESILIENT_ENERGY_MULT = 1.12       # extra control/monitoring overhead in RESILIENT mode
INIT_ENERGY = 4000.0               # starting battery per node (energy units)
PKT_GEN_PROB = 0.35                # prob a node generates a packet each tick
K_CANDIDATES = 3                   # candidate parents per node
EWMA_ALPHA = 0.3                   # threat-indicator smoothing
CONTROL_INTERVAL = 5               # ticks between controller decisions / re-routing
ATTACK_START = 200
ATTACK_DURATION = 400              # ticks
SIM_TICKS = 1000
MALICIOUS_FRACTION = 0.18          # fraction of internal (non-leaf) nodes
HYSTERESIS_BETA = 0.5              # exit threshold = BETA * theta_threat


def build_tree(n, rng):
    """Random recursive tree rooted at 0 (sink). Returns parent_candidates[i] = list of
    valid upstream candidate node ids (including the structural parent)."""
    levels = {0: 0}
    parent_struct = {0: None}
    order = list(range(1, n + 1))
    for i in order:
        existing = list(levels.keys())
        weights = np.array([1.0 / (1 + levels[j]) for j in existing])
        weights /= weights.sum()
        par = rng.choice(existing, p=weights)
        parent_struct[i] = par
        levels[i] = levels[par] + 1

    candidates = {0: []}
    for i in order:
        pool = [j for j in levels if levels[j] < levels[i] and j != i]
        others = [j for j in pool if j != parent_struct[i]]
        rng.shuffle(others)
        cand = [parent_struct[i]] + others[: K_CANDIDATES - 1]
        candidates[i] = list(dict.fromkeys(cand))
    return candidates, levels, parent_struct


def choose_malicious(candidates, levels, n, rng):
    forwarders = set()
    for i, cands in candidates.items():
        forwarders.update(cands)
    forwarders.discard(None)
    forwarders = sorted(forwarders)
    k = max(1, int(len(forwarders) * MALICIOUS_FRACTION))
    return set(rng.choice(forwarders, size=k, replace=False).tolist())


class RPLSim:
    def __init__(self, n, seed, controller, theta_threat=0.25, theta_energy=500.0,
                 cooldown=30, w_low=0.2, w_high=0.95, w_fixed=None):
        self.n = n
        self.rng = np.random.default_rng(seed)
        self.candidates, self.levels, self.parent_struct = build_tree(n, self.rng)
        self.malicious = choose_malicious(self.candidates, self.levels, n, self.rng)
        self.energy = {i: INIT_ENERGY for i in range(n + 1)}
        self.link_ewma_fail = {}
        for i, cands in self.candidates.items():
            for c in cands:
                self.link_ewma_fail[(i, c)] = 0.0
        self.current_parent = {i: self.candidates[i][0] for i in range(1, n + 1) if self.candidates[i]}
        self.controller = controller
        self.theta_threat = theta_threat
        self.theta_energy = theta_energy
        self.cooldown = cooldown
        self.w_low, self.w_high = w_low, w_high
        self.w_fixed = w_fixed

        self.mode = {i: ENERGY for i in range(1, n + 1)}
        self.t_last_switch = {i: -10_000 for i in range(1, n + 1)}
        self.threat_local = {i: 0.0 for i in range(1, n + 1)}
        self.resilient_ticks = {i: 0 for i in range(1, n + 1)}
        self.switch_count = {i: 0 for i in range(1, n + 1)}

        self.sent = 0
        self.delivered = 0
        self.sent_attack_window = 0
        self.delivered_attack_window = 0
        self.depletion_time = None

    def current_w(self, i):
        if self.controller == "static":
            return self.w_fixed
        return self.w_low if self.mode[i] == RESILIENT else self.w_high

    def in_attack(self, t):
        return ATTACK_START <= t < ATTACK_START + ATTACK_DURATION

    def path_to_sink(self, node):
        path = []
        cur = node
        hops = 0
        while cur != 0 and cur is not None and hops < self.n + 2:
            path.append(cur)
            cur = self.current_parent.get(cur, 0)
            hops += 1
        return path

    def step_traffic(self, t):
        attacking = self.in_attack(t)
        for i in range(1, self.n + 1):
            if self.rng.random() > PKT_GEN_PROB:
                continue
            self.sent += 1
            if attacking:
                self.sent_attack_window += 1
            path = self.path_to_sink(i)
            success = True
            for node in path:
                if self.energy[node] <= 0:
                    success = False
                    break
                node_mode = self.mode.get(node, ENERGY) if node != 0 else ENERGY
                mult = RESILIENT_ENERGY_MULT if node_mode == RESILIENT and self.controller == "adaptive" else 1.0
                self.energy[node] -= TX_ENERGY * mult
                if self.energy[node] <= 0 and self.depletion_time is None:
                    self.depletion_time = t
                p_fail = 1 - BASE_LINK_RELIABILITY
                if attacking and node in self.malicious:
                    p_fail = ATTACK_DROP_PROB
                if self.rng.random() < p_fail:
                    success = False
                    break
            if success:
                self.delivered += 1
                if attacking:
                    self.delivered_attack_window += 1

            if path:
                child, cand_parent = i, self.current_parent[i]
                key = (child, cand_parent)
                obs_fail = 0.0 if success else 1.0
                prev = self.link_ewma_fail.get(key, 0.0)
                self.link_ewma_fail[key] = EWMA_ALPHA * obs_fail + (1 - EWMA_ALPHA) * prev

    def recompute_routes(self):
        for i, cands in self.candidates.items():
            if not cands:
                continue
            w = self.current_w(i)
            best, best_cost = None, None
            for c in cands:
                e_norm = 1 - (self.energy[c] / INIT_ENERGY)
                r_norm = self.link_ewma_fail.get((i, c), 0.0)
                cost = w * e_norm + (1 - w) * r_norm
                if best_cost is None or cost < best_cost:
                    best, best_cost = c, cost
            self.current_parent[i] = best

    def update_controller(self, t):
        for i, cands in self.candidates.items():
            if i == 0 or not cands:
                continue
            vals = [self.link_ewma_fail.get((i, c), 0.0) for c in cands]
            self.threat_local[i] = float(np.mean(vals)) if vals else 0.0

        if self.controller != "adaptive":
            return

        exit_threshold = HYSTERESIS_BETA * self.theta_threat
        for i in range(1, self.n + 1):
            if (t - self.t_last_switch[i]) < self.cooldown:
                continue
            t_i = self.threat_local[i]
            e_i = self.energy[i]
            if self.mode[i] == ENERGY and t_i >= self.theta_threat and e_i >= self.theta_energy:
                self.mode[i] = RESILIENT
                self.t_last_switch[i] = t
                self.switch_count[i] += 1
            elif self.mode[i] == RESILIENT and t_i < exit_threshold:
                self.mode[i] = ENERGY
                self.t_last_switch[i] = t
                self.switch_count[i] += 1

    def run(self, ticks=SIM_TICKS):
        for t in range(ticks):
            self.step_traffic(t)
            if self.controller == "adaptive":
                for i in range(1, self.n + 1):
                    if self.mode[i] == RESILIENT:
                        self.resilient_ticks[i] += 1
            if t % CONTROL_INTERVAL == 0:
                self.update_controller(t)
                self.recompute_routes()
        return self.results()

    def results(self):
        pdr = self.delivered / self.sent if self.sent else float("nan")
        pdr_attack = (self.delivered_attack_window / self.sent_attack_window
                      if self.sent_attack_window else float("nan"))
        if self.controller == "adaptive":
            overhead_ratio = float(np.mean([self.resilient_ticks[i] for i in range(1, self.n + 1)])) / ATTACK_DURATION
            total_switches = int(sum(self.switch_count[i] for i in range(1, self.n + 1)))
        else:
            overhead_ratio = float("nan")
            total_switches = 0
        energy_remaining_frac = float(np.mean(list(self.energy.values()))) / INIT_ENERGY
        lifetime = self.depletion_time if self.depletion_time is not None else SIM_TICKS
        return dict(
            pdr=pdr, pdr_attack=pdr_attack, overhead_ratio=overhead_ratio,
            energy_remaining_frac=energy_remaining_frac, lifetime=lifetime,
            switch_count=total_switches,
        )


def run_condition(n, seed, controller, **kwargs):
    sim = RPLSim(n, seed, controller, **kwargs)
    return sim.run()


def mean_sem(values):
    values = np.array(values, dtype=float)
    return values.mean(), values.std(ddof=1) / np.sqrt(len(values))


# ============================================================================
# PART 2: run_table4.py — main comparison (H1, H2), with TOST for H1
# ============================================================================

def part2_table4():
    print("=" * 78)
    print("PART 2: Table 4 reproduction (main comparison, H1/H2)")
    print("Compare these numbers against Table 4 in the paper.")
    print("=" * 78)

    SEEDS = list(range(30))
    NETWORK_SIZES = [20, 50, 100]
    TOST_MARGIN = 0.03
    ADAPTIVE_PARAMS = dict(theta_threat=0.35, theta_energy=500.0, cooldown=30)
    STATIC_BASELINES = {
        "Static-MRHOF": dict(controller="static", w_fixed=1.0),
        "Fixed-Weight": dict(controller="static", w_fixed=0.5),
        "Static-Trust": dict(controller="static", w_fixed=0.2),
    }

    print(f"{'Controller':<22}{'N':>5}{'PDR (attack)':>16}{'Overhead':>14}{'H1 p':>9}{'H1 TOST p':>11}{'H2 p':>9}")

    for n in NETWORK_SIZES:
        adaptive = [run_condition(n, s, "adaptive", **ADAPTIVE_PARAMS) for s in SEEDS]
        trust = [run_condition(n, s, "static", w_fixed=0.2) for s in SEEDS]

        a_pdr = np.array([r["pdr_attack"] for r in adaptive])
        t_pdr = np.array([r["pdr_attack"] for r in trust])
        pdr_mean, pdr_sem = mean_sem(a_pdr)
        oh_mean, oh_sem = mean_sem([r["overhead_ratio"] for r in adaptive])

        _, p_h1 = stats.ttest_rel(a_pdr, t_pdr)
        p_tost, _, _ = ttost_paired(a_pdr, t_pdr, -TOST_MARGIN, TOST_MARGIN)
        _, p_h2 = stats.ttest_1samp([r["overhead_ratio"] for r in adaptive], 1.0)

        pdr_str = f"{pdr_mean:.3f}\u00b1{pdr_sem:.3f}"
        oh_str = f"{oh_mean:.3f}\u00b1{oh_sem:.3f}"
        print(f"{'Proposed (Adaptive)':<22}{n:>5}{pdr_str:>16}{oh_str:>14}{p_h1:>9.4f}{p_tost:>11.4f}{p_h2:>9.4f}")

    for name, kwargs in STATIC_BASELINES.items():
        for n in NETWORK_SIZES:
            results = [run_condition(n, s, **kwargs) for s in SEEDS]
            pdr_mean, pdr_sem = mean_sem([r["pdr_attack"] for r in results])
            pdr_str = f"{pdr_mean:.3f}\u00b1{pdr_sem:.3f}"
            print(f"{name:<22}{n:>5}{pdr_str:>16}{'\u2014':>14}{'\u2014':>9}{'\u2014':>11}{'\u2014':>9}")

    print("\nH1 TOST equivalence margin: \u00b13 percentage points of attack-window PDR.\n")


# ============================================================================
# PART 3: run_h4.py — network lifetime (H4), with TOST
# ============================================================================

def part3_h4():
    print("=" * 78)
    print("PART 3: Table 6 reproduction (H4: network lifetime, no-attack)")
    print("Compare these numbers against Table 6 in the paper.")
    print("=" * 78)

    global MALICIOUS_FRACTION, INIT_ENERGY
    MALICIOUS_FRACTION = 0.0   # no-attack, as H4 requires
    INIT_ENERGY = 600          # dedicated energy budget so depletion is observable

    SEEDS = list(range(30))
    NETWORK_SIZES = [20, 50, 100]
    ADAPTIVE_PARAMS = dict(theta_threat=0.35, theta_energy=500.0, cooldown=30)
    TOST_MARGIN_FRAC = 0.05

    print(f"{'N':>5}{'Adaptive lifetime':>22}{'Static-MRHOF lifetime':>25}{'paired p':>11}{'TOST p':>10}")
    for n in NETWORK_SIZES:
        adaptive = np.array([run_condition(n, s, "adaptive", **ADAPTIVE_PARAMS)["lifetime"] for s in SEEDS])
        mrhof = np.array([run_condition(n, s, "static", w_fixed=1.0)["lifetime"] for s in SEEDS])
        a_mean, a_sem = mean_sem(adaptive)
        m_mean, m_sem = mean_sem(mrhof)
        _, p = stats.ttest_rel(adaptive, mrhof)
        margin = TOST_MARGIN_FRAC * mrhof.mean()
        p_tost, _, _ = ttost_paired(adaptive, mrhof, -margin, margin)
        a_str = f"{a_mean:.1f} \u00b1 {a_sem:.1f}"
        m_str = f"{m_mean:.1f} \u00b1 {m_sem:.1f}"
        print(f"{n:>5}{a_str:>22}{m_str:>25}{p:>11.4f}{p_tost:>10.4f}")

    print(f"\nTOST equivalence margin: \u00b1{TOST_MARGIN_FRAC:.0%} of mean Static-MRHOF lifetime (per N).")


if __name__ == "__main__":
    part2_table4()
    print()
    part3_h4()
