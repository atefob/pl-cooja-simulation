"""
Threat-Aware Objective Function for RPL — discrete-event simulation (SimPy).

Models a single-sink RPL DODAG of N energy-constrained nodes. Each non-root
node has K candidate parents (upstream neighbors closer to the sink) and
selects among them using a cost function:

    Cost(cand) = w * E_norm(cand) + (1 - w) * R_norm(cand)

w is set by the routing mode M(t) in {ENERGY, RESILIENT}. A subset of
internal (forwarding-capable) nodes turn malicious (selective-forwarding)
during a fixed attack window, identical across all controllers/baselines
evaluated in a given seed (paired-trace design).

A global controller (mirroring the referenced adaptive-switching design)
observes a rolling, network-wide threat indicator T(t) (EWMA of forwarding
failures) and switches M(t) according to:

    M(t+1) = RESILIENT  if T(t) >= theta_threat AND avg_energy >= theta_energy
                          AND (t - t_last_switch) >= cooldown
    M(t+1) = ENERGY      if T(t) <  theta_threat AND (t - t_last_switch) >= cooldown
    M(t+1) = M(t)         otherwise (cooldown not yet satisfied)

Baselines (fixed w, no switching): Static-MRHOF (w=1), Static-Trust (w=0.2),
Fixed-Weight (w=0.5).
"""

import numpy as np

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


def build_tree(n, rng):
    """Random recursive tree rooted at 0 (sink). Returns parent_candidates[i] = list of
    valid upstream candidate node ids (including the structural parent)."""
    levels = {0: 0}
    parent_struct = {0: None}
    order = list(range(1, n + 1))
    for i in order:
        # attach to a random existing node, mildly biased toward shallower nodes
        existing = list(levels.keys())
        weights = np.array([1.0 / (1 + levels[j]) for j in existing])
        weights /= weights.sum()
        par = rng.choice(existing, p=weights)
        parent_struct[i] = par
        levels[i] = levels[par] + 1

    # candidate parents: structural parent + up to K-1 other nodes at a strictly
    # lower level (valid upstream neighbors), chosen randomly
    candidates = {0: []}
    for i in order:
        pool = [j for j in levels if levels[j] < levels[i] and j != i]
        others = [j for j in pool if j != parent_struct[i]]
        rng.shuffle(others)
        cand = [parent_struct[i]] + others[: K_CANDIDATES - 1]
        candidates[i] = list(dict.fromkeys(cand))  # dedupe, preserve order
    return candidates, levels, parent_struct


def choose_malicious(candidates, levels, n, rng):
    # A node is "internal" (forwarding-capable) if it appears as a candidate
    # parent for at least one other node.
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
        self.link_ewma_fail = {}  # (child, cand_parent) -> EWMA failure rate
        for i, cands in self.candidates.items():
            for c in cands:
                self.link_ewma_fail[(i, c)] = 0.0
        self.current_parent = {i: self.candidates[i][0] for i in range(1, n + 1) if self.candidates[i]}
        self.controller = controller  # "adaptive" | "static"
        self.theta_threat = theta_threat
        self.theta_energy = theta_energy
        self.cooldown = cooldown
        self.w_low, self.w_high = w_low, w_high
        self.w_fixed = w_fixed
        self.mode = ENERGY
        self.t_last_switch = -10_000
        self.threat_ewma = 0.0
        self.sent = 0
        self.delivered = 0
        self.sent_attack_window = 0
        self.delivered_attack_window = 0
        self.resilient_ticks = 0
        self.switch_count = 0
        self.depletion_time = None

    def current_w(self):
        if self.controller == "static":
            return self.w_fixed
        return self.w_low if self.mode == RESILIENT else self.w_high

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
        return path  # list of forwarding nodes (excludes sink), root->leaf order reversed

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
                # energy cost for forwarding
                mult = RESILIENT_ENERGY_MULT if self.mode == RESILIENT and self.controller == "adaptive" else 1.0
                self.energy[node] -= TX_ENERGY * mult
                if self.energy[node] <= 0 and self.depletion_time is None:
                    self.depletion_time = t
                p_fail = 1 - BASE_LINK_RELIABILITY
                if attacking and node in self.malicious:
                    p_fail = ATTACK_DROP_PROB
                if self.rng.random() < p_fail:
                    success = False
                    # update EWMA fail observed by the child on this link
                    child = i if node == path[0] else None
                    break
            if success:
                self.delivered += 1
                if attacking:
                    self.delivered_attack_window += 1

            # update per-link EWMA (approx: attribute outcome to first hop link)
            if path:
                child, cand_parent = i, self.current_parent[i]
                key = (child, cand_parent)
                obs_fail = 0.0 if success else 1.0
                prev = self.link_ewma_fail.get(key, 0.0)
                self.link_ewma_fail[key] = EWMA_ALPHA * obs_fail + (1 - EWMA_ALPHA) * prev

    def recompute_routes(self):
        w = self.current_w()
        for i, cands in self.candidates.items():
            if not cands:
                continue
            best, best_cost = None, None
            for c in cands:
                e_norm = 1 - (self.energy[c] / INIT_ENERGY)  # higher = worse (less energy left)
                r_norm = self.link_ewma_fail.get((i, c), 0.0)
                cost = w * e_norm + (1 - w) * r_norm
                if best_cost is None or cost < best_cost:
                    best, best_cost = c, cost
            self.current_parent[i] = best

    def update_controller(self, t):
        # network-wide threat indicator: mean EWMA fail over currently-used links
        used_links = [(i, self.current_parent[i]) for i in range(1, self.n + 1)]
        vals = [self.link_ewma_fail.get(k, 0.0) for k in used_links]
        self.threat_ewma = float(np.mean(vals)) if vals else 0.0
        if self.controller != "adaptive":
            return
        avg_energy = float(np.mean(list(self.energy.values())))
        if (t - self.t_last_switch) < self.cooldown:
            return
        # small hysteresis band (exit threshold below entry threshold) to avoid
        # oscillation from a threat indicator that dips as soon as avoidance kicks in
        exit_threshold = 0.5 * self.theta_threat
        if self.mode == ENERGY and self.threat_ewma >= self.theta_threat and avg_energy >= self.theta_energy:
            self.mode = RESILIENT
            self.t_last_switch = t
            self.switch_count += 1
        elif self.mode == RESILIENT and self.threat_ewma < exit_threshold:
            self.mode = ENERGY
            self.t_last_switch = t
            self.switch_count += 1

    def run(self, ticks=SIM_TICKS):
        for t in range(ticks):
            self.step_traffic(t)
            if self.mode == RESILIENT and self.controller == "adaptive":
                self.resilient_ticks += 1
            if t % CONTROL_INTERVAL == 0:
                self.update_controller(t)
                self.recompute_routes()
        return self.results()

    def results(self):
        pdr = self.delivered / self.sent if self.sent else float("nan")
        pdr_attack = (self.delivered_attack_window / self.sent_attack_window
                      if self.sent_attack_window else float("nan"))
        overhead_ratio = (self.resilient_ticks / ATTACK_DURATION) if self.controller == "adaptive" else float("nan")
        energy_remaining_frac = float(np.mean(list(self.energy.values()))) / INIT_ENERGY
        lifetime = self.depletion_time if self.depletion_time is not None else SIM_TICKS
        return dict(
            pdr=pdr, pdr_attack=pdr_attack, overhead_ratio=overhead_ratio,
            energy_remaining_frac=energy_remaining_frac, lifetime=lifetime,
            switch_count=self.switch_count,
        )


def run_condition(n, seed, controller, **kwargs):
    sim = RPLSim(n, seed, controller, **kwargs)
    return sim.run()
