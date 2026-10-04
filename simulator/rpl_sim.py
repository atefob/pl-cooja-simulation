"""
Threat-Aware Objective Function for RPL — discrete-time simulation (NumPy).

Models a single-sink RPL DODAG of N energy-constrained nodes. Each non-root
node has K candidate parents (upstream neighbors closer to the sink) and
selects among them using a cost function:

    Cost(cand) = w * E_norm(cand) + (1 - w) * R_norm(cand)

w is set by EACH NODE'S OWN routing mode M_i(t) in {ENERGY, RESILIENT}. A
subset of internal (forwarding-capable) nodes turn malicious (selective-
forwarding) during a fixed attack window, identical across all controllers/
baselines evaluated in a given seed (paired-trace design).

Mode switching is fully LOCAL/distributed — each node independently
tracks its own threat indicator T_i(t) (an EWMA over its own candidate
links only), its own residual energy Energy_i(t), and its own cooldown
timer, and switches its own mode M_i(t) without any network-wide
aggregation or dissemination. This removes the earlier global-state
assumption (a single network-wide T(t)/M(t) that RPL's distributed,
destination-oriented design has no natural mechanism to compute or
disseminate) and better matches how a real RPL node could plausibly
implement this controller using only information already available to it
(its own link-layer ACK/retry statistics and its own battery level).

    M_i(t+1) = RESILIENT  if T_i(t) >= theta_threat AND Energy_i(t) >= theta_energy
                            AND (t - t_last_switch_i) >= cooldown
    M_i(t+1) = ENERGY      if T_i(t) <  theta_exit AND (t - t_last_switch_i) >= cooldown
    M_i(t+1) = M_i(t)      otherwise (cooldown not yet satisfied)

Controllers / baselines (controller=... argument of run_condition):
  "adaptive"          the paper's threat-aware dynamic-weight controller
  "static", w_fixed=1.0   Static-Energy   (energy-only cost; NOT MRHOF)
  "static", w_fixed=0.5   Fixed-Weight
  "static", w_fixed=0.2   Static-Trust
  "static_mrhof_etx"  Static-MRHOF (ETX + hysteresis), an RFC 6719-style reimplementation

Optional local-detection-proxy noise (RPLSim arguments proxy_fn_rate / proxy_fp_rate)
corrupts only the signal fed to the controller's EWMA; true packet outcomes used for
PDR/lifetime accounting are never affected. Defaults (0.0, 0.0) = clean/oracle signal.

Parameters used for all main results in the paper (NOT the class defaults):
MAIN_ADAPTIVE = dict(theta_threat=0.35, theta_energy=500.0, cooldown=30).
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
HYSTERESIS_BETA = 0.5              # exit threshold = BETA * theta_threat
MRHOF_HYSTERESIS = 1.0             # RFC 6719-style parent-switch threshold, in ETX units:
                                    # a candidate must offer a path ETX at least this much
                                    # better than the current parent's to trigger a switch.


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
                 cooldown=30, w_low=0.2, w_high=0.95, w_fixed=None,
                 proxy_fn_rate=0.0, proxy_fp_rate=0.0):
        """proxy_fn_rate: false-negative rate for the LOCAL failure-observation proxy
        (probability a genuine drop, e.g. from a MAC-ACK-then-drop attacker, is
        misreported to the controller as a success). proxy_fp_rate: false-positive
        rate (probability a genuine success is misreported as a failure, modeling
        transient MAC-layer retry noise). Both default to 0.0 (oracle/clean signal,
        the paper's main-result configuration); nonzero values feed only the
        controller's OWN threat-indicator EWMA (Eq. 1) — true packet outcomes used
        for PDR/lifetime accounting are never affected, so this isolates the
        controller's robustness to imperfect local sensing from the network's
        actual delivery performance."""
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
        self.controller = controller  # "adaptive" | "static" | "static_mrhof_etx"
        self.theta_threat = theta_threat
        self.theta_energy = theta_energy
        self.cooldown = cooldown
        self.w_low, self.w_high = w_low, w_high
        self.w_fixed = w_fixed
        self.proxy_fn_rate = proxy_fn_rate
        self.proxy_fp_rate = proxy_fp_rate

        # --- Real MRHOF (ETX + hysteresis) baseline state, per peer-review request ---
        self.path_etx = {0: 0.0}  # cumulative expected-transmission-count to sink
        self._level_order = sorted(range(1, n + 1), key=lambda i: self.levels[i])

        # --- Per-node (local) controller state — see module docstring revision note ---
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
                # energy cost for forwarding — each forwarding node pays its OWN
                # resilient-mode overhead based on ITS OWN current mode (local).
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

            # update per-link EWMA (approx: attribute outcome to first hop link).
            # The controller only ever sees the (possibly noisy) OBSERVED outcome,
            # never the true 'success' used for PDR/lifetime accounting above.
            if path:
                child, cand_parent = i, self.current_parent[i]
                key = (child, cand_parent)
                true_fail = 0.0 if success else 1.0
                observed_fail = true_fail
                if true_fail == 1.0 and self.proxy_fn_rate > 0.0 and self.rng.random() < self.proxy_fn_rate:
                    observed_fail = 0.0   # false negative: real drop misreported as success
                elif true_fail == 0.0 and self.proxy_fp_rate > 0.0 and self.rng.random() < self.proxy_fp_rate:
                    observed_fail = 1.0   # false positive: real success misreported as failure
                prev = self.link_ewma_fail.get(key, 0.0)
                self.link_ewma_fail[key] = EWMA_ALPHA * observed_fail + (1 - EWMA_ALPHA) * prev

    def recompute_routes(self):
        for i, cands in self.candidates.items():
            if not cands:
                continue
            w = self.current_w(i)
            best, best_cost = None, None
            for c in cands:
                e_norm = 1 - (self.energy[c] / INIT_ENERGY)  # higher = worse (less energy left)
                r_norm = self.link_ewma_fail.get((i, c), 0.0)
                cost = w * e_norm + (1 - w) * r_norm
                if best_cost is None or cost < best_cost:
                    best, best_cost = c, cost
            self.current_parent[i] = best

    def recompute_routes_mrhof_etx(self):
        """Real RFC 6719-style MRHOF: minimize cumulative ETX to the sink, only
        switching away from the current parent if a candidate is better by more
        than MRHOF_HYSTERESIS ETX units (parent-switch hysteresis). Processed in
        ascending original-tree-level order so every candidate's path_etx is
        already known (candidates always have strictly lower original level)."""
        for i in self._level_order:
            cands = self.candidates.get(i, [])
            if not cands:
                continue
            def link_etx(c):
                fail = self.link_ewma_fail.get((i, c), 0.0)
                return 1.0 / max(1.0 - fail, 0.02)  # ETX = 1 / P(success), floored

            cur = self.current_parent.get(i)
            cur_path_etx = self.path_etx.get(cur, float("inf")) + link_etx(cur) if cur is not None else float("inf")

            best, best_path_etx = cur, cur_path_etx
            for c in cands:
                cand_path_etx = self.path_etx[c] + link_etx(c)
                if cand_path_etx < best_path_etx:
                    best, best_path_etx = c, cand_path_etx

            # RFC 6719 hysteresis: only switch if the best alternative beats the
            # current parent by more than MRHOF_HYSTERESIS ETX units.
            if best != cur and best_path_etx <= cur_path_etx - MRHOF_HYSTERESIS:
                self.current_parent[i] = best
                self.path_etx[i] = best_path_etx
            else:
                self.current_parent[i] = cur
                self.path_etx[i] = cur_path_etx

    def update_controller(self, t):
        # LOCAL threat indicator: mean EWMA fail over node i's OWN candidate links only
        # (no network-wide aggregation — see module docstring revision note).
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
        self.trapped_node_ticks = 0  # RESILIENT mode AND energy < theta_energy, simultaneously
        for t in range(ticks):
            self.step_traffic(t)
            if self.controller == "adaptive":
                for i in range(1, self.n + 1):
                    if self.mode[i] == RESILIENT:
                        self.resilient_ticks[i] += 1
                        if self.energy[i] < self.theta_energy:
                            self.trapped_node_ticks += 1
            if t % CONTROL_INTERVAL == 0:
                self.update_controller(t)
                if self.controller == "static_mrhof_etx":
                    self.recompute_routes_mrhof_etx()
                else:
                    self.recompute_routes()
        return self.results()

    def results(self):
        pdr = self.delivered / self.sent if self.sent else float("nan")
        pdr_attack = (self.delivered_attack_window / self.sent_attack_window
                      if self.sent_attack_window else float("nan"))
        if self.controller == "adaptive":
            # Average, over all nodes, of each node's own resilient-tick fraction of
            # the attack duration — the natural per-node generalization of Eq. (9).
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
            switch_count=total_switches, trapped_node_ticks=getattr(self, "trapped_node_ticks", 0),
        )


def run_condition(n, seed, controller, **kwargs):
    sim = RPLSim(n, seed, controller, **kwargs)
    return sim.run()


# --- helpers used by the run_*.py scripts ------------------------------------

MAIN_ADAPTIVE = dict(theta_threat=0.35, theta_energy=500.0, cooldown=30)


def reset_defaults():
    """Restore the module-level experiment constants to the main-comparison values.
    The run_*.py scripts change some of them (e.g. INIT_ENERGY); call this between
    experiments in the same Python process."""
    global INIT_ENERGY, ATTACK_START, ATTACK_DURATION, MALICIOUS_FRACTION, ATTACK_DROP_PROB
    INIT_ENERGY = 4000.0
    ATTACK_START = 200
    ATTACK_DURATION = 400
    MALICIOUS_FRACTION = 0.18
    ATTACK_DROP_PROB = 0.55
