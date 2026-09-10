#!/bin/bash
# ==========================================================================
# One-shot Kaggle script: real Contiki-NG/Cooja RPL threat-aware simulation
#
# STAGE 1 (baseline) is verified against real, currently-shipping Contiki-NG
# source (build succeeds via the exact API surface confirmed in this repo).
# STAGE 2 (malicious selective-forwarding attack) applies a small, targeted
# patch to os/net/mac/csma/csma.c using verified real function signatures
# (mac_call_sent_callback, random_rand, node-id.h) — but has NOT been
# compiled/run end-to-end anywhere (this sandbox blocks the Gradle download
# Contiki-NG's Cooja needs). Run this on Kaggle (full internet) and share
# any error output back so Stage 2 can be debugged together if it fails.
#
# ==========================================================================
# IMPORTANT — HOW TO RUN THIS IN A KAGGLE NOTEBOOK
# ==========================================================================
# This is a BASH script, not Python. If you paste it into a normal Kaggle
# notebook cell, the cell is executed by the Python/IPython kernel and you
# will get a SyntaxError (e.g. "unterminated string literal" on the
# `$(python3 -c "..."` line), because Python has no idea what `$(...)` is.
#
# Use ONE of these instead:
#
#   Option A — magic cell (recommended):
#     %%bash
#     <paste the rest of this file, starting from the next line, into the
#      SAME cell as the %%bash magic — %%bash must be the very first line>
#
#   Option B — save as a file, then run with the shell magic:
#     Cell 1 (Python):
#         %%writefile one_shot_kaggle_rpl.sh
#         <paste this whole file's content>
#     Cell 2 (Python):
#         !bash one_shot_kaggle_rpl.sh
#
#   Option C — upload this .sh file as a Kaggle dataset/input, then:
#         !bash /kaggle/input/<your-dataset>/one_shot_kaggle_rpl.sh
# ==========================================================================
set -uo pipefail
WORK=/kaggle/working
mkdir -p "$WORK" && cd "$WORK"

# FIX: these output directories are referenced later (Stage 5 writes .csc
# files into scenarios/, Stage 6 writes logs/, Stage 7 writes results/) but
# were never created, which would crash those stages even after fixing the
# bash-vs-python issue above.
# FIX: this working directory persists across script runs within the same
# Kaggle session, so clear out any results/scenarios/logs left over from a
# previous run to avoid mixing stale and fresh data.
rm -rf scenarios logs results
mkdir -p scenarios logs results

echo "=== [1/7] System deps ==="
apt-get update -qq && apt-get install -y -qq openjdk-21-jdk-headless git build-essential > /dev/null
java -version

echo "=== [2/7] Clone Contiki-NG + Cooja submodule ==="
if [ ! -d contiki-ng ]; then
  git clone --depth 1 https://github.com/contiki-ng/contiki-ng.git
  cd contiki-ng
  git submodule update --init --depth 1 tools/cooja
  cd ..
fi

echo "=== [3/7] Apply malicious selective-forwarding patch to csma.c ==="
# NOTE: a hand-written unified-diff patch turned out to be unreliable (missing
# line-number ranges in the @@ header caused GNU patch to reject the whole
# file as unparseable). This version edits csma.c directly by matching on the
# function's text (not line numbers), which is robust to minor upstream drift.
cd contiki-ng
git checkout -- os/net/mac/csma/csma.c 2>/dev/null || true
python3 - "os/net/mac/csma/csma.c" << 'PYEOF'
import sys

path = sys.argv[1]
with open(path) as f:
    content = f.read()

if "IS_MALICIOUS" in content:
    print("Patch already applied.")
    sys.exit(0)

define_block = (
    "#include \"sys/node-id.h\"\n"
    "#include \"lib/random.h\"\n"
    "#ifndef CSMA_MALICIOUS_DROP_PCT\n"
    "#define CSMA_MALICIOUS_DROP_PCT 60\n"
    "#endif\n\n"
    "unsigned long csma_send_total = 0;\n"
    "unsigned long csma_send_dropped = 0;\n\n"
)
sig_marker = "static void\nsend_packet(mac_callback_t sent, void *ptr)"
if sig_marker not in content:
    print("!! Could not find send_packet() signature in csma.c — upstream file structure changed.")
    sys.exit(1)
content = content.replace(sig_marker, define_block + sig_marker, 1)

init_marker = "init_sec();"
idx = content.find(init_marker)
if idx == -1:
    print("!! Could not find init_sec() call in csma.c — upstream file structure changed.")
    sys.exit(1)
insert_at = idx + len(init_marker)
injection = (
    "\n\n  csma_send_total++;\n\n"
    "#ifdef IS_MALICIOUS\n"
    "  if((random_rand() % 100) < CSMA_MALICIOUS_DROP_PCT) {\n"
    "    csma_send_dropped++;\n"
    "    mac_call_sent_callback(sent, ptr, MAC_TX_OK, 1);\n"
    "    return;\n"
    "  }\n"
    "#endif /* IS_MALICIOUS */"
)
content = content[:insert_at] + injection + content[insert_at:]

with open(path, "w") as f:
    f.write(content)
print("Patch applied successfully via direct text insertion.")
PYEOF
if [ $? -eq 0 ]; then
  PATCH_OK=1
else
  echo "!! Patch failed to apply — csma.c may have changed upstream in a way this script doesn't handle."
  echo "!! Falling back: Stage 2 (attack) will be skipped; Stage 1 (baseline) still runs."
  PATCH_OK=0
fi

echo "=== [3b/7] Instrument RPL control-plane counters (DIO/DAO rx, parent switches) ==="
# NOTE: these are externally-observable-style metrics (a real network monitor could
# count control messages / rank churn) as opposed to the csma.c drop counter above,
# which only the attacker's own memory would expose. Non-fatal: if this instrumentation
# can't attach (upstream source changed), the main simulation still runs — those
# columns will just come back empty for this run, and we'll fix and retry.
cd contiki-ng 2>/dev/null || true  # harmless no-op if already inside contiki-ng from the csma.c section above
git checkout -- os/net/routing/rpl-lite/rpl-icmp6.c os/net/routing/rpl-lite/rpl-neighbor.c 2>/dev/null || true
python3 - "os/net/routing/rpl-lite/rpl-icmp6.c" << 'PYEOF'
import sys

path = sys.argv[1]
with open(path) as f:
    content = f.read()

if "rpl_dio_rx_total" in content:
    print("RPL DIO/DAO counters already applied.")
    sys.exit(0)

def insert_after_open_brace(content, sig_marker, injection_stmt, label):
    idx = content.find(sig_marker)
    if idx == -1:
        print(f"!! Could not find {label} signature — skipping this counter.")
        return content, False
    brace_idx = content.find("{", idx)
    if brace_idx == -1:
        print(f"!! Found {label} signature but no opening brace — skipping this counter.")
        return content, False
    insert_at = brace_idx + 1
    content = content[:insert_at] + "\n  " + injection_stmt + content[insert_at:]
    return content, True

define_block = "unsigned long rpl_dio_rx_total = 0;\nunsigned long rpl_dao_rx_total = 0;\n\n"
content = define_block + content

content, ok_dio = insert_after_open_brace(
    content, "static void\ndio_input(void)", "rpl_dio_rx_total++;", "dio_input()"
)
content, ok_dao = insert_after_open_brace(
    content, "static void\ndao_input(void)", "rpl_dao_rx_total++;", "dao_input()"
)

with open(path, "w") as f:
    f.write(content)

if ok_dio or ok_dao:
    print(f"RPL DIO/DAO instrumentation applied (dio={ok_dio}, dao={ok_dao}).")
    sys.exit(0)
else:
    print("!! Neither dio_input() nor dao_input() could be instrumented.")
    sys.exit(1)
PYEOF
RPL_ICMP6_OK=$?

python3 - "os/net/routing/rpl-lite/rpl-neighbor.c" << 'PYEOF'
import sys

path = sys.argv[1]
with open(path) as f:
    content = f.read()

if "rpl_parent_switches" in content:
    print("RPL parent-switch counter already applied.")
    sys.exit(0)

define_block = "unsigned long rpl_parent_switches = 0;\n\n"

# Confirmed against actual upstream source (via grep, not guessed): the setter only
# reaches this branch on a genuine parent change, which is exactly what we want to count.
func_marker = "rpl_neighbor_set_preferred_parent(rpl_nbr_t *nbr)"
func_idx = content.find(func_marker)
if func_idx == -1:
    print("!! Could not find rpl_neighbor_set_preferred_parent() signature — skipping parent-switch counter (non-fatal).")
    sys.exit(1)

if_marker = "if(curr_instance.dag.preferred_parent != nbr) {"
if_idx = content.find(if_marker, func_idx)
if if_idx == -1:
    print("!! Found function but not the expected if-block — skipping parent-switch counter (non-fatal).")
    sys.exit(1)

insert_at = if_idx + len(if_marker)
content = define_block + content
insert_at += len(define_block)
content = content[:insert_at] + "\n    rpl_parent_switches++;" + content[insert_at:]

with open(path, "w") as f:
    f.write(content)
print("RPL parent-switch instrumentation applied.")
PYEOF
RPL_DAG_OK=$?

if [ "$RPL_ICMP6_OK" -ne 0 ] && [ "$RPL_DAG_OK" -ne 0 ]; then
  echo "!! No RPL control-plane counters could be attached this run — per-node dataset will lack these columns (csma.c counters still work)."
fi
cd ..

echo "=== [4/7] Build Cooja (this needs internet for the Gradle distribution — fine on Kaggle) ==="
cd contiki-ng/tools/cooja
chmod +x gradlew
./gradlew assemble 2>&1 | tail -60
BUILD_OK=$?
cd ../../..

if [ "$BUILD_OK" -ne 0 ] || [ ! -f contiki-ng/tools/cooja/build/libs/cooja.jar ]; then
  echo "FATAL: Cooja build failed. Check the gradle output above."
  exit 1
fi
echo "Cooja build OK: $(ls -la contiki-ng/tools/cooja/build/libs/cooja.jar)"

echo "=== [5/7] Generate .csc scenarios (baseline + attack, N=20, 3 seeds — widen after Stage 1 confirmed) ==="
cat > generate_csc.py << 'PYEOF'
#!/usr/bin/env python3
"""Generates a Contiki-NG Cooja .csc: 1 RPL root/server + N client motes in a
multi-hop UDGM topology, with a configurable subset of client motes compiled
as malicious selective-forwarding relays. XML schema verified against a real
Contiki-NG regression test (tests/14-rpl-lite/01-rpl-up-route.csc)."""
import argparse, random, textwrap

MOTE_INTERFACES = """      <moteinterface>org.contikios.cooja.interfaces.Position</moteinterface>
      <moteinterface>org.contikios.cooja.interfaces.Battery</moteinterface>
      <moteinterface>org.contikios.cooja.contikimote.interfaces.ContikiVib</moteinterface>
      <moteinterface>org.contikios.cooja.contikimote.interfaces.ContikiMoteID</moteinterface>
      <moteinterface>org.contikios.cooja.contikimote.interfaces.ContikiRS232</moteinterface>
      <moteinterface>org.contikios.cooja.contikimote.interfaces.ContikiBeeper</moteinterface>
      <moteinterface>org.contikios.cooja.interfaces.RimeAddress</moteinterface>
      <moteinterface>org.contikios.cooja.interfaces.IPAddress</moteinterface>
      <moteinterface>org.contikios.cooja.contikimote.interfaces.ContikiRadio</moteinterface>
      <moteinterface>org.contikios.cooja.contikimote.interfaces.ContikiButton</moteinterface>
      <moteinterface>org.contikios.cooja.contikimote.interfaces.ContikiPIR</moteinterface>
      <moteinterface>org.contikios.cooja.contikimote.interfaces.ContikiClock</moteinterface>
      <moteinterface>org.contikios.cooja.contikimote.interfaces.ContikiLED</moteinterface>
      <moteinterface>org.contikios.cooja.contikimote.interfaces.ContikiCFS</moteinterface>
      <moteinterface>org.contikios.cooja.interfaces.Mote2MoteRelations</moteinterface>
      <moteinterface>org.contikios.cooja.interfaces.MoteAttributes</moteinterface>"""

def mote_block(mote_id, x, y):
    return f"""      <mote>
        <interface_config>
          org.contikios.cooja.interfaces.Position
          <pos x="{x:.2f}" y="{y:.2f}" />
        </interface_config>
        <interface_config>
          org.contikios.cooja.contikimote.interfaces.ContikiMoteID
          <id>{mote_id}</id>
        </interface_config>
      </mote>"""

def motetype_block(desc, source_path, build_cmd, motes_xml):
    return f"""    <motetype>
      org.contikios.cooja.contikimote.ContikiMoteType
      <description>{desc}</description>
      <source>{source_path}</source>
      <commands>{build_cmd}</commands>
{MOTE_INTERFACES}
{motes_xml}
    </motetype>"""

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n-clients", type=int, default=12)
    ap.add_argument("--malicious", type=str, default="")
    ap.add_argument("--drop-pct", type=int, default=60)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--timeout-ms", type=int, default=900000)
    ap.add_argument("--area", type=float, default=140.0)
    ap.add_argument("--contiki-examples-dir", type=str, required=True)
    ap.add_argument("--out", type=str, required=True)
    args = ap.parse_args()

    rng = random.Random(args.seed)
    malicious_ids = set(int(x) for x in args.malicious.split(",") if x.strip())
    server_path = f"{args.contiki_examples_dir}/udp-server.c"
    client_path = f"{args.contiki_examples_dir}/udp-client.c"

    motetypes = [motetype_block(
        "RPL root / server", server_path,
        "$(MAKE) TARGET=cooja clean\n$(MAKE) -j$(CPUS) udp-server.cooja TARGET=cooja",
        mote_block(1, 0.0, 0.0),
    )]

    normal_ids, malicious_mote_ids = [], []
    for mid in range(2, args.n_clients + 2):
        (malicious_mote_ids if mid in malicious_ids else normal_ids).append(mid)

    def positions(ids):
        blocks = []
        for mid in ids:
            x = rng.uniform(-args.area / 2, args.area / 2)
            y = rng.uniform(-args.area / 2, args.area / 2)
            blocks.append(mote_block(mid, x, y))
        return "\n".join(blocks)

    if normal_ids:
        motetypes.append(motetype_block(
            "Normal client/relay", client_path,
            "$(MAKE) TARGET=cooja clean\n$(MAKE) -j$(CPUS) udp-client.cooja TARGET=cooja",
            positions(normal_ids),
        ))
    if malicious_mote_ids:
        motetypes.append(motetype_block(
            "Malicious selective-forwarding client/relay", client_path,
            (f"$(MAKE) TARGET=cooja clean\n"
             f"$(MAKE) -j$(CPUS) udp-client.cooja TARGET=cooja "
             f"DEFINES=IS_MALICIOUS=1,CSMA_MALICIOUS_DROP_PCT={args.drop_pct}"),
            positions(malicious_mote_ids),
        ))

    timeout_us_threshold = int(args.timeout_ms * 1000 * 0.95)
    script = textwrap.dedent(r"""
      sent = 0;
      received = 0;
      statsDumped = false;
      TIMEOUT(__TIMEOUT__, log.log("FINAL sent=" + sent + " received=" + received + "\n"); log.testOK(); );
      while (true) {
        YIELD();
        if (msg.indexOf("Sending request") >= 0) {
          sent++;
        } else if (msg.indexOf("Received request") >= 0) {
          received++;
        }
        if (!statsDumped && time >= __TIMEOUT_US__) {
          statsDumped = true;
          try {
            var VarMemory = Java.type("org.contikios.cooja.mote.memory.VarMemory");
            var allMotes = sim.getMotes();
            for (var i = 0; i < allMotes.length; i++) {
              var m = allMotes[i];
              var mid = m.getID();
              try {
                var mem = new VarMemory(m.getMemory());
                var total = mem.getIntValueOf("csma_send_total");
                var dropped = mem.getIntValueOf("csma_send_dropped");
                var dio = "NA";
                try { dio = mem.getIntValueOf("rpl_dio_rx_total"); } catch (e3) {}
                var dao = "NA";
                try { dao = mem.getIntValueOf("rpl_dao_rx_total"); } catch (e4) {}
                var pswitch = "NA";
                try { pswitch = mem.getIntValueOf("rpl_parent_switches"); } catch (e5) {}
                log.log("STATS id=" + mid + " total=" + total + " dropped=" + dropped +
                        " dio=" + dio + " dao=" + dao + " pswitch=" + pswitch + "\n");
              } catch (e) {
                log.log("STATS id=" + mid + " ERROR=" + e + "\n");
              }
            }
          } catch (e2) {
            log.log("STATS GLOBAL_ERROR=" + e2 + "\n");
          }
        }
      }
    """).strip().replace("__TIMEOUT__", str(args.timeout_ms)).replace("__TIMEOUT_US__", str(timeout_us_threshold))
    script_xml = script.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    csc = f"""<?xml version="1.0" encoding="UTF-8"?>
<simconf version="2022112801">
  <simulation>
    <title>RPL Threat-Aware Attack Scenario (n={args.n_clients}, malicious={sorted(malicious_ids)}, drop={args.drop_pct}%, seed={args.seed})</title>
    <randomseed>{args.seed}</randomseed>
    <motedelay_us>1000000</motedelay_us>
    <radiomedium>
      org.contikios.cooja.radiomediums.UDGM
      <transmitting_range>50.0</transmitting_range>
      <interference_range>100.0</interference_range>
      <success_ratio_tx>1.0</success_ratio_tx>
      <success_ratio_rx>1.0</success_ratio_rx>
    </radiomedium>
    <events>
      <logoutput>40000</logoutput>
    </events>
{chr(10).join(motetypes)}
  </simulation>
  <plugin>
    org.contikios.cooja.plugins.ScriptRunner
    <plugin_config>
      <script>{script_xml}</script>
      <active>true</active>
    </plugin_config>
    <bounds x="603" y="43" height="596" width="962" />
  </plugin>
</simconf>
"""
    with open(args.out, "w") as f:
        f.write(csc)

    labels_path = args.out.rsplit(".", 1)[0] + ".labels.csv"
    with open(labels_path, "w") as f:
        f.write("mote_id,malicious\n")
        f.write("1,0\n")  # root/server mote, not a client — kept for completeness
        for mid in normal_ids:
            f.write(f"{mid},0\n")
        for mid in malicious_mote_ids:
            f.write(f"{mid},1\n")

    print(f"Wrote {args.out} — {len(normal_ids)} normal + {len(malicious_mote_ids)} malicious client motes.")

if __name__ == "__main__":
    main()
PYEOF

EXDIR="$WORK/contiki-ng/examples/rpl-udp"
NETWORK_SIZES="20 50 100"  # final sweep — RPL control-plane instrumentation confirmed working
SEEDS="1 2 3 4 5"
DROP_PCTS="30 60 90"
TIMEOUT_MS=600000       # 10 minutes simulated; raise if PDR looks truncated

for N in $NETWORK_SIZES; do
  MAL_IDS=$(python3 -c "
import random
r = random.Random(999)
ids = list(range(2, $N+2))
r.shuffle(ids)
k = max(1, int($N*0.18))
print(','.join(str(x) for x in sorted(ids[:k])))
")
  for SEED in $SEEDS; do
    # Baseline (no attack: all clients compiled normally) — generated once per (N, seed);
    # it doesn't depend on DROP_PCT since baseline motes never compile the malicious code path.
    python3 generate_csc.py --n-clients "$N" --malicious "" --drop-pct 0 \
      --seed "$SEED" --timeout-ms "$TIMEOUT_MS" --contiki-examples-dir "$EXDIR" \
      --out "scenarios/baseline_n${N}_s${SEED}.csc"
    # Attack scenarios: one per DROP_PCT level, if patch applied
    if [ "$PATCH_OK" -eq 1 ]; then
      for DROP_PCT in $DROP_PCTS; do
        python3 generate_csc.py --n-clients "$N" --malicious "$MAL_IDS" --drop-pct "$DROP_PCT" \
          --seed "$SEED" --timeout-ms "$TIMEOUT_MS" --contiki-examples-dir "$EXDIR" \
          --out "scenarios/attack_n${N}_s${SEED}_d${DROP_PCT}.csc"
      done
    fi
  done
done

echo "=== [6/7] Run each scenario headlessly and capture logs ==="
GRADLE="$WORK/contiki-ng/tools/cooja/gradlew"
CONTIKI_DIR="$WORK/contiki-ng"

run_scenario () {
  CSC="$1"
  NAME=$(basename "$CSC" .csc)
  echo "--- Running $NAME ---"
  RUN_LOGDIR="$WORK/logs/$NAME"
  mkdir -p "$RUN_LOGDIR"
  ( cd "$CONTIKI_DIR/tools/cooja" && \
    ./gradlew --no-watch-fs -q run \
      -Dslf4j.provider=ch.qos.logback.classic.spi.LogbackServiceProvider \
      --args="--no-gui --contiki=$CONTIKI_DIR --logdir=$RUN_LOGDIR --random-seed=1 $WORK/$CSC" \
  ) > "$WORK/logs/${NAME}.stdout.log" 2>&1
  echo "  exit status: $? (see logs/${NAME}.stdout.log)"
}

for CSC in scenarios/*.csc; do
  run_scenario "$CSC"
done

echo "=== [7/7] Parse results into aggregate + per-node ground-truth CSVs ==="
python3 << 'PYEOF'
import re, glob, csv, os

rows = []
node_rows = []
for path in glob.glob("logs/*.stdout.log"):
    name = os.path.basename(path).replace(".stdout.log", "")
    text = ""
    testlog_path = os.path.join("logs", name, "COOJA.testlog")
    if os.path.exists(testlog_path):
        with open(testlog_path, errors="ignore") as f:
            text += f.read()
    with open(path, errors="ignore") as f:
        text += f.read()

    kind = "attack" if name.startswith("attack") else "baseline"
    dm = re.search(r"_d(\d+)$", name)
    drop_pct = int(dm.group(1)) if dm else 0

    m = re.search(r"FINAL sent=(\d+) received=(\d+)", text)
    if m:
        sent, received = int(m.group(1)), int(m.group(2))
        pdr = received / sent if sent else float("nan")
    else:
        sent = received = None
        pdr = float("nan")
    rows.append(dict(scenario=name, kind=kind, drop_pct=drop_pct, sent=sent, received=received, pdr=pdr))

    # Load this scenario's true labels (mote_id -> malicious 0/1), written by generate_csc.py
    labels = {}
    labels_path = os.path.join("scenarios", name + ".labels.csv")
    if os.path.exists(labels_path):
        with open(labels_path, newline="") as f:
            for r in csv.DictReader(f):
                labels[int(r["mote_id"])] = int(r["malicious"])
    else:
        print(f"!! No labels file for {name} — skipping per-node rows for this scenario.")

    # Parse per-node STATS lines: "STATS id=<id> total=<n> dropped=<n> dio=<n|NA> dao=<n|NA> pswitch=<n|NA>"
    for sm in re.finditer(
        r"STATS id=(\d+) total=(\d+) dropped=(\d+) dio=(\d+|NA) dao=(\d+|NA) pswitch=(\d+|NA)", text
    ):
        mid, total, dropped = int(sm.group(1)), int(sm.group(2)), int(sm.group(3))
        dio = None if sm.group(4) == "NA" else int(sm.group(4))
        dao = None if sm.group(5) == "NA" else int(sm.group(5))
        pswitch = None if sm.group(6) == "NA" else int(sm.group(6))
        drop_rate = dropped / total if total else float("nan")
        node_rows.append(dict(
            scenario=name, kind=kind, drop_pct=drop_pct, mote_id=mid, total=total, dropped=dropped,
            drop_rate=drop_rate, dio_rx=dio, dao_rx=dao, parent_switches=pswitch, malicious=labels.get(mid),
        ))
    # Surface any STATS ERROR lines so we know if the mote-memory read needs fixing.
    for em in re.finditer(r"STATS id=(\d+) ERROR=(.+)", text):
        print(f"!! {name}: mote {em.group(1)} STATS read failed: {em.group(2).strip()}")
    ge = re.search(r"STATS GLOBAL_ERROR=(.+)", text)
    if ge:
        print(f"!! {name}: dumpStats() failed entirely: {ge.group(1).strip()}")

with open("results/real_cooja_results.csv", "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=["scenario", "kind", "drop_pct", "sent", "received", "pdr"])
    w.writeheader()
    for r in rows:
        w.writerow(r)
print(f"Wrote results/real_cooja_results.csv with {len(rows)} rows")

with open("results/per_node_dataset.csv", "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=[
        "scenario", "kind", "drop_pct", "mote_id", "total", "dropped", "drop_rate",
        "dio_rx", "dao_rx", "parent_switches", "malicious",
    ])
    w.writeheader()
    for r in node_rows:
        w.writerow(r)
print(f"Wrote results/per_node_dataset.csv with {len(node_rows)} rows")

for r in rows:
    print(r)
PYEOF

echo "=== DONE. Check /kaggle/working/results/real_cooja_results.csv and /kaggle/working/logs/ for raw output. ==="
