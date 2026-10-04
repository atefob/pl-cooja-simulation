"""
Runs every reproduction script and stores each output in ../results/<script>.txt.
Total run time: roughly 5-10 minutes on a laptop. Each script can also be run on its own.

Usage:   python run_all.py
"""
import os, subprocess, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "results")
os.makedirs(OUT, exist_ok=True)

SCRIPTS = ["run_table4.py", "run_h4.py", "run_noisy_proxy.py",
           "run_sensitivity_sweep.py", "run_combined_regime.py", "run_stress_test.py",
           "run_attacker_sensitivity.py"]

for name in SCRIPTS:
    t0 = time.time()
    print(f"== {name} ...", flush=True)
    proc = subprocess.run([sys.executable, os.path.join(HERE, name)], capture_output=True, text=True)
    with open(os.path.join(OUT, name.replace(".py", ".txt")), "w", encoding="utf-8") as f:
        f.write(proc.stdout + proc.stderr)
    print(proc.stdout)
    if proc.returncode != 0:
        print(proc.stderr)
        sys.exit(f"{name} failed")
    print(f"   done in {time.time() - t0:.0f} s\n", flush=True)
