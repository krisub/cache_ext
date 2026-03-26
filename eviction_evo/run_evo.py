#!/usr/bin/env python3
"""
run_evo.py - Launch ShinkaEvolve to evolve cache_ext eviction policies.

Usage:
    PYTHONPATH=/mydata/ShinkaEvolve python run_evo.py
    PYTHONPATH=/mydata/ShinkaEvolve python run_evo.py --config_path shinka_evict.yaml
"""

import argparse
import shutil
import signal
import sys
import os
import subprocess

# Ensure ShinkaEvolve source is on the path (editable install workaround)
SHINKA_DIR = os.environ.get("SHINKA_DIR", "/mydata/ShinkaEvolve")
if SHINKA_DIR not in sys.path:
    sys.path.insert(0, SHINKA_DIR)

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ENV_TEMPLATE = os.path.join(SCRIPT_DIR, ".env.template")
SHINKA_ENV = os.path.join(SHINKA_DIR, ".env")

if os.path.exists(ENV_TEMPLATE):
    shutil.copy2(ENV_TEMPLATE, SHINKA_ENV)

MGLRU_PATH = "/sys/kernel/mm/lru_gen/enabled"

import yaml
from shinka.core import EvolutionRunner, EvolutionConfig
from shinka.database import DatabaseConfig
from shinka.launch import LocalJobConfig


def _restore_mglru():
    """Ensure MGLRU is re-enabled regardless of how we exit."""
    try:
        if os.path.exists(MGLRU_PATH):
            val = open(MGLRU_PATH).read().strip()
            if val in ("0x0000", "0"):
                subprocess.run(
                    ["sudo", "sh", "-c", f"echo 0x0007 > {MGLRU_PATH}"],
                    timeout=10, check=False, capture_output=True,
                )
                print("run_evo.py: MGLRU was disabled - restored to 0x0007", flush=True)
    except Exception:
        pass
    try:
        subprocess.run(
            ["sudo", "cgdelete", "memory:cache_ext_test"],
            timeout=10, check=False, capture_output=True,
        )
    except Exception:
        pass


def main(config_path: str):
    with open(config_path, "r") as f:
        config = yaml.safe_load(f)

    evo_config = EvolutionConfig(**config["evo_config"])
    eval_program = config.get("eval_program_path", "evaluate.py")
    job_config = LocalJobConfig(eval_program_path=eval_program)
    db_config = DatabaseConfig(**config["db_config"])

    evo_runner = EvolutionRunner(
        evo_config=evo_config,
        job_config=job_config,
        db_config=db_config,
        verbose=True,
    )
    try:
        evo_runner.run()
    except (KeyboardInterrupt, SystemExit):
        print("\nrun_evo.py: Interrupted - restoring system state...", flush=True)
    finally:
        _restore_mglru()
        subprocess.run(
        ["sudo", "chown", "-R", "krisub", "/mydata/cache_ext"],
        check=True
        )   

    subprocess.run(
        ["sudo", "chown", "-R", "krisub", "/mydata/cache_ext"],
        check=True
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Launch ShinkaEvolve for cache_ext eviction policy evolution"
    )
    parser.add_argument(
        "--config_path",
        type=str,
        default="shinka_evict.yaml",
        help="Path to the ShinkaEvolve YAML config",
    )
    args = parser.parse_args()
    main(args.config_path)
