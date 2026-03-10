#!/usr/bin/env python3
"""
run_evo.py — Launch ShinkaEvolve to evolve cache_ext eviction policies.

Usage:
    PYTHONPATH=/mydata/ShinkaEvolve python run_evo.py
    PYTHONPATH=/mydata/ShinkaEvolve python run_evo.py --config_path shinka_evict.yaml
"""

import argparse
import sys
import os
import subprocess

# Ensure ShinkaEvolve source is on the path (editable install workaround)
SHINKA_DIR = os.environ.get("SHINKA_DIR", "/mydata/ShinkaEvolve")
if SHINKA_DIR not in sys.path:
    sys.path.insert(0, SHINKA_DIR)

import yaml
from shinka.core import EvolutionRunner, EvolutionConfig
from shinka.database import DatabaseConfig
from shinka.launch import LocalJobConfig


def main(config_path: str):
    with open(config_path, "r") as f:
        config = yaml.safe_load(f)

    evo_config = EvolutionConfig(**config["evo_config"])
    job_config = LocalJobConfig(eval_program_path="evaluate.py")
    db_config = DatabaseConfig(**config["db_config"])

    evo_runner = EvolutionRunner(
        evo_config=evo_config,
        job_config=job_config,
        db_config=db_config,
        verbose=True,
    )
    evo_runner.run()
    
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
