"""
Runs every .txt config file in shared/sample_configs/ through Block 2a
and prints all results together in one place.

Usage:
    python3 test_all_samples.py
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import json
from pathlib import Path
from converter.block2a_main import run_block2a

SAMPLE_DIR = Path("shared/sample_configs")

txt_files = sorted(SAMPLE_DIR.glob("*.txt"))

if not txt_files:
    print(f"No .txt files found in {SAMPLE_DIR} -- check you're running this from the repo root.")
else:
    for file_path in txt_files:
        raw = file_path.read_text()
        result = run_block2a(raw)
        print(f"{'=' * 60}")
        print(f"FILE: {file_path.name}")
        print(f"{'=' * 60}")
        print(json.dumps(result, indent=2))
        print()