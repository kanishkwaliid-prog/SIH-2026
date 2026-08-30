"""
Quick manual test runner for Block 2a, used to test a single config file.

Usage(sample):
    `python3 test_block2a.py shared/sample_configs/cisco_switch_real.txt`
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import json
from converter.block2a_main import run_block2a

if __name__ == "__main__":
    # Guarded so pytest can import/collect this file without crashing --
    # it previously called sys.exit(1) at module level whenever no CLI arg
    # was passed, which took down the entire `pytest tests/` run for every
    # test file (an unrelated INTERNALERROR, not a frontend/backend issue,
    # but it blocked verifying anything else with the test suite).
    if len(sys.argv) != 2:
        print("Usage: python3 test_block2a.py <path-to-config-file>")
        sys.exit(1)

    file_path = sys.argv[1]
    raw = open(file_path).read()
    result = run_block2a(raw)
    print(json.dumps(result, indent=2))