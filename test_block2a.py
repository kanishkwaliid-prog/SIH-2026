"""
Quick manual test runner for Block 2a.

Usage(sample):
    `python3 test_block2a.py shared/sample_configs/cisco_switch_real.txt`
"""
import sys
import json
from converter.block2a_main import run_block2a

if len(sys.argv) != 2:
    print("Usage: python3 test_block2a.py <path-to-config-file>")
    sys.exit(1)

file_path = sys.argv[1]
raw = open(file_path).read()
result = run_block2a(raw)
print(json.dumps(result, indent=2))