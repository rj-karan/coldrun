#!/usr/bin/env python3
"""Stand-in for the semgrep CLI: canned JSON keyed on the target name."""
import json
import sys

target = sys.argv[-1]
if target.endswith("broken"):
    sys.stderr.write("semgrep exploded\n")
    sys.exit(2)
results = [
    {"check_id": "rules.semgrep.py-thing", "path": target, "start": {"line": 4},
     "extra": {"message": "does a thing", "metadata": {"severity": "high"}}},
    {"check_id": "unscored", "path": target, "start": {},
     "extra": {"message": "no severity given"}},
]
errors = [{"message": "Syntax error at line 9"}] if target.endswith("partial") else []
print(json.dumps({"results": results, "errors": errors}))
