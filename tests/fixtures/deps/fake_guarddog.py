#!/usr/bin/env python3
"""Stand-in for the guarddog CLI: canned JSON keyed on the target name."""
import json
import sys

eco, _scan, target, *rest = sys.argv[1:]
version = rest[rest.index("-v") + 1] if "-v" in rest else None
hits = {"capability-network-outbound": [{"location": "x.py:1", "code": "requests.get(u)"}]}
if target == "hooked":
    hits["capability-process-hooks"] = [
        {"location": "setup.py:11", "code": 'cmdclass={"install":  PostInstall}', "message": "hook"}
    ]
    hits["threat-process-download-exec"] = [{"location": "pkg/a.py:3", "message": "dl+exec"}]
    hits["typosquatting"] = ["requests"]
    hits["deceptive_author"] = "author name mismatch"
if target == "broken":
    sys.stderr.write("boom\n")
    sys.exit(2)
if target == "garbage":
    print("not json")
    sys.exit(0)
errors = {"download-package": "Traceback\n  ...\nGitError: Permission denied"} if target == "nodl" else {}
print(json.dumps({"package": target, "version": version, "ecosystem": eco, "results": hits, "errors": errors}))
