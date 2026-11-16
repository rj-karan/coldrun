#!/usr/bin/env python3
"""Stand-in for the guarddog CLI: canned JSON keyed on the target name."""
import json
import sys

eco, _scan, target, *rest = sys.argv[1:]
version = rest[rest.index("-v") + 1] if "-v" in rest else None
hits = {"capability-network-outbound": [{"location": "x.py:1", "code": "requests.get(u)"}]}
label = {"hooked": "suspicious", "evil": "high_risk", "lowish": "low", "fp": "no_risks_detected"}.get(target)
if target in {"evil", "lowish", "fp", "unscored"}:
    hits["threat-network-exfiltration"] = [{"location": "a.py:2", "message": "posts to pastebin"}]
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
out = {"package": target, "version": version, "ecosystem": eco, "results": hits, "errors": errors}
if label:
    out["risk_score"] = {"score": 5.0, "label": label}
print(json.dumps(out))
