#!/bin/bash
# Gate acceptance demo: one passing 3-stage pipeline plus five blocked cases.
# Each blocked case must leave stage s2 unlaunched (no "launch" event for s2).
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
GATE="$HERE/../../scripts/ringer_gate.py"
BASE="${1:-/tmp/ringer-gate-demo-$(date +%s)}"
mkdir -p "$BASE"
pipeline() { # scenario s1-manifest
  local root="$BASE/$1"; mkdir -p "$root"; cp -R "$HERE/checks" "$root/checks"
  cat > "$root/pipeline.json" <<J
{"name":"$1","root":"$root","checks_dir":"$root/checks",
 "stages":[{"name":"s1","manifest":"$HERE/$2","needs":[]},
           {"name":"s2","manifest":"$HERE/s2.json","needs":["s1"]},
           {"name":"s3","manifest":"$HERE/s3.json","needs":["s2"]}]}
J
  echo "$root/pipeline.json"
}
summary() { python3 - "$BASE/$1/gate-log.jsonl" "$1" "$2" <<'P'
import json,sys
ev=[json.loads(l) for l in open(sys.argv[1])]
launched=[e["stage"] for e in ev if e.get("event")=="launch"]
blocked=[e for e in ev if e.get("event")=="BLOCKED"]
passed=any(e.get("event")=="pipeline_pass" for e in ev)
ok = passed if sys.argv[3]=="pass" else (bool(blocked) and "s2" not in launched)
print(f"{sys.argv[2]:16} expect={sys.argv[3]:7} launched={launched} blocked={[b['reason'] for b in blocked]} -> {'OK' if ok else 'UNEXPECTED'}")
P
}
P=$(pipeline happy s1.json); python3 "$GATE" "$P"; summary happy pass
for s in failcheck timeout missing; do P=$(pipeline $s s1_$s.json); python3 "$GATE" "$P"; summary $s blocked; done
P=$(pipeline editedcheck s1.json); python3 "$GATE" "$P" --stop-after s1; echo "# tampered" >> "$BASE/editedcheck/checks/s1_numbers.sh"; python3 "$GATE" "$P" --resume; summary editedcheck blocked
P=$(pipeline stale s1.json); python3 "$GATE" "$P" --stop-after s1; echo 6 >> "$BASE/stale/work/s1/gen/numbers.txt"; python3 "$GATE" "$P" --resume; summary stale blocked
