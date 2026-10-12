#!/bin/bash
# Gate acceptance demo with real OpenCode workers.
#   pass    : the 3-stage pipeline certifies
#   blocked : s2 never launches
#   rerun   : on --resume the invalid s1 receipt is re-run, never skipped
#   mutate  : s2's worker attempts to alter its inputs, checks and gate state;
#             the sandbox denies it, digests are unchanged, no file is planted
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
GATE="$HERE/../../scripts/ringer_gate.py"
PY="${PYTHON:-python3.13}"
BASE="${1:-/tmp/ringer-gate-demo-$(date +%s)}"
mkdir -p "$BASE"
pipeline() { # scenario s1-manifest [s2-manifest]
  local root="$BASE/$1"; mkdir -p "$root"; cp -R "$HERE/checks" "$BASE/$1-checks"
  cat > "$root/pipeline.json" <<J
{"name":"$1","root":"$root","checks_dir":"$BASE/$1-checks",
 "stages":[{"name":"s1","manifest":"$HERE/$2","needs":[]},
           {"name":"s2","manifest":"$HERE/${3:-s2.json}","needs":["s1"]},
           {"name":"s3","manifest":"$HERE/s3.json","needs":["s2"]}]}
J
  echo "$root/pipeline.json"
}
summary() { "$PY" - "$BASE" "$1" "$2" <<'P'
import json,sys,pathlib
base,case,expect=sys.argv[1:]
root=pathlib.Path(base)/case
ev=[json.loads(l) for l in open(root/"gate-log.jsonl")]
launched=[e["stage"] for e in ev if e.get("event")=="launch"]
blocked=[e["reason"] for e in ev if e.get("event")=="BLOCKED"]
reruns=[e["stage"] for e in ev if e.get("event")=="receipt_invalid_rerun"]
passed=any(e.get("event")=="pipeline_pass" for e in ev)
if expect=="pass": ok=passed and not blocked
elif expect=="blocked": ok=bool(blocked) and "s2" not in launched and not passed
elif expect=="rerun": ok="s1" in reruns and launched.count("s1")==2
elif expect=="mutate":
    r=json.load(open(root/"receipts"/"s2.json"))
    att=(root/"work"/"s2"/"sum"/"mutation-attempts.txt").read_text()
    print(att.strip())
    ok=passed and not r["problems"] and "OK " not in att and "denied" in att
print(f"{case:12} expect={expect:7} launched={launched} reruns={reruns} blocked={blocked} pass={passed} -> {'OK' if ok else 'UNEXPECTED'}")
P
}
run() { "$PY" "$GATE" "$@" >/dev/null 2>&1; }
P=$(pipeline happy s1.json); run "$P"; summary happy pass
for s in failcheck timeout missing symlink codex; do P=$(pipeline $s s1_$s.json); run "$P"; summary $s blocked; done
P=$(pipeline failresume s1_failcheck.json); run "$P"; run "$P" --resume; summary failresume rerun
P=$(pipeline editedcheck s1.json); run "$P" --stop-after s1; echo "# tampered" >> "$BASE/editedcheck-checks/s1_numbers.sh"; run "$P" --resume; summary editedcheck rerun
P=$(pipeline stale s1.json); run "$P" --stop-after s1; echo 6 >> "$BASE/stale/work/s1/gen/numbers.txt"; run "$P" --resume; summary stale rerun
P=$(pipeline mutate s1.json s2_mutate.json); run "$P" --stop-after s1
M="$BASE/mutate"; IN="$M/inputs/s2/s1/gen"
PATH="$HERE/hostile:$PATH" HOSTILE_INPUT="$IN/numbers.txt" \
  HOSTILE_TARGETS="$IN/numbers.txt $IN $BASE/mutate-checks/s2_sum.sh $BASE/mutate-checks $M/receipts/s1.json $M/receipts $M/gate-log.jsonl" \
  "$PY" "$GATE" "$P" --resume --stop-after s2 >/dev/null 2>&1
run "$P" --resume; summary mutate mutate
