#!/usr/bin/env python3
"""ringer_gate: run dependent Ringer stages behind an enforced PASS gate.

Ringer runs every task in a manifest concurrently and has no dependency field,
so a PASS in one task cannot hold back another. This wrapper turns a sequence of
Ringer manifests into gated stages:

* each stage is its own `ringer.py run`;
* a stage starts only if every stage it `needs` has a receipt whose run record
  is all-PASS, whose artifacts still hash to the recorded digest (stale-receipt
  rejection, including untracked files) and whose check files are unchanged;
* validated artifacts are copied into a read-only snapshot under the consuming
  stage's inputs dir, and the snapshot digest is re-verified, so nothing can
  change between validation and consumption;
* check files live outside every worker-writable task dir, are made read-only
  during the run, and are hashed before and after it;
* any FAIL, TIMEOUT, missing artifact, missing check, missing receipt or digest
  mismatch is BLOCKED, and later stages are recorded as not_started.

Pipeline file (JSON):
{
  "name": "demo",
  "root": "/tmp/demo",                 # receipts, rendered manifests, inputs
  "checks_dir": "/tmp/demo-checks",    # protected check scripts
  "stages": [
    {"name": "s1", "manifest": "s1.json", "needs": []},
    {"name": "s2", "manifest": "s2.json", "needs": ["s1"]}
  ]
}
Manifest strings may use {inputs} (this stage's read-only input snapshot dir)
and {checks} (checks_dir). Usage:

  ringer_gate.py PIPELINE [--stop-after STAGE] [--resume]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import time
from pathlib import Path

RINGER = Path(__file__).resolve().parent.parent / "ringer.py"
RUNS_DIR = Path(os.environ.get("RINGER_STATE_DIR", "~/.ringer")).expanduser() / "runs"
EXCLUDE = {"worker.log"}


class Blocked(Exception):
    pass


def tree_digest(root: Path, exclude: set[str] = EXCLUDE) -> tuple[str, dict[str, str]]:
    """sha256 over every regular file (tracked or not) below root."""
    files: dict[str, str] = {}
    for p in sorted(root.rglob("*")):
        if p.is_file() and not p.is_symlink() and p.name not in exclude:
            files[str(p.relative_to(root))] = hashlib.sha256(p.read_bytes()).hexdigest()
    h = hashlib.sha256(json.dumps(files, sort_keys=True).encode()).hexdigest()
    return h, files


def set_writable(root: Path, writable: bool) -> None:
    for p in [root, *root.rglob("*")]:
        mode = p.stat().st_mode
        if writable:
            p.chmod(mode | stat.S_IWUSR)
        else:
            p.chmod(mode & ~(stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH))


def render(obj, subs: dict[str, str]):
    if isinstance(obj, str):
        for k, v in subs.items():
            obj = obj.replace("{" + k + "}", v)
        return obj
    if isinstance(obj, list):
        return [render(x, subs) for x in obj]
    if isinstance(obj, dict):
        return {k: render(v, subs) for k, v in obj.items()}
    return obj


class Gate:
    def __init__(self, pipeline_path: Path):
        self.pipeline_path = pipeline_path.resolve()
        self.p = json.loads(self.pipeline_path.read_text())
        self.root = Path(self.p["root"]).resolve()
        self.checks = Path(self.p["checks_dir"]).resolve()
        self.receipts = self.root / "receipts"
        self.log_path = self.root / "gate-log.jsonl"
        self.receipts.mkdir(parents=True, exist_ok=True)

    def log(self, **event) -> None:
        event["at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        with self.log_path.open("a") as f:
            f.write(json.dumps(event) + "\n")
        print(f"[gate] {json.dumps(event)}", flush=True)

    def receipt_path(self, stage: str) -> Path:
        return self.receipts / f"{stage}.json"

    # ---- validation -------------------------------------------------------
    def validate(self, need: str) -> dict:
        rp = self.receipt_path(need)
        if not rp.exists():
            raise Blocked(f"no receipt for required stage {need}")
        r = json.loads(rp.read_text())
        if r.get("verdict") != "PASS":
            raise Blocked(f"required stage {need} verdict {r.get('verdict')}")
        run_file = RUNS_DIR / f"{r['run_id']}.json"
        if not run_file.exists():
            raise Blocked(f"run record {r['run_id']} missing")
        run = json.loads(run_file.read_text())
        bad = [t["key"] for t in run["tasks"] if t.get("verdict") != "PASS"]
        if bad or not run["tasks"]:
            raise Blocked(f"run record {r['run_id']} not all PASS: {bad}")
        for key, rec in r["artifacts"].items():
            digest, _ = tree_digest(Path(rec["taskdir"]))
            if digest != rec["digest"]:
                raise Blocked(f"stale receipt: {need}/{key} artifacts changed since PASS")
        checks_now, _ = tree_digest(self.checks, exclude=set())
        if checks_now != r["checks_digest"]:
            raise Blocked(f"check files changed since {need} passed")
        return r

    def snapshot(self, stage: str, needs: dict[str, dict]) -> Path:
        inputs = self.root / "inputs" / stage
        if inputs.exists():
            set_writable(inputs, True)
            shutil.rmtree(inputs)
        for need, r in needs.items():
            for key, rec in r["artifacts"].items():
                dst = inputs / need / key
                shutil.copytree(rec["taskdir"], dst, ignore=shutil.ignore_patterns(*EXCLUDE))
                if tree_digest(dst)[0] != rec["digest"]:
                    raise Blocked(f"snapshot of {need}/{key} does not match its receipt")
        inputs.mkdir(parents=True, exist_ok=True)
        set_writable(inputs, False)
        return inputs

    # ---- execution --------------------------------------------------------
    def run_stage(self, st: dict, inputs: Path) -> dict:
        manifest = json.loads((self.pipeline_path.parent / st["manifest"]).read_text())
        manifest = render(manifest, {"inputs": str(inputs), "checks": str(self.checks)})
        for t in manifest["tasks"]:
            if not str(t.get("check", "")).strip():
                raise Blocked(f"task {t.get('key')} has no check; unchecked work cannot pass the gate")
        rendered = self.root / "manifests" / f"{st['name']}.json"
        rendered.parent.mkdir(parents=True, exist_ok=True)
        rendered.write_text(json.dumps(manifest, indent=1))

        checks_before, _ = tree_digest(self.checks, exclude=set())
        set_writable(self.checks, False)
        try:
            cmd = [str(RINGER), "--no-self-update", "run", str(rendered), "--no-dashboard", "--no-artifact"]
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  env={**os.environ, "RINGER_NO_SELF_UPDATE": "1"})
        finally:
            set_writable(self.checks, True)
        (self.root / "logs").mkdir(exist_ok=True)
        (self.root / "logs" / f"{st['name']}.out").write_text(proc.stdout + proc.stderr)
        m = re.search(r"run_id:\s*(\S+)", proc.stdout)
        if not m:
            raise Blocked(f"ringer exited {proc.returncode} without a run_id")
        run = json.loads((RUNS_DIR / f"{m.group(1)}.json").read_text())
        checks_after, _ = tree_digest(self.checks, exclude=set())
        tasks = {t["key"]: t for t in run["tasks"]}
        verdicts = {k: t.get("verdict") or t.get("status") for k, t in tasks.items()}
        verdict = "PASS" if tasks and all(v == "PASS" for v in verdicts.values()) else "FAIL"
        if checks_after != checks_before:
            verdict = "BLOCKED"
        receipt = {
            "stage": st["name"], "run_id": run["run_id"], "verdict": verdict, "verdicts": verdicts,
            "ringer_exit": proc.returncode, "checks_digest": checks_before,
            "checks_changed_during_run": checks_after != checks_before,
            "inputs_digest": tree_digest(inputs)[0],
            "artifacts": {k: {"taskdir": t["taskdir"], "digest": tree_digest(Path(t["taskdir"]))[0],
                              "files": tree_digest(Path(t["taskdir"]))[1]}
                          for k, t in tasks.items() if Path(t["taskdir"]).exists()},
            "check_output": {k: (t.get("check_output_tail") or "")[-400:] for k, t in tasks.items()},
            "finished_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        self.receipt_path(st["name"]).write_text(json.dumps(receipt, indent=1))
        return receipt

    def run(self, stop_after: str | None, resume: bool) -> int:
        stages = self.p["stages"]
        for i, st in enumerate(stages):
            name = st["name"]
            if resume and self.receipt_path(name).exists():
                self.log(stage=name, event="skip_existing_receipt")
                continue
            try:
                needs = {n: self.validate(n) for n in st.get("needs", [])}
                inputs = self.snapshot(name, needs)
                self.log(stage=name, event="launch", needs=list(needs))
                r = self.run_stage(st, inputs)
                self.log(stage=name, event="result", verdict=r["verdict"], run_id=r["run_id"],
                         verdicts=r["verdicts"])
                if r["verdict"] != "PASS":
                    raise Blocked(f"stage {name} verdict {r['verdict']} {r['verdicts']}")
            except Blocked as e:
                self.log(stage=name, event="BLOCKED", reason=str(e),
                         not_started=[s["name"] for s in stages[i + 1:]])
                return 2
            if stop_after == name:
                self.log(stage=name, event="stopped_after")
                return 0
        self.log(event="pipeline_pass")
        return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("pipeline", type=Path)
    ap.add_argument("--stop-after", help="stop after this stage passes")
    ap.add_argument("--resume", action="store_true", help="skip stages that already have receipts")
    a = ap.parse_args()
    return Gate(a.pipeline).run(a.stop_after, a.resume)


if __name__ == "__main__":
    sys.exit(main())
