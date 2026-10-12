#!/usr/bin/env python3
"""ringer_gate: run dependent Ringer stages behind an enforced PASS gate.

Ringer runs every task in a manifest concurrently and has no dependency field,
so a PASS in one task cannot hold back another. This wrapper turns a sequence of
Ringer manifests into gated stages:

* each stage is its own `ringer.py run`, under a controller timeout;
* a stage starts only if every stage it `needs` has a receipt that re-validates
  now: bound to that stage's name and manifest, its run record (copied into the
  receipt dir) is all-PASS for exactly the manifest's task keys, its artifacts
  still hash to the recorded digest (all files, tracked or not), its check files
  are unchanged, and the receipts it consumed are still the ones it recorded;
* `--resume` skips a stage only when its receipt passes that same validation;
  a failed, stale or re-defined stage is re-run, never skipped on existence;
* validated artifacts are copied into a snapshot under the consuming stage's
  inputs dir, re-verified against the receipt, and compared again after the run;
* isolation is enforced by the worker sandbox, not by file modes: every task
  must use an engine whose OS sandbox confines writes to its own task dir (the
  Seatbelt `opencode-sandboxed.sh` wrapper), no task may request full access,
  and gate state, checks and snapshots must lie outside every task dir.
  Unsupported engines are refused rather than run "unenforced";
* symlinks and special files in artifacts or checks are rejected;
* any FAIL, TIMEOUT, missing artifact, unchecked task, missing receipt or digest
  mismatch is BLOCKED, and later stages are recorded as not_started.

Pipeline file (JSON):
{
  "name": "demo",
  "root": "/tmp/demo",                 # receipts, rendered manifests, inputs, work
  "checks_dir": "/tmp/demo-checks",    # check scripts (must exist)
  "stages": [
    {"name": "s1", "manifest": "s1.json", "needs": []},
    {"name": "s2", "manifest": "s2.json", "needs": ["s1"], "timeout_s": 900}
  ]
}
Manifest strings may use {inputs} (this stage's snapshot dir), {checks}
(checks_dir) and {root}. Usage:

  ringer_gate.py PIPELINE [--stop-after STAGE] [--resume]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import threading
import time
import tomllib
from pathlib import Path

RINGER = Path(__file__).resolve().parent.parent / "ringer.py"
EXCLUDE = {"worker.log"}
TRUSTED_WRAPPER = Path(__file__).resolve().parent.parent / "engines" / "opencode-sandboxed.sh"
# Writable roots the Seatbelt wrapper grants besides the task dir and a fresh scratch dir.
WRAPPER_WRITE_ROOTS = [Path("~/.local/share/opencode").expanduser(), Path("~/.local/state/opencode").expanduser(),
                       Path("~/.config/opencode").expanduser()]
ESCAPE_FLAGS = {"--no-sandbox"}


class Blocked(Exception):
    pass


def runs_dir() -> Path:
    return Path(os.environ.get("RINGER_STATE_DIR", "~/.ringer")).expanduser() / "runs"


def ringer_config() -> dict:
    p = Path(os.environ.get("RINGER_CONFIG", "~/.config/ringer/config.toml")).expanduser()
    return tomllib.loads(p.read_text()) if p.exists() else {}


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def file_sha(p: Path) -> str:
    return sha(p.read_bytes())


def tree_digest(root: Path, exclude: set[str] = EXCLUDE) -> tuple[str, dict[str, str]]:
    """sha256 over every regular file below root; symlinks and special files are refused."""
    if not root.is_dir() or root.is_symlink():
        raise Blocked(f"{root} is not a real directory")
    files: dict[str, str] = {}
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for name in dirnames + filenames:
            p = Path(dirpath) / name
            st = p.lstat()
            if stat.S_ISLNK(st.st_mode):
                raise Blocked(f"symlink not allowed in gated tree: {p}")
            if not (stat.S_ISDIR(st.st_mode) or stat.S_ISREG(st.st_mode)):
                raise Blocked(f"special file not allowed in gated tree: {p}")
        for name in filenames:
            if name in exclude:
                continue
            p = Path(dirpath) / name
            files[str(p.relative_to(root))] = file_sha(p)
    return sha(json.dumps(files, sort_keys=True).encode()), files


def set_readonly(root: Path) -> None:
    """Defence in depth only; the sandbox is what prevents writes."""
    for p in [root, *root.rglob("*")]:
        p.chmod(p.lstat().st_mode & ~(stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH))


def make_writable(root: Path) -> None:
    for p in [root, *root.rglob("*")]:
        p.chmod(p.lstat().st_mode | stat.S_IWUSR)


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


def proc_table() -> dict[int, tuple[int, str]]:
    """pid -> (ppid, start time) for live, non-zombie processes."""
    out = subprocess.run(["ps", "-A", "-o", "pid=,ppid=,stat=,lstart="], capture_output=True, text=True).stdout
    table = {}
    for line in out.splitlines():
        pid, ppid, st, start = line.split(None, 3)
        if not st.startswith("Z"):
            table[int(pid)] = (int(ppid), start.strip())
    return table


def descendants(pid: int) -> list[int]:
    """All live descendants of pid (Ringer starts workers in their own sessions, so groups are not enough)."""
    children: dict[int, list[int]] = {}
    for c, (pp, _) in proc_table().items():
        children.setdefault(pp, []).append(c)
    found, stack = [], [pid]
    while stack:
        for c in children.get(stack.pop(), []):
            found.append(c)
            stack.append(c)
    return found


def cwd_inside(root: Path) -> list[int]:
    """Processes whose working directory is inside root (catches daemons that escaped the parent tree)."""
    out = subprocess.run(["lsof", "-a", "-d", "cwd", "-Fpn"], capture_output=True, text=True).stdout
    found, pid = [], None
    for line in out.splitlines():
        if line.startswith("p"):
            pid = int(line[1:])
        elif line.startswith("n") and pid and pid != os.getpid() and inside(Path(line[1:]), root):
            found.append(pid)
    return found


def kill_tree(pid: int, extra: list[int] = (), sweep: Path | None = None) -> list[int]:
    """Freeze then kill pid, its descendants, previously seen pids and processes working inside sweep."""
    victims: list[int] = []
    for _ in range(5):
        tree = ([pid, *descendants(pid)] if pid else []) + list(extra) + (cwd_inside(sweep) if sweep else [])
        tree += [d for p in list(tree) for d in descendants(p)]
        new = [p for p in tree if p not in victims]
        for p in new:
            try:
                os.kill(p, signal.SIGSTOP)
            except ProcessLookupError:
                pass
        victims += new
        if not new:
            break
    for p in victims:
        try:
            os.kill(p, signal.SIGKILL)
        except ProcessLookupError:
            pass
    time.sleep(0.5)
    live = proc_table()
    return [p for p in victims if p in live]


def still_same(seen: dict[int, str]) -> list[int]:
    """Seen pids still alive with the same start time (guards against pid reuse)."""
    now = proc_table()
    return [p for p, start in seen.items() if p in now and now[p][1] == start]


def run_controller_check(command: str, cwd: Path, timeout: int, out_path: Path) -> dict:
    """Execute a task's check independently of Ringer and keep its complete raw output."""
    try:
        cp = subprocess.run(command, shell=True, cwd=cwd, capture_output=True, timeout=timeout)
        rc, data = cp.returncode, cp.stdout + b"\n--- stderr ---\n" + cp.stderr
    except subprocess.TimeoutExpired as e:
        rc, data = "TIMEOUT", (e.stdout or b"") + b"\n--- stderr ---\n" + (e.stderr or b"")
    out_path.write_bytes(data)
    return {"command": command, "exit": rc, "output_path": str(out_path), "output_sha": sha(data)}


def inside(child: Path, parent: Path) -> bool:
    try:
        child.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


class Gate:
    def __init__(self, pipeline_path: Path):
        self.pipeline_path = pipeline_path.resolve()
        self.p = json.loads(self.pipeline_path.read_text())
        self.root = Path(self.p["root"]).resolve()
        self.checks = Path(self.p["checks_dir"]).resolve()
        if not self.checks.is_dir():
            raise SystemExit(f"checks_dir {self.checks} does not exist")
        self.receipts = self.root / "receipts"
        self.log_path = self.root / "gate-log.jsonl"
        self.receipts.mkdir(parents=True, exist_ok=True)
        self.stages = {s["name"]: s for s in self.p["stages"]}
        self.config = ringer_config()

    def log(self, **event) -> None:
        event["at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        with self.log_path.open("a") as f:
            f.write(json.dumps(event) + "\n")
        print(f"[gate] {json.dumps(event)}", flush=True)

    def receipt_path(self, stage: str) -> Path:
        return self.receipts / f"{stage}.json"

    def manifest_path(self, st: dict) -> Path:
        return (self.pipeline_path.parent / st["manifest"]).resolve()

    def checks_digest(self) -> str:
        return tree_digest(self.checks, exclude=set())[0]

    # ---- isolation ----------------------------------------------------------
    def guarded_paths(self) -> list[Path]:
        return [self.root / "receipts", self.root / "inputs", self.root / "manifests", self.log_path, self.checks]

    def engine_config(self, engine: str) -> dict:
        cfg = self.config.get("engines", {}).get(engine)
        if not cfg:
            raise Blocked(f"engine {engine!r} is not configured")
        return cfg

    def require_isolation(self, manifest: dict) -> None:
        """Refuse anything the Seatbelt wrapper cannot confine: wrong binary, escape flags, overlapping paths."""
        if self.config.get("allow_full_access"):
            raise Blocked("ringer config allows full access; enforced isolation cannot be claimed")
        workdir = Path(manifest["workdir"]).resolve()
        for t in manifest["tasks"]:
            engine = t.get("engine") or "codex"
            cfg = self.engine_config(engine)
            bin_path = Path(str(cfg.get("bin", "")))
            if (not bin_path.is_file() or bin_path.is_symlink()
                    or file_sha(bin_path) != file_sha(TRUSTED_WRAPPER)):
                raise Blocked(f"task {t['key']}: engine {engine!r} bin is not the trusted Seatbelt wrapper; refusing to gate it")
            if bin_path.stat().st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                raise Blocked(f"engine {engine!r} wrapper is group/world writable")
            args = [str(a) for a in cfg.get("args_template", [])]
            if args[:2] != ["{taskdir}", "{access_args}"]:
                raise Blocked(f"engine {engine!r} args_template must start with {{taskdir}}, {{access_args}}")
            extra = args + [str(a) for a in cfg.get("sandbox_args", [])] + [str(a) for a in t.get("engine_args", [])]
            if ESCAPE_FLAGS & set(extra):
                raise Blocked(f"task {t['key']}: sandbox escape flag in engine/task arguments")
            if t.get("full_access"):
                raise Blocked(f"task {t['key']} requests full_access; refusing to gate it")
            taskdir = workdir / t["key"]
            for guarded in self.guarded_paths():
                for root in [taskdir, *WRAPPER_WRITE_ROOTS]:
                    if inside(guarded, root):
                        raise Blocked(f"gate path {guarded} lies inside sandbox-writable {root}")

    def verify_invocations(self, name: str, tasks: dict) -> list[str]:
        """Check the command Ringer actually ran: trusted wrapper, own task dir first, no escape flag."""
        problems = []
        for k, t in tasks.items():
            log = Path(t.get("log_path") or "")
            cmds = [l.split("command:", 1)[1].strip() for l in (log.read_text(errors="replace").splitlines() if log.is_file() else [])
                    if l.startswith("[ringer.py] command:")]
            if not cmds:
                problems.append(f"{k}: no recorded worker command")
            for c in cmds:
                argv = shlex.split(c.replace("< /dev/null", ""))
                if len(argv) < 2 or Path(argv[0]).resolve() != Path(str(self.engine_config(t.get("engine") or "codex")["bin"])).resolve():
                    problems.append(f"{k}: worker not launched through the trusted wrapper")
                elif Path(argv[1]).resolve() != Path(t["taskdir"]).resolve():
                    problems.append(f"{k}: wrapper confined to {argv[1]}, not the task dir")
                elif ESCAPE_FLAGS & set(argv[2:3]):
                    problems.append(f"{k}: worker launched with a sandbox escape flag")
        return problems

    def binding(self, st: dict) -> dict:
        """What a receipt must still match: stage definition, dependency set and runtime configuration."""
        manifest = json.loads(self.manifest_path(st).read_text())
        engines = sorted({t.get("engine") or "codex" for t in manifest["tasks"]})
        runtime = {"allow_full_access": self.config.get("allow_full_access", False),
                   "engines": {e: self.config.get("engines", {}).get(e) for e in engines},
                   "wrapper_sha": file_sha(TRUSTED_WRAPPER), "gate_sha": file_sha(Path(__file__))}
        return {"stage_def_sha": sha(json.dumps(st, sort_keys=True).encode()),
                "needs_list": sorted(st.get("needs", [])),
                "runtime_sha": sha(json.dumps(runtime, sort_keys=True, default=str).encode())}

    # ---- validation ---------------------------------------------------------
    def validate(self, name: str, seen: frozenset = frozenset()) -> dict:
        if name in seen:
            raise Blocked(f"dependency cycle at {name}")
        st = self.stages.get(name)
        if st is None:
            raise Blocked(f"unknown stage {name}")
        rp = self.receipt_path(name)
        if not rp.exists():
            raise Blocked(f"no receipt for stage {name}")
        r = json.loads(rp.read_text())
        if r.get("stage") != name or r.get("pipeline") != self.p.get("name"):
            raise Blocked(f"receipt {rp.name} is bound to another stage or pipeline")
        if r.get("verdict") != "PASS":
            raise Blocked(f"stage {name} verdict {r.get('verdict')}")
        if r.get("manifest_sha") != file_sha(self.manifest_path(st)):
            raise Blocked(f"stage {name} manifest changed since its receipt")
        now = self.binding(st)
        for k, v in now.items():
            if r.get("binding", {}).get(k) != v:
                raise Blocked(f"stage {name} {k} changed since its receipt")
        if sorted(r.get("needs", {})) != now["needs_list"]:
            raise Blocked(f"stage {name} receipt dependencies differ from the current pipeline")
        run_copy = self.receipts / f"{name}.run.json"
        if not run_copy.exists() or file_sha(run_copy) != r.get("run_record_sha"):
            raise Blocked(f"run record for {name} missing or altered")
        run = json.loads(run_copy.read_text())
        expected = sorted(t["key"] for t in json.loads(self.manifest_path(st).read_text())["tasks"])
        got = sorted(t["key"] for t in run["tasks"])
        if got != expected or sorted(r["artifacts"]) != expected:
            raise Blocked(f"stage {name} receipt covers {got}, manifest expects {expected}")
        bad = [t["key"] for t in run["tasks"] if t.get("verdict") != "PASS"]
        if bad:
            raise Blocked(f"run record for {name} not all PASS: {bad}")
        for key, rec in r["artifacts"].items():
            if tree_digest(Path(rec["taskdir"]))[0] != rec["digest"]:
                raise Blocked(f"stale receipt: {name}/{key} artifacts changed since PASS")
        if self.checks_digest() != r["checks_digest"]:
            raise Blocked(f"check files changed since {name} passed")
        for need, need_sha in r.get("needs", {}).items():
            self.validate(need, seen | {name})
            if file_sha(self.receipt_path(need)) != need_sha:
                raise Blocked(f"{name} consumed a different {need} receipt than the current one")
        return r

    def snapshot(self, stage: str, needs: dict[str, dict]) -> Path:
        inputs = self.root / "inputs" / stage
        if inputs.exists():
            make_writable(inputs)
            shutil.rmtree(inputs)
        inputs.mkdir(parents=True)
        for need, r in needs.items():
            for key, rec in r["artifacts"].items():
                dst = inputs / need / key
                shutil.copytree(rec["taskdir"], dst, symlinks=True, ignore=shutil.ignore_patterns(*EXCLUDE))
                if tree_digest(dst)[0] != rec["digest"]:
                    raise Blocked(f"snapshot of {need}/{key} does not match its receipt")
        set_readonly(inputs)
        return inputs

    # ---- execution ----------------------------------------------------------
    def run_stage(self, st: dict, needs: dict[str, dict]) -> dict:
        name = st["name"]
        mpath = self.manifest_path(st)
        inputs = self.snapshot(name, needs)
        manifest = render(json.loads(mpath.read_text()),
                          {"inputs": str(inputs), "checks": str(self.checks), "root": str(self.root)})
        for t in manifest["tasks"]:
            if not str(t.get("check", "")).strip():
                raise Blocked(f"task {t.get('key')} has no check; unchecked work cannot pass the gate")
        self.require_isolation(manifest)
        rendered = self.root / "manifests" / f"{name}.json"
        rendered.parent.mkdir(parents=True, exist_ok=True)
        rendered.write_text(json.dumps(manifest, indent=1))

        checks_before = self.checks_digest()
        inputs_before = tree_digest(inputs)[0]
        limit = st.get("timeout_s") or 120 + sum(
            (t.get("timeout_s", 900) + t.get("check_timeout_s", 60)) * t.get("max_attempts", 2)
            for t in manifest["tasks"])
        logs = self.root / "logs"
        logs.mkdir(exist_ok=True)
        cmd = [sys.executable, str(RINGER), "--no-self-update", "run", str(rendered),
               "--no-dashboard", "--no-artifact"]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                                env={**os.environ, "RINGER_NO_SELF_UPDATE": "1"}, start_new_session=True)
        out_path = logs / f"{name}.out"
        seen: dict[int, str] = {}
        workdir = Path(manifest["workdir"]).resolve()
        deadline = time.monotonic() + limit
        reader = threading.Thread(target=lambda: out_path.write_text(proc.stdout.read() or ""))
        reader.start()
        while proc.poll() is None and time.monotonic() < deadline:
            table = proc_table()  # remember workers (pid + start time) before they can be reparented
            seen.update({p: table[p][1] for p in descendants(proc.pid) if p in table})
            time.sleep(0.25)
        if proc.poll() is None:
            alive = kill_tree(proc.pid, still_same(seen), workdir)
            reader.join(10)
            raise Blocked(f"stage {name} exceeded controller timeout {limit}s; survivors after kill: {alive}")
        reader.join()
        out = out_path.read_text()
        leftovers = still_same(seen) + cwd_inside(workdir)
        if leftovers:
            survivors = kill_tree(0, leftovers, workdir)
            raise Blocked(f"stage {name} left background processes {sorted(set(leftovers))} after Ringer exited; "
                          f"killed, survivors: {survivors}")
        m = re.search(r"run_id:\s*(\S+)", out or "")
        if not m:
            raise Blocked(f"ringer exited {proc.returncode} without a run_id")
        run_file = runs_dir() / f"{m.group(1)}.json"
        run_copy = self.receipts / f"{name}.run.json"
        shutil.copyfile(run_file, run_copy)
        run = json.loads(run_copy.read_text())

        checks_after = self.checks_digest()
        inputs_after = tree_digest(inputs)[0]
        tasks = {t["key"]: t for t in run["tasks"]}
        verdicts = {k: t.get("verdict") or t.get("status") for k, t in tasks.items()}
        expected = sorted(t["key"] for t in manifest["tasks"])
        verdict = "PASS" if sorted(tasks) == expected and all(v == "PASS" for v in verdicts.values()) else "FAIL"
        problems = []
        if checks_after != checks_before:
            problems.append("check files changed during run")
        if inputs_after != inputs_before:
            problems.append("input snapshot changed during run")
        if problems:
            verdict = "BLOCKED"

        problems += self.verify_invocations(name, tasks)
        if problems and verdict == "PASS":
            verdict = "BLOCKED"
        artifacts, raw = {}, {}
        for k, t in tasks.items():
            taskdir = Path(t["taskdir"])
            spec_t = manifest_task(manifest, k)
            ctl = run_controller_check(spec_t["check"], taskdir, int(spec_t.get("check_timeout_s", 60)),
                                       self.receipts / f"{name}.{k}.check.out") if taskdir.is_dir() else {"exit": "NO_TASKDIR"}
            if ctl["exit"] != 0 and verdict == "PASS":
                verdict = "FAIL"
                problems.append(f"{k}: controller re-run of the check exited {ctl['exit']}")
            missing = [f for f in manifest_task(manifest, k).get("expect_files", []) if not (taskdir / f).is_file()]
            if missing:
                verdict = "FAIL" if verdict == "PASS" else verdict
                problems.append(f"{k}: missing expected files {missing}")
            digest, files = tree_digest(taskdir) if taskdir.is_dir() else ("", {})
            artifacts[k] = {"taskdir": str(taskdir), "digest": digest, "files": files}
            log_copy = self.receipts / f"{name}.{k}.worker.log"
            if t.get("log_path") and Path(t["log_path"]).is_file():
                shutil.copyfile(t["log_path"], log_copy)
            raw[k] = {"worker_log_copy": str(log_copy), "ringer_check_returncode": t.get("check_returncode"),
                      "controller_check": ctl}
        receipt = {
            "pipeline": self.p.get("name"), "stage": name, "run_id": run["run_id"], "verdict": verdict,
            "verdicts": verdicts, "problems": problems, "ringer_exit": proc.returncode,
            "manifest_sha": file_sha(mpath), "rendered_manifest_sha": file_sha(rendered), "binding": self.binding(st),
            "run_record_sha": file_sha(run_copy), "checks_digest": checks_before,
            "inputs_digest": inputs_before,
            "needs": {n: file_sha(self.receipt_path(n)) for n in needs},
            "artifacts": artifacts, "raw": raw,
            "finished_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        self.receipt_path(name).write_text(json.dumps(receipt, indent=1))
        return receipt

    def run(self, stop_after: str | None, resume: bool) -> int:
        order = self.p["stages"]
        for i, st in enumerate(order):
            name = st["name"]
            try:
                if resume and self.receipt_path(name).exists():
                    try:
                        self.validate(name)
                        self.log(stage=name, event="receipt_revalidated_skip")
                        if stop_after == name:
                            return 0
                        continue
                    except Blocked as e:
                        self.log(stage=name, event="receipt_invalid_rerun", reason=str(e))
                needs = {n: self.validate(n) for n in st.get("needs", [])}
                self.log(stage=name, event="launch", needs=list(needs))
                r = self.run_stage(st, needs)
                self.log(stage=name, event="result", verdict=r["verdict"], run_id=r["run_id"],
                         verdicts=r["verdicts"], problems=r["problems"])
                if r["verdict"] != "PASS":
                    raise Blocked(f"stage {name} verdict {r['verdict']} {r['verdicts']} {r['problems']}")
            except Blocked as e:
                self.log(stage=name, event="BLOCKED", reason=str(e),
                         not_started=[s["name"] for s in order[i + 1:]])
                return 2
            if stop_after == name:
                self.log(stage=name, event="stopped_after")
                return 0
        for st in order:  # final certification: every receipt must still validate
            try:
                self.validate(st["name"])
            except Blocked as e:
                self.log(event="BLOCKED", reason=f"final revalidation: {e}")
                return 2
        self.log(event="pipeline_pass")
        return 0


def manifest_task(manifest: dict, key: str) -> dict:
    return next((t for t in manifest["tasks"] if t["key"] == key), {})


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("pipeline", type=Path)
    ap.add_argument("--stop-after", help="stop after this stage passes")
    ap.add_argument("--resume", action="store_true", help="skip stages whose receipts still validate")
    a = ap.parse_args()
    return Gate(a.pipeline).run(a.stop_after, a.resume)


if __name__ == "__main__":
    sys.exit(main())
