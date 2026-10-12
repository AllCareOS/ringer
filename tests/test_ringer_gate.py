#!/usr/bin/env python3
"""scripts/ringer_gate.py: a dependent stage launches only on a receipt that re-validates.

Pinned here (no workers spawn; receipts and run records are fabricated):
  * symlinks in artifacts are refused, so a link target cannot change behind a digest
  * engines without a verified write sandbox, and full_access tasks, are refused
  * --resume never skips a stage on receipt existence alone: FAIL, stale,
    changed-manifest and changed-check receipts are re-run, not certified
  * a missing checks_dir is an error, not an empty digest
  * the engine bin must be byte-identical to the repo's Seatbelt wrapper, with
    no escape flag in its arguments, and gate state outside its writable roots
  * the command Ringer actually logged must launch the wrapper on the task dir
  * receipts bind the current dependency set and runtime configuration
  * a timeout kills Ringer's detached worker sessions, not just its own group
  * the controller re-runs each check and keeps its complete raw output
"""
from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("ringer_gate", ROOT / "scripts" / "ringer_gate.py")
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)

SANDBOX_CONFIG = (f'allow_full_access = false\n[engines.opencode]\nbin = "{gate.TRUSTED_WRAPPER}"\n'
                  'args_template = ["{taskdir}", "{access_args}", "run", "--dir", "{taskdir}", "{spec}"]\n'
                  'sandbox_args = []\nfull_access_args = ["--no-sandbox"]\n')


class GateFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        cfg = self.base / "config.toml"
        cfg.write_text(SANDBOX_CONFIG)
        self.env = {"RINGER_CONFIG": str(cfg), "RINGER_STATE_DIR": str(self.base / "state")}
        self._old = {k: os.environ.get(k) for k in self.env}
        os.environ.update(self.env)
        self.checks = self.base / "checks"
        self.checks.mkdir()
        (self.checks / "c.sh").write_text("true\n")
        self.root = self.base / "root"
        (self.base / "s1.json").write_text(json.dumps({"workdir": str(self.root / "work" / "s1"), "tasks": [
            {"key": "gen", "engine": "opencode", "check": "sh {checks}/c.sh", "expect_files": ["out.txt"]}]}))
        self.pipeline = self.base / "pipeline.json"
        self.pipeline.write_text(json.dumps({"name": "t", "root": str(self.root), "checks_dir": str(self.checks),
                                             "stages": [{"name": "s1", "manifest": "s1.json", "needs": []}]}))

    def tearDown(self) -> None:
        for k, v in self._old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        self.tmp.cleanup()

    def write_receipt(self, g, verdict: str = "PASS") -> Path:
        taskdir = self.root / "work" / "s1" / "gen"
        taskdir.mkdir(parents=True, exist_ok=True)
        (taskdir / "out.txt").write_text("hello\n")
        run = {"run_id": "r1", "tasks": [{"key": "gen", "verdict": verdict, "taskdir": str(taskdir)}]}
        run_copy = g.receipts / "s1.run.json"
        run_copy.write_text(json.dumps(run))
        receipt = {"pipeline": "t", "stage": "s1", "run_id": "r1", "verdict": verdict,
                   "manifest_sha": gate.file_sha(self.base / "s1.json"), "run_record_sha": gate.file_sha(run_copy),
                   "checks_digest": g.checks_digest(), "needs": {}, "binding": g.binding(g.stages["s1"]),
                   "artifacts": {"gen": {"taskdir": str(taskdir), "digest": gate.tree_digest(taskdir)[0]}}}
        g.receipt_path("s1").write_text(json.dumps(receipt))
        return taskdir

    def resume_with_fake_run(self, g, fake_verdict: str) -> tuple[int, list[str]]:
        calls: list[str] = []

        def fake_run_stage(st, needs):
            calls.append(st["name"])
            return {"verdict": fake_verdict, "run_id": "r2", "verdicts": {"gen": fake_verdict}, "problems": []}

        g.run_stage = fake_run_stage
        return g.run(None, True), calls


class SymlinkTests(GateFixture):
    def test_symlink_in_artifact_is_refused(self) -> None:
        d = self.base / "art"
        d.mkdir()
        (self.base / "outside.txt").write_text("v1")
        (d / "link.txt").symlink_to(self.base / "outside.txt")
        with self.assertRaisesRegex(gate.Blocked, "symlink"):
            gate.tree_digest(d)


class IsolationTests(GateFixture):
    def manifest(self, **task) -> dict:
        t = {"key": "gen", "engine": "opencode", "check": "true", **task}
        return {"workdir": str(self.root / "work" / "s1"), "tasks": [t]}

    def test_unsandboxed_engine_is_refused(self) -> None:
        g = gate.Gate(self.pipeline)
        with self.assertRaisesRegex(gate.Blocked, "not configured|not the trusted Seatbelt wrapper"):
            g.require_isolation(self.manifest(engine="codex"))

    def test_full_access_task_is_refused(self) -> None:
        g = gate.Gate(self.pipeline)
        with self.assertRaisesRegex(gate.Blocked, "full_access"):
            g.require_isolation(self.manifest(full_access=True))

    def test_gate_state_inside_task_dir_is_refused(self) -> None:
        g = gate.Gate(self.pipeline)
        m = self.manifest()
        m["workdir"] = str(self.root.parent)
        m["tasks"][0]["key"] = "root"
        with self.assertRaisesRegex(gate.Blocked, "sandbox-writable"):
            g.require_isolation(m)

    def test_sandboxed_engine_passes(self) -> None:
        gate.Gate(self.pipeline).require_isolation(self.manifest())


class ResumeTests(GateFixture):
    def test_valid_receipt_is_skipped(self) -> None:
        g = gate.Gate(self.pipeline)
        self.write_receipt(g)
        code, calls = self.resume_with_fake_run(g, "FAIL")
        self.assertEqual((code, calls), (0, []))

    def test_fail_receipt_is_rerun_not_certified(self) -> None:
        g = gate.Gate(self.pipeline)
        self.write_receipt(g, verdict="FAIL")
        code, calls = self.resume_with_fake_run(g, "FAIL")
        self.assertEqual((code, calls), (2, ["s1"]))
        self.assertNotIn("pipeline_pass", g.log_path.read_text())

    def test_stale_artifact_is_rerun(self) -> None:
        g = gate.Gate(self.pipeline)
        taskdir = self.write_receipt(g)
        (taskdir / "out.txt").write_text("changed\n")
        code, calls = self.resume_with_fake_run(g, "FAIL")
        self.assertEqual((code, calls), (2, ["s1"]))

    def test_changed_manifest_is_rerun(self) -> None:
        g = gate.Gate(self.pipeline)
        self.write_receipt(g)
        (self.base / "s1.json").write_text((self.base / "s1.json").read_text().replace("out.txt", "o2.txt"))
        code, calls = self.resume_with_fake_run(g, "FAIL")
        self.assertEqual((code, calls), (2, ["s1"]))

    def test_changed_check_is_rerun(self) -> None:
        g = gate.Gate(self.pipeline)
        self.write_receipt(g)
        (self.checks / "c.sh").write_text("exit 0\n")
        code, calls = self.resume_with_fake_run(g, "FAIL")
        self.assertEqual((code, calls), (2, ["s1"]))

    def test_altered_run_record_is_rerun(self) -> None:
        g = gate.Gate(self.pipeline)
        self.write_receipt(g)
        (g.receipts / "s1.run.json").write_text('{"run_id":"r1","tasks":[]}')
        code, calls = self.resume_with_fake_run(g, "FAIL")
        self.assertEqual((code, calls), (2, ["s1"]))


class WrapperBindingTests(GateFixture):
    def manifest(self, **task) -> dict:
        t = {"key": "gen", "engine": "opencode", "check": "true", **task}
        return {"workdir": str(self.root / "work" / "s1"), "tasks": [t]}

    def reconfigure(self, text: str) -> gate.Gate:
        Path(os.environ["RINGER_CONFIG"]).write_text(text)
        return gate.Gate(self.pipeline)

    def test_lookalike_wrapper_is_refused(self) -> None:
        fake = self.base / "engines" / "opencode-sandboxed.sh"
        fake.parent.mkdir()
        fake.write_text("#!/bin/sh\nshift; exec opencode \"$@\"\n")
        g = self.reconfigure(SANDBOX_CONFIG.replace(str(gate.TRUSTED_WRAPPER), str(fake)))
        with self.assertRaisesRegex(gate.Blocked, "not the trusted Seatbelt wrapper"):
            g.require_isolation(self.manifest())

    def test_escape_flag_in_args_template_is_refused(self) -> None:
        g = self.reconfigure(SANDBOX_CONFIG.replace('"run",', '"--no-sandbox", "run",'))
        with self.assertRaisesRegex(gate.Blocked, "escape flag"):
            g.require_isolation(self.manifest())

    def test_escape_flag_in_task_engine_args_is_refused(self) -> None:
        with self.assertRaisesRegex(gate.Blocked, "escape flag"):
            gate.Gate(self.pipeline).require_isolation(self.manifest(engine_args=["--no-sandbox"]))

    def test_gate_state_inside_wrapper_write_root_is_refused(self) -> None:
        old = gate.WRAPPER_WRITE_ROOTS
        gate.WRAPPER_WRITE_ROOTS = [self.base]
        try:
            with self.assertRaisesRegex(gate.Blocked, "sandbox-writable"):
                gate.Gate(self.pipeline).require_isolation(self.manifest())
        finally:
            gate.WRAPPER_WRITE_ROOTS = old

    def write_log(self, command: str) -> dict:
        taskdir = self.root / "work" / "s1" / "gen"
        taskdir.mkdir(parents=True, exist_ok=True)
        log = taskdir / "worker.log"
        log.write_text(f"[ringer.py] engine: opencode\n[ringer.py] command: {command} < /dev/null\n")
        return {"gen": {"engine": "opencode", "taskdir": str(taskdir), "log_path": str(log)}}

    def test_logged_invocation_is_verified(self) -> None:
        g = gate.Gate(self.pipeline)
        td = self.root / "work" / "s1" / "gen"
        ok = self.write_log(f"{gate.TRUSTED_WRAPPER} {td} run --dir {td} spec")
        self.assertEqual(g.verify_invocations("s1", ok), [])
        esc = self.write_log(f"{gate.TRUSTED_WRAPPER} {td} --no-sandbox run spec")
        self.assertTrue(any("escape" in p for p in g.verify_invocations("s1", esc)))
        other = self.write_log(f"{gate.TRUSTED_WRAPPER} {self.base} run spec")
        self.assertTrue(any("not the task dir" in p for p in g.verify_invocations("s1", other)))
        wrong = self.write_log(f"/usr/bin/env {td} run spec")
        self.assertTrue(any("trusted wrapper" in p for p in g.verify_invocations("s1", wrong)))


class BindingTests(GateFixture):
    def test_changed_dependency_set_is_rerun(self) -> None:
        g = gate.Gate(self.pipeline)
        self.write_receipt(g)
        p = json.loads(self.pipeline.read_text())
        p["stages"].insert(0, {"name": "s0", "manifest": "s1.json", "needs": []})
        p["stages"][1]["needs"] = ["s0"]
        self.pipeline.write_text(json.dumps(p))
        with self.assertRaisesRegex(gate.Blocked, "changed since its receipt"):
            gate.Gate(self.pipeline).validate("s1")

    def test_changed_runtime_config_is_rerun(self) -> None:
        g = gate.Gate(self.pipeline)
        self.write_receipt(g)
        Path(os.environ["RINGER_CONFIG"]).write_text(SANDBOX_CONFIG.replace('"run",', '"run", "--auto",'))
        with self.assertRaisesRegex(gate.Blocked, "runtime_sha changed"):
            gate.Gate(self.pipeline).validate("s1")


class KillTreeTests(unittest.TestCase):
    def test_detached_grandchild_is_killed(self) -> None:
        marker = f"{time.time_ns()}"
        child = subprocess.Popen([sys.executable, "-c", (
            "import subprocess,sys,time;"
            f"subprocess.Popen(['sleep','7{marker[-5:]}'], start_new_session=True);"
            "time.sleep(600)")])
        time.sleep(1.0)
        grandchildren = gate.descendants(child.pid)
        self.assertTrue(grandchildren, "fixture should have spawned a detached sleeper")
        self.assertEqual(gate.kill_tree(child.pid), [])
        child.wait(timeout=5)
        for p in grandchildren:
            with self.assertRaises(ProcessLookupError):
                os.kill(p, 0)


class ControllerCheckTests(unittest.TestCase):
    def test_full_raw_output_is_kept(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "check.out"
            r = gate.run_controller_check("python3 -c \"print('x'*5000)\"; echo err >&2; exit 3", Path(d), 30, out)
            self.assertEqual(r["exit"], 3)
            data = out.read_bytes()
            self.assertIn(b"x" * 5000, data)
            self.assertIn(b"err", data)
            self.assertEqual(r["output_sha"], gate.sha(data))


class ChecksDirTests(GateFixture):
    def test_missing_checks_dir_is_an_error(self) -> None:
        for p in self.checks.iterdir():
            p.unlink()
        self.checks.rmdir()
        with self.assertRaises(SystemExit):
            gate.Gate(self.pipeline)


if __name__ == "__main__":
    unittest.main()
