#!/usr/bin/env python3
"""scripts/ringer_gate.py: a dependent stage launches only on a receipt that re-validates.

Pinned here (no workers spawn; receipts and run records are fabricated):
  * symlinks in artifacts are refused, so a link target cannot change behind a digest
  * engines without a verified write sandbox, and full_access tasks, are refused
  * --resume never skips a stage on receipt existence alone: FAIL, stale,
    changed-manifest and changed-check receipts are re-run, not certified
  * a missing checks_dir is an error, not an empty digest
"""
from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("ringer_gate", ROOT / "scripts" / "ringer_gate.py")
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)

SANDBOX_CONFIG = 'allow_full_access = false\n[engines.opencode]\nbin = "/x/engines/opencode-sandboxed.sh"\n'


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
                   "checks_digest": g.checks_digest(), "needs": {},
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
        with self.assertRaisesRegex(gate.Blocked, "no verified write sandbox"):
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
        with self.assertRaisesRegex(gate.Blocked, "inside writable task dir"):
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


class ChecksDirTests(GateFixture):
    def test_missing_checks_dir_is_an_error(self) -> None:
        for p in self.checks.iterdir():
            p.unlink()
        self.checks.rmdir()
        with self.assertRaises(SystemExit):
            gate.Gate(self.pipeline)


if __name__ == "__main__":
    unittest.main()
