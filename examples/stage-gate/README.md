# Stage gate demo

`run_demo.sh [BASE_DIR]` drives `scripts/ringer_gate.py` with real Ringer runs (Python 3.11+, the sandboxed `opencode` engine in `~/.config/ringer/config.toml`). Every line must end `OK`:

- `happy`: numbers -> sum -> report certifies (`pipeline_pass`).
- `failcheck`, `timeout`, `missing`, `symlink`, `codex`: stage s2 never launches (failing check, worker timeout, missing expected file, symlinked artifact, engine without a verified write sandbox).
- `failresume`, `editedcheck`, `stale`: on `--resume` the invalid s1 receipt (FAIL, check edited after PASS, artifact edited after PASS) is re-run, never skipped.
- `treekill`: a never-finishing worker (`sleeper/opencode`) that also leaves a detached grandchild; the stage controller timeout must kill Ringer, the worker and the grandchild.
- `mutate`: a deterministic hostile worker (`hostile/opencode`, run through the real Seatbelt wrapper) tries to chmod and write its input snapshot, the check scripts, the receipts and the gate log. Every attempt must be denied and the pipeline still certifies on unchanged inputs.

Input snapshots are left read-only; run `chmod -R u+w BASE_DIR` before deleting a demo directory.
