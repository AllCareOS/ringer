# Stage gate demo

`run_demo.sh [BASE_DIR]` runs a 3-stage OpenCode pipeline (numbers -> sum -> report) through `scripts/ringer_gate.py`, then five cases that must stop before stage s2 launches: failing check, worker timeout, missing expected file, check script edited after s1 passed, and s1 artifact edited after its receipt (stale receipt). Each line ends `OK` when the gate behaved as required. Requires the `opencode` engine in `~/.config/ringer/config.toml`.
