# WakeTrace

im building WakeTrace because I wanted to answer one question: what if a Python script looks fine today, but waits a day or two before doing something suspicious? I don't wanna leave a test running for days just to find out.

WakeTrace runs a temporary copy of a script at different simulated times and records what happens. The idea is to make delayed behavior easier to spot and explain, while keeping the test away from my real files and network.

## What I've built so far

- The time hook moves the script's Python clocks forward and skips long sleeps, so I can test hours or days of behavior quickly.
- The runner makes a temporary copy and runs it inside a bubblewrap sandbox on linux.
- It records file access, environment reads, network attempts, spawned processes, native library loads, and output.
- Dummy secrets called canaries help show when a script reads, prints, writes, or tries to send one.
- Multi-horizon runs compare what the script does now with what it does later.

## What's new in this part

I can now make a **behavior lock** from a baseline script. The lock records its file hash, the time horizons I tested, and the capabilities I observed. Then I can run a candidate script and compare its behavior with that baseline.

The comparison gives me findings, a risk score, and a verdict: `CLEAN`, `WARNING`, `BLOCKED`, or `INCOMPLETE`. It also keeps the evidence for each time horizon, so I can see *when* a new action first appeared. An incomplete run or missing time coverage shouldn't quietly turn into a clean result.

The baseline is something I choose to trust for the comparison. Making a lock doesn't prove that the baseline itself is safe.

## Files so far

- `runner.py` runs the script at different time horizons and summarizes what happened.
- `isolation.py` checks and sets up the sandbox and resource limits.
- `sandbox_hooks/sitecustomize.py` changes the child's view of time and records events.
- `sandbox_hooks/launch.py` starts the copied script inside the sandbox.
- `package_input.py` checks executable directory inputs.
- `observer.py` supports optional host syscall observation.
- `lockfile.py` creates and loads behavior locks.
- `differ.py` compares a run with a behavior lock and builds a report.
- `schema.py` validates locks and reports before they are used.
- `tests/test_1.py`, `tests/test_2.py`, `tests/test_3.py`, and `tests/test_5.py` test the hook, runner, comparison, and containment behavior with small synthetic scripts.

## What you need

- Linux with working unprivileged user namespaces
- CPython 3.14, including `/usr/bin/python3` at version 3.14
- Bubblewrap (`bwrap`)
- `pytest` in a working local `.venv` to run the tests
- `strace` only if you enable the optional host observer

The runner checks containment before it runs a target. If that check fails, it stops instead of running the target normally on your machine.

## Run the tests

From the WakeTrace folder:

```bash
.venv/bin/python -m pytest -q tests/test_1.py tests/test_2.py tests/test_3.py tests/test_5.py
```

There isn't a CLI or dashboard in this part yet, so these tests are the easiest way to see the baseline, delayed behavior, and containment checks in action.

## Where it is right now

This is still an early build. A clean result means WakeTrace didn't see a concerning difference in the horizons it tested; it doesn't prove a script is safe. The time changes and event hooks mainly cover Python behavior. The CLI, dashboard, and GitHub admission workflow come later.