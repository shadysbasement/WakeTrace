# WakeTrace v1.0.2

im creating WakeTrace cuz i wanted to check one thing, what if a python script looks fine when you run it today, but waits a day or two before doing something suspicious? (basically a time-bomb script), and i don't wanna leave a test running for days just to find out.

this is the first contained version of that idea. it runs a copy of a script at different simulated times and records what happens at each one. the goal is to make delayed behavior easier to spot and explain.

## What works in this version

- The time hook can make the python's clock move forward and skip long sleeps, so a test finishes faster than it woulda.
- The runner makes a temporary copy of the input and it runs it inside a bubblewrap sandbox on linux.
- It records file access, environment reads, network attempts, processes, native library loads, and captured output. (rn i might add more things in the future)
- It uses dummy secret values (canaries) to show when a script reads, prints, or tries to send one. (kinda like a honeypot)
- A multi-horizon run compares the fresh run with later runs and reports the first hour where it sees a new risk action.
- The tests uses small scripts made just for testing, so like they don't need a real suspicious package.

## What you need for this

- Linux
- CPython 3.14, including `/usr/bin/python3` at version 3.14
- Bubblewrap (`bwrap`)
- `pytest` in your local `.venv` to run the testss
- `strace` only if you turn on the optional host observer

The runner checks its containment setup before it runs a target, so if that check ends up failing, it stops instead of running the target normally on your pc.

## Files so far

- `runner.py` it stages the scripts, runs the time horizons and creates the summary
- `isolation.py` sets up and checks the sandbox and resource limits
- `package_input.py` this checks executable directory inputs
- `observer.py` supports the optional host syscall observer
- `sandbox_hooks/sitecustomize.py` changes the child's view of time and records events
- `sandbox_hooks/launch.py` starts the copied script inside the sandbox
- `tests/test_1.py` checks the hook itself
- `tests/test_2.py` checks the contained runner and multi-horizon behavior

## Run the tests

from the WakeTrace folder, after creating a Python 3.14 virtual environment and installing `pytest` in it run this:

```bash
.venv/bin/python -m pytest -q tests/test_1.py tests/test_2.py
```

the runner tests also need bubblewrap and the linux setup above, if a test fails, check the error before calling this version finished.

## Where it is right now

This is still an early build, it can give useful evidence about delayed behavior, but like a clean run does not really prove that a script is safe. The time changes and event hooks mainly cover Python behavior, and the full CLI, dashboard, and GitHub admission workflow are later parts of the project.