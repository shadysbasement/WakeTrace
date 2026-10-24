[![WakeTrace banner](docs/assets/waketrace-banner.svg)](docs/assets/waketrace-banner.svg)

# WakeTrace

[GitHub repo](https://github.com/shadysbasement/WakeTrace) · [Full-size banner](docs/assets/waketrace-banner.svg) · [Logo](docs/assets/waketrace-logo.svg) · [Demo screenshot](docs/assets/demo-terminal.png) · [Command screenshot](docs/assets/commands-terminal.png)

I started WakeTrace because I kept thinking about a script that behaves normally when you first run it, then does something completely different a few days later. If I have to wait three days to find out, I've already missed the point.

WakeTrace lets me run a copy of a Python script or package at different simulated times. It records what happened, compares that behavior with a baseline I chose, and shows me *when* something new appeared. The example in this repo is a small time bomb made for testing; it doesn't need a real secret or a real network connection.

## The idea

Say I trust version one of a package and want to check version two. I make a behavior lock from version one, then run version two at `0`, `24`, and `72` hours. If it starts reading a secret, opening a file, launching a process, or attempting a network request only at hour `72`, I want to see that difference in the report instead of guessing from the source code.

WakeTrace runs the copy inside a Bubblewrap sandbox. It also gives the run fake secrets, called canaries, so the report can show if one was read or used. Package installation and the package exercise happen inside containment too.

## Try the demo

You'll need Linux, Python 3.14 at `/usr/bin/python3`, Bubblewrap (`bwrap`), and working unprivileged user namespaces. From the WakeTrace folder, run:

```bash
.venv/bin/python main.py preflight
.venv/bin/python main.py demo
```

`preflight` checks that the sandbox can start. `demo` compares the included clean script with the delayed one. It writes `behavior.lock.json` and `reports/latest_report.json` in the folder you ran it from. Open the report and look at the findings for each hour; the interesting part is when the new behavior first shows up.

This is a screenshot from an actual demo run. It stays clean at `0` and `24` hours, then catches the new behavior at `72` hours:

[![WakeTrace demo terminal output](docs/assets/demo-terminal.png)](docs/assets/demo-terminal.png)

If you want to see every command before using your own files:

```bash
.venv/bin/python main.py --help
.venv/bin/python main.py lock --help
.venv/bin/python main.py verify --help
```

Here's what the main command list looks like:

[![WakeTrace command help in the terminal](docs/assets/commands-terminal.png)](docs/assets/commands-terminal.png)

## Check your own script

Start with a baseline you have actually reviewed and decided to trust:

```bash
.venv/bin/python main.py lock path/to/baseline.py -o baseline.lock.json --horizons 0,24,72
.venv/bin/python main.py verify path/to/candidate.py -b baseline.lock.json -r report.json --horizons 0,24,72
```

The lock records the baseline's identity and what it did at those hours. The verify command saves a report with the candidate's findings, evidence, risk score, and verdict. WakeTrace can also work with wheels, source archives, and source directories; for those, use `--exercise` to say whether it should import a module, run a console entry point, or run a command.

There's also a local admission gate for a stricter check. It takes a plan, a signed approval for the baseline, and named scenarios, then returns `PASS`, `REVIEW`, `BLOCK`, or `ERROR`. It needs `strace` on your `PATH` and OpenSSL. Run `.venv/bin/python main.py gate --help` to see its inputs. The gate is local for now; it isn't a required GitHub check yet.

## Run the tests

With `pytest` installed in a working Python 3.14 `.venv`, and `strace` on your `PATH`:

```bash
PATH="$PWD/.venv/bin:$PATH" .venv/bin/python -m pytest -q tests/test_1.py tests/test_2.py tests/test_3.py tests/test_4.py tests/test_5.py tests/test_6.py tests/test_7.py tests/test_10.py
```

These tests use small scripts and packages written for WakeTrace. They cover the clock hook, containment, behavior locks, package setup, CLI, and admission gate.

## If you're looking through the code

Start with `main.py` for the commands. `runner.py`, `isolation.py`, and `sandbox_hooks/` handle the contained runs and record events. `package_input.py` and `package_runner.py` handle package inputs. `lockfile.py`, `differ.py`, and `schema.py` turn runs into locks and reports. The `gate_*.py` files and `gate.py` handle plans, approvals, and admission decisions. The `demo_pkgs/`, `examples/`, and `tests/` folders have the synthetic examples and checks.

## What a clean result means

It means WakeTrace didn't find a concerning difference in the paths and times it tested. It doesn't mean the code is safe in every situation. Some native clock calls can still see real time, and a blocked network attempt doesn't prove that anything was sent. I want the report to be useful about what it *saw*, and honest about what it couldn't see.

The [standalone WakeTrace logo](docs/assets/waketrace-logo.svg) is here too if you want to use it outside the README.
