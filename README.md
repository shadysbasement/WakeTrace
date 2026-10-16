# WakeTrace

I started WakeTrace cuz i wanted to look at a simple question: what if a script seems fine when you first run it, but does something different after a few hours or days? (basically a time bomb script)

The idea is to check for that delayed behavior without actually waitin days to see it, this first commit is just me getting the time part working, it is a small prototype, not the finished security tool yet.

## What im working on right now

For this first version, im writing a python hook that can make a test script see a different time, it also records some of what the script does, so i can check the result instead of just guessing whether the time change worked.

the test uses a small script i wrote, it checks that a long sleep can finish quickly and that the script's clocks move forward as expected.

## What's in this first commit

- `sandbox_hooks/sitecustomize.py`: the time and event hook.
- `sandbox_hooks/__init__.py`: marks the folder as a Python package.
- `tests/test_1.py`: tests the idea using a synthetic script.

## Running the test

From the WakeTrace folder, run:

```bash
python3 -m pytest -q tests