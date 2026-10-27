"""Repeat a small synthetic gate corpus and print measured local results."""

import json
from pathlib import Path
import statistics
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_10 import decide, setup_case, sign
from package_input import inspect


CASES = [
    ("benign", "PASS", "print('ok')\n", [0]),
    ("output_exposure", "REVIEW", "import os\nprint(os.environ['OPENAI_API_KEY'])\n", [0]),
    ("encoded_canary", "REVIEW", "import base64,os\nprint(base64.b64encode(os.environ['OPENAI_API_KEY'].encode()).decode())\n", [0]),
    ("blocked_network", "BLOCK", "import socket\ns=socket.socket()\ntry:s.connect(('127.0.0.1',9))\nexcept OSError:pass\n", [0]),
    ("delayed_file_age", "BLOCK", "import os,time\nif time.time()-os.path.getmtime(__file__)>48*3600:\n print(os.environ['OPENAI_API_KEY'])\n", [0, 72]),
    ("long_sleep", "REVIEW", "import os,time\ntime.sleep(72*3600)\nprint(os.environ['OPENAI_API_KEY'])\n", [0]),
    ("native_ctypes", "ERROR", "import ctypes\nctypes.CDLL(None).time(None)\n", [0]),
    ("unsupported_clock", "ERROR", "import time\nprint(time.time_ns())\n", [0]),
    ("hookless_child", "ERROR", "import subprocess\nsubprocess.run(['python3','-S','-c','print(1)'])\n", [0]),
    ("trace_tamper", "ERROR", "open('/trace/events.jsonl','a').write('{broken\\n')\n", [0]),
    ("target_crash", "ERROR", "raise RuntimeError('synthetic')\n", [0]),
    ("timeout", "ERROR", "while True:pass\n", [0]),
    ("baseline_tamper", "ERROR", "print('ok')\n", [0]),
    ("candidate_swap", "ERROR", "print('changed')\n", [0]),
]


def measure():
    observations = []
    for repeat in range(2):
        for name, expected, code, hours in CASES:
            with tempfile.TemporaryDirectory() as temp:
                plan, path, public, private = setup_case(temp, hours=hours)
                candidate = Path(plan["candidate"]["path"])
                candidate.write_text(code)
                if name != "candidate_swap":
                    plan["candidate"]["sha256"] = inspect(candidate)["sha256"]
                if name == "timeout":
                    plan["limits"] = {"timeout": 0.2}
                path.write_text(json.dumps(plan))
                if name == "timeout":
                    sign(path, temp, private)
                if name == "baseline_tamper":
                    Path(plan["baseline"]["path"]).write_text("print('tampered')\n")
                start = time.monotonic()
                decision, result = decide(path, temp, public)
                elapsed = time.monotonic() - start
                saved = Path(temp, "out", "result.json").read_text()
                redacted = "sk-proj-wake-" not in saved and "AKIA_WAKE_" not in saved
                observations.append({"case": name, "repeat": repeat + 1, "expected": expected,
                                     "decision": decision, "seconds": round(elapsed, 3),
                                     "redacted": redacted})
    times = [item["seconds"] for item in observations]
    correct = sum(item["decision"] == item["expected"] for item in observations)
    redacted = sum(item["redacted"] for item in observations)
    repeatable = sum(observations[i]["decision"] == observations[i + len(CASES)]["decision"]
                     for i in range(len(CASES)))
    benign = [item for item in observations if item["case"] == "benign"]
    return {"cases": observations, "correct": [correct, len(observations)],
            "benign_false_alarms": [sum(item["decision"] != "PASS" for item in benign), len(benign)],
            "error_decisions": [sum(item["decision"] == "ERROR" for item in observations), len(observations)],
            "repeatable": [repeatable, len(CASES)],
            "redacted": [redacted, len(observations)],
            "median_seconds": round(statistics.median(times), 3),
            "p95_seconds": round(sorted(times)[int(0.95 * (len(times) - 1))], 3)}


if __name__ == "__main__":
    result = measure()
    print(json.dumps(result, indent=2))
    if result["correct"][0] != result["correct"][1] or result["redacted"][0] != result["redacted"][1]:
        raise SystemExit(1)
