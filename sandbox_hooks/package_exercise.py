import importlib
import importlib.metadata
import json
import os
import subprocess
import sys


def main():
    exercise = json.loads(sys.argv[1])
    mode = exercise["mode"]
    args = exercise.get("args", [])
    os.environ.update(exercise.get("env", {}))
    if mode == "import":
        sys.argv = [exercise["module"], *args]
        importlib.import_module(exercise["module"])
    elif mode == "console":
        dist = importlib.metadata.distribution(exercise["distribution"])
        points = [point for point in dist.entry_points if
                  point.group == "console_scripts" and point.name == exercise["entry"]]
        if len(points) != 1:
            raise ValueError("console entry point is missing or ambiguous")
        sys.argv = [exercise["entry"], *args]
        value = points[0].load()()
        if isinstance(value, int):
            return value
    elif mode == "command":
        command = exercise["argv"] + args
        child = os.environ.copy()
        child["WAKETRACE_ACTIVE"] = "1"
        exe = command[0]
        if exe in ("python", "python3"):
            command[0] = sys.executable
        elif "/" in exe:
            raise ValueError("test command executable must be a simple name")
        result = subprocess.run(command, env=child, check=False)
        return result.returncode
    else:
        raise ValueError("unsupported exercise mode")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())