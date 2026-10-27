"""Open the packaged Streamlit dashboard."""

from importlib.util import find_spec
import subprocess
import sys


def main():
    spec = find_spec("dashboard")
    if spec is None or spec.origin is None:
        print("WakeTrace dashboard file is missing", file=sys.stderr)
        return 2
    try:
        import streamlit  # noqa: F401
    except ImportError:
        print("Install waketrace[dashboard] to open the dashboard", file=sys.stderr)
        return 2
    return subprocess.call([sys.executable, "-m", "streamlit", "run", spec.origin])


if __name__ == "__main__":
    raise SystemExit(main())
