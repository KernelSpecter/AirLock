"""Zero-dependency test runner: `python tests/run.py`.

Runs every test_* function in this directory. Handy on machines without
pytest installed; `python -m pytest` works too.
"""

import sys
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import tests.test_detectors as suite


def main() -> int:
    fns = [getattr(suite, n) for n in dir(suite) if n.startswith("test_")]
    passed = failed = 0
    for fn in sorted(fns, key=lambda f: f.__name__):
        try:
            fn()
            passed += 1
            print(f"PASS  {fn.__name__}")
        except Exception:
            failed += 1
            print(f"FAIL  {fn.__name__}")
            traceback.print_exc()
    print(f"\n{passed} passed, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
