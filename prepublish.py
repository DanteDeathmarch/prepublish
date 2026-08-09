#!/usr/bin/env python3
"""
prepublish -- audit a repo before it goes public. Publish it only if it's clean.

This is the entry point. It exists because every other tool in the suite is named after
its repo, so `curl .../prepublish.py` is what people actually try first — and it used
to 404, which is a bad first impression for a tool whose whole pitch is catching the
things you didn't notice.

    prepublish.py ./my-project              # audit only (safe, read-only, the default)
    prepublish.py ./my-project --json       # machine-readable, for CI
    prepublish.py ./my-project --explain    # show why each finding matters
    prepublish.py ./my-project --publish    # audit -> package -> re-audit -> push

Exit: 0 = clear · 1 = findings block the publish · 2 = usage error

Auditing is the default and it never writes anything. Publishing is opt-in, because a
tool that might push your repo the first time you run it is not a tool anyone should
trust.

The full pipeline (`--publish`) needs `audit.py`, `package.py` and `publish.py` beside
this file — clone the repo rather than curling a single script if you want it.

MIT. https://github.com/DanteDeathmarch/prepublish
"""

import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).parent
__version__ = "1.0.0"


def _run(script, args):
    target = HERE / script
    if not target.exists():
        print(f"{script} not found next to this file.\n"
              f"You have the single-file download. For the full pipeline:\n"
              f"  git clone https://github.com/DanteDeathmarch/prepublish",
              file=sys.stderr)
        return 2
    return subprocess.run([sys.executable, str(target), *args]).returncode


def main():
    argv = sys.argv[1:]
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0 if argv else 2
    if argv[0] == "--version":
        print(f"prepublish {__version__}")
        return 0

    if "--publish" in argv:
        return _run("publish.py", [a for a in argv if a != "--publish"])
    return _run("audit.py", argv)


if __name__ == "__main__":
    sys.exit(main())
