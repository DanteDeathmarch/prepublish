#!/usr/bin/env python3
"""
package.py -- make a repo look finished without touching what it does.

THE HARD CONSTRAINT: presentation changes only. The tool's source must come out
byte-identical. This is enforced, not promised -- every source file is SHA-256 hashed
before and after, and the script fails loudly if a single byte moved.

Why that constraint matters: a packager that "tidies" code is a packager that
introduces bugs into something already tested and audited. The audit ran against
specific bytes. If those bytes change after the audit, the audit is void.

What it does add:
    - badges (license, python version, dependency count)
    - a consistent header block
    - CONTRIBUTING.md and a short SECURITY.md
    - .gitattributes for sane diffs
    - a check that the README's claimed usage matches the tool's real --help

    python package.py ../sheetcheck
    python package.py ../sheetcheck --dry-run
"""

import hashlib
import re
import subprocess
import sys
from pathlib import Path

__version__ = "1.0.0"

SOURCE_SUFFIXES = {".py", ".js", ".ts", ".sh", ".rb", ".go", ".rs"}


def hash_sources(root):
    """SHA-256 every source file. This is the contract we enforce."""
    out = {}
    for p in sorted(root.rglob("*")):
        if ".git" in p.parts or "__pycache__" in p.parts:
            continue
        if p.is_file() and p.suffix in SOURCE_SUFFIXES:
            out[str(p.relative_to(root))] = hashlib.sha256(p.read_bytes()).hexdigest()
    return out


def detect(root):
    """Work out what to put on the badges. Never guess -- read the files."""
    info = {"license": None, "pyver": None, "deps": 0, "entry": None}

    lic = next((p for p in root.iterdir()
                if p.is_file() and p.name.upper().startswith("LICENSE")), None)
    if lic:
        t = lic.read_text(encoding="utf-8", errors="ignore")
        for name in ("MIT", "Apache", "GPL", "BSD", "MPL", "Unlicense"):
            if name.lower() in t.lower():
                info["license"] = name
                break

    if any((root / f).exists() for f in
           ("requirements.txt", "pyproject.toml", "setup.py", "Pipfile")):
        req = root / "requirements.txt"
        info["deps"] = len([l for l in req.read_text(encoding="utf-8").splitlines()
                            if l.strip() and not l.startswith("#")]) if req.exists() else -1

    for p in root.glob("*.py"):
        t = p.read_text(encoding="utf-8", errors="ignore")
        if "__main__" in t:
            info["entry"] = p.name
            m = re.search(r"Python (\d\.\d+)\+", t)
            if m:
                info["pyver"] = m.group(1)
            break

    if not info["pyver"]:
        rd = next((p for p in root.iterdir()
                   if p.is_file() and p.name.upper().startswith("README")), None)
        if rd:
            m = re.search(r"Python (\d\.\d+)\+", rd.read_text(encoding="utf-8", errors="ignore"))
            if m:
                info["pyver"] = m.group(1)

    return info


def badges(info):
    b = []
    if info["license"]:
        b.append(f"![License](https://img.shields.io/badge/license-{info['license']}-blue)")
    if info["pyver"]:
        b.append(f"![Python](https://img.shields.io/badge/python-{info['pyver']}%2B-blue)")
    if info["deps"] == 0:
        b.append("![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)")
    elif info["deps"] > 0:
        b.append(f"![Dependencies](https://img.shields.io/badge/dependencies-{info['deps']}-yellow)")
    return " ".join(b)


CONTRIBUTING = """# Contributing

Issues and pull requests are welcome.

**Before opening a PR**

- Keep it dependency-free. The whole point is that this runs anywhere with no install.
- Add a case to the examples in the README if you change behaviour.
- If you change a threshold, say why in the PR — the current numbers are floors chosen
  to catch obviously-broken files, not to be authoritative.

**Reporting a bug**

Include the command you ran, what you expected, and what happened. If a file was
misjudged, say which verdict you expected and why — false PASSes are more serious than
false FAILs here.
"""

SECURITY = """# Security

This tool reads files locally and makes **no network calls of any kind**. Nothing is
uploaded, and there is no telemetry.

If you find a security issue, please open an issue describing the problem. If you
believe it should not be public, say so in the issue and leave out the details until
we can arrange somewhere better.
"""

GITATTRIBUTES = """* text=auto eol=lf
*.py text diff=python
*.md text
*.xlsx binary
"""


def check_readme_matches_help(root, info, problems):
    """A README that documents flags the tool does not have is worse than no README.

    Probes EVERY entry point, not just the first one found. A repo that ships several
    commands (audit / package / publish) documents the union of their flags, and
    checking only the first produced a confident false warning listing six real,
    working flags as phantom.
    """
    rd = next((p for p in root.iterdir()
               if p.is_file() and p.name.upper().startswith("README")), None)
    if not rd:
        return
    readme = rd.read_text(encoding="utf-8", errors="ignore")

    entries = [p for p in root.glob("*.py")
               if "__main__" in p.read_text(encoding="utf-8", errors="ignore")]
    if not entries:
        return

    real = set()
    probed = 0
    for e in entries:
        try:
            r = subprocess.run([sys.executable, str(e), "--help"],
                               capture_output=True, text=True, timeout=45)
            real |= set(re.findall(r"(--[a-z][a-z\-]{2,})", r.stdout + r.stderr))
            probed += 1
        except Exception:  # noqa: BLE001
            continue
    if not probed:
        return

    documented = set(re.findall(r"(--[a-z][a-z\-]{2,})", readme))
    phantom = documented - real - {"--help"}
    if phantom:
        problems.append(f"README documents flags no entry point has "
                        f"({probed} probed): {', '.join(sorted(phantom))}")


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    dry = "--dry-run" in sys.argv
    if not args:
        print(__doc__)
        return 2

    root = Path(args[0]).resolve()
    if not root.is_dir():
        print(f"Not a directory: {root}", file=sys.stderr)
        return 2

    before = hash_sources(root)
    info = detect(root)
    problems = []
    check_readme_matches_help(root, info, problems)

    added = []

    rd = next((p for p in root.iterdir()
               if p.is_file() and p.name.upper().startswith("README")), None)
    if rd:
        readme = rd.read_text(encoding="utf-8")
        badge_line = badges(info)
        if badge_line and "img.shields.io" not in readme:
            lines = readme.splitlines()
            # Insert directly under the H1 so it renders as a header block.
            #
            # Must track fenced code blocks. `# ` also starts a shell comment, so a
            # README whose first heading-looking line is inside a ```bash fence got
            # badge markdown injected INTO the code sample. That shipped to a live
            # profile page before anyone noticed — the badges rendered as literal
            # text in the middle of a copy-paste command.
            in_fence = False
            placed = False
            for i, ln in enumerate(lines):
                if ln.lstrip().startswith("```"):
                    in_fence = not in_fence
                    continue
                if not in_fence and ln.startswith("# "):
                    lines.insert(i + 1, "")
                    lines.insert(i + 2, badge_line)
                    placed = True
                    break
            if not placed:
                print("  WARN: no top-level heading outside a code fence — "
                      "badges not added")
            readme = "\n".join(lines)
            if not dry:
                rd.write_text(readme, encoding="utf-8")
            added.append("README badges")

    for fname, content in (("CONTRIBUTING.md", CONTRIBUTING),
                           ("SECURITY.md", SECURITY),
                           (".gitattributes", GITATTRIBUTES)):
        if not (root / fname).exists():
            if not dry:
                (root / fname).write_text(content, encoding="utf-8")
            added.append(fname)

    after = hash_sources(root)

    print(f"package {__version__} — {root.name}")
    for a in added:
        print(f"  + {a}" + ("  (dry-run)" if dry else ""))
    if not added:
        print("  nothing to add — already packaged")

    # THE CONTRACT.
    if before != after:
        changed = [k for k in before if before.get(k) != after.get(k)]
        changed += [k for k in after if k not in before]
        print("\n  FAILED: source files changed. That must never happen.", file=sys.stderr)
        for c in changed:
            print(f"    {c}", file=sys.stderr)
        print("  The audit ran against the old bytes and is now void.", file=sys.stderr)
        return 1
    print(f"\n  source unchanged — {len(before)} file(s) hash-verified identical")

    for p in problems:
        print(f"  WARN: {p}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
