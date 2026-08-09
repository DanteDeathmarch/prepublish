#!/usr/bin/env python3
"""
audit.py -- the gate that stands in for a human before an autonomous publish.

WHY THIS IS STRICT: publishing to a public repo is not reversible in the way people
assume. GitHub is indexed within seconds and credential scrapers watch the firehose.
Deleting a repo after the fact does not un-leak a key -- it only removes the evidence.
So this tool is deliberately biased toward false positives. A blocked publish costs
minutes. A leaked key costs an account.

Five audits:
    SECURITY       secrets, private keys, internal hosts, local paths, PII,
                   internal project names.  ALWAYS FATAL. Never downgradeable.
    DELIVERABILITY can a stranger obtain this and run it?
    USABILITY      does it explain itself and fail helpfully?
    QUALITY        does it actually run, and are the exit codes real?
    VIABILITY      is there a buyer, a price, and one job?

Usage:
    python audit.py ../sheetcheck
    python audit.py ../sheetcheck --json
    python audit.py ../sheetcheck --explain      # show why each finding matters

Exit: 0 = clear to publish · 1 = findings block publish · 2 = usage error

Security findings CANNOT be waived by a flag. That is on purpose -- a waiver flag is
the mechanism by which every scanner eventually gets ignored.
"""

import hashlib
import json
import math
import os
import re
import subprocess
import sys
from pathlib import Path

__version__ = "1.0.0"

# ---------------------------------------------------------------------------
# SECURITY PATTERNS
# High-signal only. A scanner that cries wolf gets switched off, and a scanner
# that is switched off is worse than none because it implies coverage.
# ---------------------------------------------------------------------------

SECRET_PATTERNS = [
    (r"sk-[A-Za-z0-9]{20,}",                      "OpenAI-style API key"),
    (r"sk-ant-[A-Za-z0-9_\-]{20,}",               "Anthropic API key"),
    (r"gh[pousr]_[A-Za-z0-9]{30,}",               "GitHub token"),
    (r"github_pat_[A-Za-z0-9_]{40,}",             "GitHub fine-grained PAT"),
    (r"AKIA[0-9A-Z]{16}",                         "AWS access key id"),
    (r"AIza[0-9A-Za-z_\-]{35}",                   "Google API key"),
    (r"xox[baprs]-[A-Za-z0-9\-]{10,}",            "Slack token"),
    (r"-----BEGIN [A-Z ]*PRIVATE KEY-----",       "private key block"),
    (r"gsk_[A-Za-z0-9]{40,}",                     "Groq API key"),
    (r"csk-[A-Za-z0-9]{20,}",                     "Cerebras API key"),
    (r"hf_[A-Za-z0-9]{30,}",                      "HuggingFace token"),
    (r"dp\.pt\.[A-Za-z0-9]{30,}",                 "Doppler service token"),
    (r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.", "JWT (may embed claims)"),
    # Assignment-shaped secrets: KEY = "something long". Excludes obvious placeholders.
    (r"(?i)(api[_-]?key|secret|password|passwd|token|bearer)\s*[:=]\s*"
     r"[\"'][^\"'\s]{16,}[\"']",                  "hardcoded credential assignment"),
]

# Things that are not credentials but still must never ship publicly.
EXPOSURE_PATTERNS = [
    (r"100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.\d{1,3}\.\d{1,3}",
     "Tailscale tailnet IP — maps your private network"),
    (r"[A-Za-z]:[\\/]Users[\\/][A-Za-z0-9._\-]+",
     "absolute local path — leaks the OS username"),
    (r"/home/[a-z][a-z0-9._\-]{2,}/",
     "absolute home path — leaks the username"),
    (r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}",
     "email address"),
    # NOTE: bare `localhost:PORT` is deliberately NOT here.
    #
    # It was, and it blocked a tool whose entire purpose is talking to a local gateway
    # — the port appeared in its README as documentation and in its source as a
    # default. That is a false positive, and the fix is a better pattern, not a waiver
    # flag. `localhost` means "this machine" to whoever runs it and discloses nothing
    # about anyone's network.
    #
    # What DOES disclose something is a private hostname or a non-loopback internal
    # address, both of which are still caught below.
    (r"\b(?:10\.\d{1,3}|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}\b",
     "private LAN address — maps your internal network"),
    # Filenames are not hostnames. Two guards, each added after a real false positive
    # in this very file:
    #   lookbehind  — stops a dotted filename (dot + env + dot + local) matching
    #   lookahead   — stops a file extension (something + dot + local + dot + json)
    # A third false positive came from an explanatory COMMENT that spelled the example
    # out literally. Self-matching has now bitten this project three times: a process
    # query counting itself, a stub detector flagging its own patterns, and this.
    # Write examples so they cannot match.
    (r"(?<![.\w-])[a-z][a-z0-9-]{2,}\.(?:local|internal|lan|corp|intranet)"
     r"(?![a-z0-9-])(?!\.[a-z]{2,5}\b)",
     "internal hostname"),
]

# Internal names that must never appear in anything public.
#
# These are deliberately NOT hardcoded. Two reasons, and the second one is the one
# that matters:
#   1. Every org's internal names are different, so hardcoding ours makes the tool
#      useless to anyone else.
#   2. A list of your private project names IS itself sensitive. Baking it into the
#      scanner means the scanner can never be published -- it would correctly fail
#      its own audit. That is not a hypothetical: it happened on the first attempt.
#
# Loaded from, in order: $AUDIT_INTERNAL_NAMES (comma-separated), then
# internal-names.txt next to this file (one per line, # for comments). Both are
# gitignored. Absent both, this check is skipped and says so out loud -- silent
# skipping is how a gate becomes decorative.

def _load_internal_names():
    env = os.environ.get("AUDIT_INTERNAL_NAMES", "").strip()
    if env:
        return [n.strip().lower() for n in env.split(",") if n.strip()]
    cfg = Path(__file__).parent / "internal-names.txt"
    if cfg.exists():
        return [ln.strip().lower() for ln in cfg.read_text(encoding="utf-8").splitlines()
                if ln.strip() and not ln.startswith("#")]
    return []


INTERNAL_NAMES = _load_internal_names()

# Files whose contents we never scan for text findings (binary or vendored).
SKIP_SUFFIX = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip", ".xlsx",
               ".woff", ".woff2", ".ttf", ".pyc", ".so", ".dll", ".exe"}
SKIP_DIRS = {".git", "__pycache__", "node_modules", "venv", ".venv", "dist", "build"}

PLACEHOLDER_HINTS = ("your", "example", "changeme", "xxxx", "<", "placeholder",
                     "dummy", "fake", "redacted", "notreal", "sample", "yourname",
                     "username", "user-name", "me@", "foo", "bar")

# Files whose whole purpose is to hold credentials for CI. Secrets belong in the
# provider's secret store and are referenced, never written literally.
CI_PATHS = (".github/workflows", ".gitlab-ci", "azure-pipelines", ".circleci",
            "Jenkinsfile", ".travis.yml", "bitbucket-pipelines")

# A literal value assigned inside a CI env: block, as opposed to a ${{ secrets.X }}
# reference or an $ENV interpolation.
CI_LITERAL = re.compile(
    r"(?im)^\s*[A-Z][A-Z0-9_]{2,}\s*:\s*(?!\s*[\"']?\$)(?!\s*[\"']?\{\{)"
    r"[\"']?([^\s\"'#]{12,})[\"']?\s*$")


def shannon_entropy(s):
    """Bits per character. High entropy = random-looking = probably a key."""
    if not s:
        return 0.0
    from collections import Counter
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())


# Tokens that look like credentials regardless of vendor prefix. This is the check
# that catches formats nobody enumerated -- a new provider, an internal system, a
# rotated scheme. Pattern lists only ever catch yesterday's leaks.
HIGH_ENTROPY_CANDIDATE = re.compile(r"[A-Za-z0-9+/=_\-]{32,}")

# Things that are legitimately long and random-looking but are not secrets.
ENTROPY_EXEMPT = re.compile(
    r"(?i)(sha256|sha512|sha1|md5|integrity=|[0-9a-f]{40}|[0-9a-f]{64}"
    r"|data:image|base64,|https?://|users\.noreply|Co-Authored-By)")


class Finding:
    def __init__(self, audit, severity, msg, where="", why=""):
        self.audit, self.severity, self.msg, self.where, self.why = (
            audit, severity, msg, where, why)

    def as_dict(self):
        return {"audit": self.audit, "severity": self.severity, "message": self.msg,
                "where": self.where, "why": self.why}


def walk(root):
    """Yield the files that would actually be published.

    In a git repo that means git's view, not the filesystem's: `git ls-files` with
    --others --exclude-standard gives tracked files plus untracked-but-not-ignored
    ones. Anything in .gitignore is never pushed, so scanning it produces findings
    nobody can act on.

    This matters more than it sounds. This tool's own internal-name config is
    gitignored and contains, by definition, every internal name -- scanning the raw
    filesystem made the tool permanently unable to pass its own audit for files that
    were never going to be published.

    Falls back to a filesystem walk outside a git repo, which is the conservative
    direction (scan more, not less).
    """
    root = Path(root)
    if (root / ".git").exists():
        try:
            r = subprocess.run(
                ["git", "-C", str(root), "ls-files", "--cached", "--others",
                 "--exclude-standard"],
                capture_output=True, text=True, timeout=60)
            if r.returncode == 0:
                for rel in r.stdout.splitlines():
                    p = root / rel.strip()
                    if not rel.strip() or not p.is_file():
                        continue
                    if p.suffix.lower() in SKIP_SUFFIX:
                        continue
                    yield p
                return
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass  # fall through to the filesystem walk

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            p = Path(dirpath) / fn
            if p.suffix.lower() in SKIP_SUFFIX:
                continue
            yield p


def read(p):
    try:
        return p.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def looks_like_placeholder(line):
    low = line.lower()
    return any(h in low for h in PLACEHOLDER_HINTS)


# ---------------------------------------------------------------------------
# 1. SECURITY  — always fatal
# ---------------------------------------------------------------------------

def audit_security(root):
    out = []
    root = Path(root)

    # A gate that silently does not run is decorative, and worse than none because it
    # is trusted. If no internal-name list is configured, that half of the scan is
    # simply not happening -- say so at FAIL level so it blocks a publish until
    # somebody makes a deliberate decision about it.
    if not INTERNAL_NAMES:
        out.append(Finding(
            "SECURITY", "FAIL",
            "no internal-name list configured — that check did NOT run",
            "internal-names.txt",
            "Set AUDIT_INTERNAL_NAMES or create internal-names.txt. Passing this "
            "audit without it means 'no secrets found', not 'nothing private found'."))

    for p in walk(root):
        rel = p.relative_to(root)
        text = read(p)
        if not text:
            continue

        for i, line in enumerate(text.splitlines(), 1):
            if len(line) > 2000:      # minified/vendored; scanning is noise
                continue

            for pat, label in SECRET_PATTERNS:
                if re.search(pat, line):
                    if looks_like_placeholder(line):
                        continue
                    out.append(Finding(
                        "SECURITY", "FATAL", f"{label} found",
                        f"{rel}:{i}",
                        "A credential in a public repo is scraped within seconds. "
                        "Deleting the repo does not un-leak it — rotate the key."))

            for pat, label in EXPOSURE_PATTERNS:
                m = re.search(pat, line)
                if m:
                    if looks_like_placeholder(line):
                        continue
                    # An email in LICENSE/AUTHORS is intentional attribution.
                    if "@" in m.group(0) and rel.name.upper().startswith(("LICENSE", "AUTHORS", "CONTRIB")):
                        continue
                    out.append(Finding(
                        "SECURITY", "FATAL", f"{label}: {m.group(0)[:60]}",
                        f"{rel}:{i}",
                        "Reveals private infrastructure or identity to anyone who "
                        "reads the source."))

            low = line.lower()
            for name in INTERNAL_NAMES:
                if name in low:
                    out.append(Finding(
                        "SECURITY", "FATAL",
                        f"internal project name '{name}' appears in a public artifact",
                        f"{rel}:{i}",
                        "Internal names map your private org structure and, in at "
                        "least one case, are explicitly off-limits."))

            # Entropy check. Pattern lists catch yesterday's credential formats; this
            # catches the ones nobody enumerated -- a new provider, an internal system,
            # a rotated scheme. Threshold 4.0 bits/char with mixed case and digits is
            # well above English prose (~2.5-3.0) and above hex hashes (~4.0 but
            # exempted explicitly).
            if not ENTROPY_EXEMPT.search(line):
                for tok in HIGH_ENTROPY_CANDIDATE.findall(line):
                    if looks_like_placeholder(line):
                        break
                    has_mix = (any(c.isdigit() for c in tok)
                               and any(c.islower() for c in tok)
                               and any(c.isupper() for c in tok))
                    if has_mix and shannon_entropy(tok) >= 4.0:
                        out.append(Finding(
                            "SECURITY", "FATAL",
                            f"high-entropy string ({shannon_entropy(tok):.1f} bits/char, "
                            f"{len(tok)} chars) — looks like a credential",
                            f"{rel}:{i}",
                            "Matches no known key format, which is exactly why this "
                            "check exists. If it is not a secret, move it to a config "
                            "file or add a placeholder marker."))
                        break

        # CI config: a secret written literally here is published like any other file,
        # and CI files are the single most common place people paste one "temporarily".
        if any(c in str(rel).replace("\\", "/") for c in CI_PATHS):
            for m in CI_LITERAL.finditer(text):
                val = m.group(1)
                if looks_like_placeholder(m.group(0)) or val.startswith(("$", "{")):
                    continue
                if shannon_entropy(val) >= 3.5 or len(val) >= 24:
                    ln = text[:m.start()].count("\n") + 1
                    out.append(Finding(
                        "SECURITY", "FATAL",
                        f"literal value in CI config: {m.group(0).strip()[:50]}",
                        f"{rel}:{ln}",
                        "CI secrets must be references (${{ secrets.NAME }} or $ENV), "
                        "never literals. This file is published like any other."))

        # Files that should never be committed at all.
        if rel.name in (".env", ".env.local", ".env.production", "credentials.json",
                        "secrets.json", "id_rsa", "id_ed25519", ".npmrc", ".pypirc",
                        "service-account.json", ".netrc", "terraform.tfvars"):
            out.append(Finding("SECURITY", "FATAL", f"sensitive file present: {rel}",
                               str(rel), "This file type exists to hold credentials."))

    # Git history. Fixing a file in the working tree does NOT remove it from earlier
    # commits -- `git log -p` on a published repo hands the old version to anyone.
    #
    # This scans history for EVERYTHING the working tree is scanned for, not just
    # secrets. An earlier version of this function checked only SECRET_PATTERNS and
    # returned CLEAR on a repo whose previous commit still contained an internal org
    # name. A gate with a hole in it is worse than no gate, because it is trusted.
    if (root / ".git").exists():
        try:
            r = subprocess.run(["git", "-C", str(root), "log", "--all", "-p", "--no-color"],
                               capture_output=True, text=True, timeout=120)
            # Only look at added lines; a '-' line is content being REMOVED, which is
            # still in history, so we take both '+' and '-' but skip diff headers.
            hist_lines = [ln for ln in r.stdout.splitlines()
                          if (ln.startswith("+") or ln.startswith("-"))
                          and not ln.startswith(("+++", "---"))]
            hist = "\n".join(hist_lines)

            for pat, label in SECRET_PATTERNS:
                m = re.search(pat, hist)
                if m and not looks_like_placeholder(m.group(0)):
                    out.append(Finding(
                        "SECURITY", "FATAL",
                        f"{label} present in GIT HISTORY (not just working tree)",
                        "git history",
                        "Removing a file does not remove it from earlier commits. "
                        "Rewrite history or publish from a fresh repo."))

            for pat, label in EXPOSURE_PATTERNS:
                m = re.search(pat, hist)
                if m and not looks_like_placeholder(m.group(0)):
                    # LICENSE/AUTHORS attribution emails are intentional.
                    if "@" in m.group(0) and re.search(
                            r"(?im)^[+-].*(license|authors|contributing)", hist):
                        continue
                    out.append(Finding(
                        "SECURITY", "FATAL",
                        f"{label} in GIT HISTORY: {m.group(0)[:60]}",
                        "git history",
                        "Old commits are public too. Rewrite history or start clean."))

            low_hist = hist.lower()
            for name in INTERNAL_NAMES:
                if name in low_hist:
                    out.append(Finding(
                        "SECURITY", "FATAL",
                        f"internal project name '{name}' in GIT HISTORY",
                        "git history",
                        "Fixing the file does not fix the commit that introduced it. "
                        "Recreate the repo with a single clean commit."))
            # Commit MESSAGES are published too and are not diff lines, so the filter
            # above skips them entirely. A message like "fix the <internal-org> path"
            # leaks exactly as much as the code would.
            msgs = subprocess.run(
                ["git", "-C", str(root), "log", "--all", "--format=%an%n%ae%n%s%n%b"],
                capture_output=True, text=True, timeout=60).stdout
            low_msgs = msgs.lower()
            for name in INTERNAL_NAMES:
                if name in low_msgs:
                    out.append(Finding(
                        "SECURITY", "FATAL",
                        f"internal project name '{name}' in a COMMIT MESSAGE",
                        "git log",
                        "Commit messages are as public as the code."))
            for pat, label in SECRET_PATTERNS:
                m = re.search(pat, msgs)
                if m and not looks_like_placeholder(m.group(0)):
                    out.append(Finding(
                        "SECURITY", "FATAL", f"{label} in a COMMIT MESSAGE",
                        "git log", "Rewrite history or start clean."))
            for pat, label in EXPOSURE_PATTERNS:
                m = re.search(pat, msgs)
                if m and not looks_like_placeholder(m.group(0)):
                    # Author name/email in commit metadata is unavoidable and expected.
                    if "@" in m.group(0):
                        continue
                    out.append(Finding(
                        "SECURITY", "FATAL", f"{label} in a COMMIT MESSAGE: {m.group(0)[:50]}",
                        "git log", "Commit messages are as public as the code."))

        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
            out.append(Finding(
                "SECURITY", "FATAL", f"could not scan git history ({type(e).__name__})",
                ".git",
                "Unscanned history cannot be declared clean. Fix the scan, or "
                "publish from a fresh repo with no prior commits."))

    return out


# ---------------------------------------------------------------------------
# 2. DELIVERABILITY — can a stranger get it and run it?
# ---------------------------------------------------------------------------

def audit_deliverability(root):
    out, root = [], Path(root)
    names = {p.name.upper() for p in root.iterdir() if p.is_file()}

    if not any(n.startswith("README") for n in names):
        out.append(Finding("DELIVERABILITY", "FAIL", "no README",
                           "", "Directories reject submissions with no README, and "
                               "a stranger has no entry point."))
    lic_name = next((n for n in names if n.startswith("LICENSE")), None)
    if not lic_name:
        out.append(Finding("DELIVERABILITY", "FAIL", "no LICENSE",
                           "", "Without a license nobody may legally use it, which "
                               "makes it unusable in exactly the commercial context "
                               "we are targeting."))
    else:
        # A LICENSE file that EXISTS is not a LICENSE file that grants anything.
        # The old check only tested for the filename, so an empty file, a stub, or a
        # template with the copyright line still unfilled all passed — and shipping
        # that is legally identical to shipping no license at all.
        lic = next(p for p in root.iterdir()
                   if p.is_file() and p.name == lic_name)
        body = read(lic)
        low = body.lower()
        KNOWN = ("mit license", "apache license", "gnu general public",
                 "bsd ", "mozilla public license", "the unlicense",
                 "isc license", "creative commons")
        if len(body.strip()) < 200:
            out.append(Finding(
                "DELIVERABILITY", "FAIL",
                f"{lic_name} is only {len(body.strip())} chars — not a real licence",
                lic_name,
                "An empty or stub LICENSE grants nothing. Legally it is the same as "
                "having no licence, but it looks like you have one."))
        elif not any(k in low for k in KNOWN):
            out.append(Finding(
                "DELIVERABILITY", "FAIL",
                f"{lic_name} does not match any known licence text",
                lic_name,
                "Either it is a custom licence (say so deliberately) or the file is "
                "not what you think it is."))
        elif re.search(r"\[(year|yyyy|fullname|name of copyright owner)\]", low) or \
                re.search(r"copyright \(c\)\s*(19|20)?xx", low):
            out.append(Finding(
                "DELIVERABILITY", "FAIL",
                f"{lic_name} still has unfilled template placeholders",
                lic_name,
                "A licence with [year] and [fullname] left in reads as copy-pasted "
                "and leaves the copyright holder undefined."))
    if not (root / ".gitignore").exists():
        out.append(Finding("DELIVERABILITY", "WARN", "no .gitignore",
                           "", "Raises the chance of committing something private later."))

    py = list(root.glob("*.py"))
    imports = set()
    for p in py:
        for m in re.finditer(r"^\s*(?:import|from)\s+([A-Za-z_][A-Za-z0-9_]*)", read(p), re.M):
            imports.add(m.group(1))
    stdlib = set(getattr(sys, "stdlib_module_names", ())) | {
        "os", "sys", "re", "json", "glob", "zipfile", "pathlib", "subprocess",
        "hashlib", "typing", "dataclasses", "collections", "itertools", "math",
        "time", "datetime", "argparse", "csv", "io", "shutil", "tempfile", "urllib"}
    third = {i for i in imports if i not in stdlib}
    has_manifest = any((root / f).exists() for f in
                       ("requirements.txt", "pyproject.toml", "setup.py", "Pipfile"))
    if third and not has_manifest:
        out.append(Finding("DELIVERABILITY", "FAIL",
                           f"third-party imports with no manifest: {', '.join(sorted(third))}",
                           "", "A stranger runs it, hits ImportError, and leaves."))

    readme = ""
    for p in root.iterdir():
        if p.is_file() and p.name.upper().startswith("README"):
            readme = read(p)
            break
    if readme and not re.search(r"(?i)#+\s*(install|usage|quick ?start|getting started)", readme):
        out.append(Finding("DELIVERABILITY", "WARN",
                           "README has no Install/Usage heading", "README",
                           "First question a stranger has is 'how do I run this'."))
    return out


# ---------------------------------------------------------------------------
# 3. USABILITY — does it explain itself and fail helpfully?
# ---------------------------------------------------------------------------

def audit_usability(root):
    out, root = [], Path(root)
    entry = None
    for cand in root.glob("*.py"):
        t = read(cand)
        if "__main__" in t:
            entry = cand
            break
    if not entry:
        out.append(Finding("USABILITY", "WARN", "no obvious entry point",
                           "", "Nothing to run means nothing to try."))
        return out

    for flag in ("--help", "--version"):
        try:
            r = subprocess.run([sys.executable, str(entry), flag],
                               capture_output=True, text=True, timeout=45)
            if r.returncode != 0 or not (r.stdout or r.stderr).strip():
                out.append(Finding("USABILITY", "FAIL", f"{flag} produced nothing useful",
                                   entry.name,
                                   "Users and package managers both probe these first."))
        except Exception as e:  # noqa: BLE001
            out.append(Finding("USABILITY", "FAIL", f"{flag} crashed: {type(e).__name__}",
                               entry.name, "A crash on --help reads as abandonware."))

    try:
        r = subprocess.run([sys.executable, str(entry), "definitely-not-a-real-path-xyz"],
                           capture_output=True, text=True, timeout=45)
        msg = (r.stdout + r.stderr)
        if "Traceback" in msg:
            out.append(Finding("USABILITY", "FAIL", "raw traceback on bad input",
                               entry.name,
                               "Users read a traceback as 'this is broken', not "
                               "'I typed it wrong'."))
    except Exception:  # noqa: BLE001
        pass
    return out


# ---------------------------------------------------------------------------
# 4. QUALITY — does it compile and are the exit codes meaningful?
# ---------------------------------------------------------------------------

def audit_quality(root):
    out, root = [], Path(root)
    for p in root.rglob("*.py"):
        if any(d in p.parts for d in SKIP_DIRS):
            continue
        try:
            compile(read(p), str(p), "exec")
        except SyntaxError as e:
            out.append(Finding("QUALITY", "FAIL", f"syntax error: {e.msg} (line {e.lineno})",
                               p.name, "It does not even parse."))

    for p in root.rglob("*.py"):
        if any(d in p.parts for d in SKIP_DIRS):
            continue
        t = read(p)
        for m in re.finditer(r"(?i)#\s*(TODO|FIXME|XXX|HACK)\b", t):
            line = t[:m.start()].count("\n") + 1
            out.append(Finding("QUALITY", "WARN", f"{m.group(1).upper()} left in source",
                               f"{p.name}:{line}",
                               "Ships as a public statement that it is unfinished."))
        if re.search(r"except\s*:\s*\n\s*pass", t):
            out.append(Finding("QUALITY", "WARN", "bare `except: pass`", p.name,
                               "Silently swallows failures — the exact bug class that "
                               "has cost this org the most."))
    return out


# ---------------------------------------------------------------------------
# 5. VIABILITY — is there a buyer, a price, and one job?
# ---------------------------------------------------------------------------

def audit_viability(root):
    out, root = [], Path(root)
    readme = ""
    for p in root.iterdir():
        if p.is_file() and p.name.upper().startswith("README"):
            readme = read(p)
            break
    if not readme:
        return [Finding("VIABILITY", "FAIL", "no README to evaluate", "",
                        "Cannot assess an offer that is not stated.")]

    first = "\n".join(readme.splitlines()[:12])
    if len(first.strip()) < 60:
        out.append(Finding("VIABILITY", "WARN", "no one-line value statement up top",
                           "README",
                           "A reader decides in one line whether this is for them."))
    if not re.search(r"(?i)\b(for|built for|who|if you)\b", readme[:1500]):
        out.append(Finding("VIABILITY", "WARN", "no named buyer in the opening",
                           "README",
                           "'Anyone who...' is not a buyer. Name the person."))
    if not re.search(r"(?i)#+\s*(why|the problem|what it does)", readme):
        out.append(Finding("VIABILITY", "WARN", "no stated problem",
                           "README", "A tool with no stated problem has no buyer."))
    if not re.search(r"(?i)(does not|doesn't|not check|limitation|caveat)", readme):
        out.append(Finding("VIABILITY", "WARN", "no stated limitations",
                           "README",
                           "Claiming no limits reads as unserious and generates refunds."))
    return out


# ---------------------------------------------------------------------------

def main():
    argv = [a for a in sys.argv[1:] if not a.startswith("--")]
    as_json = "--json" in sys.argv
    explain = "--explain" in sys.argv
    if "--version" in sys.argv:
        print(f"audit {__version__}")
        return 0
    if not argv or "--help" in sys.argv or "-h" in sys.argv:
        print(__doc__)
        return 0 if "--help" in sys.argv or "-h" in sys.argv else 2

    root = Path(argv[0]).resolve()
    if not root.is_dir():
        print(f"Not a directory: {root}", file=sys.stderr)
        return 2

    findings = []
    findings += audit_security(root)
    findings += audit_deliverability(root)
    findings += audit_usability(root)
    findings += audit_quality(root)
    findings += audit_viability(root)

    fatal = [f for f in findings if f.severity == "FATAL"]
    fail = [f for f in findings if f.severity == "FAIL"]
    warn = [f for f in findings if f.severity == "WARN"]
    clear = not fatal and not fail

    if as_json:
        print(json.dumps({
            "version": __version__,
            "target": str(root),
            "verdict": "CLEAR" if clear else "BLOCKED",
            "counts": {"fatal": len(fatal), "fail": len(fail), "warn": len(warn)},
            "findings": [f.as_dict() for f in findings],
        }, indent=2))
        return 0 if clear else 1

    print(f"\nAUDIT — {root.name}\n" + "=" * 74)
    for group, label in ((fatal, "FATAL"), (fail, "FAIL"), (warn, "WARN")):
        for f in group:
            loc = f" [{f.where}]" if f.where else ""
            print(f"  {label:5} {f.audit:14} {f.msg}{loc}")
            if explain and f.why:
                print(f"        └─ {f.why}")
    if not findings:
        print("  no findings")

    print("=" * 74)
    print(f"  FATAL {len(fatal)}   FAIL {len(fail)}   WARN {len(warn)}")
    if fatal:
        print("\n  BLOCKED — security findings cannot be waived.")
        print("  Publishing is not reversible: a leaked credential is scraped within")
        print("  seconds and deleting the repo removes only the evidence.")
    elif fail:
        print("\n  BLOCKED — fix the FAILs above, then re-run.")
    else:
        print("\n  CLEAR TO PUBLISH" + (f"  ({len(warn)} warnings, non-blocking)" if warn else ""))
    return 0 if clear else 1


if __name__ == "__main__":
    sys.exit(main())
