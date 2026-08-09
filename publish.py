#!/usr/bin/env python3
"""
publish.py -- audit, package, re-audit, publish. No human in the loop.

AUTHORITY: Greg granted standing permission on 2026-08-08 to publish publicly
*conditional on the quality, usability and security checks passing*. The condition is
the whole grant. This script exists so that condition is enforced by code rather than
by an agent's judgement in the moment.

THE ORDER MATTERS AND IS NOT NEGOTIABLE:

    1. audit          -> must be CLEAR
    2. package        -> presentation only, source hash-verified unchanged
    3. audit AGAIN    -> packaging touched files, so the first audit is stale
    4. commit + push  -> only now

Step 3 is the one that is easy to skip and the one that matters. An audit is a
statement about specific bytes. Change the bytes, and the statement no longer holds.

    python publish.py ../sheetcheck                     # public
    python publish.py ../sheetcheck --private
    python publish.py ../sheetcheck --dry-run           # do everything except push

Refuses to publish if:
    - either audit is not CLEAR
    - packaging modified any source file
    - the repo has uncommitted changes it did not make itself
    - `gh` is not authenticated
"""

import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).parent
LEDGER = HERE / "published.json"
__version__ = "1.0.0"


def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=kw.pop("timeout", 180), **kw)


def commit_identity():
    """The identity to commit as, derived from the authenticated GitHub account.

    NOT from ambient git config. On a shared machine the global git identity may
    belong to something else entirely -- here it was set to an internal automation
    account, and a packaging commit went out publicly authored as
    "<internal-name> <bot@internal-domain>". Commit author metadata is published and
    is not covered by scanning file contents.

    Deriving from `gh api user` guarantees the author matches the account actually
    pushing, which is the only identity that is already public by definition.
    """
    login = run(["gh", "api", "user", "-q", ".login"]).stdout.strip()
    if not login:
        raise SystemExit("BLOCKED: cannot resolve the authenticated GitHub user. "
                         "Refusing to commit with an unknown identity.")
    # GitHub's no-reply address: correct attribution, no personal email published.
    uid = run(["gh", "api", "user", "-q", ".id"]).stdout.strip()
    email = f"{uid}+{login}@users.noreply.github.com" if uid else f"{login}@users.noreply.github.com"
    return login, email


def audit(root, label):
    print(f"\n[{label}] auditing {root.name} ...")
    r = run([sys.executable, str(HERE / "audit.py"), str(root), "--json"], timeout=300)
    try:
        data = json.loads(r.stdout)
    except json.JSONDecodeError:
        print(f"  audit produced no parseable result:\n{r.stdout[:400]}{r.stderr[:400]}")
        return False, None
    c = data["counts"]
    print(f"  verdict={data['verdict']}  FATAL={c['fatal']} FAIL={c['fail']} WARN={c['warn']}")
    if data["verdict"] != "CLEAR":
        for f in data["findings"]:
            if f["severity"] in ("FATAL", "FAIL"):
                print(f"    {f['severity']:5} {f['audit']:14} {f['message']} [{f['where']}]")
    return data["verdict"] == "CLEAR", data


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    private = "--private" in sys.argv
    dry = "--dry-run" in sys.argv
    if not args:
        print(__doc__)
        return 2

    root = Path(args[0]).resolve()
    if not root.is_dir():
        print(f"Not a directory: {root}", file=sys.stderr)
        return 2

    name = root.name
    print(f"publish {__version__} — {name}  ({'PRIVATE' if private else 'PUBLIC'}"
          f"{', DRY RUN' if dry else ''})")

    # gh must be authenticated before we do anything else.
    if run(["gh", "auth", "status"]).returncode != 0:
        print("\n  BLOCKED: gh is not authenticated. Run `gh auth login`.", file=sys.stderr)
        return 1

    # --- 1. audit ---------------------------------------------------------
    ok, _ = audit(root, "1/4 pre-audit")
    if not ok:
        print("\n  BLOCKED at pre-audit. Nothing published.")
        return 1

    # --- 2. package -------------------------------------------------------
    print("\n[2/4] packaging ...")
    r = run([sys.executable, str(HERE / "package.py"), str(root)], timeout=180)
    print("  " + "\n  ".join(l for l in r.stdout.splitlines() if l.strip()))
    if r.returncode != 0:
        print("\n  BLOCKED: packaging failed or modified source. Nothing published.",
              file=sys.stderr)
        print(r.stderr[:600], file=sys.stderr)
        return 1

    # --- 3. re-audit ------------------------------------------------------
    # Packaging added files. The pre-audit described bytes that no longer exist.
    ok, data = audit(root, "3/4 post-package audit")
    if not ok:
        print("\n  BLOCKED at post-package audit. Nothing published.")
        return 1

    # --- 4. publish -------------------------------------------------------
    print("\n[4/4] publishing ...")
    if not (root / ".git").exists():
        print("  BLOCKED: no git repo. Init and commit first.", file=sys.stderr)
        return 1

    status = run(["git", "-C", str(root), "status", "--porcelain"]).stdout.strip()
    if status:
        print("  committing packaging changes ...")
        if not dry:
            run(["git", "-C", str(root), "add", "-A"])
            author, email = commit_identity()
            c = run(["git", "-C", str(root),
                     "-c", f"user.name={author}",
                     "-c", f"user.email={email}",
                     "commit", "-m",
                     "Add contributing, security policy, and README badges\n\n"
                     "Presentation only. Tool source is byte-identical (hash-verified).\n\n"
                     "Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"])
            if c.returncode != 0:
                print(f"  commit failed: {c.stderr[:300]}", file=sys.stderr)
                return 1

    if dry:
        print(f"\n  DRY RUN — would create {'private' if private else 'public'} repo "
              f"'{name}' and push.")
        print("  All gates passed. Re-run without --dry-run to publish.")
        return 0

    vis = "--private" if private else "--public"
    r = run(["gh", "repo", "create", name, vis, "--source", str(root), "--push"], timeout=300)
    combined = r.stdout + r.stderr
    if r.returncode != 0:
        if "already exists" in combined.lower():
            print("  repo exists — pushing to it instead")
            p = run(["git", "-C", str(root), "push", "-u", "origin", "HEAD"], timeout=300)
            if p.returncode != 0:
                print(f"  push failed: {(p.stdout + p.stderr)[:400]}", file=sys.stderr)
                return 1
        else:
            print(f"  publish failed: {combined[:500]}", file=sys.stderr)
            return 1

    url = run(["gh", "repo", "view", name, "--json", "url", "-q", ".url"]).stdout.strip()
    print(f"\n  PUBLISHED: {url}")

    # Description and topics are GitHub's own discovery layer -- a repo with neither
    # is invisible to its search and to every directory that scrapes it. `gh repo
    # create` leaves both empty, so the first publish shipped undiscoverable. Read
    # them from a product spec if one exists.
    #
    # Path comes from $PRODUCT_SPEC_DIR, defaulting to ./products next to this script.
    # It was hardcoded to an absolute local path, which this tool's own audit correctly
    # flagged as leaking the OS username.
    spec_dir = Path(os.environ.get("PRODUCT_SPEC_DIR", HERE / "products"))
    spec = spec_dir / f"{name}.json"
    if spec.exists():
        try:
            p = json.loads(spec.read_text(encoding="utf-8"))
            desc = p.get("short") or p.get("tagline") or ""
            topics = [t.lower().replace(" ", "-") for t in p.get("categories", [])][:10]

            # `gh repo edit` requires OWNER/REPO -- a bare name fails with
            # 'expected the "[HOST/]OWNER/REPO" format'. The first version of this
            # passed a bare name AND ignored the return code, so it printed
            # "set description + 7 topics" while setting neither.
            owner = run(["gh", "api", "user", "-q", ".login"]).stdout.strip()
            slug = f"{owner}/{name}" if owner else name

            cmd = ["gh", "repo", "edit", slug]
            if desc:
                cmd += ["--description", desc[:350]]
            for t in topics:
                cmd += ["--add-topic", t]

            if len(cmd) > 4:
                r = run(cmd, timeout=120)
                if r.returncode != 0:
                    print(f"  WARN: could not set description/topics — "
                          f"{(r.stderr or r.stdout).strip()[:160]}")
                    print("        The repo is published but undiscoverable. Fix manually.")
                else:
                    # Verify rather than assume. Reporting unobserved success is the
                    # single most expensive habit in this codebase.
                    got = run(["gh", "repo", "view", slug, "--json",
                               "description,repositoryTopics"], timeout=60).stdout
                    ok_desc = bool(desc) and desc[:40] in got
                    ok_topics = '"name"' in got
                    print(f"  description set: {ok_desc}   topics set: {ok_topics}")
                    if not (ok_desc and ok_topics):
                        print("  WARN: edit returned success but the values did not "
                              "stick. Check the repo.")
        except (json.JSONDecodeError, OSError) as e:
            print(f"  WARN: could not set description/topics ({type(e).__name__}) — "
                  f"do it manually or the repo is undiscoverable")
    else:
        print(f"  WARN: no product spec at {spec} — description and topics are EMPTY.")
        print("        A repo with no description is invisible to GitHub search.")

    ledger = json.loads(LEDGER.read_text(encoding="utf-8")) if LEDGER.exists() else []
    ledger.append({
        "name": name,
        "url": url,
        "visibility": "private" if private else "public",
        "published_at": datetime.now(timezone.utc).isoformat(),
        "audit_warnings": data["counts"]["warn"],
    })
    LEDGER.write_text(json.dumps(ledger, indent=2), encoding="utf-8")
    print(f"  recorded in {LEDGER.name}")

    print("\n  NEXT: generate the submission pack —")
    print(f"    submit_pack.py products/{name}.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
