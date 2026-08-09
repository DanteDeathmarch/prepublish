# prepublish

![License](https://img.shields.io/badge/license-MIT-blue) ![Python](https://img.shields.io/badge/python-3.8%2B-blue) ![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)

**Audit a repo before it goes public. Publish it only if it's clean.**

For anyone about to `gh repo create --public` on something they've been building
privately — especially if an AI agent wrote part of it and you haven't read every line.

```bash
python audit.py ./my-project
```

```
AUDIT — my-project
==========================================================================
  FATAL SECURITY       GitHub token found [.env:1]
  FATAL SECURITY       sensitive file present: .env [.env]
  FATAL SECURITY       OpenAI-style API key found [tool.py:2]
  FATAL SECURITY       Tailscale tailnet IP — maps your private network [tool.py:3]
  FATAL SECURITY       absolute local path — leaks the OS username [tool.py:4]
  FAIL  DELIVERABILITY no LICENSE
  FAIL  USABILITY      --help produced nothing useful [tool.py]
  WARN  QUALITY        bare `except: pass` [tool.py]
==========================================================================
  FATAL 5   FAIL 3   WARN 8

  BLOCKED — security findings cannot be waived.
```

## Why

Publishing is not as reversible as it feels. GitHub is indexed within seconds and
credential scrapers watch the event firehose. **Deleting the repo afterwards doesn't
un-leak the key — it only removes the evidence.**

And the leak is usually not a key. It's `C:\Users\yourname\...` in a default path, your
private network IP in a config, your employer's internal project name in a comment, or
a secret in commit #3 that you "removed" in commit #4 and is still sitting in
`git log -p`.

## Install

Nothing to install. Python 3.8+, standard library only.

```bash
curl -O https://raw.githubusercontent.com/DanteDeathmarch/prepublish/main/audit.py
python audit.py ./my-project
```

## The five audits

| Audit | Checks | Blocking? |
|---|---|---|
| **SECURITY** | API keys (12 formats), private keys, `.env` and friends, tailnet IPs, absolute home paths, emails, internal service ports, your own internal project names — **in the working tree, in the full git history, and in commit messages** | **always fatal, never waivable** |
| **DELIVERABILITY** | README, LICENSE, `.gitignore`, undeclared third-party imports | blocks |
| **USABILITY** | `--help` and `--version` actually work; no raw traceback on bad input | blocks |
| **QUALITY** | files parse; no `TODO`/`FIXME` left in source; no bare `except: pass` | warns |
| **VIABILITY** | README states a problem, a named audience, and its own limitations | warns |

### Security findings cannot be waived

There is no `--force`, no `--ignore`, no allowlist flag. That is deliberate: a waiver
flag is the mechanism by which every scanner eventually becomes decorative.

If a finding is a false positive, fix the line so it reads as a placeholder
(`your-key-here`, `<TOKEN>`, `example`), which the scanner already recognises.

### It checks git history and commit messages, not just files

Most scanners read the working tree. That misses the most common real leak: a
credential committed once and deleted later. `git log -p` still serves it, and so does
every fork and every clone.

This scans:
- every tracked file in the working tree
- every added and removed line across all branches
- every commit message, author line, and body

## Configure your own internal names

The names that must never ship are different for everyone, and **a list of your private
project names is itself sensitive** — so it isn't in the source.

```bash
# option 1: a file next to audit.py (add it to .gitignore)
cat > internal-names.txt <<'EOF'
acme-internal
project-condor
staging-cluster
EOF

# option 2: environment
export AUDIT_INTERNAL_NAMES="acme-internal,project-condor"
```

If neither is set, the audit **fails** rather than passing quietly. A pass without it
means "no secrets found", not "nothing private found", and the difference matters.

## Publish only if clean

```bash
python publish.py ./my-project              # public
python publish.py ./my-project --dry-run    # everything except the push
python publish.py ./my-project --private
```

Runs: **audit → package → audit again → commit → push.**

The second audit is the one people skip and the one that matters. Packaging changes
files, and an audit is a statement about specific bytes — change the bytes and the
statement no longer holds.

`package.py` adds badges, `CONTRIBUTING.md`, `SECURITY.md`, and `.gitattributes`. It
SHA-256 hashes every source file before and after and **aborts if a single byte
moved** — presentation must never alter behaviour that was just audited.

## Exit codes

`0` clear · `1` findings block the publish · `2` usage error

Drops straight into CI:

```yaml
- run: python audit.py . || exit 1
```

## What it does NOT do

- **It is not a guarantee.** It catches the patterns it knows. A novel credential
  format, an obfuscated string, or a secret inside a binary will pass.
- It does not scan binaries, images, or `node_modules`.
- It does not judge whether your code is *good* — only whether it is safe to show and
  possible for a stranger to run.
- It cannot rewrite git history for you. If history is dirty, the fix is a fresh repo
  with one clean commit.

Treat a CLEAR as "no known problems found", never as "verified safe".

## License

MIT.