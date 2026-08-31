"""Real tests for audit.py -- the gate that stands in for a human before an
autonomous publish. Every test below operates on real temp files and, where
git history matters, a real temp git repo -- this tool's whole design is
"scan what git would actually publish," so a test double for git would be
testing a different tool.

Written 2026-08-31. Zero automated tests existed for prepublish before this.
"""

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import audit  # noqa: E402


def _write(root, rel, text):
    p = Path(root) / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


def _ip(a, b, c, d):
    """Assemble a dotted-quad at runtime so no literal IP-shaped string sits
    in this file's own source -- audit.py scans this repo too, and the
    point of these fixtures is to produce a matching value when WRITTEN TO
    A TEMP FILE, not to appear as one in the test source itself."""
    return f"{a}.{b}.{c}.{d}"


def _git(root, *args):
    return subprocess.run(["git", "-C", str(root), *args],
                          capture_output=True, text=True, timeout=30)


def _init_repo(root):
    _git(root, "init", "-q")
    _git(root, "config", "user.email", "test@example.invalid")
    _git(root, "config", "user.name", "Test")


class TestSecretPatterns(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tmpdir.name)

    def tearDown(self):
        self.tmpdir.cleanup()

    def _fatal_msgs(self, audit_name="SECURITY"):
        findings = audit.audit_security(self.root)
        return [f.msg for f in findings if f.severity == "FATAL"]

    def test_openai_style_key_caught(self):
        _write(self.root, "config.py", 'KEY = "sk-' + "a" * 40 + '"\n')
        self.assertTrue(any("OpenAI" in m for m in self._fatal_msgs()))

    def test_anthropic_key_caught(self):
        _write(self.root, "config.py", 'KEY = "sk-ant-' + "a" * 30 + '"\n')
        self.assertTrue(any("Anthropic" in m for m in self._fatal_msgs()))

    def test_aws_access_key_caught(self):
        _write(self.root, "config.py", 'AWS_KEY = "AKIA' + "A" * 16 + '"\n')
        self.assertTrue(any("AWS" in m for m in self._fatal_msgs()))

    def test_private_key_block_caught(self):
        # Built from separate word parts, not one contiguous literal -- this
        # file is itself scanned by audit.py when this repo is audited, and
        # audit_security() has TWO independent checks for a PEM header
        # (SECRET_PATTERNS' dashed form, plus a bare "BEGIN ... PRIVATE KEY"
        # check with no dashes required). A literal block here self-matches
        # both, the same self-matching trap this codebase has hit and fixed
        # several times elsewhere tonight. Keeping the words as separate
        # list items (never joined until runtime) means no contiguous
        # "BEGIN ... PRIVATE KEY" substring exists anywhere in this source.
        dashes = "-" * 5
        words = ["BEGIN", "RSA", "PRIVATE", "KEY"]
        header = " ".join(words)
        footer = " ".join(["END"] + words[1:])
        pem_block = f"{dashes}{header}{dashes}\nMIIExyz\n{dashes}{footer}{dashes}\n"
        _write(self.root, "id_rsa.txt", pem_block)
        self.assertTrue(any("PRIVATE KEY" in m or "private key" in m
                            for m in self._fatal_msgs()))

    def test_hardcoded_credential_assignment_caught(self):
        field, value = "pass" + "word", "actualSecretValue1234"
        _write(self.root, "settings.py", f'{field} = "{value}"\n')
        self.assertTrue(any("credential" in m for m in self._fatal_msgs()))

    def test_placeholder_value_not_flagged(self):
        _write(self.root, "config.py.example",
               'API_KEY = "sk-' + "x" * 40 + '"  # your api key here, example only\n')
        self.assertEqual(self._fatal_msgs(), [])

    def test_placeholder_hint_changeme_not_flagged(self):
        _write(self.root, ".env.sample", "PASSWORD=changeme\n")
        self.assertEqual(self._fatal_msgs(), [])


class TestSensitiveFiles(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tmpdir.name)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_dotenv_file_is_fatal_even_if_empty(self):
        # The whole point of name-based blocking: a binary/empty credential
        # file must still be caught, since content-scanning a .p12 sees nothing.
        _write(self.root, ".env", "")
        findings = audit.audit_security(self.root)
        self.assertTrue(any(f.severity == "FATAL" and ".env" in f.msg for f in findings))

    def test_pem_extension_is_fatal(self):
        _write(self.root, "server.pem", "not even real pem content")
        findings = audit.audit_security(self.root)
        self.assertTrue(any(f.severity == "FATAL" and "server.pem" in f.msg
                            for f in findings))

    def test_ordinary_python_file_is_not_flagged_by_name(self):
        _write(self.root, "main.py", "print('hello')\n")
        findings = audit.audit_security(self.root)
        self.assertEqual([f for f in findings if "main.py" in f.msg], [])


class TestExposurePatterns(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tmpdir.name)

    def tearDown(self):
        self.tmpdir.cleanup()

    def _fatal_msgs(self):
        return [f.msg for f in audit.audit_security(self.root) if f.severity == "FATAL"]

    def test_tailscale_ip_caught(self):
        # A fake address in the same CGNAT range the pattern matches --
        # never a real tailnet IP. See _ip()'s docstring for why this is
        # assembled at runtime instead of written as a literal.
        _write(self.root, "notes.md", f"reachable at {_ip(100, 88, 1, 1)} always\n")
        self.assertTrue(any("Tailscale" in m for m in self._fatal_msgs()))

    def test_windows_user_path_caught(self):
        user = "someuser"
        sep = "\\"
        path = "C:" + sep + "Users" + sep + user + sep + "logs"
        _write(self.root, "notes.md", f"logs live in {path}\n")
        self.assertTrue(any("local path" in m for m in self._fatal_msgs()))

    def test_private_lan_ip_caught(self):
        _write(self.root, "notes.md", f"internal server at {_ip(192, 168, 77, 77)}\n")
        self.assertTrue(any("private LAN" in m for m in self._fatal_msgs()))

    def test_localhost_is_not_flagged(self):
        # Documented deliberate exemption -- localhost reveals nothing.
        _write(self.root, "README.md", "connects to http://localhost:8080\n")
        self.assertEqual(self._fatal_msgs(), [])

    def test_dotted_filename_not_mistaken_for_internal_host(self):
        # Regression guard for the documented false positive: a real filename
        # like config.local.json must not match the internal-hostname pattern.
        _write(self.root, "README.md", "copy config.local.json to config.json\n")
        self.assertEqual([m for m in self._fatal_msgs() if "internal hostname" in m], [])

    def test_email_in_license_is_exempt(self):
        email = "dev" + "@" + "northgate-labs.dev"
        _write(self.root, "LICENSE", f"MIT License\n\nCopyright (c) 2026 {email}\n")
        self.assertEqual([m for m in self._fatal_msgs() if "email" in m], [])

    def test_email_outside_license_is_caught(self):
        email = "dev" + "@" + "northgate-labs.dev"
        _write(self.root, "notes.md", f"contact {email} for access\n")
        self.assertTrue(any("email" in m for m in self._fatal_msgs()))


class TestEntropyDetection(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tmpdir.name)

    def tearDown(self):
        self.tmpdir.cleanup()

    def _fatal_msgs(self):
        return [f.msg for f in audit.audit_security(self.root) if f.severity == "FATAL"]

    def test_unenumerated_high_entropy_token_caught(self):
        # A format with no vendor prefix in SECRET_PATTERNS -- this is the
        # exact case the entropy check exists for. Joined from four 8-char
        # chunks so no single 32+ char run (the check's own threshold) sits
        # in this file's source -- see _ip()'s docstring for why.
        token = "Zk9mQ2wX" + "7pR3vT8y" + "U1nH5jL0" + "aB6dE4gI"
        _write(self.root, "config.py", f'TOKEN = "{token}"\n')
        self.assertTrue(any("entropy" in m for m in self._fatal_msgs()))

    def test_sha256_hash_is_exempt_from_entropy_check(self):
        h = "a" * 64
        _write(self.root, "checksums.txt", f"sha256: {h}\n")
        self.assertEqual([m for m in self._fatal_msgs() if "entropy" in m], [])

    def test_base64_image_data_uri_is_exempt(self):
        _write(self.root, "logo.svg",
               'data:image/png;base64,' + "A" * 60 + '\n')
        self.assertEqual([m for m in self._fatal_msgs() if "entropy" in m], [])

    def test_english_prose_is_not_high_entropy(self):
        _write(self.root, "README.md",
               "This tool checks whether your code is safe to publish today.\n")
        self.assertEqual([m for m in self._fatal_msgs() if "entropy" in m], [])


class TestInternalNames(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tmpdir.name)
        self._orig_names = audit.INTERNAL_NAMES

    def tearDown(self):
        self.tmpdir.cleanup()
        audit.INTERNAL_NAMES = self._orig_names

    def test_configured_internal_name_is_fatal(self):
        audit.INTERNAL_NAMES = ["acme-internal-codename"]
        _write(self.root, "README.md", "part of the acme-internal-codename stack\n")
        findings = audit.audit_security(self.root)
        self.assertTrue(any(f.severity == "FATAL" and "internal project name" in f.msg
                            for f in findings))

    def test_unconfigured_list_fails_loudly_not_silently(self):
        # The gate's own documented discipline: no internal-name list means
        # that half of the scan did not run, and passing silently would be
        # worse than blocking -- verify it actually blocks (FAIL), not skip.
        audit.INTERNAL_NAMES = []
        _write(self.root, "README.md", "nothing sensitive here\n")
        findings = audit.audit_security(self.root)
        self.assertTrue(any("did NOT run" in f.msg for f in findings))


class TestGitHistoryLeak(unittest.TestCase):
    """The single most important claim in this tool's docstring: fixing the
    working tree does not remove a secret from history. Uses a real git
    repo, not a mock -- this tool's whole design is 'scan what git would
    actually publish.'"""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tmpdir.name)
        _init_repo(self.root)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_secret_removed_from_working_tree_still_caught_in_history(self):
        f = _write(self.root, "config.py", 'KEY = "sk-' + "b" * 40 + '"\n')
        _git(self.root, "add", "config.py")
        _git(self.root, "commit", "-q", "-m", "add config with a real-looking key")
        # Now "fix" it -- exactly the false sense of safety this test exists for.
        f.write_text('KEY = os.environ["KEY"]\n', encoding="utf-8")
        _git(self.root, "add", "config.py")
        _git(self.root, "commit", "-q", "-m", "remove hardcoded key")

        findings = audit.audit_security(self.root)
        history_findings = [f for f in findings
                            if f.severity == "FATAL" and "GIT HISTORY" in f.msg]
        self.assertTrue(history_findings,
                        "a secret removed from the working tree but still in an "
                        "earlier commit must still block as FATAL")

    def test_clean_history_is_not_flagged(self):
        _write(self.root, "README.md", "a perfectly ordinary readme\n")
        _git(self.root, "add", "README.md")
        _git(self.root, "commit", "-q", "-m", "initial commit, nothing sensitive")
        findings = audit.audit_security(self.root)
        self.assertEqual([f for f in findings if "GIT HISTORY" in f.msg], [])


class TestDeliverability(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tmpdir.name)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_missing_readme_and_license_fail(self):
        _write(self.root, "tool.py", "print('hi')\n")
        findings = audit.audit_deliverability(self.root)
        msgs = [f.msg for f in findings]
        self.assertTrue(any("no README" in m for m in msgs))
        self.assertTrue(any("no LICENSE" in m for m in msgs))

    def test_stub_license_fails(self):
        _write(self.root, "README.md", "# Tool\n\n## Install\npip install it\n")
        _write(self.root, "LICENSE", "TODO\n")
        findings = audit.audit_deliverability(self.root)
        self.assertTrue(any("not a real licence" in f.msg for f in findings))

    def test_real_mit_license_passes(self):
        _write(self.root, "README.md", "# Tool\n\n## Install\npip install it\n")
        _write(self.root, "LICENSE",
               "MIT License\n\nCopyright (c) 2026 Real Person\n\n" +
               "Permission is hereby granted, free of charge, " * 20)
        findings = audit.audit_deliverability(self.root)
        self.assertEqual([f for f in findings if "LICENSE" in f.where], [])

    def test_third_party_import_without_manifest_fails(self):
        _write(self.root, "README.md", "# Tool\n\n## Install\npip install it\n")
        _write(self.root, "LICENSE",
               "MIT License\n\nCopyright (c) 2026 Real Person\n\n" +
               "Permission is hereby granted, free of charge, " * 20)
        _write(self.root, "tool.py", "import requests\nrequests.get('x')\n")
        findings = audit.audit_deliverability(self.root)
        self.assertTrue(any("no manifest" in f.msg for f in findings))


class TestFullVerdict(unittest.TestCase):
    """End-to-end: a genuinely clean, minimal package must clear the SECURITY
    audit outright, and a package with a real secret must not."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tmpdir.name)
        self._orig_names = audit.INTERNAL_NAMES
        audit.INTERNAL_NAMES = ["not-present-anywhere-marker"]

    def tearDown(self):
        self.tmpdir.cleanup()
        audit.INTERNAL_NAMES = self._orig_names

    def test_clean_package_has_zero_security_fatals(self):
        _write(self.root, "README.md",
               "# tool\n\nDoes one thing. No known limitations noted here yet.\n")
        _write(self.root, "tool.py", "import sys\nprint(sys.argv)\n")
        findings = audit.audit_security(self.root)
        self.assertEqual([f for f in findings if f.severity == "FATAL"], [])

    def test_package_with_real_secret_has_at_least_one_fatal(self):
        _write(self.root, "tool.py", 'KEY = "sk-' + "c" * 40 + '"\nimport sys\n')
        findings = audit.audit_security(self.root)
        self.assertTrue(any(f.severity == "FATAL" for f in findings))


if __name__ == "__main__":
    unittest.main()
