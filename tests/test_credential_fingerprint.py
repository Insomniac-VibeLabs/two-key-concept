"""Credential fingerprints: whitespace is stripped first, and the hash is an HMAC under a per-install key."""

import hashlib
import hmac
import os
import stat
import tempfile
import unittest
from pathlib import Path

from two_key import identity
from two_key.identity import (FINGERPRINT_DOMAIN, FINGERPRINT_KEY_ENV, IdentityError, credential_fingerprint,
                              fingerprint_key, fingerprint_key_id)
from test_judge_agent_separation import Env, claude


class KeyFile(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = os.path.join(self.tmp.name, "conf", "two-key", "fingerprint.key")
        old = os.environ.get(FINGERPRINT_KEY_ENV)
        os.environ[FINGERPRINT_KEY_ENV] = self.path
        self.addCleanup(lambda: os.environ.__setitem__(FINGERPRINT_KEY_ENV, old) if old is not None
                        else os.environ.pop(FINGERPRINT_KEY_ENV, None))
        identity._FINGERPRINT_KEYS.clear()
        self.addCleanup(identity._FINGERPRINT_KEYS.clear)

    def test_created_once_0600_in_a_0700_directory(self):
        key = fingerprint_key()
        self.assertEqual(len(key), 32)
        self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(os.stat(os.path.dirname(self.path)).st_mode), 0o700)
        identity._FINGERPRINT_KEYS.clear()
        self.assertEqual(fingerprint_key(), key, "an existing key is read, never regenerated")

    def test_fingerprint_is_hmac_of_stripped_secret(self):
        key = fingerprint_key()
        want = "hmac-sha256:" + hmac.new(key, FINGERPRINT_DOMAIN + b"sk-abc", hashlib.sha256).hexdigest()
        self.assertEqual(credential_fingerprint("sk-abc"), want)
        plain = "sha256:" + hashlib.sha256(FINGERPRINT_DOMAIN + b"sk-abc").hexdigest()
        self.assertNotEqual(credential_fingerprint("sk-abc").split(":", 1)[1], plain.split(":", 1)[1])

    def test_whitespace_is_stripped_first(self):
        fp = credential_fingerprint("sk-abc")
        for variant in ("sk-abc\n", "  sk-abc", "\tsk-abc \r\n"):
            self.assertEqual(credential_fingerprint(variant), fp, repr(variant))
        self.assertEqual(credential_fingerprint(" \n\t"), "none")
        self.assertNotEqual(credential_fingerprint("sk-a bc"), credential_fingerprint("sk-abc"))

    def test_another_install_gets_other_fingerprints(self):
        a = credential_fingerprint("sk-abc", key=b"a" * 32)
        b = credential_fingerprint("sk-abc", key=b"b" * 32)
        self.assertNotEqual(a, b)
        self.assertNotEqual(fingerprint_key_id(b"a" * 32), fingerprint_key_id(b"b" * 32))

    def test_group_readable_key_is_refused(self):
        fingerprint_key()
        os.chmod(self.path, 0o640)
        identity._FINGERPRINT_KEYS.clear()
        with self.assertRaisesRegex(IdentityError, "fingerprint_key_insecure"):
            fingerprint_key()

    def test_symlink_is_refused(self):
        os.makedirs(os.path.dirname(self.path))
        target = Path(self.tmp.name) / "elsewhere"
        target.write_bytes(b"x" * 32)
        os.chmod(target, 0o600)
        os.symlink(target, self.path)
        with self.assertRaisesRegex(IdentityError, "fingerprint_key_unreadable"):
            fingerprint_key()

    def test_wrong_length_is_refused(self):
        os.makedirs(os.path.dirname(self.path))
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.write(fd, b"short")
        os.close(fd)
        with self.assertRaisesRegex(IdentityError, "fingerprint_key_unreadable: .* 32-byte key"):
            fingerprint_key()

    @unittest.skipIf(hasattr(os, "geteuid") and os.geteuid() == 0, "root can write anywhere")
    def test_uncreatable_key_fails_closed(self):
        ro = Path(self.tmp.name) / "ro"
        ro.mkdir(mode=0o500)
        self.addCleanup(os.chmod, ro, 0o700)
        os.environ[FINGERPRINT_KEY_ENV] = str(ro / "fingerprint.key")
        with self.assertRaisesRegex(IdentityError, "fingerprint_key_unavailable"):
            fingerprint_key()


class Separation(Env):
    def test_agent_key_with_a_trailing_newline_still_matches_the_judge(self):
        os.environ["SEP_AGENT_KEY"] = "agent-secret-key\n"
        self.refused([claude(key="  agent-secret-key")], "same credential fingerprint")

    def test_record_names_the_fingerprint_scheme_not_the_key(self):
        tk = self.started([claude()])
        rec = tk.separation.to_record()
        self.assertEqual(rec["credential_fingerprint"]["alg"], "hmac-sha256")
        self.assertEqual(rec["credential_fingerprint"]["key_id"], fingerprint_key_id())
        self.assertNotIn(fingerprint_key().hex(), str(rec))


if __name__ == "__main__":
    unittest.main(verbosity=2)
