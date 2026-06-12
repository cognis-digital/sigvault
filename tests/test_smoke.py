"""Smoke tests for sigvault. Standard library only, no network."""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sigvault import TOOL_NAME, TOOL_VERSION, generate_key, sign_file, verify_file
from sigvault.cli import main


class TestMetadata(unittest.TestCase):
    def test_metadata(self):
        self.assertEqual(TOOL_NAME, "sigvault")
        self.assertTrue(TOOL_VERSION)


class TestSignVerify(unittest.TestCase):
    def test_hmac_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            art = os.path.join(tmp, "artifact.bin")
            with open(art, "wb") as fh:
                fh.write(b"hello cognis")
            key = generate_key("hmac")
            env = sign_file(art, key)
            res = verify_file(art, env, key)
            self.assertTrue(res["ok"])
            self.assertTrue(res["subject_match"])

    def test_tamper_breaks_verification(self):
        with tempfile.TemporaryDirectory() as tmp:
            art = os.path.join(tmp, "a.bin")
            with open(art, "wb") as fh:
                fh.write(b"original")
            key = generate_key("hmac")
            env = sign_file(art, key)
            with open(art, "wb") as fh:
                fh.write(b"tampered")  # change after signing
            res = verify_file(art, env, key)
            self.assertFalse(res["ok"])


class TestCli(unittest.TestCase):
    def test_keygen_sign_verify_flow(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = os.path.join(tmp, "k")
            art = os.path.join(tmp, "app.txt")
            with open(art, "w") as fh:
                fh.write("payload")
            self.assertEqual(main(["keygen", "--scheme", "hmac", "--out", base]), 0)
            env_path = os.path.join(tmp, "app.txt.dsse.json")
            self.assertEqual(main(["sign", art, "--key", base + ".key",
                                   "--out", env_path]), 0)
            self.assertEqual(main(["verify", art, "--envelope", env_path,
                                   "--key", base + ".pub"]), 0)

    def test_no_command_exits_2(self):
        self.assertEqual(main([]), 2)


if __name__ == "__main__":
    unittest.main()
