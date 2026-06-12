"""Feature tests for sigvault — co-signing, threshold verify, SBOM attest, CLI."""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sigvault import (
    SBOM_PREDICATE_TYPE, add_signature, attest_sbom, generate_key, sign_file,
    verify_envelope, verify_file, verify_threshold,
)
from sigvault.core import SigvaultError
from sigvault.cli import main


def _artifact(tmp, content=b"release-binary"):
    p = os.path.join(tmp, "app.bin")
    with open(p, "wb") as fh:
        fh.write(content)
    return p


class TestCoSign(unittest.TestCase):
    def test_add_second_signature(self):
        with tempfile.TemporaryDirectory() as tmp:
            art = _artifact(tmp)
            k1, k2 = generate_key("hmac"), generate_key("hmac")
            env = sign_file(art, k1)
            env2 = add_signature(env, k2)
            self.assertEqual(len(env2["signatures"]), 2)
            # both keys verify their own signature
            self.assertTrue(verify_envelope(env2, k1)["ok"])
            self.assertTrue(verify_envelope(env2, k2)["ok"])

    def test_add_signature_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            art = _artifact(tmp)
            k = generate_key("hmac")
            env = sign_file(art, k)
            env2 = add_signature(env, k)  # same key, no dup
            self.assertEqual(len(env2["signatures"]), 1)

    def test_add_signature_does_not_mutate_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            art = _artifact(tmp)
            k1, k2 = generate_key("hmac"), generate_key("hmac")
            env = sign_file(art, k1)
            add_signature(env, k2)
            self.assertEqual(len(env["signatures"]), 1)  # original untouched

    def test_malformed_envelope(self):
        with self.assertRaises(SigvaultError):
            add_signature({"no": "payload"}, generate_key("hmac"))


class TestThreshold(unittest.TestCase):
    def test_two_of_three(self):
        with tempfile.TemporaryDirectory() as tmp:
            art = _artifact(tmp)
            k1, k2, k3 = (generate_key("hmac") for _ in range(3))
            env = add_signature(sign_file(art, k1), k2)  # signed by k1 + k2
            res = verify_threshold(env, [k1, k2, k3], threshold=2)
            self.assertTrue(res["ok"])
            self.assertEqual(res["valid_signers"], 2)

    def test_below_threshold_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            art = _artifact(tmp)
            k1, k2 = generate_key("hmac"), generate_key("hmac")
            env = sign_file(art, k1)  # only k1
            res = verify_threshold(env, [k1, k2], threshold=2)
            self.assertFalse(res["ok"])
            self.assertEqual(res["valid_signers"], 1)

    def test_signer_counted_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            art = _artifact(tmp)
            k1 = generate_key("hmac")
            env = sign_file(art, k1)
            env["signatures"].append(dict(env["signatures"][0]))  # duplicate
            res = verify_threshold(env, [k1], threshold=1)
            self.assertEqual(res["valid_signers"], 1)


class TestSbomAttest(unittest.TestCase):
    def test_attest_and_verify(self):
        with tempfile.TemporaryDirectory() as tmp:
            art = _artifact(tmp)
            k = generate_key("hmac")
            sbom = {"bomFormat": "CognisBOM", "components": [{"name": "zlib"}]}
            env = attest_sbom(art, sbom, k)
            res = verify_file(art, env, k)
            self.assertTrue(res["ok"])
            self.assertEqual(res["statement"]["predicateType"], SBOM_PREDICATE_TYPE)
            self.assertEqual(res["statement"]["predicate"]["components"][0]["name"], "zlib")

    def test_attest_missing_file(self):
        with self.assertRaises(SigvaultError):
            attest_sbom("/no/such", {}, generate_key("hmac"))


class TestCliFeatures(unittest.TestCase):
    def test_add_sig_and_threshold_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            art = _artifact(tmp)
            b1, b2 = os.path.join(tmp, "k1"), os.path.join(tmp, "k2")
            self.assertEqual(main(["keygen", "--scheme", "hmac", "--out", b1]), 0)
            self.assertEqual(main(["keygen", "--scheme", "hmac", "--out", b2]), 0)
            env = os.path.join(tmp, "e.dsse.json")
            self.assertEqual(main(["sign", art, "--key", b1 + ".key", "--out", env]), 0)
            self.assertEqual(main(["add-sig", env, "--key", b2 + ".key"]), 0)
            # threshold of 2 across both public keys passes
            self.assertEqual(main(["verify-threshold", env,
                                   "--key", b1 + ".pub", "--key", b2 + ".pub",
                                   "--threshold", "2"]), 0)

    def test_threshold_fails_nonzero(self):
        with tempfile.TemporaryDirectory() as tmp:
            art = _artifact(tmp)
            b1, b2 = os.path.join(tmp, "k1"), os.path.join(tmp, "k2")
            main(["keygen", "--scheme", "hmac", "--out", b1])
            main(["keygen", "--scheme", "hmac", "--out", b2])
            env = os.path.join(tmp, "e.dsse.json")
            main(["sign", art, "--key", b1 + ".key", "--out", env])  # 1 signer
            self.assertEqual(main(["verify-threshold", env,
                                   "--key", b1 + ".pub", "--key", b2 + ".pub",
                                   "--threshold", "2"]), 1)

    def test_attest_sbom_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            art = _artifact(tmp)
            base = os.path.join(tmp, "k")
            main(["keygen", "--scheme", "hmac", "--out", base])
            sbom = os.path.join(tmp, "sbom.json")
            with open(sbom, "w") as fh:
                json.dump({"components": []}, fh)
            out = os.path.join(tmp, "a.dsse.json")
            self.assertEqual(main(["attest-sbom", art, "--sbom", sbom,
                                   "--key", base + ".key", "--out", out]), 0)
            self.assertTrue(os.path.isfile(out))


if __name__ == "__main__":
    unittest.main()
