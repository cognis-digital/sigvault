"""Deep tests for sigvault — PAE, DSSE, in-toto/SLSA, policy, keys, MCP."""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sigvault import (
    build_statement,
    canonical_json,
    dsse_pae,
    evaluate_policy,
    explain_envelope,
    generate_key,
    load_private_key,
    load_public_key,
    sign_file,
    sign_statement,
    slsa_provenance,
    subject_for_file,
    verify_envelope,
    verify_file,
)
from sigvault.core import _HAVE_ED25519, SLSA_PREDICATE_TYPE, SigvaultError
from sigvault import mcp_server


def _artifact(tmp, content=b"data"):
    p = os.path.join(tmp, "art.bin")
    with open(p, "wb") as fh:
        fh.write(content)
    return p


class TestEncodings(unittest.TestCase):
    def test_canonical_json_sorted(self):
        self.assertEqual(canonical_json({"b": 1, "a": 2}), b'{"a":2,"b":1}')

    def test_pae_format(self):
        pae = dsse_pae("t", b"body")
        self.assertEqual(pae, b"DSSEv1 1 t 4 body")


class TestStatement(unittest.TestCase):
    def test_statement_shape(self):
        with tempfile.TemporaryDirectory() as tmp:
            art = _artifact(tmp)
            stmt = build_statement([subject_for_file(art)], SLSA_PREDICATE_TYPE,
                                   slsa_provenance("b", "bt"))
            self.assertEqual(stmt["predicateType"], SLSA_PREDICATE_TYPE)
            self.assertIn("buildDefinition", stmt["predicate"])
            self.assertEqual(len(stmt["subject"][0]["digest"]["sha256"]), 64)


class TestKeys(unittest.TestCase):
    def test_hmac_key_files_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            kp = generate_key("hmac")
            base = os.path.join(tmp, "k")
            kp.to_files(base)
            loaded = load_private_key(base + ".key")
            self.assertEqual(loaded.key_id, kp.key_id)
            pub = load_public_key(base + ".pub")
            self.assertEqual(pub.key_id, kp.key_id)

    @unittest.skipUnless(_HAVE_ED25519, "ed25519 not available")
    def test_ed25519_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            art = _artifact(tmp)
            kp = generate_key("ed25519")
            env = sign_file(art, kp)
            self.assertTrue(verify_file(art, env, kp)["ok"])

    def test_auto_scheme(self):
        kp = generate_key("auto")
        self.assertIn(kp.scheme, ("ed25519", "hmac"))


class TestDsseVerify(unittest.TestCase):
    def test_wrong_key_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            art = _artifact(tmp)
            k1, k2 = generate_key("hmac"), generate_key("hmac")
            env = sign_file(art, k1)
            self.assertFalse(verify_envelope(env, k2)["ok"])

    def test_malformed_envelope_raises(self):
        with self.assertRaises(SigvaultError):
            verify_envelope({"no": "payload"}, generate_key("hmac"))

    def test_statement_recovered(self):
        with tempfile.TemporaryDirectory() as tmp:
            art = _artifact(tmp)
            kp = generate_key("hmac")
            res = verify_envelope(sign_file(art, kp), kp)
            self.assertEqual(res["statement"]["_type"].split("/")[-2], "Statement")


class TestPolicy(unittest.TestCase):
    def test_builder_id_enforced(self):
        with tempfile.TemporaryDirectory() as tmp:
            art = _artifact(tmp)
            kp = generate_key("hmac")
            env = sign_file(art, kp, builder_id="cognis-digital/ci")
            ok = evaluate_policy(env, kp,
                                 {"required_builder_id": "cognis-digital/ci"})
            self.assertTrue(ok["ok"])
            bad = evaluate_policy(env, kp,
                                  {"required_builder_id": "someone-else"})
            self.assertFalse(bad["ok"])

    def test_predicate_and_min_sigs(self):
        with tempfile.TemporaryDirectory() as tmp:
            art = _artifact(tmp)
            kp = generate_key("hmac")
            env = sign_file(art, kp)
            res = evaluate_policy(env, kp,
                                  {"required_predicate": SLSA_PREDICATE_TYPE,
                                   "min_signatures": 1})
            self.assertTrue(res["ok"])
            res2 = evaluate_policy(env, kp, {"min_signatures": 2})
            self.assertFalse(res2["ok"])


class TestMcp(unittest.TestCase):
    def test_list(self):
        tl = mcp_server.handle_request({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        names = {t["name"] for t in tl["result"]["tools"]}
        self.assertEqual(names, {"sign", "verify", "policy"})

    def test_sign_then_verify_via_mcp(self):
        with tempfile.TemporaryDirectory() as tmp:
            art = _artifact(tmp)
            kp = generate_key("hmac")
            base = os.path.join(tmp, "k")
            kp.to_files(base)
            r = mcp_server.handle_request({
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": "sign",
                           "arguments": {"file": art, "key": base + ".key"}}})
            env = json.loads(r["result"]["content"][0]["text"])
            env_path = os.path.join(tmp, "e.json")
            with open(env_path, "w") as fh:
                json.dump(env, fh)
            r2 = mcp_server.handle_request({
                "jsonrpc": "2.0", "id": 3, "method": "tools/call",
                "params": {"name": "verify",
                           "arguments": {"file": art, "envelope": env_path,
                                         "key": base + ".pub"}}})
            self.assertFalse(r2["result"]["isError"])


class TestAiHook(unittest.TestCase):
    def test_off_by_default(self):
        for v in ("COGNIS_AI_BACKEND", "COGNIS_AI_ENDPOINT"):
            os.environ.pop(v, None)
        with tempfile.TemporaryDirectory() as tmp:
            art = _artifact(tmp)
            kp = generate_key("hmac")
            out = explain_envelope(sign_file(art, kp))
            self.assertTrue(out["_ai"].startswith("disabled"))
            self.assertEqual(out["predicate_type"], SLSA_PREDICATE_TYPE)


if __name__ == "__main__":
    unittest.main()
