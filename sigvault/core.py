"""Core engine for sigvault — artifact signing, verification & provenance.

sigvault signs software artifacts and emits supply-chain attestations in two
widely-used, open envelope formats:

  * DSSE  — a Dead Simple Signing Envelope (the canonical payload + a detached
            signature over a Pre-Authentication Encoding of it)
  * in-toto Statement — the predicate wrapper carried inside the DSSE payload,
            with a SLSA-style provenance predicate

Signing schemes (stdlib only, no external crypto package):

  * ed25519 — used when the running Python build exposes it (most do); this is
              the strong, asymmetric default. Keys are generated, saved, and
              loaded as raw 32-byte seeds (hex).
  * hmac    — a portable, symmetric fallback that works on ANY Python; useful
              for self-contained CI gates where a shared secret is acceptable.

Everything else — canonical JSON, the DSSE PAE, the in-toto Statement shape,
digests, verification policy — is original and standard-library only.

This is original Cognis Digital work implementing the public DSSE / in-toto /
SLSA shapes; it contains no third-party code, names, or branding.
"""

from __future__ import annotations

import base64
import hashlib
import hmac as _hmac
import json
import os
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

TOOL_NAME = "sigvault"
TOOL_VERSION = "0.1.0"

DSSE_PAYLOAD_TYPE = "application/vnd.in-toto+json"
INTOTO_STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
SLSA_PREDICATE_TYPE = "https://slsa.dev/provenance/v1"

# Detect a usable ed25519 implementation in the standard library / runtime.
try:  # pragma: no cover - availability depends on the build
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey, Ed25519PublicKey)
    from cryptography.hazmat.primitives import serialization
    _HAVE_ED25519 = True
except Exception:  # pragma: no cover
    _HAVE_ED25519 = False


class SigvaultError(Exception):
    """User-facing signing/verification error."""


# --------------------------------------------------------------------------- #
# Encoding helpers
# --------------------------------------------------------------------------- #

def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


def canonical_json(obj: Any) -> bytes:
    """Deterministic JSON encoding (sorted keys, no extra whitespace)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def dsse_pae(payload_type: str, payload: bytes) -> bytes:
    """Pre-Authentication Encoding for DSSE.

    PAE(type, body) = "DSSEv1" SP len(type) SP type SP len(body) SP body
    """
    return b"DSSEv1 " + \
        str(len(payload_type)).encode() + b" " + payload_type.encode() + b" " + \
        str(len(payload)).encode() + b" " + payload


# --------------------------------------------------------------------------- #
# Keys
# --------------------------------------------------------------------------- #

@dataclass
class KeyPair:
    scheme: str                  # "ed25519" | "hmac"
    private: bytes               # seed (ed25519) or secret (hmac)
    public: bytes                # public key (ed25519) or same secret (hmac)
    key_id: str

    def to_files(self, base: str) -> Tuple[str, str]:
        priv_path, pub_path = base + ".key", base + ".pub"
        with open(priv_path, "w", encoding="utf-8") as fh:
            json.dump({"scheme": self.scheme, "key_id": self.key_id,
                       "private": _b64e(self.private)}, fh, indent=2)
        with open(pub_path, "w", encoding="utf-8") as fh:
            json.dump({"scheme": self.scheme, "key_id": self.key_id,
                       "public": _b64e(self.public)}, fh, indent=2)
        try:
            os.chmod(priv_path, 0o600)
        except OSError:
            pass
        return priv_path, pub_path


def _key_id(scheme: str, public: bytes) -> str:
    return scheme + ":" + sha256_bytes(public)[:16]


def generate_key(scheme: str = "auto") -> KeyPair:
    """Generate a key pair. ``auto`` prefers ed25519, falls back to hmac."""
    if scheme == "auto":
        scheme = "ed25519" if _HAVE_ED25519 else "hmac"
    if scheme == "ed25519":
        if not _HAVE_ED25519:
            raise SigvaultError("ed25519 unavailable in this Python; use hmac")
        sk = Ed25519PrivateKey.generate()
        seed = sk.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption())
        pub = sk.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw)
        return KeyPair("ed25519", seed, pub, _key_id("ed25519", pub))
    if scheme == "hmac":
        secret = os.urandom(32)
        return KeyPair("hmac", secret, secret, _key_id("hmac", secret))
    raise SigvaultError(f"unknown scheme: {scheme}")


def load_private_key(path: str) -> KeyPair:
    with open(path, "r", encoding="utf-8") as fh:
        d = json.load(fh)
    scheme = d["scheme"]
    priv = _b64d(d["private"])
    if scheme == "ed25519":
        if not _HAVE_ED25519:
            raise SigvaultError("ed25519 unavailable in this Python")
        sk = Ed25519PrivateKey.from_private_bytes(priv)
        pub = sk.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw)
    else:
        pub = priv
    return KeyPair(scheme, priv, pub, d.get("key_id") or _key_id(scheme, pub))


def load_public_key(path: str) -> KeyPair:
    with open(path, "r", encoding="utf-8") as fh:
        d = json.load(fh)
    pub = _b64d(d["public"])
    return KeyPair(d["scheme"], b"", pub, d.get("key_id") or _key_id(d["scheme"], pub))


# --------------------------------------------------------------------------- #
# Raw sign / verify over PAE
# --------------------------------------------------------------------------- #

def _raw_sign(key: KeyPair, message: bytes) -> bytes:
    if key.scheme == "ed25519":
        sk = Ed25519PrivateKey.from_private_bytes(key.private)
        return sk.sign(message)
    if key.scheme == "hmac":
        return _hmac.new(key.private, message, hashlib.sha256).digest()
    raise SigvaultError(f"unknown scheme: {key.scheme}")


def _raw_verify(key: KeyPair, message: bytes, signature: bytes) -> bool:
    if key.scheme == "ed25519":
        try:
            Ed25519PublicKey.from_public_bytes(key.public).verify(signature, message)
            return True
        except Exception:
            return False
    if key.scheme == "hmac":
        expected = _hmac.new(key.public, message, hashlib.sha256).digest()
        return _hmac.compare_digest(expected, signature)
    return False


# --------------------------------------------------------------------------- #
# in-toto Statement / SLSA provenance
# --------------------------------------------------------------------------- #

def build_statement(subjects: List[Dict[str, Any]],
                    predicate_type: str,
                    predicate: Dict[str, Any]) -> Dict[str, Any]:
    """Build an in-toto v1 Statement."""
    return {
        "_type": INTOTO_STATEMENT_TYPE,
        "subject": subjects,
        "predicateType": predicate_type,
        "predicate": predicate,
    }


def subject_for_file(path: str, name: Optional[str] = None) -> Dict[str, Any]:
    return {"name": name or os.path.basename(path),
            "digest": {"sha256": sha256_file(path)}}


def slsa_provenance(builder_id: str, build_type: str,
                    invocation: Optional[Dict[str, Any]] = None,
                    materials: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """A minimal SLSA v1-shaped provenance predicate."""
    return {
        "buildDefinition": {
            "buildType": build_type,
            "externalParameters": invocation or {},
            "resolvedDependencies": materials or [],
        },
        "runDetails": {
            "builder": {"id": builder_id},
            "metadata": {
                "invocationId": sha256_bytes(os.urandom(16))[:16],
                "startedOn": int(time.time()),
            },
        },
    }


# --------------------------------------------------------------------------- #
# DSSE envelope: sign / verify
# --------------------------------------------------------------------------- #

def sign_statement(statement: Dict[str, Any], key: KeyPair) -> Dict[str, Any]:
    """Produce a DSSE envelope wrapping an in-toto statement."""
    payload = canonical_json(statement)
    pae = dsse_pae(DSSE_PAYLOAD_TYPE, payload)
    sig = _raw_sign(key, pae)
    return {
        "payloadType": DSSE_PAYLOAD_TYPE,
        "payload": _b64e(payload),
        "signatures": [{"keyid": key.key_id, "sig": _b64e(sig)}],
    }


def sign_file(path: str, key: KeyPair, *,
              builder_id: str = "cognis-digital/sigvault",
              build_type: str = "https://cognis.digital/buildtypes/manual") -> Dict[str, Any]:
    """Sign a file: build a provenance statement and wrap it in a DSSE envelope."""
    if not os.path.isfile(path):
        raise SigvaultError(f"file not found: {path}")
    statement = build_statement(
        subjects=[subject_for_file(path)],
        predicate_type=SLSA_PREDICATE_TYPE,
        predicate=slsa_provenance(builder_id, build_type,
                                  invocation={"path": os.path.basename(path)}))
    return sign_statement(statement, key)


# SBOM attestation predicate type (CycloneDX/SPDX-style "this artifact's BOM").
SBOM_PREDICATE_TYPE = "https://cognis.digital/attestations/sbom/v1"


def attest_sbom(path: str, sbom: Dict[str, Any], key: KeyPair) -> Dict[str, Any]:
    """Sign an SBOM *about* a file as a DSSE in-toto attestation.

    The file's digest is the subject; the SBOM document is the predicate.
    """
    if not os.path.isfile(path):
        raise SigvaultError(f"file not found: {path}")
    statement = build_statement(
        subjects=[subject_for_file(path)],
        predicate_type=SBOM_PREDICATE_TYPE,
        predicate=sbom)
    return sign_statement(statement, key)


def add_signature(envelope: Dict[str, Any], key: KeyPair) -> Dict[str, Any]:
    """Co-sign an existing DSSE envelope with an additional key.

    The same payload (and its PAE) is signed; the new signature is appended.
    Returns a NEW envelope (the input is not mutated). Idempotent per key id.
    """
    try:
        payload = _b64d(envelope["payload"])
        payload_type = envelope.get("payloadType", DSSE_PAYLOAD_TYPE)
        sigs = list(envelope.get("signatures", []))
    except (KeyError, ValueError, TypeError) as exc:
        raise SigvaultError(f"malformed DSSE envelope: {exc}") from exc
    pae = dsse_pae(payload_type, payload)
    new_sig = {"keyid": key.key_id, "sig": _b64e(_raw_sign(key, pae))}
    if not any(s.get("keyid") == key.key_id for s in sigs):
        sigs.append(new_sig)
    return {"payloadType": payload_type, "payload": envelope["payload"],
            "signatures": sigs}


def verify_threshold(envelope: Dict[str, Any], keys: List[KeyPair],
                     threshold: int = 1) -> Dict[str, Any]:
    """Verify an envelope reaches ``threshold`` distinct valid signers from ``keys``.

    Returns {ok, valid_signers, threshold, signer_ids}. A signer counts once
    even if the envelope carries duplicate signatures.
    """
    try:
        payload = _b64d(envelope["payload"])
        payload_type = envelope.get("payloadType", DSSE_PAYLOAD_TYPE)
        sigs = envelope.get("signatures", [])
    except (KeyError, ValueError, TypeError) as exc:
        raise SigvaultError(f"malformed DSSE envelope: {exc}") from exc
    pae = dsse_pae(payload_type, payload)
    valid: set = set()
    for key in keys:
        for s in sigs:
            try:
                if _raw_verify(key, pae, _b64d(s["sig"])):
                    valid.add(key.key_id)
                    break
            except (KeyError, ValueError):
                continue
    return {"ok": len(valid) >= threshold, "valid_signers": len(valid),
            "threshold": threshold, "signer_ids": sorted(valid)}


def verify_envelope(envelope: Dict[str, Any], key: KeyPair) -> Dict[str, Any]:
    """Verify a DSSE envelope's signature(s) against a public key.

    Returns {ok, key_id, verified_signatures, statement}.
    """
    try:
        payload = _b64d(envelope["payload"])
        payload_type = envelope.get("payloadType", DSSE_PAYLOAD_TYPE)
        sigs = envelope.get("signatures", [])
    except (KeyError, ValueError, TypeError) as exc:
        raise SigvaultError(f"malformed DSSE envelope: {exc}") from exc

    pae = dsse_pae(payload_type, payload)
    verified = 0
    for s in sigs:
        try:
            if _raw_verify(key, pae, _b64d(s["sig"])):
                verified += 1
        except (KeyError, ValueError):
            continue
    statement = None
    try:
        statement = json.loads(payload.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        pass
    return {"ok": verified > 0, "key_id": key.key_id,
            "verified_signatures": verified, "statement": statement}


def verify_file(path: str, envelope: Dict[str, Any], key: KeyPair) -> Dict[str, Any]:
    """Verify the envelope AND that it actually attests to ``path``'s digest."""
    res = verify_envelope(envelope, key)
    digest = sha256_file(path)
    subject_match = False
    stmt = res.get("statement") or {}
    for subj in stmt.get("subject", []):
        if subj.get("digest", {}).get("sha256") == digest:
            subject_match = True
            break
    res["subject_match"] = subject_match
    res["digest"] = digest
    res["ok"] = bool(res["ok"] and subject_match)
    return res


# --------------------------------------------------------------------------- #
# Verification policy (a simple multi-rule gate)
# --------------------------------------------------------------------------- #

def evaluate_policy(envelope: Dict[str, Any], key: KeyPair,
                    policy: Dict[str, Any]) -> Dict[str, Any]:
    """Evaluate a small verification policy against a signed envelope.

    Policy keys (all optional):
      required_builder_id   — runDetails.builder.id must equal this
      required_predicate    — predicateType must equal this
      min_signatures        — minimum number of valid signatures (default 1)
    """
    res = verify_envelope(envelope, key)
    stmt = res.get("statement") or {}
    problems: List[str] = []

    if not res["ok"]:
        problems.append("signature did not verify")
    min_sigs = int(policy.get("min_signatures", 1))
    if res["verified_signatures"] < min_sigs:
        problems.append(f"need >= {min_sigs} valid signatures, "
                        f"got {res['verified_signatures']}")
    if policy.get("required_predicate") and \
            stmt.get("predicateType") != policy["required_predicate"]:
        problems.append("predicateType mismatch")
    if policy.get("required_builder_id"):
        bid = (stmt.get("predicate", {}).get("runDetails", {})
               .get("builder", {}).get("id"))
        if bid != policy["required_builder_id"]:
            problems.append(f"builder id mismatch (got {bid})")

    return {"ok": not problems, "problems": problems,
            "verified_signatures": res["verified_signatures"]}


# --------------------------------------------------------------------------- #
# AI hook (opt-in, default OFF)
# --------------------------------------------------------------------------- #

def explain_envelope(envelope: Dict[str, Any]) -> Dict[str, Any]:
    """Plain-English summary of what an attestation claims (local fleet, OFF by default)."""
    try:
        stmt = json.loads(_b64d(envelope["payload"]).decode())
    except Exception:
        stmt = {}
    out = {"subjects": [s.get("name") for s in stmt.get("subject", [])],
           "predicate_type": stmt.get("predicateType"),
           "summary": "", "_ai": "disabled — set COGNIS_AI_BACKEND to enable"}
    backend = _load_ai_backend()
    if backend is None or not backend.is_enabled() or not backend.health():
        return out
    try:
        out["summary"] = backend._chat(
            "Summarize this software attestation in two sentences.",
            json.dumps(stmt)) or ""
        out["_ai"] = "summarized by local fleet"
    except Exception:
        pass
    return out


def _load_ai_backend():
    import importlib.util
    here = os.path.dirname(os.path.abspath(__file__))
    cand = os.path.abspath(os.path.join(here, "..", "..", "..", "_shared",
                                        "cognis_ai_backend.py"))
    if os.path.isfile(cand):
        try:
            spec = importlib.util.spec_from_file_location("cognis_ai_backend", cand)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)  # type: ignore[union-attr]
            return mod.CognisAIBackend()
        except Exception:
            return None
    return None
