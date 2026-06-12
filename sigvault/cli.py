"""Command-line interface for sigvault."""

from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from sigvault import TOOL_NAME, TOOL_VERSION
from sigvault.core import (
    SigvaultError,
    evaluate_policy,
    generate_key,
    load_private_key,
    load_public_key,
    sign_file,
    verify_file,
)


def _emit(text: str, out: Optional[str]) -> None:
    if out:
        with open(out, "w", encoding="utf-8") as fh:
            fh.write(text if text.endswith("\n") else text + "\n")
        print(f"wrote {out}", file=sys.stderr)
    else:
        print(text)


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Artifact signing, verification & SLSA/in-toto provenance — "
                    "DSSE envelopes, ed25519 or portable HMAC, no external crypto.")
    p.add_argument("--version", action="version",
                   version=f"{TOOL_NAME} {TOOL_VERSION}")
    sub = p.add_subparsers(dest="command")

    k = sub.add_parser("keygen", help="Generate a signing key pair.")
    k.add_argument("--scheme", choices=("auto", "ed25519", "hmac"), default="auto")
    k.add_argument("--out", default="sigvault-key",
                   help="Base path; writes <base>.key and <base>.pub")

    s = sub.add_parser("sign", help="Sign a file; emit a DSSE provenance envelope.")
    s.add_argument("file")
    s.add_argument("--key", required=True, help="Private key (.key).")
    s.add_argument("--builder-id", default="cognis-digital/sigvault")
    s.add_argument("--out", help="Write the envelope (default: <file>.dsse.json).")

    v = sub.add_parser("verify", help="Verify an envelope against a file + public key.")
    v.add_argument("file")
    v.add_argument("--envelope", required=True, help="DSSE envelope (.dsse.json).")
    v.add_argument("--key", required=True, help="Public key (.pub).")
    v.add_argument("--format", choices=("table", "json"), default="table")

    pol = sub.add_parser("policy", help="Evaluate a verification policy on an envelope.")
    pol.add_argument("envelope")
    pol.add_argument("--key", required=True, help="Public key (.pub).")
    pol.add_argument("--required-builder-id")
    pol.add_argument("--required-predicate")
    pol.add_argument("--min-signatures", type=int, default=1)
    pol.add_argument("--format", choices=("table", "json"), default="table")

    sub.add_parser("mcp", help="Run as an MCP server (stdio JSON-RPC).")
    return p


def _run_keygen(a) -> int:
    try:
        kp = generate_key(a.scheme)
        priv, pub = kp.to_files(a.out)
    except (OSError, SigvaultError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(f"sigvault keygen — scheme={kp.scheme}  key_id={kp.key_id}")
    print(f"  private: {priv}")
    print(f"  public : {pub}")
    return 0


def _run_sign(a) -> int:
    try:
        key = load_private_key(a.key)
        env = sign_file(a.file, key, builder_id=a.builder_id)
    except (OSError, SigvaultError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    out = a.out or (a.file + ".dsse.json")
    _emit(json.dumps(env, indent=2), out)
    print(f"signed {a.file} -> {out}  (key {key.key_id})", file=sys.stderr)
    return 0


def _run_verify(a) -> int:
    try:
        key = load_public_key(a.key)
        with open(a.envelope, "r", encoding="utf-8") as fh:
            env = json.load(fh)
        res = verify_file(a.file, env, key)
    except (OSError, SigvaultError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if a.format == "json":
        printable = {k: v for k, v in res.items() if k != "statement"}
        _emit(json.dumps(printable, indent=2), None)
    else:
        print(f"sigvault verify — {a.file}")
        print("=" * 60)
        print(f"  key_id            : {res['key_id']}")
        print(f"  valid signatures  : {res['verified_signatures']}")
        print(f"  subject digest ok : {res['subject_match']}")
        print("RESULT: " + ("PASS" if res["ok"] else "FAIL"))
    return 0 if res["ok"] else 1


def _run_policy(a) -> int:
    try:
        key = load_public_key(a.key)
        with open(a.envelope, "r", encoding="utf-8") as fh:
            env = json.load(fh)
    except (OSError, SigvaultError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    policy = {"min_signatures": a.min_signatures}
    if a.required_builder_id:
        policy["required_builder_id"] = a.required_builder_id
    if a.required_predicate:
        policy["required_predicate"] = a.required_predicate
    res = evaluate_policy(env, key, policy)
    if a.format == "json":
        _emit(json.dumps(res, indent=2), None)
    else:
        print("sigvault policy")
        print("=" * 60)
        for p in res["problems"]:
            print(f"  ! {p}")
        print("RESULT: " + ("PASS" if res["ok"] else "FAIL"))
    return 0 if res["ok"] else 1


def _run_mcp() -> int:
    from sigvault.mcp_server import run_mcp_server
    run_mcp_server()
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command == "keygen":
        return _run_keygen(args)
    if args.command == "sign":
        return _run_sign(args)
    if args.command == "verify":
        return _run_verify(args)
    if args.command == "policy":
        return _run_policy(args)
    if args.command == "mcp":
        return _run_mcp()
    parser.print_help(sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
