"""sigvault MCP server — stdio JSON-RPC 2.0. Standard library only.

    {"command": "python", "args": ["-m", "sigvault", "mcp"]}
"""

from __future__ import annotations

import json
import sys
from typing import Any, Dict, Optional

from sigvault import TOOL_NAME, TOOL_VERSION
from sigvault.core import (
    SigvaultError,
    evaluate_policy,
    load_private_key,
    load_public_key,
    sign_file,
    verify_file,
)

PROTOCOL_VERSION = "2024-11-05"

_TOOLS = [
    {
        "name": "sign",
        "description": "Sign a file and emit a DSSE in-toto/SLSA provenance "
                       "envelope using a private key.",
        "inputSchema": {
            "type": "object",
            "properties": {"file": {"type": "string"},
                           "key": {"type": "string", "description": "Private key path."},
                           "builder_id": {"type": "string"}},
            "required": ["file", "key"], "additionalProperties": False,
        },
    },
    {
        "name": "verify",
        "description": "Verify a DSSE envelope against a file and a public key, "
                       "including that the attestation covers the file's digest.",
        "inputSchema": {
            "type": "object",
            "properties": {"file": {"type": "string"},
                           "envelope": {"type": "string"},
                           "key": {"type": "string", "description": "Public key path."}},
            "required": ["file", "envelope", "key"], "additionalProperties": False,
        },
    },
    {
        "name": "policy",
        "description": "Evaluate a verification policy (builder id, predicate "
                       "type, minimum signatures) against an envelope.",
        "inputSchema": {
            "type": "object",
            "properties": {"envelope": {"type": "string"},
                           "key": {"type": "string"},
                           "required_builder_id": {"type": "string"},
                           "required_predicate": {"type": "string"},
                           "min_signatures": {"type": "integer"}},
            "required": ["envelope", "key"], "additionalProperties": False,
        },
    },
]


def _result(req_id, result): return {"jsonrpc": "2.0", "id": req_id, "result": result}
def _error(req_id, code, msg): return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": msg}}


def _load_env(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _call_tool(name: str, args: Dict[str, Any]) -> Dict[str, Any]:
    if name == "sign":
        f, k = args.get("file"), args.get("key")
        if not isinstance(f, str) or not isinstance(k, str):
            raise ValueError("`file` and `key` (strings) are required")
        env = sign_file(f, load_private_key(k),
                        builder_id=args.get("builder_id") or "cognis-digital/sigvault")
        return {"content": [{"type": "text", "text": json.dumps(env, indent=2)}],
                "isError": False}
    if name == "verify":
        f, e, k = args.get("file"), args.get("envelope"), args.get("key")
        if not all(isinstance(x, str) for x in (f, e, k)):
            raise ValueError("`file`, `envelope`, `key` (strings) are required")
        res = verify_file(f, _load_env(e), load_public_key(k))
        printable = {kk: vv for kk, vv in res.items() if kk != "statement"}
        return {"content": [{"type": "text", "text": json.dumps(printable, indent=2)}],
                "isError": not res["ok"]}
    if name == "policy":
        e, k = args.get("envelope"), args.get("key")
        if not isinstance(e, str) or not isinstance(k, str):
            raise ValueError("`envelope` and `key` (strings) are required")
        policy = {"min_signatures": args.get("min_signatures", 1)}
        if args.get("required_builder_id"):
            policy["required_builder_id"] = args["required_builder_id"]
        if args.get("required_predicate"):
            policy["required_predicate"] = args["required_predicate"]
        res = evaluate_policy(_load_env(e), load_public_key(k), policy)
        return {"content": [{"type": "text", "text": json.dumps(res, indent=2)}],
                "isError": not res["ok"]}
    raise ValueError(f"unknown tool: {name}")


def handle_request(req: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    method = req.get("method")
    req_id = req.get("id")
    params = req.get("params") or {}
    is_notification = "id" not in req

    if method == "initialize":
        res = _result(req_id, {"protocolVersion": PROTOCOL_VERSION,
                               "capabilities": {"tools": {"listChanged": False}},
                               "serverInfo": {"name": TOOL_NAME, "version": TOOL_VERSION}})
        return None if is_notification else res
    if method in ("notifications/initialized", "initialized"):
        return None
    if method == "ping":
        return None if is_notification else _result(req_id, {})
    if method == "tools/list":
        return _result(req_id, {"tools": _TOOLS})
    if method == "tools/call":
        name = params.get("name", "")
        args = params.get("arguments") or {}
        try:
            return _result(req_id, _call_tool(name, args))
        except (ValueError, OSError, SigvaultError, json.JSONDecodeError) as exc:
            return _error(req_id, -32602, str(exc))
        except Exception as exc:  # pragma: no cover
            return _error(req_id, -32603, f"internal error: {exc}")
    if is_notification:
        return None
    return _error(req_id, -32601, f"method not found: {method}")


def run_mcp_server(stdin=None, stdout=None) -> None:
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            stdout.write(json.dumps(_error(None, -32700, "parse error")) + "\n")
            stdout.flush()
            continue
        response = handle_request(req)
        if response is not None:
            stdout.write(json.dumps(response) + "\n")
            stdout.flush()


if __name__ == "__main__":
    run_mcp_server()
