# sigvault

**Artifact signing, verification & SLSA/in-toto provenance — with no external
crypto dependency.** Produce **DSSE** envelopes wrapping **in-toto** statements
with **SLSA-style provenance**, then verify them against an artifact and a
public key, or gate a pipeline with a verification policy.

Part of the **Cognis Neural Suite**.

---

## Why

Supply-chain attestation tooling is usually a heavy install. sigvault gives you
the core workflow — sign, verify, provenance, policy — in pure Python:

- **ed25519** signing when your Python exposes it (the strong default),
- a portable **HMAC** fallback that works on *any* Python (great for
  self-contained CI gates and air-gapped builds),
- standards-shaped envelopes (**DSSE**, **in-toto Statement v1**,
  **SLSA provenance v1**) so the output interoperates with the wider ecosystem.

## Commands

```bash
# Generate a key pair (writes <base>.key and <base>.pub).
python -m sigvault keygen --scheme auto --out sv

# Sign a file -> DSSE provenance envelope.
python -m sigvault sign app.bin --key sv.key --builder-id cognis-digital/ci

# Verify: signature valid AND attestation covers the file's digest.
python -m sigvault verify app.bin --envelope app.bin.dsse.json --key sv.pub

# Gate on a policy.
python -m sigvault policy app.bin.dsse.json --key sv.pub \
    --required-builder-id cognis-digital/ci \
    --required-predicate https://slsa.dev/provenance/v1 \
    --min-signatures 1

# Run as a local MCP server (stdio JSON-RPC).
python -m sigvault mcp
```

## What sets sigvault apart

- **Verifies the binding, not just the signature.** `verify` confirms the
  envelope's subject digest matches the artifact on disk — catches a swapped
  binary even if the signature itself is valid.
- **Policy gate** for CI: required builder id, required predicate type, minimum
  valid signatures — exits non-zero on violation.
- **Two schemes, one format.** ed25519 or HMAC, both emitting the same DSSE /
  in-toto / SLSA shapes.
- **MCP-native** (`sign` / `verify` / `policy`) and an opt-in local-fleet AI hook
  (default OFF) that explains what an attestation claims in plain English.
- **Pairs with [oradeck](https://github.com/cognis-digital/oradeck) and
  [airlock](https://github.com/cognis-digital/airlock):** sign the artifacts,
  mirror them with their attestations, bundle the whole app for the air-gap.

## Tests

```bash
python -m pytest -q     # or: python -m unittest discover -s tests
```

## License

Cognis Open Collaboration License (COCL) 1.0 — see [`LICENSE`](LICENSE).
© 2026 Cognis Digital LLC. Original Cognis work implementing the public DSSE /
in-toto / SLSA shapes; no third-party code, names, or branding.
