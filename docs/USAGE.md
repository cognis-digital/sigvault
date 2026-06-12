# sigvault — Usage Guide

sigvault signs artifacts and produces DSSE envelopes wrapping in-toto
statements (SLSA provenance or SBOM attestations), with ed25519 or portable
HMAC keys — no external crypto package.

## Keys

```bash
python -m sigvault keygen --scheme auto --out sv   # ed25519 if available, else hmac
# -> sv.key (private), sv.pub (public)
```

## Single-signer flow

```bash
python -m sigvault sign app.bin --key sv.key --builder-id cognis-digital/ci
python -m sigvault verify app.bin --envelope app.bin.dsse.json --key sv.pub
```
`verify` checks the signature **and** that the envelope's subject digest matches
the file on disk — a swapped binary fails even with a valid signature.

## Multi-signer (co-signing + threshold)

Two-person-rule releases: have each signer co-sign the same envelope, then
require N distinct valid signers.

```bash
# First signer produces the envelope:
python -m sigvault sign app.bin --key alice.key --out app.dsse.json
# Second signer appends a signature (input not mutated; idempotent per key):
python -m sigvault add-sig app.dsse.json --key bob.key
# Gate: require 2 distinct valid signers from a trusted key set.
python -m sigvault verify-threshold app.dsse.json \
    --key alice.pub --key bob.pub --threshold 2
```
A signer is counted once even if duplicate signatures are present.

## SBOM attestations

Sign an SBOM *about* an artifact (subject = the file's digest, predicate = the
SBOM document):

```bash
python -m sigvault attest-sbom app.bin --sbom sbom.json --key sv.key
# -> app.bin.sbom.dsse.json  (predicateType = .../attestations/sbom/v1)
```

## Policy gate (single envelope)

```bash
python -m sigvault policy app.bin.dsse.json --key sv.pub \
    --required-builder-id cognis-digital/ci \
    --required-predicate https://slsa.dev/provenance/v1 \
    --min-signatures 1
```

## Envelope shape (DSSE)

```json
{
  "payloadType": "application/vnd.in-toto+json",
  "payload": "<base64 in-toto Statement>",
  "signatures": [{"keyid": "ed25519:abc…", "sig": "<base64>"}]
}
```
The signature is over the DSSE Pre-Authentication Encoding
(`DSSEv1 <len> <type> <len> <payload>`), not the raw payload — so a payload-type
swap can't pass verification.

## MCP server

```bash
python -m sigvault mcp   # sign / verify / policy over stdio JSON-RPC
```
