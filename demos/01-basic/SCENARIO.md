# Demo 01 — Sign an artifact and verify its provenance

sigvault signs a build artifact, producing a **DSSE envelope** that wraps an
**in-toto Statement** with a **SLSA-style provenance** predicate. Verification
checks both the signature *and* that the attestation actually covers the
artifact's sha256.

## Run it

```bash
# 1. Make a key pair (ed25519 if available, else portable HMAC).
python -m sigvault keygen --scheme auto --out /tmp/sv

# 2. Create something to sign.
echo "release-binary-v1" > /tmp/app.bin

# 3. Sign it -> /tmp/app.bin.dsse.json
python -m sigvault sign /tmp/app.bin --key /tmp/sv.key \
    --builder-id cognis-digital/ci --out /tmp/app.bin.dsse.json

# 4. Verify the envelope against the artifact + public key.
python -m sigvault verify /tmp/app.bin --envelope /tmp/app.bin.dsse.json \
    --key /tmp/sv.pub

# 5. Gate on a policy (builder id + predicate + minimum signatures).
python -m sigvault policy /tmp/app.bin.dsse.json --key /tmp/sv.pub \
    --required-builder-id cognis-digital/ci \
    --required-predicate https://slsa.dev/provenance/v1
```

## Tamper check

If you edit `/tmp/app.bin` after signing and re-run `verify`, it FAILS: the
artifact's digest no longer matches the subject recorded in the attestation,
and the process exits non-zero. That is the integrity guarantee.
