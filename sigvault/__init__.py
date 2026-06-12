"""sigvault — artifact signing, verification & SLSA/in-toto provenance.

Part of the Cognis Neural Suite.
"""

from sigvault.core import (
    TOOL_NAME,
    TOOL_VERSION,
    SBOM_PREDICATE_TYPE,
    KeyPair,
    SigvaultError,
    add_signature,
    attest_sbom,
    build_statement,
    canonical_json,
    dsse_pae,
    evaluate_policy,
    explain_envelope,
    generate_key,
    load_private_key,
    load_public_key,
    sha256_file,
    sign_file,
    sign_statement,
    slsa_provenance,
    subject_for_file,
    verify_envelope,
    verify_file,
    verify_threshold,
)

__version__ = TOOL_VERSION

__all__ = [
    "TOOL_NAME",
    "TOOL_VERSION",
    "SBOM_PREDICATE_TYPE",
    "__version__",
    "KeyPair",
    "SigvaultError",
    "add_signature",
    "attest_sbom",
    "build_statement",
    "canonical_json",
    "dsse_pae",
    "evaluate_policy",
    "explain_envelope",
    "generate_key",
    "load_private_key",
    "load_public_key",
    "sha256_file",
    "sign_file",
    "sign_statement",
    "slsa_provenance",
    "subject_for_file",
    "verify_envelope",
    "verify_file",
    "verify_threshold",
]
