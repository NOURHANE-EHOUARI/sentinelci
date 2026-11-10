"""The verified remediation loop (task A6, SPEC §9): fixers propose patches, the gate decides if one is
verified.

Fixers only propose (`PatchProposal`); a patch is VERIFIED only by the gate (`VerificationResult`), from the
scans and the decision of the patched commit. Nothing here merges anything."""
