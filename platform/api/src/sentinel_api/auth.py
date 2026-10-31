"""Bearer tokens for the write endpoints. The API keeps only their SHA-256, never a token itself."""

from __future__ import annotations

import hashlib
import hmac

from fastapi import HTTPException, Request, status


def require_writer(request: Request) -> None:
    """Allow the request only with `Authorization: Bearer <token>` for a configured token (fail closed)."""
    scheme, _, token = request.headers.get("Authorization", "").partition(" ")
    allowed: frozenset[str] = request.app.state.settings.token_sha256
    if scheme.lower() == "bearer" and token.strip():
        digest = hashlib.sha256(token.strip().encode("utf-8")).hexdigest()
        # Compare with every configured hash, in constant time, without stopping at the first match.
        matches = [hmac.compare_digest(digest, known) for known in sorted(allowed)]
        if any(matches):
            return
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="a valid ingestion token is required",
        headers={"WWW-Authenticate": "Bearer"},
    )
