"""Bearer tokens for the write endpoints. The API keeps only their SHA-256, never a token itself."""

from __future__ import annotations

import hashlib
import hmac
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

# Declares the scheme in the OpenAPI document (`securitySchemes.HTTPBearer`). auto_error=False: a missing or
# malformed header reaches require_writer, which answers 401 with the same body as a wrong token.
_bearer = HTTPBearer(auto_error=False)


def require_writer(
    request: Request, credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)]
) -> None:
    """Allow the request only with `Authorization: Bearer <token>` for a configured token (fail closed)."""
    allowed: frozenset[str] = request.app.state.settings.token_sha256
    token = credentials.credentials.strip() if credentials is not None else ""
    if token:
        digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
        # Compare with every configured hash, in constant time, without stopping at the first match.
        matches = [hmac.compare_digest(digest, known) for known in sorted(allowed)]
        if any(matches):
            return
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="a valid ingestion token is required",
        headers={"WWW-Authenticate": "Bearer"},
    )
