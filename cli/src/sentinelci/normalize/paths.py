"""Repository-relative path handling shared by all normalizers."""

from pathlib import Path, PurePosixPath

from sentinelci.normalize.errors import NormalizationError


def to_repo_relative(raw_path: str, repo_root: Path | None = None) -> str:
    """Return a clean POSIX path relative to the repository root, or fail closed.

    Absolute paths are accepted only when they are inside `repo_root`. Paths containing `..` are rejected.
    """
    if not raw_path:
        raise NormalizationError("empty file path in scanner output")
    candidate = Path(raw_path)
    if candidate.is_absolute():
        if repo_root is None:
            raise NormalizationError(f"absolute path {raw_path!r} but no repository root was given")
        try:
            candidate = candidate.resolve().relative_to(repo_root.resolve())
        except ValueError as exc:
            raise NormalizationError(f"path {raw_path!r} is outside the repository") from exc
    posix = PurePosixPath(candidate.as_posix())
    if ".." in posix.parts:
        raise NormalizationError(f"path {raw_path!r} escapes the repository")
    cleaned = posix.as_posix().removeprefix("./")
    if not cleaned or cleaned == ".":
        raise NormalizationError(f"path {raw_path!r} does not point to a file")
    return cleaned
