"""Shared fixtures of the deploy tests."""

from pathlib import Path

import pytest

# The identity of the commits and tags these tests make without naming one, set here so that they never
# depend on the machine's own git configuration. GitHub's runners have none, and their user's name is
# empty, which git refuses ("empty ident name"): the release tests failed there on their first run, on
# 24 November. It is a global configuration file, the lowest scope that names a user: an identity a script
# sets itself (`git -c user.name=...`, the demo's GitOps commits) still wins, where the GIT_AUTHOR_*
# variables would override it.
GIT_IDENTITY = "[user]\n\tname = SentinelCI test\n\temail = test@example.invalid\n"


@pytest.fixture(autouse=True)
def git_identity(tmp_path_factory: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch) -> None:
    """Every git command a deploy test runs with the inherited environment reads this identity only."""
    config: Path = tmp_path_factory.mktemp("git-identity") / "gitconfig"
    config.write_text(GIT_IDENTITY)
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(config))
    for name in ("GIT_AUTHOR_NAME", "GIT_AUTHOR_EMAIL", "GIT_COMMITTER_NAME", "GIT_COMMITTER_EMAIL"):
        monkeypatch.delenv(name, raising=False)
