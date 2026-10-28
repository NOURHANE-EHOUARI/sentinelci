from typer.testing import CliRunner

from sentinelci import __version__
from sentinelci.cli import app


def test_version_prints_engine_version() -> None:
    result = CliRunner().invoke(app, ["version"])
    assert result.exit_code == 0
    assert result.stdout.strip() == __version__
