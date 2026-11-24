import pytest

import mcpscan
from mcpscan import cli


def test_version():
    assert mcpscan.__version__ == "0.1.0"


def test_cli_version(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["--version"])
    assert exc.value.code == 0 and "0.1.0" in capsys.readouterr().out
