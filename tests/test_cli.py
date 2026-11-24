import json
import sys
from pathlib import Path

import pytest

from mcpscan import cli

FAKE = str(Path(__file__).with_name("fake_server.py"))
TOKEN = "ghp_" + "Z9y8X7w6V5u4T3s2R1q0P9o8N7m6L5k4J3i2"


def test_version(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["--version"])
    assert exc.value.code == 0 and "mcpscan" in capsys.readouterr().out


def test_inventory_of_a_listing_and_a_config(tmp_path, capsys):
    listing = tmp_path / "fs.json"
    listing.write_text(json.dumps({"tools": [{"name": "a"}, {"name": "b"}], "prompts": []}))
    config = tmp_path / "claude_desktop_config.json"
    config.write_text(json.dumps({"mcpServers": {"gh": {"command": "npx", "env": {"T": TOKEN}}}}))
    assert cli.main(["inventory", str(listing), str(config)]) == 0
    out = capsys.readouterr().out
    report = json.loads(out)
    assert report["listings"][0]["counts"] == {"tool": 2}
    assert report["configs"][0]["plainTextSecrets"] == ["env.T"]
    assert TOKEN not in out


def test_inventory_reports_bad_files_and_exits_nonzero(tmp_path, capsys):
    bad = tmp_path / "broken.json"
    bad.write_text("{not json")
    missing = tmp_path / "missing.json"
    assert cli.main(["inventory", str(bad), str(missing)]) == 1
    errors = json.loads(capsys.readouterr().out)["errors"]
    assert {e["file"] for e in errors} == {str(bad), str(missing)}


def test_capture_without_sandbox_writes_a_file(tmp_path):
    out = tmp_path / "cap.json"
    code = cli.main(
        ["capture", "--name", "fake", "--no-sandbox", "-o", str(out), "--", sys.executable, FAKE]
    )
    assert code == 0
    assert len(json.loads(out.read_text())["tools"]) == 2


def test_capture_needs_exactly_one_mode(capsys):
    with pytest.raises(SystemExit):
        cli.main(["capture", "--name", "x", "--", "node", "a.js"])
    with pytest.raises(SystemExit):
        cli.main(["capture", "--name", "x", "--image", "img", "--no-sandbox", "--", "a"])


def test_capture_failure_is_a_clean_error(capsys):
    code = cli.main(
        [
            "capture",
            "--name",
            "x",
            "--no-sandbox",
            "--timeout",
            "3",
            "--",
            sys.executable,
            FAKE,
            "exit",
        ]
    )
    assert code == 2 and "exited" in capsys.readouterr().err
