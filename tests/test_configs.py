import dataclasses
import json

import pytest

from mcpscan import configs
from mcpscan.collect import CollectError

GH = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
AWS = "AKIA" + "ABCDEFGHIJKLMNOP"
SLACK = "xoxb-" + "1234567890-abcdefghij"
PASSWORD = "hunter2-correct-horse"

CLAUDE_DESKTOP = {
    "mcpServers": {
        "github": {
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-github"],
            "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": GH},
        },
        "db": {
            "command": "uvx",
            "args": ["db-mcp", "--password", PASSWORD, f"--api-key={AWS}", SLACK],
        },
        "remote": {
            "url": f"https://admin:{PASSWORD}@mcp.example.com/sse?token={GH}&page=2",
            "headers": {"Authorization": f"Bearer {GH}"},
        },
    }
}

VSCODE = """{
  // VS Code allows comments
  "inputs": [{"type": "promptString", "id": "gh", "password": true}],
  "servers": {
    "github": {
      "type": "stdio",
      "command": "docker",
      "args": ["run", "-i", "ghcr.io/github/github-mcp-server"],
      "env": {"GITHUB_TOKEN": "${input:gh}"}, /* a reference, not a secret */
    },
    "docs": {"type": "http", "url": "https://docs.example.com/mcp"},
  },
}"""


def everything(servers) -> str:
    return json.dumps([dataclasses.asdict(s) for s in servers]) + repr(servers)


def by_name(servers):
    return {s.name: s for s in servers}


def test_no_secret_survives_parsing():
    servers = configs.parse_config(json.dumps(CLAUDE_DESKTOP))
    text = everything(servers)
    for secret in (GH, AWS, SLACK, PASSWORD):
        assert secret not in text


def test_where_secrets_were_is_kept():
    s = by_name(configs.parse_config(json.dumps(CLAUDE_DESKTOP)))
    assert s["github"].secrets == ("env.GITHUB_PERSONAL_ACCESS_TOKEN",)
    assert s["github"].env["GITHUB_PERSONAL_ACCESS_TOKEN"].startswith("<redacted")
    assert set(s["db"].secrets) == {"args[2]", "args[3]", "args[4]"}
    assert s["db"].args[:2] == ("db-mcp", "--password")  # flags stay readable
    assert set(s["remote"].secrets) == {"url", "headers.Authorization"}
    assert s["remote"].url.startswith("https://<redacted>@mcp.example.com/sse?token=<redacted>")
    assert s["remote"].url.endswith("&page=2")


def test_vscode_config_with_comments_and_references():
    s = by_name(configs.parse_config(VSCODE, source="mcp.json"))
    assert s["github"].env == {"GITHUB_TOKEN": "${input:gh}"}
    assert s["github"].secrets == ()
    assert s["docs"].transport == "http" and s["docs"].url == "https://docs.example.com/mcp"
    assert s["github"].transport == "stdio"


def test_comment_markers_inside_strings_are_kept():
    text = '{"mcpServers": {"x": {"url": "https://a.example/b//c", "args": ["/*not*/"]}}}'
    [server] = configs.parse_config(text)
    assert server.url == "https://a.example/b//c" and server.args == ("/*not*/",)


def test_ordinary_arguments_are_not_redacted():
    text = json.dumps({"mcpServers": {"fs": {"command": "npx", "args": ["-y", "fs", "/home/me"]}}})
    [server] = configs.parse_config(text)
    assert server.args == ("-y", "fs", "/home/me") and server.secrets == ()


BAD = {
    "not json": "{nope",
    "not an object": "[]",
    "no servers": '{"other": {}}',
    "server not an object": '{"mcpServers": {"x": "npx"}}',
    "no command or url": '{"mcpServers": {"x": {"args": []}}}',
    "args not a list": '{"mcpServers": {"x": {"command": "a", "args": "b"}}}',
    "env not an object": '{"mcpServers": {"x": {"command": "a", "env": ["b"]}}}',
    "unterminated comment": '{"mcpServers": {} /* oops',
}


@pytest.mark.parametrize("name", BAD)
def test_bad_configs_are_refused(name):
    with pytest.raises(CollectError):
        configs.parse_config(BAD[name])


def test_error_messages_never_echo_the_file(tmp_path):
    path = tmp_path / "claude_desktop_config.json"
    path.write_text('{"mcpServers": {"x": {"command": "a", "env": {"K": "' + GH + '"}}} oops')
    with pytest.raises(CollectError) as exc:
        configs.load_config(path)
    assert GH not in str(exc.value)


def test_load_config_caps_and_encoding(tmp_path, monkeypatch):
    path = tmp_path / "c.json"
    path.write_bytes(b"\xff\xfe")
    with pytest.raises(CollectError, match="UTF-8"):
        configs.load_config(path)
    monkeypatch.setattr(configs, "MAX_FILE_BYTES", 5)
    path.write_text(json.dumps(CLAUDE_DESKTOP))
    with pytest.raises(CollectError, match="cap"):
        configs.load_config(path)


def test_every_env_value_is_redacted_but_only_secrets_are_reported():
    env = {
        "LOG_LEVEL": "debug",
        "PORT": "8080",
        "STRIPE_KEY": "rk_live_short",
        "DB_PASSWORD": "pw",
        "RANDOM_LOOKING": "q8Zr2LmV9xKp4TnW7bYc3HdJ6sFg",
    }
    text = json.dumps({"mcpServers": {"x": {"command": "a", "env": env}}})
    [server] = configs.parse_config(text)
    assert all(v.startswith("<redacted") for v in server.env.values())
    assert set(server.secrets) == {"env.STRIPE_KEY", "env.DB_PASSWORD", "env.RANDOM_LOOKING"}
