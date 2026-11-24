import sys
from pathlib import Path

import pytest

from mcpscan import collect, live
from mcpscan.live import CaptureError

FAKE = str(Path(__file__).with_name("fake_server.py"))


def run(mode, **kw):
    return live.capture([sys.executable, FAKE, mode], server="fake", **kw)


def test_captures_every_list_with_pagination():
    out = run("ok")
    assert [t["name"] for t in out["tools"]] == ["add", "echo"]  # two pages joined
    assert out["prompts"][0]["name"] == "greet"
    assert out["resources"][0]["uri"] == "mem://a"
    assert out["resourceTemplates"] == []  # optional list refused by the server: empty, not fatal
    assert out["serverInfo"] == {"name": "fake", "version": "0"}
    assert out["instructions"] == "Use add for sums."
    items = collect.parse_listing(out)
    assert {i.kind for i in items} == {"server", "tool", "prompt", "resource"}


def test_only_advertised_lists_are_asked_for():
    out = run("tools_only")
    assert "resources" not in out and "tools" in out


def test_server_requests_are_answered_and_refused_safely():
    out = run("ping_first")
    assert len(out["tools"]) == 2


def test_stdout_banners_are_tolerated_and_counted():
    assert run("banner")["stdoutNoiseLines"] == 1


@pytest.mark.parametrize(
    ("mode", "message"),
    [
        ("hang", "in time"),
        ("exit", "exited"),
        ("huge", "bytes"),
        ("cursor_loop", "repeated a page cursor"),
        ("list_error", "tools/list failed"),
    ],
)
def test_hostile_or_broken_servers_fail_cleanly(mode, message):
    with pytest.raises(CaptureError, match=message):
        run(mode, timeout=3)


def test_a_command_that_does_not_exist():
    with pytest.raises(CaptureError, match="couldn't start"):
        live.capture(["definitely-not-a-real-binary-xyz"], server="x")


def test_sandbox_flags():
    argv = live.sandbox_argv("ghcr.io/acme/server:1.2", ["node", "index.js"])
    joined = " ".join(argv)
    for flag in (
        "--network none",
        "--read-only",
        "--cap-drop ALL",
        "--security-opt no-new-privileges",
        "--user 65534:65534",
        "--pids-limit 128",
    ):
        assert flag in joined
    assert argv[-3:] == ["ghcr.io/acme/server:1.2", "node", "index.js"]


@pytest.mark.parametrize("image", ["--privileged", "img; rm -rf /", "Image With Spaces", ""])
def test_unsafe_image_names_are_refused(image):
    with pytest.raises(CaptureError):
        live.sandbox_argv(image, [])


def test_only_initialize_and_list_methods_are_ever_sent(monkeypatch):
    sent = []
    original = live._Session.send

    def record(self, message):
        sent.append(message.get("method"))
        original(self, message)

    monkeypatch.setattr(live._Session, "send", record)
    run("ping_first")
    methods = {m for m in sent if m}
    assert methods == {
        "initialize",
        "notifications/initialized",
        "tools/list",
        "prompts/list",
        "resources/list",
        "resources/templates/list",
    }


def test_the_command_is_resolved_on_path(monkeypatch):
    real_which = live.shutil.which
    monkeypatch.setattr(
        live.shutil,
        "which",
        lambda name: sys.executable if name == "npx-like" else real_which(name),
    )
    out = live.capture(["npx-like", FAKE, "ok"], server="fake")
    assert len(out["tools"]) == 2
