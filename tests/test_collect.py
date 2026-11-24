import json

import pytest

from mcpscan import collect
from mcpscan.collect import CollectError

TOOL = {
    "name": "read_file",
    "description": "Read a file.",
    "inputSchema": {
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "Path to read"},
            "mode": {"type": "string", "enum": ["text", "binary"], "default": "text"},
            "opts": {
                "type": "object",
                "properties": {"note": {"type": "string", "description": "deep hidden text"}},
            },
        },
    },
}
PROMPT = {
    "name": "summarise",
    "description": "Summarise a document",
    "arguments": [{"name": "doc", "description": "The document"}],
}
RESOURCE = {"uri": "file:///notes.txt", "name": "notes", "description": "Team notes"}


def listing(**extra):
    return {"tools": [TOOL], **extra}


def texts(item):
    return {t.where: t.value for t in item.texts}


def test_a_bare_tools_list_result():
    [item] = collect.parse_listing(listing(), server="files")
    assert item.ref == "files/tool/read_file"
    found = texts(item)
    assert found["description"] == "Read a file."
    assert found["inputSchema.properties.path.description"] == "Path to read"


def test_nested_schema_text_is_collected():
    found = [t.value for t in collect.parse_listing(listing())[0].texts]
    assert "deep hidden text" in found
    assert "binary" in found and "text" in found  # enum values and the default
    assert "note" in found  # property names reach the model as argument names


def test_prompts_and_resources_are_items_too():
    items = collect.parse_listing(listing(prompts=[PROMPT], resources=[RESOURCE]))
    kinds = {i.kind: i for i in items}
    assert set(kinds) == {"tool", "prompt", "resource"}
    assert texts(kinds["prompt"])["arguments[0].description"] == "The document"
    assert texts(kinds["resource"])["description"] == "Team notes"


def test_a_json_rpc_response_and_a_capture_file():
    wrapped = {"jsonrpc": "2.0", "id": 1, "result": listing()}
    assert collect.parse_listing(wrapped)[0].name == "read_file"
    capture = {"server": "fs", **listing()}
    assert collect.parse_listing(capture)[0].server == "fs"


def test_hash_ignores_key_order_and_catches_any_change():
    a = collect.parse_listing(listing())[0]
    reordered = json.loads(json.dumps(TOOL, sort_keys=True))
    b = collect.parse_listing({"tools": [reordered]})[0]
    assert a.sha256 == b.sha256 and len(a.sha256) == 64
    changed = json.loads(json.dumps(TOOL))
    changed["inputSchema"]["properties"]["opts"]["properties"]["note"]["description"] += "!"
    assert collect.parse_listing({"tools": [changed]})[0].sha256 != a.sha256


BAD = {
    "not an object": [],
    "json-rpc error": {"jsonrpc": "2.0", "id": 1, "error": {"code": -1, "message": "x"}},
    "nothing listed": {"server": "x"},
    "tools not a list": {"tools": {"name": "x"}},
    "entry not an object": {"tools": ["read_file"]},
    "no name": {"tools": [{"description": "x"}]},
    "empty name": {"tools": [{"name": ""}]},
    "duplicate names": {"tools": [TOOL, TOOL]},
}


@pytest.mark.parametrize("name", BAD)
def test_bad_listings_are_refused(name):
    with pytest.raises(CollectError):
        collect.parse_listing(BAD[name])


def test_too_many_items(monkeypatch):
    monkeypatch.setattr(collect, "MAX_ITEMS", 3)
    tools = [{"name": f"t{i}"} for i in range(4)]
    with pytest.raises(CollectError, match="more than 3"):
        collect.parse_listing({"tools": tools})


def test_schema_depth_and_size_caps(monkeypatch):
    deep: dict = {"type": "string"}
    for _ in range(collect.MAX_SCHEMA_DEPTH + 2):
        deep = {"type": "object", "properties": {"x": deep}}
    with pytest.raises(CollectError, match="deeper"):
        collect.parse_listing({"tools": [{"name": "t", "inputSchema": deep}]})
    monkeypatch.setattr(collect, "MAX_SCHEMA_NODES", 5)
    with pytest.raises(CollectError, match="nodes"):
        collect.parse_listing(listing())


def test_files_are_capped_and_must_be_utf8_json(tmp_path, monkeypatch):
    path = tmp_path / "srv.json"
    path.write_text(json.dumps(listing()))
    assert collect.load_listing(path)[0].server == "srv"
    path.write_bytes(b"\xef\xbb\xbf" + json.dumps(listing()).encode())  # BOM is fine
    assert collect.load_listing(path)
    path.write_bytes(b"\xff\xfe not json")
    with pytest.raises(CollectError, match="UTF-8 JSON"):
        collect.load_listing(path)
    monkeypatch.setattr(collect, "MAX_FILE_BYTES", 10)
    path.write_text(json.dumps(listing()))
    with pytest.raises(CollectError, match="cap"):
        collect.read_json(path, max_bytes=10)


def test_absurd_nesting_in_the_file_is_refused(tmp_path):
    path = tmp_path / "deep.json"
    path.write_text("[" * 100_000 + "]" * 100_000)
    with pytest.raises(CollectError):
        collect.load_listing(path)
