"""Turn saved MCP listings into items: every tool, prompt and resource, with all the text a model
will see from it.

A listing is untrusted input written by whoever runs the server. Accepted shapes:
- a capture written by `mcpscan capture` ({"server": ..., "instructions": ..., "tools": [...], ...})
- a bare `tools/list` result ({"tools": [...]}), optionally with prompts/resources
- a JSON-RPC response wrapping either of the above ({"jsonrpc": "2.0", "result": {...}})

Text isn't only in `description`. Parameter descriptions, titles, enum values, defaults and
examples deep inside an input schema reach the model too, and poisoning hides there.
"""

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path

MAX_FILE_BYTES = 5 * 1024 * 1024
MAX_ITEMS = 2000
MAX_SCHEMA_DEPTH = 32
MAX_SCHEMA_NODES = 20_000

KINDS = {
    "tools": "tool",
    "prompts": "prompt",
    "resources": "resource",
    "resourceTemplates": "resource_template",
}
SCHEMA_TEXT_KEYS = ("title", "description", "default", "examples", "enum", "const", "pattern")


class CollectError(ValueError):
    """The input isn't a listing we can read safely."""


@dataclass(frozen=True)
class Text:
    """One piece of model-visible text and where it came from (e.g. `inputSchema.properties.x`)."""

    where: str
    value: str


@dataclass(frozen=True)
class Item:
    server: str
    kind: str  # tool | prompt | resource | resource_template
    name: str
    texts: tuple[Text, ...]
    definition: dict = field(repr=False, compare=False)
    sha256: str = ""

    @property
    def ref(self) -> str:
        return f"{self.server}/{self.kind}/{self.name}"


def definition_hash(definition: dict) -> str:
    """Stable hash of a definition: key order and whitespace don't change it, any value does."""
    canonical = json.dumps(definition, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _schema_texts(node, where: str, out: list[Text], budget: list[int], depth: int = 0) -> None:
    if depth > MAX_SCHEMA_DEPTH:
        raise CollectError(f"schema deeper than {MAX_SCHEMA_DEPTH} levels at {where}")
    budget[0] -= 1
    if budget[0] < 0:
        raise CollectError(f"schema has more than {MAX_SCHEMA_NODES} nodes")
    if isinstance(node, dict):
        for key, value in node.items():
            path = f"{where}.{key}"
            if key == "properties" and isinstance(value, dict):
                for prop in value:
                    # Property names are shown to the model as argument names.
                    out.append(Text(f"{path}.{prop}#name", str(prop)))
            if key in SCHEMA_TEXT_KEYS:
                for text in _strings(value):
                    out.append(Text(path, text))
            if isinstance(value, dict | list):
                _schema_texts(value, path, out, budget, depth + 1)
    elif isinstance(node, list):
        for i, value in enumerate(node):
            if isinstance(value, dict | list):
                _schema_texts(value, f"{where}[{i}]", out, budget, depth + 1)


def _strings(value) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [v for v in value if isinstance(v, str)]
    return []


def _item(server: str, kind: str, raw) -> Item:
    if not isinstance(raw, dict):
        raise CollectError(f"a {kind} entry isn't an object")
    name_key = (
        "uri" if kind == "resource" else "uriTemplate" if kind == "resource_template" else "name"
    )
    name = raw.get("name") or raw.get(name_key)
    if not isinstance(name, str) or not name:
        raise CollectError(f"a {kind} entry has no name")
    texts = [Text("name", name)]
    for key in ("title", "description", "uri", "uriTemplate", "mimeType"):
        if isinstance(raw.get(key), str):
            texts.append(Text(key, raw[key]))
    annotations = raw.get("annotations")
    if isinstance(annotations, dict) and isinstance(annotations.get("title"), str):
        texts.append(Text("annotations.title", annotations["title"]))
    budget = [MAX_SCHEMA_NODES]
    for schema_key in ("inputSchema", "outputSchema"):
        if schema_key in raw:
            _schema_texts(raw[schema_key], schema_key, texts, budget)
    for i, arg in enumerate(raw.get("arguments") or []):  # prompt arguments
        if isinstance(arg, dict):
            for key in ("name", "title", "description"):
                if isinstance(arg.get(key), str):
                    texts.append(Text(f"arguments[{i}].{key}", arg[key]))
    return Item(server, kind, name, tuple(texts), raw, definition_hash(raw))


def parse_listing(data, server: str = "unknown") -> list[Item]:
    if isinstance(data, dict) and "jsonrpc" in data:
        if "error" in data:
            raise CollectError("the JSON-RPC response is an error, not a listing")
        data = data.get("result")
    if not isinstance(data, dict):
        raise CollectError("a listing must be a JSON object")
    if isinstance(data.get("server"), str) and data["server"]:
        server = data["server"]
    if not any(key in data for key in KINDS) and "instructions" not in data:
        raise CollectError(f"no {', '.join(KINDS)} in the listing")
    items: list[Item] = []
    instructions = data.get("instructions")
    if isinstance(instructions, str) and instructions:
        definition = {"instructions": instructions}
        texts = (Text("instructions", instructions),)
        items.append(
            Item(server, "server", "instructions", texts, definition, definition_hash(definition))
        )
    for key, kind in KINDS.items():
        entries = data.get(key, [])
        if not isinstance(entries, list):
            raise CollectError(f"'{key}' must be a list")
        if len(items) + len(entries) > MAX_ITEMS:
            raise CollectError(f"more than {MAX_ITEMS} items")
        items.extend(_item(server, kind, raw) for raw in entries)
    seen: set[str] = set()
    for item in items:
        if item.ref in seen:
            # Two tools with one name: a client keeps one, and which one isn't defined.
            raise CollectError(f"duplicate {item.kind} name '{item.name}'")
        seen.add(item.ref)
    return items


def read_json(path: Path, max_bytes: int = MAX_FILE_BYTES):
    size = path.stat().st_size
    if size > max_bytes:
        raise CollectError(f"{path.name} is {size:,} bytes, over the {max_bytes:,} cap")
    try:
        return json.loads(path.read_bytes().decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CollectError(f"{path.name} isn't valid UTF-8 JSON: {exc}") from exc
    except RecursionError as exc:
        raise CollectError(f"{path.name} is nested too deeply") from exc


def load_listing(path: Path) -> list[Item]:
    return parse_listing(read_json(path), server=path.stem)
