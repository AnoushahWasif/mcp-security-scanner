"""Read tool, prompt and resource definitions out of Python MCP server source, without running it.

Covers the two common ways Python servers declare them:
- FastMCP decorators: `@mcp.tool()`, `@mcp.prompt()`, `@mcp.resource("uri")`, with the name and
  description from decorator arguments or the function name and docstring (as FastMCP does),
  and parameters from the signature, including `Annotated[..., Field(description=...)]`.
- Low-level servers: `Tool(name=..., description=..., inputSchema={...})` calls with literal values.

The result is the same shape as a `tools/list` capture, so everything downstream treats them alike.
The code is parsed, never imported: importing a server runs it.
"""

import ast
from pathlib import Path

from mcpscan.collect import MAX_FILE_BYTES, CollectError

DECORATORS = {"tool": "tools", "prompt": "prompts", "resource": "resources"}
JSON_TYPES = {
    "str": "string",
    "int": "integer",
    "float": "number",
    "bool": "boolean",
    "list": "array",
    "dict": "object",
}
SKIP_PARAMS = {"self", "ctx", "context"}


def _text(node) -> str | None:
    """A string literal, an implicit concatenation or an f-string (with {…} for the holes)."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        return "".join(v.value if isinstance(v, ast.Constant) else "{…}" for v in node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = _text(node.left), _text(node.right)
        if left is not None and right is not None:
            return left + right
    return None


def _literal(node):
    try:
        return ast.literal_eval(node)
    except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
        return None


def _kwargs(call: ast.Call) -> dict[str, ast.AST]:
    return {k.arg: k.value for k in call.keywords if k.arg}


def _field_description(node) -> str | None:
    """`Field(description="...")` or `Field(..., description="...")`."""
    if isinstance(node, ast.Call):
        name = (
            node.func.attr if isinstance(node.func, ast.Attribute) else getattr(node.func, "id", "")
        )
        if name == "Field":
            description = _kwargs(node).get("description")
            return _text(description) if description is not None else None
    return None


def _param_schema(arg: ast.arg, default) -> dict:
    schema: dict = {}
    annotation = arg.annotation
    if isinstance(annotation, ast.Subscript) and getattr(annotation.value, "id", "") == "Annotated":
        parts = annotation.slice.elts if isinstance(annotation.slice, ast.Tuple) else []
        if parts:
            annotation = parts[0]
            for extra in parts[1:]:
                description = _field_description(extra) or _text(extra)
                if description:
                    schema["description"] = description
    base = annotation.value if isinstance(annotation, ast.Subscript) else annotation
    type_name = getattr(base, "id", None)
    if type_name in JSON_TYPES:
        schema["type"] = JSON_TYPES[type_name]
    if default is not None:
        description = _field_description(default)
        if description:
            schema["description"] = description
        else:
            value = _literal(default)
            if isinstance(value, str | int | float | bool):
                schema["default"] = value
    return schema


def _input_schema(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> dict:
    args = [a for a in fn.args.args + fn.args.kwonlyargs if a.arg not in SKIP_PARAMS]
    positional = fn.args.args
    with_defaults = positional[len(positional) - len(fn.args.defaults) :]
    defaults = {a.arg: d for a, d in zip(with_defaults, fn.args.defaults, strict=True)}
    for a, d in zip(fn.args.kwonlyargs, fn.args.kw_defaults, strict=True):
        if d is not None:
            defaults[a.arg] = d
    properties, required = {}, []
    for arg in args:
        properties[arg.arg] = _param_schema(arg, defaults.get(arg.arg))
        if arg.arg not in defaults:
            required.append(arg.arg)
    schema: dict = {"type": "object", "properties": properties}
    if required:
        schema["required"] = required
    return schema


def _decorated(fn, decorator) -> tuple[str, dict] | None:
    call = decorator if isinstance(decorator, ast.Call) else None
    target = call.func if call else decorator
    if not isinstance(target, ast.Attribute) or target.attr not in DECORATORS:
        return None
    key = DECORATORS[target.attr]
    kwargs = _kwargs(call) if call else {}
    name = _text(kwargs["name"]) if "name" in kwargs else None
    description = _text(kwargs["description"]) if "description" in kwargs else None
    entry: dict = {
        "name": name or fn.name,
        "description": description if description is not None else (ast.get_docstring(fn) or ""),
    }
    if "title" in kwargs and _text(kwargs["title"]):
        entry["title"] = _text(kwargs["title"])
    if key == "resources":
        uri = _text(call.args[0]) if call and call.args else _text(kwargs.get("uri"))
        if not uri:
            return None
        entry["uri" if "{" not in uri else "uriTemplate"] = uri
        if "{" in uri:
            key = "resourceTemplates"
    elif key == "tools":
        entry["inputSchema"] = _input_schema(fn)
        annotations = _literal(kwargs["annotations"]) if "annotations" in kwargs else None
        if isinstance(annotations, dict):
            entry["annotations"] = annotations
    else:  # prompts
        schema = _input_schema(fn)
        entry["arguments"] = [
            {"name": n, **({"description": p["description"]} if "description" in p else {}),
             "required": n in schema.get("required", [])}
            for n, p in schema["properties"].items()
        ]  # fmt: skip
    return key, entry


def _tool_call(call: ast.Call) -> dict | None:
    name = call.func.attr if isinstance(call.func, ast.Attribute) else getattr(call.func, "id", "")
    if name != "Tool":
        return None
    kwargs = _kwargs(call)
    tool_name = _text(kwargs.get("name")) if "name" in kwargs else None
    if not tool_name:
        return None
    entry: dict = {"name": tool_name, "description": _text(kwargs.get("description")) or ""}
    schema = _literal(kwargs["inputSchema"]) if "inputSchema" in kwargs else None
    if isinstance(schema, dict):
        entry["inputSchema"] = schema
    return entry


def extract_source(source: str, server: str) -> dict:
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError, MemoryError) as exc:
        raise CollectError(f"{server}: not parseable Python ({type(exc).__name__})") from None
    out: dict = {"server": server, "tools": [], "prompts": [], "resources": []}
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            for decorator in node.decorator_list:
                found = _decorated(node, decorator)
                if found:
                    key, entry = found
                    out.setdefault(key, []).append(entry)
        elif isinstance(node, ast.Call):
            entry = _tool_call(node)
            if entry:
                out["tools"].append(entry)
    return out


def extract_file(path: Path, server: str | None = None) -> dict:
    size = path.stat().st_size
    if size > MAX_FILE_BYTES:
        raise CollectError(f"{path.name} is {size:,} bytes, over the {MAX_FILE_BYTES:,} cap")
    try:
        source = path.read_bytes().decode("utf-8-sig")
    except UnicodeDecodeError:
        raise CollectError(f"{path.name} isn't UTF-8") from None
    return extract_source(source, server or path.parent.name)
