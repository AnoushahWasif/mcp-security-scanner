"""Read MCP client configs and redact secrets the moment they're parsed.

Supported: Claude Desktop (`claude_desktop_config.json`), Cursor (`.cursor/mcp.json`), Claude
Code / generic (`.mcp.json`) with an `mcpServers` object, and VS Code (`.vscode/mcp.json`) with a
`servers` object, comments and trailing commas.

Nothing secret survives parsing: env and header values are always replaced, and arguments or URLs
that look like credentials are too. What's kept is *where* a secret was, so a later check can
report "plain-text token in env.GITHUB_TOKEN" without ever holding the token.
"""

import json
import math
import re
from dataclasses import dataclass
from pathlib import Path

from mcpscan.collect import MAX_FILE_BYTES, CollectError

# ${input:x} and ${env:X} are references a client resolves at start-up: not secrets, and the
# right way to pass one, so they're kept as written.
REFERENCE = re.compile(r"^\$\{(?:input|env):[A-Za-z0-9_.-]+\}$")
TOKEN_SHAPES = re.compile(
    r"(?:ghp_|gho_|ghs_|github_pat_|glpat-|sk-ant-|sk-|xox[abpr]-|AIza|AKIA[0-9A-Z]{16}"
    r"|eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.)"
)
SECRET_WORDS = re.compile(
    r"token|secret|passw|api[-_]?key|apikey|auth|credential|private|(?:^|[_-])key(?:$|[_-])", re.I
)
SECRET_QUERY = re.compile(r"([?&](?:[^=&]*(?:token|key|secret|sig|auth)[^=&]*)=)[^&#]*", re.I)


def redacted(value: str) -> str:
    return f"<redacted {len(value)} chars>"


def _entropy(value: str) -> float:
    counts = {c: value.count(c) for c in set(value)}
    return -sum(n / len(value) * math.log2(n / len(value)) for n in counts.values())


def looks_secret(key: str, value: str) -> bool:
    """Every env/header value is redacted anyway; this decides which ones get *reported*, so
    LOG_LEVEL=debug isn't called a plain-text secret."""
    if SECRET_WORDS.search(key) or TOKEN_SHAPES.search(value):
        return True
    return (
        len(value) >= 24
        and " " not in value
        and any(c.isdigit() for c in value)
        and any(c.isalpha() for c in value)
        and _entropy(value) > 3.5
    )


@dataclass(frozen=True)
class ServerConfig:
    name: str
    transport: str  # stdio | http | sse
    command: str
    args: tuple[str, ...]
    env: dict
    url: str
    headers: dict
    secrets: tuple[str, ...]  # where plain-text secrets were found, e.g. "env.GITHUB_TOKEN"
    source: str


def strip_jsonc(text: str) -> str:
    """Remove // and /* */ comments and trailing commas, leaving string contents alone."""
    out, i, n, in_string = [], 0, len(text), False
    while i < n:
        c = text[i]
        if in_string:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 1
            elif c == '"':
                in_string = False
        elif c == '"':
            in_string = True
            out.append(c)
        elif text.startswith("//", i):
            while i < n and text[i] != "\n":
                i += 1
            continue
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            if end == -1:
                raise CollectError("unterminated /* comment")
            i = end + 2
            continue
        else:
            out.append(c)
        i += 1
    return re.sub(r",(\s*[}\]])", r"\1", "".join(out))


def _redact_map(values, prefix: str, secrets: list[str]) -> dict:
    if values is None:
        return {}
    if not isinstance(values, dict):
        raise CollectError(f"{prefix} must be an object")
    out = {}
    for key, value in values.items():
        value = str(value)
        if REFERENCE.match(value) or value == "":
            out[key] = value
        else:
            out[key] = redacted(value)
            if looks_secret(str(key), value):
                secrets.append(f"{prefix}.{key}")
    return out


def _redact_args(args, secrets: list[str]) -> tuple[str, ...]:
    if args is None:
        return ()
    if not isinstance(args, list):
        raise CollectError("args must be a list")
    out: list[str] = []
    previous = ""
    for i, arg in enumerate(str(a) for a in args):
        flag, eq, value = arg.partition("=")
        if REFERENCE.match(arg):
            out.append(arg)
        elif eq and flag.startswith("-") and SECRET_WORDS.search(flag) and value:
            out.append(f"{flag}={redacted(value)}")
            secrets.append(f"args[{i}]")
        elif TOKEN_SHAPES.search(arg) or (
            previous.startswith("-") and SECRET_WORDS.search(previous) and not arg.startswith("-")
        ):
            out.append(redacted(arg))
            secrets.append(f"args[{i}]")
        else:
            out.append(_redact_url(arg, f"args[{i}]", secrets))
        previous = arg
    return tuple(out)


def _redact_url(url: str, where: str, secrets: list[str]) -> str:
    if "://" not in url:
        return url
    scheme, rest = url.split("://", 1)
    host_part, slash, path = rest.partition("/")
    if "@" in host_part:  # user:password@host
        host_part = "<redacted>@" + host_part.rsplit("@", 1)[1]
        secrets.append(where)
    cleaned = f"{scheme}://{host_part}{slash}{path}"
    scrubbed = SECRET_QUERY.sub(lambda m: m.group(1) + "<redacted>", cleaned)
    if scrubbed != cleaned and where not in secrets:
        secrets.append(where)
    return scrubbed


def _server(name: str, raw, source: str) -> ServerConfig:
    if not isinstance(raw, dict):
        raise CollectError(f"server '{name}' isn't an object")
    secrets: list[str] = []
    url = raw.get("url") or raw.get("serverUrl") or ""
    command = str(raw.get("command") or "")
    if not url and not command:
        raise CollectError(f"server '{name}' has neither a command nor a url")
    transport = str(raw.get("type") or raw.get("transport") or ("stdio" if command else "http"))
    if transport in {"streamable-http", "streamableHttp", "http"}:
        transport = "http"
    return ServerConfig(
        name=name,
        transport=transport,
        command=command,
        args=_redact_args(raw.get("args"), secrets),
        env=_redact_map(raw.get("env"), "env", secrets),
        url=_redact_url(str(url), "url", secrets),
        headers=_redact_map(raw.get("headers"), "headers", secrets),
        secrets=tuple(secrets),
        source=source,
    )


def parse_config(text: str, source: str = "config") -> list[ServerConfig]:
    try:
        data = json.loads(strip_jsonc(text))
    except json.JSONDecodeError as exc:
        raise CollectError(f"{source} isn't valid JSON: {exc.msg} at line {exc.lineno}") from None
    except RecursionError:
        raise CollectError(f"{source} is nested too deeply") from None
    if not isinstance(data, dict):
        raise CollectError(f"{source} must be a JSON object")
    servers = data.get("mcpServers", data.get("servers"))
    if not isinstance(servers, dict):
        raise CollectError(f"{source} has no 'mcpServers' or 'servers' object")
    return [_server(str(name), raw, source) for name, raw in servers.items()]


def load_config(path: Path) -> list[ServerConfig]:
    size = path.stat().st_size
    if size > MAX_FILE_BYTES:
        raise CollectError(f"{path.name} is {size:,} bytes, over the {MAX_FILE_BYTES:,} cap")
    try:
        text = path.read_bytes().decode("utf-8-sig")
    except UnicodeDecodeError:
        raise CollectError(f"{path.name} isn't UTF-8") from None
    return parse_config(text, source=path.name)
