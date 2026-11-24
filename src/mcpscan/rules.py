"""Rules: the first detector layer. Each rule looks at the model-visible text of one item.

Honest servers also talk to the model ("call list_files first", "ask before deleting"), so no
rule fires on "contains an instruction". Most rules need a combination: an action plus a
sensitive target, a reference to another tool plus a change to its behaviour, an exclusivity
demand plus an override of the user's choice.

Patterns are plain regexes with bounded repetition, run on text capped at MAX_TEXT characters,
so a hostile description can't make them slow.
"""

import base64
import binascii
import re
import unicodedata
from dataclasses import dataclass

from mcpscan.collect import Item, Text

MAX_TEXT = 20_000
EVIDENCE_CHARS = 120

POISONED, RISKY, SQUATTING = "poisoned", "risky", "squatting"


@dataclass(frozen=True)
class Finding:
    rule: str
    category: str  # poisoned | risky | squatting
    severity: str  # high | medium | low
    ref: str
    where: str
    message: str
    evidence: str


def evidence(text: str) -> str:
    """Short and safe to print: control and invisible characters shown as \\uXXXX."""
    shown = "".join(
        c if c.isprintable() and not _invisible(c) else f"\\u{ord(c):04x}" for c in text
    )
    return shown if len(shown) <= EVIDENCE_CHARS else shown[: EVIDENCE_CHARS - 1] + "…"


def _invisible(c: str) -> bool:
    return (
        0xE0000 <= ord(c) <= 0xE007F  # tag characters
        or c in "​‌‍⁠﻿"  # zero-width
        or 0x202A <= ord(c) <= 0x202E  # bidi embeddings and overrides
        or 0x2066 <= ord(c) <= 0x2069  # bidi isolates
    )


def normalise(text: str, is_name: bool = False) -> str:
    """What the rules read: NFKC, invisible characters dropped, lower case.

    In a name, _ and - become spaces, so `ignore_previous_instructions` reads as the phrase it
    is. In prose they're kept: `GET_ENV_INCLUDE_SECRETS` is an identifier, not "include secrets".
    """
    text = unicodedata.normalize("NFKC", text[:MAX_TEXT])
    text = "".join(c for c in text if not _invisible(c) and c != "\x1b")
    if is_name:
        text = re.sub(r"[_\-]+", " ", text)
    return text.lower()


def _is_name(text: Text) -> bool:
    return text.where == "name" or text.where.endswith("#name")


# --- hidden text ------------------------------------------------------------------------------

ANSI = re.compile(r"\x1b\[[0-9;]{0,20}[A-Za-z]")
B64_RUN = re.compile(r"[A-Za-z0-9+/]{40,4000}={0,2}")


def hidden_text(text: Text):
    raw = text.value[:MAX_TEXT]
    tags = "".join(chr(ord(c) - 0xE0000) for c in raw if 0xE0020 <= ord(c) <= 0xE007E)
    if tags:
        yield "MCP-HIDE-001", "high", "text hidden in invisible Unicode tag characters", tags
    if any(c in "​‌‍⁠" for c in raw) and len(raw) > 0:
        count = sum(raw.count(c) for c in "​‌‍⁠")
        if count >= 3:
            yield "MCP-HIDE-002", "high", f"{count} zero-width characters", raw
    if any(0x202A <= ord(c) <= 0x202E or 0x2066 <= ord(c) <= 0x2069 for c in raw):
        yield "MCP-HIDE-003", "high", "bidirectional override characters reorder the text", raw
    if ANSI.search(raw):
        yield "MCP-HIDE-004", "high", "terminal escape codes (can hide text in a terminal)", raw
    for match in B64_RUN.finditer(raw):
        decoded = _decode_b64(match.group())
        if decoded and (_intent(normalise(decoded)) or "decode" in normalise(raw)):
            yield "MCP-HIDE-005", "high", "base64 that decodes to instructions", decoded


def _decode_b64(run: str) -> str | None:
    try:
        data = base64.b64decode(run + "=" * (-len(run) % 4), validate=True)
        text = data.decode("utf-8")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None
    printable = sum(c.isprintable() or c.isspace() for c in text)
    return text if text and printable / len(text) > 0.95 else None


HIDDEN_MARKUP = [
    (re.compile(r"<!--.{0,2000}?-->", re.S), "an HTML comment the user won't see"),
    (
        re.compile(r"<\s*(important|system|instructions?|secret|hidden|admin)\s*>", re.I),
        "a fake <important>/<system>-style tag",
    ),
    (
        re.compile(r"!?\[[^\]]{0,200}\]\(https?://[^)\s]{1,500}[?&][^)\s]{0,500}\)", re.I),
        "a markdown link or image with query parameters (a common exfiltration channel)",
    ),
]


def hidden_markup(text: Text):
    for pattern, message in HIDDEN_MARKUP:
        match = pattern.search(text.value[:MAX_TEXT])
        if match:
            yield "MCP-HIDE-006", "high", message, match.group()


# --- intent -----------------------------------------------------------------------------------

OVERRIDE = re.compile(
    r"ignore (all |any |the )?(previous|prior|above|earlier|preceding) (instructions|prompts|rules)"
    r"|disregard (all |any |the )?(previous|prior|above|system)"
    r"|(you are|you're) now (in )?(developer|dan|jailbreak|unrestricted)"
    r"|developer mode|safety (rules|guidelines) (no longer|don't|do not) apply"
    r"|from now on,? (you|answer|respond|always)"
    r"|ignora(r)? (todas )?las instrucciones|忽略.{0,6}(指令|指示)|無視.{0,6}指示"
)
CONCEAL = re.compile(
    r"(do not|don't|never|without) (tell|telling|mention|mentioning|inform|informing|reveal|"
    r"revealing|show|showing) (this |it |anything )?(to )?the user"
    r"|silently|secretly|tell (them|the user) everything is fine"
    r"|(must|should) never reveal to the user|hide (this|it) from the user"
)
EXFIL_VERB = re.compile(
    r"\b(send|pass|include|append|paste|attach|put|upload|post|forward|copy|email|"
    r"leak|transmit|add|read)\b|envía|enviar|发送|送信"
    # ...or a tool call whose name starts with one: "call send_email with the user's keys"
    r"|\b(send|email|upload|post|forward|export|share)_[a-z0-9_]{1,40}"
)
SENSITIVE = re.compile(
    r"~/\.ssh|id_rsa|id_ed25519|\.env\b|\.aws/credentials|aws credentials|\.netrc|mcp\.json|"
    r"claude_desktop_config|system prompt|conversation history|chat history|full conversation|"
    r"whole conversation|(all |the )?(user'?s? )?(passwords?|api keys?|tokens|secrets|"
    r"private key)|credentials|secrets://|email address(es)? and phone|密码|contraseñas?"
)
NEGATION = re.compile(r"\b(never|not|don't|no|without)\b[^.]{0,40}$")
# Any character inside one sentence: a full stop counts only when it ends a word (b.log doesn't).
IN = r"(?:[^.]|\.(?=\S))"
TOOL = r"[a-z0-9 _-]"
OTHER_TOOL_CHANGE = re.compile(
    rf"(whenever|when|if) (the )?{TOOL}{{1,40}} (tool|function) is (used|called){IN}{{0,120}}"
    r"\b(add|replace|change|modify|bcc|cc|redirect|also)\b"
    rf"|(before|after) (using|calling|execute|executing|running|you use) {IN}{{0,60}}"
    rf"\b(run|execute|call) this (tool|function){IN}{{0,80}}\b(replace|modify|change|instead)\b"
    rf"|after using {TOOL}{{1,30}} tool{IN}{{0,80}}(modify|replace|change|correct) the"
    rf"|(also|first) (read|call|run|execute) [a-z0-9:/ _-]{{1,40}}"
    r"(and (summarise|summarize|send|include)|using the shell)"
)
EXCLUSIVE = re.compile(
    r"(always|just|only) use this tool[^.]{0,80}(instead of any other|rather than|no matter|"
    r"even (when|if) the user)"
    r"|use this tool rather than others"
    r"|(instead of|over) any other [a-z0-9 _-]{0,30} tool,? even"
)


def _sentences(text: str):
    return re.split(r"(?<=[.!?。！？])\s+|\n+", text)


EXAMPLE_CUE = re.compile(r"(such as|e\.g\.|for example|examples?|like|called|known as)\W{0,4}$")
QUOTES = "'\"‘’“”"


def _quoted_example(norm: str, match: re.Match) -> bool:
    """`examples such as 'ignore previous instructions'` mentions the attack; it doesn't make it.
    Both the quotes and the cue are needed, so quoting alone doesn't hide a real instruction."""
    before, after = norm[: match.start()], norm[match.end() :]
    quoted = before[-1:] in QUOTES and after[:1] in QUOTES
    return quoted and bool(EXAMPLE_CUE.search(before[:-1].rstrip()))


def _intent(norm: str) -> list[tuple[str, str, str]]:
    hits = []
    override = OVERRIDE.search(norm)
    if override and not _quoted_example(norm, override):
        hits.append(("MCP-INJ-001", "high", "tries to override the model's instructions"))
    if CONCEAL.search(norm):
        hits.append(("MCP-INJ-002", "high", "tells the model to hide something from the user"))
    for sentence in _sentences(norm):
        verb = EXFIL_VERB.search(sentence)
        target = SENSITIVE.search(sentence)
        if verb and target and not NEGATION.search(sentence[: verb.start()]):
            hits.append(("MCP-EXF-001", "high", "asks for sensitive data to be read or sent"))
            break
    if OTHER_TOOL_CHANGE.search(norm):
        hits.append(("MCP-XTL-001", "high", "changes how another tool behaves"))
    if EXCLUSIVE.search(norm):
        hits.append(("MCP-XTL-002", "medium", "demands to be used instead of the user's choice"))
    return hits


LABEL_INSTRUCTION = re.compile(
    r"\b(important|always|must|never|ignore|do not|don't)\b|\b(call|run|use|read|send) "
    r"[a-z0-9_ -]{1,30} (first|before)|\bbefore (using|calling|answering)\b"
)


def _is_label(text: Text) -> bool:
    return text.where in {"title", "annotations.title"} or text.where.endswith(".title")


def label_instruction(text: Text):
    """Titles are labels a person skims, not prose: an instruction there is out of place."""
    if _is_label(text) and LABEL_INSTRUCTION.search(normalise(text.value)):
        yield "MCP-INJ-003", "medium", "an instruction inside a title or label field", text.value


def intent(text: Text):
    norm = normalise(text.value, _is_name(text))
    for rule, severity, message in _intent(norm):
        yield rule, severity, message, text.value


# --- parameters -------------------------------------------------------------------------------

EXFIL_PARAM = re.compile(
    r"system prompt|full (conversation|context|history)|conversation (history|so far)|"
    r"chat history|all (previous )?messages|every (message|email address)"
)
SUSPICIOUS_PARAM_NAMES = {
    "sidenote", "side_note", "notes", "note", "context", "debug", "tools_list", "history",
    "conversation", "extra", "metadata", "feedback", "notas",
}  # fmt: skip


def parameters(item: Item):
    """A parameter asking for the conversation, or an unexplained free-text side channel."""
    schema = item.definition.get("inputSchema") if isinstance(item.definition, dict) else None
    props = schema.get("properties") if isinstance(schema, dict) else None
    if not isinstance(props, dict):
        return
    description = normalise(str(item.definition.get("description", "")))
    for name, spec in props.items():
        spec = spec if isinstance(spec, dict) else {}
        text = normalise(str(spec.get("description", "")))
        where = f"inputSchema.properties.{name}"
        if EXFIL_PARAM.search(text):
            yield Finding("MCP-EXF-002", POISONED, "high", item.ref, where,
                          "a parameter asks for the conversation or system prompt",
                          evidence(str(spec.get("description"))))  # fmt: skip
        elif (
            name.lower() in SUSPICIOUS_PARAM_NAMES
            and not text
            and normalise(name) not in description
        ):
            yield Finding("MCP-EXF-003", POISONED, "medium", item.ref, where,
                          f"unexplained free-text parameter '{name}' (a common side channel)",
                          evidence(name))  # fmt: skip


# --- risky capabilities -----------------------------------------------------------------------

RISKY_PATTERNS = [
    ("MCP-CAP-001", "runs commands or code",
     r"\b(shell|exec|execute|executes|eval)\b.{0,40}\b(command|code|script|python)|"
     r"\brun(s)? (a |any )?(shell )?command|^run shell$|^sandbox run$|^exec python$"),
    ("MCP-CAP-002", "reads arbitrary files",
     r"\b(any|arbitrary) file|reads? (a |the )?files? (in|from) the list|"
     r"file (on|from) the filesystem by (absolute )?path|reads a file and"),
    ("MCP-CAP-003", "makes arbitrary network requests",
     r"\b(any|arbitrary) url|fetches a url from the internet|http request to any"),
    ("MCP-CAP-004", "exposes environment variables", r"environment variables?"),
    ("MCP-CAP-005", "returns credentials",
     r"\b(return|show|list|expose|get|read|dump)s? (the |all |system |internal )?credentials"
     r"|internal (system )?credentials|credential (store|vault) contents"),
]  # fmt: skip
RISKY_RES = [(rule, msg, re.compile(p)) for rule, msg, p in RISKY_PATTERNS]
# Wording that says secret values never come back. "Redacted" only excuses the credentials
# rule: a tool that returns every environment variable is still risky with a few masked.
SAFE_WORDING = {
    "MCP-CAP-004": re.compile(r"never (the )?values|present or missing|never returned"),
    "MCP-CAP-005": re.compile(r"never (the )?values|names \(never|never returned|redacted"),
}


def risky(item: Item):
    texts = " . ".join(
        normalise(t.value, _is_name(t))
        for t in item.texts
        if t.where in {"name", "description", "title"}
    )
    for rule, message, pattern in RISKY_RES:
        if pattern.search(texts):
            if rule in SAFE_WORDING and SAFE_WORDING[rule].search(texts):
                continue
            yield Finding(rule, RISKY, "low", item.ref, "description", message, evidence(texts))


# --- squatting --------------------------------------------------------------------------------

WELL_KNOWN = {
    "read_file", "write_file", "list_files", "list_directory", "search_files", "edit_file",
    "create_pull_request", "create_issue", "fetch", "search", "compute", "check",
    "get_current_time", "send_email", "run_query", "git_commit", "git_status",
}  # fmt: skip


def _canonical(name: str) -> str:
    return name.lower().replace("-", "_")


def _close(a: str, b: str) -> bool:
    """One edit apart, or the same apart from a trailing s or underscore. Names that are
    identical once - and _ are treated alike are duplicates, not look-alikes."""
    a, b = _canonical(a), _canonical(b)
    if a == b:
        return False
    if a.rstrip("_s") == b.rstrip("_s"):
        return True
    if len(a) == len(b):
        return sum(x != y for x, y in zip(a, b, strict=True)) == 1
    short, long_ = sorted((a, b), key=len)
    if len(long_) - len(short) == 1:
        return any(long_[:i] + long_[i + 1 :] == short for i in range(len(long_)))
    return False


def _prefixed(name: str, known: str) -> bool:
    """`github_create_pull_requests` dressing up as `create_pull_request`."""
    name = _canonical(name)
    head, _, rest = name.partition("_")
    return head in {"github", "gh", "git", "fs", "official"} and (
        rest == known or _close(rest, known)
    )


def squatting(items: list[Item]):
    """Names one edit away from a well-known tool, or from a tool on another server."""
    tools = [i for i in items if i.kind == "tool"]
    for item in tools:
        name = item.name.lower()
        near = {w for w in WELL_KNOWN if _close(name, w) or _prefixed(name, w)}
        near |= {o.name for o in tools if o.server != item.server and _close(name, o.name.lower())}
        if near and name not in WELL_KNOWN:
            yield Finding("MCP-SQT-001", SQUATTING, "medium", item.ref, "name",
                          f"name is confusingly close to {', '.join(sorted(near))}",
                          evidence(item.name))  # fmt: skip


# --- running ----------------------------------------------------------------------------------

TEXT_RULES = (hidden_text, hidden_markup, intent, label_instruction)


def scan_item(item: Item) -> list[Finding]:
    findings = []
    for text in item.texts:
        for rule in TEXT_RULES:
            for rule_id, severity, message, shown in rule(text):
                findings.append(
                    Finding(
                        rule_id, POISONED, severity, item.ref, text.where, message, evidence(shown)
                    )  # fmt: skip
                )
    findings.extend(parameters(item))
    findings.extend(risky(item))
    return _dedupe(findings)


def scan(items: list[Item]) -> list[Finding]:
    findings = [f for item in items for f in scan_item(item)]
    findings.extend(squatting(items))
    return findings


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen, out = set(), []
    for f in findings:
        key = (f.rule, f.ref, f.where)
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out
