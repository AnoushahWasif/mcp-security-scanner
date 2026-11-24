"""Capture a server's listings over stdio: initialize, then list. Tools are never called.

The server is untrusted code, so by default it runs in Docker with no network, a read-only
filesystem, no capabilities, a non-root user and memory/process limits (decision 6). The image
must already contain the server: with no network, `npx some-server` can't download anything,
which is the point.

Every read has a deadline and a size cap, because a hostile server can stall, flood stdout or
paginate forever.
"""

import contextlib
import json
import queue
import re
import shutil
import subprocess
import threading
import time

from mcpscan import __version__
from mcpscan.collect import CollectError

PROTOCOL_VERSION = "2025-06-18"
TIMEOUT_SECONDS = 30
MAX_LINE_BYTES = 4 * 1024 * 1024
MAX_TOTAL_BYTES = 16 * 1024 * 1024
MAX_PAGES = 50
MAX_NOISE_LINES = 200
IMAGE = re.compile(r"^[a-z0-9][a-z0-9._/:@-]{0,254}$")

LISTS = {  # capability -> [(method, result key)]
    "tools": [("tools/list", "tools")],
    "prompts": [("prompts/list", "prompts")],
    "resources": [
        ("resources/list", "resources"),
        ("resources/templates/list", "resourceTemplates"),
    ],
}


class CaptureError(CollectError):
    pass


def sandbox_argv(image: str, command: list[str], docker: str = "docker") -> list[str]:
    if not IMAGE.match(image):
        # Also stops an "image" like --privileged being read as a docker flag.
        raise CaptureError(f"'{image}' isn't a plain image reference")
    return [
        docker, "run", "--rm", "-i",
        "--network", "none",
        "--read-only",
        "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--user", "65534:65534",
        "--memory", "512m",
        "--pids-limit", "128",
        "--cpus", "1",
        image, *command,
    ]  # fmt: skip


class _Session:
    def __init__(self, argv: list[str], timeout: float):
        self.deadline = time.monotonic() + timeout
        # On Windows, npx and similar are .cmd files that Popen won't find by bare name.
        argv = [shutil.which(argv[0]) or argv[0], *argv[1:]]
        self.proc = subprocess.Popen(  # an argv list, never a shell
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.lines: queue.Queue = queue.Queue()
        self.total = 0
        self.noise = 0
        self.next_id = 1
        threading.Thread(target=self._read_stdout, daemon=True).start()
        # stderr is drained so a chatty server can't block on a full pipe; it's never kept,
        # since servers log secrets there.
        threading.Thread(target=self._drain, args=(self.proc.stderr,), daemon=True).start()

    def _read_stdout(self):
        while True:
            line = self.proc.stdout.readline(MAX_LINE_BYTES + 1)
            if not line:
                self.lines.put(None)
                return
            if len(line) > MAX_LINE_BYTES:
                self.lines.put(CaptureError(f"a message is over {MAX_LINE_BYTES:,} bytes"))
                return
            self.total += len(line)
            if self.total > MAX_TOTAL_BYTES:
                self.lines.put(CaptureError(f"the server sent over {MAX_TOTAL_BYTES:,} bytes"))
                return
            self.lines.put(line)

    @staticmethod
    def _drain(stream):
        while stream.read(65536):
            pass

    def send(self, message: dict) -> None:
        try:
            self.proc.stdin.write(json.dumps(message).encode() + b"\n")
            self.proc.stdin.flush()
        except OSError as exc:
            raise CaptureError(f"the server stopped reading: {exc}") from None

    def receive(self) -> dict:
        while True:
            left = self.deadline - time.monotonic()
            if left <= 0:
                raise CaptureError("the server didn't answer in time")
            try:
                line = self.lines.get(timeout=left)
            except queue.Empty:
                raise CaptureError("the server didn't answer in time") from None
            if line is None:
                raise CaptureError(f"the server exited (code {self.proc.poll()})")
            if isinstance(line, Exception):
                raise line
            try:
                message = json.loads(line)
            except (json.JSONDecodeError, UnicodeDecodeError, RecursionError):
                message = None
            if not isinstance(message, dict):
                # Some servers print banners or logs to stdout. Tolerated, up to a point.
                self.noise += 1
                if self.noise > MAX_NOISE_LINES:
                    raise CaptureError("too many non-JSON-RPC lines on stdout")
                continue
            return message

    def request(self, method: str, params: dict | None = None) -> dict:
        request_id = self.next_id
        self.next_id += 1
        self.send({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params or {}})
        while True:
            message = self.receive()
            if "method" in message:
                self._answer_server(message)
                continue
            if message.get("id") != request_id:
                continue  # a late answer to something else
            if "error" in message:
                error = message["error"] if isinstance(message["error"], dict) else {}
                raise CaptureError(f"{method} failed: {str(error.get('message'))[:200]}")
            result = message.get("result")
            if not isinstance(result, dict):
                raise CaptureError(f"{method} returned no result object")
            return result

    def _answer_server(self, message: dict) -> None:
        if "id" not in message:
            return  # a notification (logging, progress, list_changed)
        if message.get("method") == "ping":
            self.send({"jsonrpc": "2.0", "id": message["id"], "result": {}})
        else:
            # We offer no sampling, roots or elicitation: a server asking for them gets told no.
            self.send(
                {
                    "jsonrpc": "2.0",
                    "id": message["id"],
                    "error": {"code": -32601, "message": "not supported by mcpscan"},
                }
            )

    def close(self) -> None:
        with contextlib.suppress(OSError):
            self.proc.stdin.close()
        try:
            self.proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()


def _paginate(session: _Session, method: str, key: str) -> list:
    entries, cursor, seen = [], None, set()
    for _ in range(MAX_PAGES):
        result = session.request(method, {"cursor": cursor} if cursor else {})
        page = result.get(key, [])
        if not isinstance(page, list):
            raise CaptureError(f"{method} returned '{key}' that isn't a list")
        entries.extend(page)
        cursor = result.get("nextCursor")
        if not cursor:
            return entries
        if cursor in seen:
            raise CaptureError(f"{method} repeated a page cursor")
        seen.add(cursor)
    raise CaptureError(f"{method} has more than {MAX_PAGES} pages")


def capture(argv: list[str], server: str, timeout: float = TIMEOUT_SECONDS) -> dict:
    """Run the server, list everything it offers, stop it. Returns a capture-file dict."""
    try:
        session = _Session(argv, timeout)
    except OSError as exc:
        raise CaptureError(f"couldn't start the server: {exc}") from None
    try:
        init = session.request(
            "initialize",
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "mcpscan", "version": __version__},
            },
        )
        session.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        capabilities = init.get("capabilities")
        if not isinstance(capabilities, dict):
            raise CaptureError("initialize returned no capabilities")
        out = {
            "server": server,
            "serverInfo": init.get("serverInfo")
            if isinstance(init.get("serverInfo"), dict)
            else {},
            "protocolVersion": str(init.get("protocolVersion", "")),
        }
        if isinstance(init.get("instructions"), str):
            # Clients put these into the model's context: the most direct place to poison.
            out["instructions"] = init["instructions"]
        for capability, methods in LISTS.items():
            if capability in capabilities:
                for method, key in methods:
                    try:
                        out[key] = _paginate(session, method, key)
                    except CaptureError:
                        if method != "resources/templates/list":
                            raise
                        out[key] = []  # optional even when resources are offered
        out["stdoutNoiseLines"] = session.noise
        return out
    finally:
        session.close()
