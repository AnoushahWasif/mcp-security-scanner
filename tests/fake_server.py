"""A stdio MCP server for tests. Its first argument picks a behaviour, good or hostile."""

import json
import sys
import time

MODE = sys.argv[1] if len(sys.argv) > 1 else "ok"
TOOLS = [
    {"name": "add", "description": "Add two numbers", "inputSchema": {"type": "object"}},
    {"name": "echo", "description": "Echo text", "inputSchema": {"type": "object"}},
]


def send(message):
    sys.stdout.write(json.dumps(message) + "\n")
    sys.stdout.flush()


def result(request, value):
    send({"jsonrpc": "2.0", "id": request["id"], "result": value})


def tools_page(request):
    cursor = request.get("params", {}).get("cursor")
    if MODE == "cursor_loop":
        return result(request, {"tools": TOOLS[:1], "nextCursor": "same"})
    if MODE == "list_error":
        return send({"jsonrpc": "2.0", "id": request["id"], "error": {"code": -1, "message": "no"}})
    if cursor is None:
        return result(request, {"tools": TOOLS[:1], "nextCursor": "page2"})
    return result(request, {"tools": TOOLS[1:]})


def main():
    if MODE == "banner":
        print("Starting server v1.0 ...", flush=True)  # stdout noise some servers produce
    if MODE == "exit":
        return
    calls = []
    for line in sys.stdin:
        request = json.loads(line)
        method = request.get("method")
        calls.append(method)
        if MODE == "hang":
            time.sleep(60)
        if MODE == "huge":
            sys.stdout.write("x" * (5 * 1024 * 1024) + "\n")
            sys.stdout.flush()
            continue
        if method == "initialize":
            if MODE == "ping_first":
                send({"jsonrpc": "2.0", "id": "s1", "method": "ping"})
                send({"jsonrpc": "2.0", "id": "s2", "method": "sampling/createMessage"})
                send({"jsonrpc": "2.0", "method": "notifications/message", "params": {}})
                replies = (json.loads(sys.stdin.readline()) for _ in range(2))
                answers = {a["id"]: a for a in replies}
                if answers["s1"].get("result") != {} or answers["s2"]["error"]["code"] != -32601:
                    return  # wrong answers: exit, which fails the capture
            caps = {"tools": {}, "prompts": {}}
            if MODE != "tools_only":
                caps["resources"] = {}
            result(request, {"protocolVersion": "2025-06-18", "capabilities": caps,
                             "serverInfo": {"name": "fake", "version": "0"}})  # fmt: skip
        elif method == "tools/list":
            tools_page(request)
        elif method == "prompts/list":
            result(request, {"prompts": [{"name": "greet", "description": "Say hi"}]})
        elif method == "resources/list":
            result(request, {"resources": [{"uri": "mem://a", "name": "a"}]})
        elif method == "resources/templates/list":
            send({"jsonrpc": "2.0", "id": request["id"], "error": {"code": -32601, "message": "x"}})
        elif method == "tools/call":
            # Never expected: the test checks the scanner doesn't send it.
            sys.stderr.write("TOOL CALLED\n")
            result(request, {"content": []})


if __name__ == "__main__":
    main()
