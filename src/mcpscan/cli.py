"""mcpscan command line.

mcpscan inventory FILE...                       what the listings and configs contain
mcpscan capture --image IMG --name N -- CMD...  list a server's tools inside Docker
"""

import argparse
import json
import sys
from pathlib import Path

from mcpscan import __version__, collect, configs, live
from mcpscan.collect import CollectError


def _is_config(data) -> bool:
    return isinstance(data, dict) and ("mcpServers" in data or "servers" in data)


def inventory(paths: list[Path]) -> dict:
    report: dict = {"listings": [], "configs": [], "errors": []}
    for path in paths:
        try:
            text = path.read_bytes()[: collect.MAX_FILE_BYTES + 1].decode("utf-8-sig", "replace")
            try:
                is_config = _is_config(json.loads(configs.strip_jsonc(text)))
            except (json.JSONDecodeError, CollectError, RecursionError):
                is_config = path.name.endswith("mcp.json")  # let the parser explain the error
            if is_config:
                for server in configs.load_config(path):
                    report["configs"].append(
                        {
                            "file": str(path),
                            "server": server.name,
                            "transport": server.transport,
                            "command": " ".join([server.command, *server.args]).strip(),
                            "url": server.url,
                            "plainTextSecrets": list(server.secrets),
                        }
                    )
            else:
                items = collect.load_listing(path)
                counts: dict[str, int] = {}
                for item in items:
                    counts[item.kind] = counts.get(item.kind, 0) + 1
                report["listings"].append(
                    {
                        "file": str(path),
                        "server": items[0].server if items else path.stem,
                        "counts": counts,
                        "texts": sum(len(i.texts) for i in items),
                    }
                )
        except (CollectError, OSError) as exc:
            report["errors"].append({"file": str(path), "error": str(exc)})
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="mcpscan", description="Scan MCP servers and client configs for security problems."
    )
    parser.add_argument("--version", action="version", version=f"mcpscan {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    inv = sub.add_parser("inventory", help="list what saved listings and client configs contain")
    inv.add_argument("files", nargs="+", type=Path)

    cap = sub.add_parser("capture", help="list a server's tools, prompts and resources")
    cap.add_argument("--name", required=True, help="server name used in reports")
    cap.add_argument("--image", help="Docker image that already contains the server")
    cap.add_argument(
        "--no-sandbox",
        action="store_true",
        help="run the command directly on this machine (only for servers you trust)",
    )
    cap.add_argument("--timeout", type=float, default=live.TIMEOUT_SECONDS)
    cap.add_argument("-o", "--output", type=Path, help="write the capture here (default: stdout)")
    cap.add_argument("server_command", nargs=argparse.REMAINDER, help="-- then the command")

    args = parser.parse_args(argv)

    if args.command == "inventory":
        report = inventory(args.files)
        print(json.dumps(report, indent=2))
        return 1 if report["errors"] else 0

    command = [c for c in args.server_command if c != "--"] if args.server_command else []
    if args.no_sandbox == bool(args.image):
        parser.error("give exactly one of --image or --no-sandbox")
    if args.image:
        argv_ = live.sandbox_argv(args.image, command)
    elif command:
        argv_ = command
    else:
        parser.error("--no-sandbox needs a command after --")
    try:
        result = live.capture(argv_, server=args.name, timeout=args.timeout)
    except CollectError as exc:
        print(f"mcpscan: {exc}", file=sys.stderr)
        return 2
    text = json.dumps(result, indent=2, ensure_ascii=False)
    if args.output:
        args.output.write_text(text + "\n", encoding="utf-8")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
