import argparse

from mcpscan import __version__


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="mcpscan", description="Scan MCP servers and client configs for security problems."
    )
    parser.add_argument("--version", action="version", version=f"mcpscan {__version__}")
    parser.parse_args(argv)
    parser.print_help()
    return 0
