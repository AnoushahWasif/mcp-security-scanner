"""The benchmark: pinned sources, labels and the dev/test split (decision 4).

Protocol, so the test score means something:
- Rules are written from the *dev* sources only.
- Test sources are pinned now but labelled only after the rules are frozen. The git history shows
  the order: the commit adding test labels comes after the last rules commit.
- Test sources with no licence (Damn Vulnerable MCP Server) are fetched at a pinned commit at run
  time and never copied into this repo.

Labels per item:
- poisoned: model-visible text that tries to steer the model (hidden instructions, exfiltration,
  instructions about other tools, concealment)
- risky: an honest description of a dangerous capability (shell, arbitrary file read, credentials)
- squatting: a name made to be confused with another tool or server
- benign: none of the above
"""

import hashlib
import json
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from mcpscan import collect, extract
from mcpscan.collect import Item

ROOT = Path(__file__).resolve().parents[2]
BENCH = ROOT / "bench"
CACHE = BENCH / "cache"
LABELS = {"poisoned", "risky", "squatting", "benign"}
SPLITS = {"dev", "test"}


class BenchError(RuntimeError):
    pass


@dataclass(frozen=True)
class Source:
    name: str
    split: str
    licence: str
    repo: str = ""
    commit: str = ""
    files: str = ""  # glob of server sources inside the repo
    listing: str = ""  # or a committed listing file under bench/


def load_sources(path: Path = BENCH / "sources.json") -> list[Source]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    sources = [Source(**entry) for entry in raw]
    names = [s.name for s in sources]
    if len(names) != len(set(names)):
        raise BenchError("duplicate source names")
    for s in sources:
        if s.split not in SPLITS:
            raise BenchError(f"{s.name}: split must be dev or test")
        if bool(s.repo) == bool(s.listing):
            raise BenchError(f"{s.name}: give either a repo or a listing file")
        if s.repo and (len(s.commit) != 40 or not s.files):
            raise BenchError(f"{s.name}: a repo source needs a full 40-character commit and a glob")
    return sources


def _git(*args: str, cwd: Path | None = None) -> str:
    result = subprocess.run(
        ["git", *args], cwd=cwd, capture_output=True, text=True, timeout=300, check=False
    )
    if result.returncode != 0:
        raise BenchError(f"git {args[0]} failed: {result.stderr.strip()[:300]}")
    return result.stdout.strip()


def fetch(source: Source, cache: Path = CACHE) -> Path:
    """Check out exactly the pinned commit, and refuse anything else."""
    target = cache / source.name
    if not (target / ".git").exists():
        target.mkdir(parents=True, exist_ok=True)
        _git("init", "-q", cwd=target)
        _git("remote", "add", "origin", source.repo, cwd=target)
    _git("fetch", "-q", "--depth", "1", "origin", source.commit, cwd=target)
    _git("checkout", "-q", "--force", source.commit, cwd=target)
    head = _git("rev-parse", "HEAD", cwd=target)
    if head != source.commit:
        raise BenchError(f"{source.name}: checked out {head}, pinned {source.commit}")
    return target


def items_of(source: Source, cache: Path = CACHE) -> list[Item]:
    if source.listing:
        return collect.load_listing(BENCH / source.listing)
    folder = fetch(source, cache)
    items: list[Item] = []
    for path in sorted(folder.glob(source.files)):
        rel = path.relative_to(folder).with_suffix("").as_posix().replace("/", ".")
        listing = extract.extract_file(path, server=f"{source.name}:{rel}")
        items.extend(collect.parse_listing(listing))
    return items


def load_labels(path: Path) -> dict[str, dict]:
    labels = json.loads(path.read_text(encoding="utf-8"))
    for ref, entry in labels.items():
        if entry.get("label") not in LABELS:
            raise BenchError(f"{ref}: label must be one of {sorted(LABELS)}")
        if entry["label"] != "benign" and not entry.get("reason"):
            raise BenchError(f"{ref}: a non-benign label needs a reason")
    return labels


def check_coverage(items: list[Item], labels: dict[str, dict]) -> None:
    """Every item labelled, and no label for an item that doesn't exist."""
    refs = {i.ref for i in items}
    missing = sorted(refs - set(labels))
    stale = sorted(set(labels) - refs)
    if missing or stale:
        raise BenchError(f"unlabelled: {missing[:5]} ({len(missing)} in all), stale: {stale[:5]}")


def fingerprint(items: list[Item]) -> dict:
    """Count and one hash over every item's definition hash: any change to any item shows."""
    digest = hashlib.sha256()
    for ref, sha in sorted((i.ref, i.sha256) for i in items):
        digest.update(f"{ref}\t{sha}\n".encode())
    return {"items": len(items), "sha256": digest.hexdigest()}


def build_manifest(sources: list[Source], cache: Path = CACHE) -> dict:
    return {s.name: {"split": s.split, **fingerprint(items_of(s, cache))} for s in sources}


def check_manifest(manifest: dict, expected: dict) -> list[str]:
    """Sources whose content differs from what was frozen."""
    problems = []
    for name in sorted(set(manifest) | set(expected)):
        if manifest.get(name) != expected.get(name):
            problems.append(name)
    return problems


def main(argv: list[str] | None = None) -> int:

    args = sys.argv[1:] if argv is None else argv
    path = BENCH / "manifest.json"
    manifest = build_manifest(load_sources())
    if args == ["freeze"]:
        path.write_text(json.dumps(manifest, indent=2) + "\n")
        print(json.dumps(manifest, indent=2))
        return 0
    changed = check_manifest(manifest, json.loads(path.read_text()))
    if changed:
        print(f"changed since frozen: {', '.join(changed)}")
        return 1
    print(f"{sum(m['items'] for m in manifest.values())} items in {len(manifest)} sources match")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
