"""Score findings against labels, item by item.

An item counts as flagged for a category if any finding of that category points at it. The
headline is poisoning: precision, recall, and false alarms per 100 benign items, which is what
a developer running the scanner actually feels.

    uv run python -m mcpscan.evaluate dev [rules|guard|rules+guard]
    uv run python -m mcpscan.evaluate ablation      # all three on dev (needs the guard extra)

The test split is refused until the rules freeze.
"""

import json
import sys
from collections import Counter, defaultdict

from mcpscan import bench, rules
from mcpscan.collect import Item

CATEGORIES = ("poisoned", "risky", "squatting")


def score(items: list[Item], labels: dict[str, dict], findings: list[rules.Finding]) -> dict:
    flagged: dict[str, set[str]] = defaultdict(set)
    for f in findings:
        flagged[f.category].add(f.ref)
    refs = [i.ref for i in items]
    benign = [r for r in refs if labels[r]["label"] == "benign"]
    out: dict = {"items": len(refs), "benign": len(benign)}
    for category in CATEGORIES:
        positives = {r for r in refs if labels[r]["label"] == category}
        hits = flagged[category] & set(refs)
        tp = len(hits & positives)
        fp = len(hits - positives)
        out[category] = {
            "positives": len(positives),
            "true_positives": tp,
            "false_positives": fp,
            "recall": round(tp / len(positives), 3) if positives else None,
            "precision": round(tp / len(hits), 3) if hits else None,
            "benign_flagged": len(hits & set(benign)),
            "false_alarms_per_100_benign": round(100 * len(hits & set(benign)) / len(benign), 1)
            if benign
            else None,
        }
    by_type: dict[str, Counter] = defaultdict(Counter)
    for r in refs:
        if labels[r]["label"] == "poisoned":
            kind = labels[r].get("type", "?")
            by_type[kind]["total"] += 1
            by_type[kind]["caught"] += r in flagged["poisoned"]
    out["poisoned_recall_by_type"] = {
        k: f"{v['caught']}/{v['total']}" for k, v in sorted(by_type.items())
    }
    return out


def mistakes(items, labels, findings, category="poisoned") -> dict:
    flagged = {f.ref for f in findings if f.category == category}
    refs = {i.ref for i in items}
    positives = {r for r in refs if labels[r]["label"] == category}
    return {
        "missed": sorted(positives - flagged),
        "false_alarms": sorted((flagged & refs) - positives),
    }


LAYERS = ("rules", "guard", "rules+guard")


def findings_for(items: list[Item], layers: str, guard_model=None) -> list[rules.Finding]:
    found: list[rules.Finding] = []
    if "rules" in layers:
        found += rules.scan(items)
    if "guard" in layers:
        from mcpscan import guard

        found += guard.scan(items, guard_model or guard.load())
    return found


def run(split: str, layers: str = "rules", guard_model=None) -> dict:
    if split != "dev":
        raise SystemExit("only the dev split can be scored until the rules are frozen (day 9)")
    if layers not in LAYERS:
        raise SystemExit(f"layers must be one of {', '.join(LAYERS)}")
    sources = [s for s in bench.load_sources() if s.split == split]
    items = [i for s in sources for i in bench.items_of(s)]
    labels = bench.load_labels(bench.BENCH / "labels" / f"{split}.json")
    bench.check_coverage(items, labels)
    findings = findings_for(items, layers, guard_model)
    return {
        "layers": layers,
        "score": score(items, labels, findings),
        **mistakes(items, labels, findings),
    }


def ablation(split: str = "dev") -> dict:
    """The same split scored by each layer alone and together."""
    from mcpscan import guard

    model = guard.load()
    return {layers: run(split, layers, model) for layers in LAYERS}


if __name__ == "__main__":
    args = sys.argv[1:]
    if args[:1] == ["ablation"]:
        result = ablation(*args[1:2])
    else:
        result = run(*args[:2]) if args else run("dev")
    print(json.dumps(result, indent=2, ensure_ascii=False))
