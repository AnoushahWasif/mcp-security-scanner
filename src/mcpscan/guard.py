"""Second detector layer: the prompt-injection-guard model (TF-IDF + logistic regression).

The model comes from a pinned GitHub release of prompt-injection-guard, in its pickle-free
format: JSON vocabularies and safetensors weights, so loading it runs no code. Before it's
used:
- the manifest must match the pinned SHA-256, and every file must match the manifest;
- check.json (pinned separately) holds the guard repo's own scores on fixed probe texts, and
  this module's rebuild must reproduce every one of them. That catches any drift between the
  copied normaliser and the original.

Needs the `guard` extra: `uv sync --extra guard`.
"""

import hashlib
import hmac
import json
import os
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from mcpscan.collect import Item
from mcpscan.guard_normalize import MAX_CHARS, normalize
from mcpscan.rules import POISONED, Finding, evidence

RELEASE = "https://github.com/AnoushahWasif/prompt-injection-guard/releases/download/model-tfidf-v1"
MANIFEST_SHA256 = "0e4be548e1a126594dee3eb33e459413d983956e9fe83cde066c0daf2bcfbeea"
CHECK_SHA256 = "3cd9e016d0f1d83ebd21fdf299702eb538674ef61e80eaa044627bfa2d97dc0b"
FILES = ("config.json", "vocab_words.json", "vocab_chars.json", "weights.safetensors")
MAX_FILE_BYTES = 20 * 1024 * 1024
MIN_TEXT_CHARS = 20  # names and enum values are too short for the model to say anything useful
COMMON = ("sublinear_tf", "lowercase", "norm", "smooth_idf")


class GuardError(RuntimeError):
    """The model couldn't be fetched, verified or rebuilt. Never scores with a doubtful model."""


def cache_dir() -> Path:
    base = os.environ.get("MCPSCAN_CACHE") or Path.home() / ".cache" / "mcpscan"
    return Path(base) / "guard" / "model-tfidf-v1"


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _get(name: str, folder: Path, opener=urllib.request.urlopen) -> bytes:
    path = folder / name
    if path.exists():
        return path.read_bytes()
    try:
        with opener(f"{RELEASE}/{name}", timeout=60) as response:
            data = response.read(MAX_FILE_BYTES + 1)
    except OSError as exc:
        raise GuardError(f"couldn't download {name}: {exc}") from None
    if len(data) > MAX_FILE_BYTES:
        raise GuardError(f"{name} is over {MAX_FILE_BYTES:,} bytes")
    folder.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".part")
    tmp.write_bytes(data)
    tmp.replace(path)
    return data


@dataclass
class Guard:
    model: object
    threshold: float
    review: float

    def scores(self, texts: list[str]) -> list[float]:
        normalised = [normalize(t[:MAX_CHARS]).text for t in texts]
        return [float(s) for s in self.model.predict_proba(normalised)[:, 1]]


def _vectoriser(settings: dict, vocab: dict, idf):
    from sklearn.feature_extraction.text import TfidfVectorizer

    if len(vocab) != idf.shape[0] or sorted(vocab.values()) != list(range(len(vocab))):
        raise GuardError("vocabulary and idf don't match")
    vec = TfidfVectorizer(
        analyzer=settings["analyzer"],
        ngram_range=tuple(settings["ngram_range"]),
        vocabulary=vocab,
        **{k: settings[k] for k in COMMON},
    )
    vec._validate_vocabulary()
    vec.idf_ = idf
    return vec


def load(folder: Path | None = None, opener=urllib.request.urlopen) -> Guard:
    try:
        import numpy as np
        from safetensors.numpy import load as load_tensors
        from sklearn.linear_model import LogisticRegression
        from sklearn.pipeline import FeatureUnion, Pipeline
    except ImportError:
        raise GuardError("the guard layer needs the extra: uv sync --extra guard") from None

    folder = folder or cache_dir()
    raw_manifest = _get("manifest.json", folder, opener)
    if not hmac.compare_digest(_sha(raw_manifest), MANIFEST_SHA256):
        raise GuardError("manifest.json doesn't match the pinned hash; refusing the model")
    manifest = json.loads(raw_manifest)
    if set(manifest.get("files", {})) != set(FILES):
        raise GuardError("unexpected file list in the manifest")
    data = {}
    for name in FILES:
        raw = _get(name, folder, opener)
        if not hmac.compare_digest(_sha(raw), manifest["files"][name]):
            raise GuardError(f"{name} doesn't match the manifest; refusing the model")
        data[name] = raw
    raw_check = _get("check.json", folder, opener)
    if not hmac.compare_digest(_sha(raw_check), CHECK_SHA256):
        raise GuardError("check.json doesn't match the pinned hash; refusing the model")

    config = json.loads(data["config.json"])
    tensors = load_tensors(data["weights.safetensors"])
    words = _vectoriser(
        config["features"]["words"], json.loads(data["vocab_words.json"]), tensors["idf_words"]
    )
    chars = _vectoriser(
        config["features"]["chars"], json.loads(data["vocab_chars.json"]), tensors["idf_chars"]
    )
    coef = tensors["coef"]
    if coef.shape != (1, len(words.vocabulary_) + len(chars.vocabulary_)):
        raise GuardError("coefficients don't match the vocabularies")
    clf = LogisticRegression()
    clf.coef_, clf.intercept_, clf.classes_ = coef, tensors["intercept"], np.array([0, 1])
    clf.n_features_in_ = coef.shape[1]
    model = Pipeline(
        [("features", FeatureUnion([("words", words), ("chars", chars)])), ("clf", clf)]
    )
    guard = Guard(model, float(config["threshold"]), float(config["review_threshold"]))

    check = json.loads(raw_check)
    probes = check["probes"]
    if [normalize(p["text"]).text for p in probes] != [p["normalized"] for p in probes]:
        raise GuardError("the copied normaliser no longer matches the guard's; refusing")
    got = guard.scores([p["text"] for p in probes])
    if any(abs(g - p["score"]) > 1e-9 for g, p in zip(got, probes, strict=True)):
        raise GuardError("rebuilt model scores differ from the guard repo's; refusing")
    return guard


def scan(items: list[Item], guard: Guard) -> list[Finding]:
    """One finding per text the model scores at or above its block threshold."""
    texts = [(item, t) for item in items for t in item.texts if len(t.value) >= MIN_TEXT_CHARS]
    if not texts:
        return []
    scores = guard.scores([t.value for _, t in texts])
    return [
        Finding(
            "MCP-ML-001",
            POISONED,
            "medium",
            item.ref,
            text.where,
            f"the prompt-injection model scores this {score:.2f} (threshold {guard.threshold:.2f})",
            evidence(text.value),
        )  # fmt: skip
        for (item, text), score in zip(texts, scores, strict=True)
        if score >= guard.threshold
    ]
