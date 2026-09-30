"""Train the composite head and evaluate it against the baselines.

Core metric helpers are pure and unit-tested; `main` orchestrates the real
run: load prepared JSONL -> featurize (cached) -> train -> evaluate ->
baselines on the same test set -> per-signal ablation -> results JSON.

    python evals/run_eval.py [--gpt-subset 200]
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Dict, List, Sequence

import numpy as np
from sklearn.metrics import precision_score, recall_score, roc_auc_score, roc_curve
from sklearn.model_selection import cross_val_score

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from laya_phishield.combine import LogisticHead, feature_vector

__all__ = ["evaluate_scores", "ablation", "train_and_evaluate", "stratified_subset"]

RESULTS_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "evals", "results.json"
)


def evaluate_scores(y_true: Sequence[int], scores: Sequence[float]) -> Dict[str, float]:
    """AUC, FPR at 95% TPR, and precision/recall at the 0.5 threshold."""
    y = np.asarray(y_true, dtype=int)
    s = np.asarray(scores, dtype=float)
    fpr, tpr, thresholds = roc_curve(y, s)
    auc = float(roc_auc_score(y, s))
    # Lowest FPR reached while sensitivity is at least 95%.
    mask = tpr >= 0.95
    fpr_at = float(fpr[mask].min()) if mask.any() else 1.0
    preds = (s >= 0.5).astype(int)
    return {
        "auc": auc,
        "fpr_at_95tpr": fpr_at,
        "precision_at_05": float(precision_score(y, preds, zero_division=0)),
        "recall_at_05": float(recall_score(y, preds, zero_division=0)),
        "n": int(len(y)),
    }


def stratified_subset(records: List[dict], n: int) -> List[dict]:
    """Class-balanced prefix subset: records interleaved by label.

    The prepared test set is written grouped by class, so a plain prefix
    would be single-class; interleaving keeps the subset representative at
    any n.
    """
    by_label: Dict[int, List[dict]] = {}
    for record in records:
        by_label.setdefault(record.get("label"), []).append(record)
    order = sorted(by_label, key=lambda k: -len(by_label[k]))
    subset: List[dict] = []
    while len(subset) < n and any(by_label.values()):
        for label in order:
            if by_label[label] and len(subset) < n:
                subset.append(by_label[label].pop(0))
    return subset


def ablation(records: List[dict], cv: int = 3) -> Dict[str, float]:
    """Cross-validated AUC with each single signal zeroed out.

    Descriptive only (computed over the whole featurized corpus, not the
    held-out test): the value is how much separation survives losing one
    signal, for the README ablation table.
    """
    X = np.asarray([feature_vector(r["signals"], r["flags"]) for r in records])
    y = np.asarray([r["label"] for r in records])
    from laya_phishield.signals import SIGNAL_NAMES

    def _cv_auc(matrix: np.ndarray) -> float:
        head = LogisticHead()
        return float(cross_val_score(head.model, matrix, y, cv=cv, scoring="roc_auc").mean())

    scores: Dict[str, float] = {}
    for i, name in enumerate(SIGNAL_NAMES):
        masked = X.copy()
        masked[:, i] = 0.0
        scores[name] = _cv_auc(masked)
    return scores


def train_and_evaluate(train_records: List[dict], test_records: List[dict]) -> dict:
    """Fit the head on train records, evaluate on test records."""
    head = LogisticHead().fit(train_records)
    y_true = [r["label"] for r in test_records]
    scores = [head.score(r["signals"], r["flags"]) for r in test_records]
    metrics = evaluate_scores(y_true, scores)
    metrics["coefficients"] = head.to_dict()
    # One phishing and one legitimate example: the explainability showcase
    # must show both sides, and the class-grouped test order would make a
    # plain prefix single-class.
    examples = []
    for label in (1, 0):
        for r in test_records:
            if r["label"] == label:
                examples.append({
                    "label": label,
                    "reasons": head.reasons(r["signals"], r["flags"], k=3),
                })
                break
    metrics["example_reasons"] = examples
    return metrics


def _gpt_leg(test_raw: List[dict], subset_size: int, cache_path: str) -> dict:
    """GPT-4o-mini zero-shot on a class-balanced subset, cached per record.

    Returns metrics plus token usage and a cost-per-1k figure when price
    env vars are set; non-conforming answers are counted, not silently
    scored legitimate.
    """
    from baselines import gpt4o_mini_score_raw
    from featurize import _load_cache, record_hash

    subset = stratified_subset(test_raw, subset_size)
    cache = _load_cache(cache_path)
    os.makedirs(os.path.dirname(cache_path), exist_ok=True)
    scores: List[float] = []
    unparsed = 0
    usage_total = {"prompt_tokens": 0, "completion_tokens": 0}
    with open(cache_path, "a", encoding="utf-8") as fh:
        for i, record in enumerate(subset):
            h = record_hash(record["raw"])
            entry = cache.get(h)
            if entry is None:
                try:
                    score, usage = gpt4o_mini_score_raw(record["raw"])
                except Exception as exc:
                    return {"error": "gpt run aborted at %d/%d: %s" % (i, len(subset), exc)}
                entry = {"score": score, "usage": usage}
                cache[h] = entry
                fh.write(json.dumps({"hash": h, **entry}) + "\n")
                fh.flush()
                usage_total["prompt_tokens"] += usage.get("prompt_tokens", 0)
                usage_total["completion_tokens"] += usage.get("completion_tokens", 0)
            elif entry.get("score") is None:
                unparsed += 1
            scores.append(entry.get("score") or 0.0)
            if (i + 1) % 20 == 0:
                print("gpt %d/%d" % (i + 1, len(subset)), flush=True)
    metrics = evaluate_scores([r["label"] for r in subset], scores)
    metrics["unparsed_answers"] = unparsed
    metrics["usage"] = usage_total
    price_in = float(os.environ.get("OPENAI_PRICE_INPUT_PER_MTOK", 0) or 0)
    price_out = float(os.environ.get("OPENAI_PRICE_OUTPUT_PER_MTOK", 0) or 0)
    if price_in or price_out:
        cost = (usage_total["prompt_tokens"] * price_in
                + usage_total["completion_tokens"] * price_out) / 1e6
        metrics["cost_usd_per_1000_emails"] = cost / max(1, len(subset)) * 1000
    else:
        metrics["cost_usd_per_1000_emails"] = "TODO(measure): set OPENAI_PRICE_INPUT_PER_MTOK/OPENAI_PRICE_OUTPUT_PER_MTOK"
    return metrics


def main() -> int:
    from baselines import forced_choice_score, keyword_score
    from featurize import default_cache_path, featurize_records

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gpt-subset", type=int, default=200)
    parser.add_argument("--skip-gpt", action="store_true")
    args = parser.parse_args()

    prepared_dir = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "prepared")

    def load_split(name: str) -> List[dict]:
        path = os.path.join(prepared_dir, "%s.jsonl" % name)
        with open(path, encoding="utf-8") as fh:
            return [json.loads(line) for line in fh if line.strip()]

    train_raw = load_split("train")
    test_raw = load_split("test")
    print("train: %d  test: %d" % (len(train_raw), len(test_raw)))

    import laya

    agent = laya.Agent()
    train = featurize_records(agent, train_raw, default_cache_path("signals.jsonl"))
    test = featurize_records(agent, test_raw, default_cache_path("signals.jsonl"))

    results = {"composite": train_and_evaluate(train, test)}

    # Keyword baseline: deterministic, no model.
    results["keyword"] = evaluate_scores(
        [r["label"] for r in test_raw], [keyword_score(r["raw"]) for r in test_raw])

    # Forced-choice baseline: cached per record, scores kept in test order
    # so they stay aligned with the labels list.
    from featurize import record_hash, _load_cache

    fc_cache_path = default_cache_path("forced_choice.jsonl")
    fc_cache = _load_cache(fc_cache_path)
    os.makedirs(os.path.dirname(fc_cache_path), exist_ok=True)
    fc_scores: List[float] = []
    computed = 0
    with open(fc_cache_path, "a", encoding="utf-8") as fh:
        for record in test_raw:
            h = record_hash(record["raw"])
            entry = fc_cache.get(h)
            if entry is None:
                entry = {"score": forced_choice_score(agent, record["raw"])}
                fc_cache[h] = entry
                fh.write(json.dumps({"hash": h, **entry}) + "\n")
                fh.flush()
                computed += 1
                if computed % 50 == 0:
                    print("forced-choice %d fresh" % computed, flush=True)
            fc_scores.append(entry["score"])
    results["forced_choice"] = evaluate_scores([r["label"] for r in test_raw], fc_scores)

    # Per-signal ablation over the full featurized corpus.
    results["ablation"] = ablation(train + test)

    # GPT-4o-mini zero-shot on a balanced subset, only when a key exists.
    if not args.skip_gpt and os.environ.get("OPENAI_API_KEY"):
        results["gpt4o_mini"] = _gpt_leg(test_raw, args.gpt_subset,
                                         default_cache_path("gpt4o_mini.jsonl"))
    else:
        results["gpt4o_mini"] = {"status": "skipped: set OPENAI_API_KEY to run"}

    with open(RESULTS_PATH, "w", encoding="utf-8") as fh:
        json.dump(results, fh, indent=2)
    print("wrote %s" % RESULTS_PATH)
    # Keep the packaged head artifact in sync with this run.
    artifact_dir = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "src", "laya_phishield", "data")
    os.makedirs(artifact_dir, exist_ok=True)
    with open(os.path.join(artifact_dir, "head.json"), "w", encoding="utf-8") as fh:
        json.dump(results["composite"]["coefficients"], fh, indent=2)
    print("wrote src/laya_phishield/data/head.json")
    for name in ("composite", "keyword", "forced_choice", "gpt4o_mini"):
        if name in results:
            print(name, {k: v for k, v in results[name].items()
                         if k in ("auc", "fpr_at_95tpr", "n", "status", "error")})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
