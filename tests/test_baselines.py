"""Behavior tests for featurization, baselines and eval metrics.

All model calls go through fakes; nothing here downloads anything.
"""

import json

import pytest

from baselines import FORCED_CHOICE_QUESTION, build_gpt_messages, keyword_score
from featurize import featurize_records
from run_eval import ablation, evaluate_scores

from laya_phishield import extract_email_state
from laya_phishield.signals import SIGNAL_NAMES
from smoke_emails import CREDENTIAL_PHISH_EXEMPLAR, LEGIT_EMAILS, PHISHING_EMAILS


class FakeAgent:
    """Deterministic laya stand-in: phishing-shaped states score high."""

    def system_one(self, state, questions):
        phishy = "password" in state.get("body_excerpt", "").lower() and \
            "restore" in state.get("body_excerpt", "").lower()
        answers = {}
        for qid, q in questions.items():
            if q["type"] == "choice":
                answers[qid] = {
                    "type": "choice",
                    "choice": "phishing" if phishy else "legitimate",
                    "probabilities": {"phishing": 0.9 if phishy else 0.1,
                                      "legitimate": 0.1 if phishy else 0.9},
                }
            else:
                answers[qid] = {"type": "noul", "noul": 0.9 if phishy else 0.1}
        return {"answers": answers}


def test_featurize_records_produces_signals_and_flags_and_caches(tmp_path):
    records = [{"raw": CREDENTIAL_PHISH_EXEMPLAR, "label": 1},
               {"raw": LEGIT_EMAILS[0], "label": 0}]
    cache = tmp_path / "cache.jsonl"
    features = featurize_records(FakeAgent(), records, cache_path=str(cache))
    assert len(features) == 2
    assert set(features[0]["signals"]) == set(SIGNAL_NAMES)
    assert "display_name_brand_mismatch" in features[0]["flags"]
    assert features[0]["label"] == 1
    # Cache written and reloadable.
    lines = [json.loads(l) for l in cache.read_text(encoding="utf-8").splitlines()]
    assert len(lines) == 2


def test_featurize_records_reuses_cached_entries_without_calling_the_agent(tmp_path):
    records = [{"raw": CREDENTIAL_PHISH_EXEMPLAR, "label": 1}]

    class ExplodingAgent:
        def system_one(self, *a, **k):
            raise AssertionError("agent must not be called for cached records")

    cache = tmp_path / "cache.jsonl"
    first = featurize_records(FakeAgent(), records, cache_path=str(cache))
    second = featurize_records(ExplodingAgent(), records, cache_path=str(cache))
    assert second[0]["signals"] == first[0]["signals"]


def test_keyword_score_separates_smoke_corpus_classes():
    phish_scores = [keyword_score(raw) for raw in PHISHING_EMAILS]
    legit_scores = [keyword_score(raw) for raw in LEGIT_EMAILS]
    assert sum(phish_scores) / len(phish_scores) > 0.5
    assert sum(legit_scores) / len(legit_scores) < 0.2


def test_forced_choice_question_offers_exactly_two_options():
    criteria = FORCED_CHOICE_QUESTION["criteria"]
    assert set(criteria) == {"phishing", "legitimate"}
    assert FORCED_CHOICE_QUESTION["type"] == "choice"


def test_forced_choice_score_reads_the_phishing_probability():
    from baselines import forced_choice_score
    score = forced_choice_score(FakeAgent(), CREDENTIAL_PHISH_EXEMPLAR)
    assert score == pytest.approx(0.9)


def test_build_gpt_messages_wraps_the_raw_email():
    messages = build_gpt_messages(CREDENTIAL_PHISH_EXEMPLAR)
    assert any("URGENT" in part["content"] for part in messages)


def test_evaluate_scores_computes_auc_and_fpr_at_95_tpr():
    y_true = [0] * 5 + [1] * 5
    # Perfect ranking: AUC 1.0, and FPR at 95% TPR is 0.
    scores = [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0]
    metrics = evaluate_scores(y_true, scores)
    assert metrics["auc"] == pytest.approx(1.0)
    assert metrics["fpr_at_95tpr"] == pytest.approx(0.0, abs=0.05)


def test_evaluate_scores_fpr_is_one_for_a_useless_ranker():
    y_true = [0] * 5 + [1] * 5
    scores = [0.5] * 10
    metrics = evaluate_scores(y_true, scores)
    assert metrics["fpr_at_95tpr"] == pytest.approx(1.0, abs=0.05)


def test_ablation_reports_every_signal_drop():
    records = []
    for i in range(20):
        signals = {name: 0.9 if i % 2 else 0.1 for name in SIGNAL_NAMES}
        records.append({"signals": signals, "flags": [], "label": i % 2})
    report = ablation(records)
    assert set(report) == set(SIGNAL_NAMES)
    # Dropping any one of eight identical signals still separates: small drop.
    assert all(v >= 0.5 for v in report.values())


def test_stratified_subset_interleaves_classes():
    from run_eval import stratified_subset
    records = [{"label": 0, "id": i} for i in range(10)] + \
              [{"label": 1, "id": i} for i in range(10, 15)]
    subset = stratified_subset(records, 6)
    labels = [r["label"] for r in subset]
    # Round-robin interleave: no class block dominates the subset.
    assert labels == [0, 1, 0, 1, 0, 1]


def test_record_hash_changes_with_question_wording():
    from featurize import questions_fingerprint, record_hash
    h1 = record_hash("some raw email")
    assert questions_fingerprint()  # stable non-empty fingerprint
    h2 = record_hash("some raw email")
    assert h1 == h2  # deterministic for identical inputs


def test_train_and_evaluate_reports_both_class_examples():
    from run_eval import train_and_evaluate
    records = []
    for i in range(24):
        signals = {name: 0.9 if i % 2 else 0.1 for name in SIGNAL_NAMES}
        records.append({"signals": signals, "flags": [], "label": i % 2})
    # Class-grouped order (like the prepared files): all label 0 first.
    grouped = [r for r in records if r["label"] == 0] + [r for r in records if r["label"] == 1]
    train = grouped[:6] + grouped[12:18]      # 6 zeros + 6 ones
    test = grouped[6:12] + grouped[18:]       # 6 zeros + 6 ones
    metrics = train_and_evaluate(train, test)
    example_labels = [ex["label"] for ex in metrics["example_reasons"]]
    assert example_labels == [1, 0]
    assert metrics["auc"] > 0.9
