"""Behavior tests for the logistic combination head.

Training runs on synthetic numeric features only: no laya checkpoint is
involved anywhere in this file.
"""

import pytest

from laya_phishield.combine import ALL_FLAG_CODES, LogisticHead, feature_vector
from laya_phishield.signals import SIGNAL_NAMES


def _record(asks, urgency, label, flags=()):
    signals = {name: 0.05 for name in SIGNAL_NAMES}
    signals["asks_credentials"] = asks
    signals["urgency_pressure"] = urgency
    return {"signals": signals, "flags": list(flags), "label": label}


PHISH = [_record(0.9, 0.8, 1) for _ in range(30)]
LEGIT = [_record(0.1, 0.1, 0) for _ in range(30)]


def test_feature_vector_is_signals_then_flags_in_stable_order():
    signals = {name: 0.1 for name in SIGNAL_NAMES}
    signals["asks_credentials"] = 0.7
    vec = feature_vector(signals, ["url_ip_literal", "spf_fail"])
    assert len(vec) == len(SIGNAL_NAMES) + len(ALL_FLAG_CODES)
    assert vec[0] == pytest.approx(0.7)          # asks_credentials is first signal
    flag_base = len(SIGNAL_NAMES)
    assert vec[flag_base + ALL_FLAG_CODES.index("url_ip_literal")] == 1.0
    assert vec[flag_base + ALL_FLAG_CODES.index("spf_fail")] == 1.0
    assert sum(v == 1.0 for v in vec[flag_base:]) == 2


def test_unknown_flags_are_ignored_in_the_feature_vector():
    signals = {name: 0.1 for name in SIGNAL_NAMES}
    vec = feature_vector(signals, ["made_up_flag"])
    assert sum(vec[len(SIGNAL_NAMES):]) == 0


def test_head_separates_trivially_separable_records():
    head = LogisticHead()
    head.fit(PHISH + LEGIT)
    phish_score = head.score(_record(0.95, 0.9, 1)["signals"], [])
    legit_score = head.score(_record(0.05, 0.05, 0)["signals"], [])
    assert phish_score > 0.9
    assert legit_score < 0.1


def test_flags_raise_the_score_for_identical_signals():
    # The head can only weigh flags it saw varying during training.
    phish_flagged = [_record(0.6, 0.6, 1, flags=["url_ip_literal"]) for _ in range(30)]
    legit_plain = [_record(0.6, 0.6, 0) for _ in range(30)]
    head = LogisticHead()
    head.fit(phish_flagged + legit_plain)
    signals = _record(0.5, 0.5, 1)["signals"]
    plain = head.score(signals, [])
    flagged = head.score(signals, ["url_ip_literal", "reply_to_mismatch"])
    assert flagged > plain


def test_reasons_rank_positive_contributions_first():
    head = LogisticHead()
    head.fit(PHISH + LEGIT)
    reasons = head.reasons(_record(0.95, 0.9, 1)["signals"], [])
    assert reasons[0][0] in ("asks_credentials", "urgency_pressure")
    assert all(c > 0 for _, c in reasons)
    assert reasons[0][1] >= reasons[1][1]


def test_reasons_include_firing_deterministic_flags():
    head = LogisticHead()
    phish_flagged = [_record(0.9, 0.8, 1, flags=["url_ip_literal"]) for _ in range(30)]
    head.fit(phish_flagged + LEGIT)
    reasons = head.reasons(_record(0.9, 0.8, 1)["signals"], ["url_ip_literal"])
    assert "url_ip_literal" in [name for name, _ in reasons]


def test_coefficients_roundtrip_through_dict():
    head = LogisticHead()
    head.fit(PHISH + LEGIT)
    clone = LogisticHead.from_dict(head.to_dict())
    signals = _record(0.6, 0.4, 1)["signals"]
    assert clone.score(signals, []) == pytest.approx(head.score(signals, []))


def test_fit_refuses_empty_records():
    with pytest.raises(ValueError):
        LogisticHead().fit([])


def test_from_dict_rejects_a_foreign_feature_layout():
    head = LogisticHead()
    head.fit(PHISH + LEGIT)
    artifact = head.to_dict()
    artifact["feature_names"] = artifact["feature_names"][::-1]
    with pytest.raises(ValueError):
        LogisticHead.from_dict(artifact)
