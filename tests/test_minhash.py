"""Behavior tests for the MinHash near-duplicate dedup used by data prep."""

from minhash import dedup_records, jaccard_estimate, shingles, signature


NEAR_DUP_A = """\
From: security@paypal.example
Subject: account limited

Dear customer, your account has been limited. Confirm your password at
http://203.0.113.9/verify within 24 hours or the account will be closed.
"""

NEAR_DUP_B = """\
From: no-reply@paypal.example
Subject: account limited

Dear valued customer, your account has been limited. Confirm your password at
http://203.0.113.9/verify within 24 hours or the account will be closed.
"""

UNRELATED = """\
From: alice@acme.example
Subject: lunch

Do you want to grab lunch on Friday? I heard the new place is good.
"""


def test_shingles_are_lowercased_word_ngrams():
    grams = shingles("Hello WORLD hello", k=2)
    assert "hello world" in grams
    assert "world hello" in grams


def test_identical_texts_have_identical_signatures():
    assert signature(NEAR_DUP_A) == signature(NEAR_DUP_A)


def test_near_duplicates_score_much_higher_than_unrelated_pairs():
    near = jaccard_estimate(NEAR_DUP_A, NEAR_DUP_B)
    far = jaccard_estimate(NEAR_DUP_A, UNRELATED)
    assert near > 0.45
    assert far < 0.1


def test_dedup_keeps_one_copy_of_each_near_duplicate_cluster():
    records = [
        {"id": "a1", "text": NEAR_DUP_A},
        {"id": "a2", "text": NEAR_DUP_B},
        {"id": "u1", "text": UNRELATED},
    ]
    kept, report = dedup_records(records, text_key="text")
    kept_ids = [r["id"] for r in kept]
    assert kept_ids == ["a1", "u1"]
    assert report["input"] == 3
    assert report["kept"] == 2
    assert report["removed"] == 1


def test_dedup_prefers_to_keep_the_provided_order():
    records = [
        {"id": "u1", "text": UNRELATED},
        {"id": "a1", "text": NEAR_DUP_A},
        {"id": "a2", "text": NEAR_DUP_B},
    ]
    kept, _ = dedup_records(records, text_key="text")
    assert [r["id"] for r in kept] == ["u1", "a1"]


def test_body_less_records_never_collapse_into_one_cluster():
    records = [
        {"id": "e1", "text": "", "label": 1},
        {"id": "e2", "text": "   ", "label": 1},
        {"id": "e3", "text": "\n\n", "label": 0},
    ]
    kept, report = dedup_records(records, text_key="text")
    assert [r["id"] for r in kept] == ["e1", "e2", "e3"]
    assert report["removed"] == 0


def test_report_breaks_removals_into_within_and_cross_class():
    records = [
        {"id": "a1", "text": NEAR_DUP_A, "label": 1},
        {"id": "a2", "text": NEAR_DUP_B, "label": 1},
        {"id": "u1", "text": UNRELATED, "label": 0},
    ]
    _, report = dedup_records(records, text_key="text")
    assert report["removed_within_phish"] == 1
    assert report["removed_within_legit"] == 0
    assert report["removed_cross_class"] == 0
