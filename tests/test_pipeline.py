"""Behavior tests for the scan pipeline: raw email in, verdict with reasons out.

The laya agent is injected as a fake; the head comes from the packaged
artifact trained in Phase 2.
"""

import pytest

from laya_phishield.combine import LogisticHead
from laya_phishield.pipeline import scan_email, load_head
from laya_phishield.signals import SIGNAL_NAMES
from smoke_emails import CREDENTIAL_PHISH_EXEMPLAR, LEGIT_EMAILS


class FakeAgent:
    """Phishing-shaped states light up the credential and link signals."""

    def system_one(self, state, questions):
        text = (state.get("subject", "") + " " + state.get("body_excerpt", "")).lower()
        phishy = "password" in text or "account" in text
        answers = {}
        for qid in questions:
            answers[qid] = {"type": "noul", "noul": 0.85 if phishy else 0.08}
        return {"answers": answers}


def test_load_head_reads_the_packaged_artifact():
    head = load_head()
    assert isinstance(head, LogisticHead)
    # The shipped head must score a credential phish far above plain legit mail.
    phish = scan_email(FakeAgent(), head, CREDENTIAL_PHISH_EXEMPLAR)
    legit = scan_email(FakeAgent(), head, LEGIT_EMAILS[0])
    assert phish.score > 0.9
    assert legit.score < 0.1


def test_scan_email_returns_a_complete_verdict():
    verdict = scan_email(FakeAgent(), load_head(), CREDENTIAL_PHISH_EXEMPLAR)
    assert 0.0 <= verdict.score <= 1.0
    assert verdict.label in ("phishing", "legitimate")
    assert set(verdict.signals) == set(SIGNAL_NAMES)
    assert verdict.flags  # exemplar carries display_name_brand_mismatch
    assert verdict.reasons
    names = [name for name, _ in verdict.reasons]
    assert all(name in SIGNAL_NAMES or name in head_flag_names() for name in names)
    assert all(contribution > 0 for _, contribution in verdict.reasons)
    assert verdict.reasons[0][1] >= verdict.reasons[-1][1]


def head_flag_names():
    from laya_phishield.combine import ALL_FLAG_CODES
    return ALL_FLAG_CODES


def test_scan_email_orders_reasons_strongest_first_for_a_legit_email():
    verdict = scan_email(FakeAgent(), load_head(), LEGIT_EMAILS[0])
    assert verdict.label == "legitimate"
    contributions = [c for _, c in verdict.reasons]
    assert contributions == sorted(contributions, reverse=True)
