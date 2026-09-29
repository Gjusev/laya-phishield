"""Opt-in smoke run against a real laya checkpoint (downloads on first use).

Skipped by default; run explicitly with:

    pytest -m slow
"""

import statistics

import pytest

from laya_phishield import extract_email_state, rank_reasons, score_signals
from smoke_emails import (
    CREDENTIAL_PHISH_EXEMPLAR,
    LEGIT_EMAILS,
    PHISHING_EMAILS,
)

pytestmark = pytest.mark.slow


@pytest.fixture(scope="module")
def agent():
    laya = pytest.importorskip("laya")
    return laya.Agent()


def _signal_probs(agent, raw_email):
    email = extract_email_state(raw_email)
    return score_signals(agent, email.state)


def test_credential_phish_trips_asks_credentials_as_top_reason(agent):
    """Phase 1 acceptance criterion."""
    probs = _signal_probs(agent, CREDENTIAL_PHISH_EXEMPLAR)
    ranked = rank_reasons(probs)
    assert probs["asks_credentials"] > 0.9
    assert ranked[0][0] == "asks_credentials"


def test_smoke_summary_phishing_beats_legit_per_class(agent):
    """Mean top-signal probability must be higher on phishing than on legit.

    A weak gate on purpose: Phase 2 trains the combiner and publishes real
    metrics; this only checks the signals separate the two smoke classes at
    all.
    """
    phish_scores = [
        max(_signal_probs(agent, raw).values()) for raw in PHISHING_EMAILS
    ]
    legit_scores = [
        max(_signal_probs(agent, raw).values()) for raw in LEGIT_EMAILS
    ]
    print("\nphishing mean top signal: %.3f" % statistics.mean(phish_scores))
    print("legit    mean top signal: %.3f" % statistics.mean(legit_scores))
    for raw in LEGIT_EMAILS:
        email = extract_email_state(raw)
        probs = score_signals(agent, email.state)
        print("  legit '%s...' top=%s %.3f"
              % (email.state["subject"][:40], *rank_reasons(probs)[0]))
    assert statistics.mean(phish_scores) > statistics.mean(legit_scores)
