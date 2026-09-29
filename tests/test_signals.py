"""Behavior tests for the eight atomic laya signals over a structured state.

The laya Agent is a system boundary: tests inject a deterministic fake that
speaks the same `system_one(state, questions)` protocol, so no checkpoint is
ever downloaded here.
"""

from laya_phishield.signals import SIGNAL_NAMES, SIGNAL_QUESTIONS, rank_reasons, score_signals


class FakeAgent:
    """Deterministic stand-in for laya.Agent: fixed noul probabilities."""

    def __init__(self, probabilities):
        self.probabilities = probabilities
        self.seen = None

    def system_one(self, state, questions):
        self.seen = {"state": state, "questions": questions}
        return {
            "answers": {
                qid: {"type": "noul", "noul": self.probabilities[qid]}
                for qid in questions
            }
        }


STATE = {
    "subject": "URGENT: verify your account",
    "sender_display": "PayPal Support",
    "sender_domain": "alert-center-paypal.com",
    "reply_to_domain": "",
    "first_url_host": "",
    "body_excerpt": "Click to verify.",
    "deterministic_flags": [],
}


def test_there_are_exactly_eight_signals_with_the_planned_names():
    planned = [
        "asks_credentials", "urgency_pressure", "payment_gift_request",
        "brand_impersonation", "requests_pii", "too_good_to_be_true",
        "suspicious_instructions", "external_link_risk",
    ]
    assert sorted(SIGNAL_NAMES) == sorted(planned)
    assert sorted(SIGNAL_QUESTIONS) == sorted(planned)


def test_each_signal_is_a_short_positive_noul_instruction():
    for name, question in SIGNAL_QUESTIONS.items():
        assert set(question) == {"type", "instructions"}, name
        assert question["type"] == "noul", name
        instruction = question["instructions"]
        assert 40 < len(instruction) < 220, name
        # Positive phrasing: no negated question text.
        assert " not " not in instruction.lower(), name
        assert "never" not in instruction.lower(), name


def test_score_signals_returns_one_probability_per_signal():
    probabilities = {name: 0.5 for name in SIGNAL_NAMES}
    probabilities["asks_credentials"] = 0.93
    probabilities["urgency_pressure"] = 0.87
    result = score_signals(FakeAgent(probabilities), STATE)
    assert result["asks_credentials"] == 0.93
    assert result["urgency_pressure"] == 0.87
    assert len(result) == 8


def test_score_signals_passes_the_state_and_all_questions_in_one_call():
    agent = FakeAgent({name: 0.5 for name in SIGNAL_NAMES})
    score_signals(agent, STATE)
    assert agent.seen["state"] == STATE
    assert sorted(agent.seen["questions"]) == sorted(SIGNAL_NAMES)


def test_rank_reasons_orders_signals_highest_probability_first():
    probabilities = {name: 0.1 for name in SIGNAL_NAMES}
    probabilities["asks_credentials"] = 0.93
    probabilities["urgency_pressure"] = 0.87
    ranked = rank_reasons(probabilities)
    assert ranked[0] == ("asks_credentials", 0.93)
    assert ranked[1] == ("urgency_pressure", 0.87)
    assert len(ranked) == 8


def test_extracted_state_feeds_the_signals_and_carries_readable_flags():
    from laya_phishield import extract_email_state

    agent = FakeAgent({name: 0.5 for name in SIGNAL_NAMES})
    email = extract_email_state(CREDENTIAL_PHISH)
    score_signals(agent, email.state)
    assert agent.seen["state"] is email.state
    assert any("IP address" in f for f in email.state["deterministic_flags"])


CREDENTIAL_PHISH = """\
From: "PayPal Security" <no-reply@paypal-secure-alert.example>
To: victim@corp.example
Subject: Action required within 24h: account limited
Content-Type: text/plain; charset="utf-8"

Dear Customer,

We detected unusual activity and have limited your account. Confirm your
password at http://203.0.113.9/paypal/verify to restore access within 24
hours, or your account will be permanently closed.

PayPal Security Team
"""
