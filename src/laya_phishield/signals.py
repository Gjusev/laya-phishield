"""The eight atomic laya signals evaluated over a structured email state.

Each signal is one narrow yes/no question (a noul) answered by the local
System 1 decision model in a single forward pass. Questions follow laya's
preset house style: one short sentence, positively phrased, no criteria
text. Positive phrasing is deliberate — negated and forced-choice questions
are the documented failure mode this decomposition exists to avoid — and
every wording below was validated against a real checkpoint over the smoke
corpus (see `data/signals_schema.md` for the full per-signal contract).
"""

from __future__ import annotations

from typing import Dict, List, Tuple

__all__ = ["SIGNAL_NAMES", "SIGNAL_QUESTIONS", "score_signals", "rank_reasons"]

SIGNAL_QUESTIONS: Dict[str, Dict] = {
    "asks_credentials": {
        "type": "noul",
        "instructions": "Does the email tell the recipient to confirm their "
        "password or account login to restore or keep access?",
    },
    "urgency_pressure": {
        "type": "noul",
        "instructions": "Does the email pressure the recipient to act "
        "immediately or within hours, for example threatening consequences "
        "for delay?",
    },
    "payment_gift_request": {
        "type": "noul",
        "instructions": "Does the email ask for a payment, transfer, gift "
        "cards or cryptocurrency to the sender or an account the sender "
        "names?",
    },
    "brand_impersonation": {
        "type": "noul",
        "instructions": "Does the email borrow the name or branding of a "
        "known company or bank while `sender_domain` belongs to a different "
        "organization?",
    },
    "requests_pii": {
        "type": "noul",
        "instructions": "Does the email ask the recipient to send personal "
        "identity data such as an ID number, card number or date of birth?",
    },
    "too_good_to_be_true": {
        "type": "noul",
        "instructions": "Does the email promise an unearned prize, lottery "
        "win, inheritance or windfall?",
    },
    "suspicious_instructions": {
        "type": "noul",
        "instructions": "Does the email ask the recipient to keep the "
        "request secret from colleagues or bypass normal procedures?",
    },
    "external_link_risk": {
        "type": "noul",
        "instructions": "Does the email send the recipient to click a link "
        "hosted on a domain unrelated to the sender or the brand it claims?",
    },
}

SIGNAL_NAMES: Tuple[str, ...] = tuple(SIGNAL_QUESTIONS)


def score_signals(agent, state: dict) -> Dict[str, float]:
    """Evaluate all eight signals over `state` in one call to the agent.

    `agent` is any object exposing laya's `system_one(state, questions)`
    protocol (a `laya.Agent` in production, a deterministic fake in tests).
    Returns one calibrated probability per signal name.
    """
    result = agent.system_one(state, SIGNAL_QUESTIONS)
    answers = result["answers"]
    return {name: float(answers[name]["noul"]) for name in SIGNAL_NAMES}


def rank_reasons(signals: Dict[str, float]) -> List[Tuple[str, float]]:
    """Order (signal, probability) pairs strongest first for the verdict text.

    Phase 1 orders by signal probability; the Phase 2 logistic head replaces
    this with per-signal score contributions while keeping this interface.
    """
    return sorted(signals.items(), key=lambda item: item[1], reverse=True)
