"""Baselines evaluated on the same test set as the composite model.

- keyword scorer: deterministic weighted rules over the extracted state,
  the classical heuristic every product shipped before ML.
- forced-choice laya: one wide choice question (phishing vs legitimate) —
  the exact approach the eight-signal decomposition claims to beat.
- GPT-4o-mini zero-shot: opt-in (needs OPENAI_API_KEY and the `eval`
  extra); cost per 1,000 emails is reported when it runs.
"""

from __future__ import annotations

import os
import sys
from typing import Dict, List

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from laya_phishield import extract_email_state

__all__ = [
    "KEYWORD_RULES",
    "keyword_score",
    "FORCED_CHOICE_QUESTION",
    "forced_choice_score",
    "build_gpt_messages",
    "gpt4o_mini_score",
]

# Substring -> weight; score is the squashed weighted sum.
KEYWORD_RULES: List[tuple] = [
    ("verify your account", 2.0),
    ("confirm your password", 2.0),
    ("confirm your account", 1.5),
    ("account has been limited", 2.0),
    ("account will be", 1.0),
    ("log in.*immediately", 1.0),
    ("within 24 hours", 1.5),
    ("within 12 hours", 1.5),
    ("immediately", 0.5),
    ("suspended", 1.0),
    ("unusual activity", 1.0),
    ("click the link", 1.0),
    ("gift card", 2.0),
    ("lottery", 1.5),
    ("you have won", 2.0),
    ("inheritance", 1.5),
    ("next of kin", 2.0),
    ("claim your", 1.0),
    ("wire transfer", 1.0),
    ("bitcoin", 1.0),
    ("processing fee", 1.5),
    ("keep this confidential", 2.0),
    ("do not discuss", 1.5),
]

_FLAG_WEIGHTS = {
    "url_ip_literal": 1.5,
    "url_punycode": 1.5,
    "brand_lookalike_domain": 1.5,
    "brand_in_subdomain": 1.0,
    "display_name_brand_mismatch": 1.0,
    "reply_to_mismatch": 0.5,
    "spf_fail": 0.5,
    "dkim_fail": 0.5,
}


def keyword_score(raw_email: str) -> float:
    """Deterministic keyword+flag heuristic in [0, 1]."""
    import re

    email = extract_email_state(raw_email)
    text = (email.state["subject"] + "\n" + email.state["body_excerpt"]).lower()
    raw_score = 0.0
    for pattern, weight in KEYWORD_RULES:
        if re.search(pattern, text):
            raw_score += weight
    for code in email.flag_codes:
        raw_score += _FLAG_WEIGHTS.get(code, 0.0)
    return min(1.0, raw_score / 4.0)


FORCED_CHOICE_QUESTION = {
    "type": "choice",
    "instructions": "Is this email a phishing or scam attempt to steal money, "
    "credentials or personal data, or a legitimate email?",
    "criteria": {
        "phishing": "phishing, scam, or fraud",
        "legitimate": "a legitimate email",
    },
}


def forced_choice_score(agent, raw_email: str) -> float:
    """Probability the forced-choice laya question assigns to phishing."""
    email = extract_email_state(raw_email)
    result = agent.system_one(email.state, {"question": FORCED_CHOICE_QUESTION})
    return float(result["answers"]["question"]["probabilities"]["phishing"])


def build_gpt_messages(raw_email: str) -> List[Dict[str, str]]:
    """Zero-shot chat messages for the LLM baseline."""
    return [
        {
            "role": "system",
            "content": "You are an email security analyst. Classify the email "
            "as phishing (scam to steal money, credentials or personal data) "
            "or legitimate. Answer with exactly one word: phishing or "
            "legitimate.",
        },
        {"role": "user", "content": raw_email[:12000]},
    ]


def gpt4o_mini_score_raw(raw_email: str, client=None):
    """(score, usage) from GPT-4o-mini; score is None when the answer does
    not conform (counted by the caller, never silently legitimate)."""
    if client is None:
        api_key = os.environ.get("OPENAI_API_KEY")
        if not api_key:
            raise RuntimeError(
                'gpt4o_mini_score needs OPENAI_API_KEY (and `uv pip install -e ".[eval]"'
                " for the openai package)")
        from openai import OpenAI

        client = OpenAI(api_key=api_key)
    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=build_gpt_messages(raw_email),
        temperature=0,
        max_tokens=5,
    )
    answer = (response.choices[0].message.content or "").strip().lower()
    usage = {
        "prompt_tokens": getattr(response.usage, "prompt_tokens", 0) or 0,
        "completion_tokens": getattr(response.usage, "completion_tokens", 0) or 0,
    }
    if answer.startswith("phishing"):
        return 1.0, usage
    if answer.startswith("legitimate"):
        return 0.0, usage
    return None, usage


def gpt4o_mini_score(raw_email: str, client=None) -> float:
    """1.0 when GPT-4o-mini says phishing, 0.0 otherwise."""
    score, _ = gpt4o_mini_score_raw(raw_email, client=client)
    return 1.0 if score else 0.0
