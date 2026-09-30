"""The scan pipeline: raw email in, verdict with reasons out.

Wires the three stages into one call: deterministic extraction, the eight
semantic signals, and the trained logistic head. The laya agent is always
injected (never imported here), so tests and the product share one code
path with zero checkpoint downloads at import time.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from .combine import ALL_FLAG_CODES, LogisticHead
from .extract import extract_email_state
from .signals import SIGNAL_NAMES, rank_reasons, score_signals

__all__ = ["Verdict", "scan_email", "load_head", "PHISH_THRESHOLD"]

#: Operating point from the Phase 2 eval (precision 0.913 / recall 0.808).
PHISH_THRESHOLD = 0.5

_ARTIFACT = "data/head.json"


@dataclass
class Verdict:
    """One email's verdict: score, label, and the reasons that fired."""

    score: float
    label: str
    signals: dict
    flags: List[str]
    reasons: List[Tuple[str, float]]
    state: dict = field(default_factory=dict, repr=False)

    def to_dict(self) -> dict:
        return {
            "score": round(self.score, 4),
            "label": self.label,
            "signals": {k: round(v, 4) for k, v in self.signals.items()},
            "flags": list(self.flags),
            "reasons": [(name, round(value, 4)) for name, value in self.reasons],
        }


def load_head(path: Optional[str] = None) -> LogisticHead:
    """Load the trained head; defaults to the artifact packaged with the module."""
    if path is None:
        import importlib.resources

        path_file = importlib.resources.files(__package__).joinpath(_ARTIFACT)
        data = json.loads(path_file.read_text(encoding="utf-8"))
    else:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    return LogisticHead.from_dict(data)


def scan_email(agent, head: LogisticHead, raw_email: str,
               reasons_k: int = 3) -> Verdict:
    """Full pipeline over one raw email."""
    email = extract_email_state(raw_email)
    signals = score_signals(agent, email.state)
    score = head.score(signals, email.flag_codes)
    reasons = head.reasons(signals, email.flag_codes, k=reasons_k)
    return Verdict(
        score=score,
        label="phishing" if score >= PHISH_THRESHOLD else "legitimate",
        signals=signals,
        flags=email.flag_codes,
        reasons=reasons,
        state=email.state,
    )
