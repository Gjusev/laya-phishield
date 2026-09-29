"""laya-phishield: explainable phishing detection: eight atomic signals from a local decision model plus header/URL heuristics, combined by a classical head with per-signal reasons."""

from .extract import ExtractedEmail, extract_email_state
from .signals import SIGNAL_NAMES, SIGNAL_QUESTIONS, rank_reasons, score_signals

__version__ = "0.1.0"

__all__ = [
    "ExtractedEmail",
    "extract_email_state",
    "SIGNAL_NAMES",
    "SIGNAL_QUESTIONS",
    "score_signals",
    "rank_reasons",
    "__version__",
]
