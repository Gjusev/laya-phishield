"""Logistic combination head: eight signal probabilities plus deterministic
flag codes in, one phishing score with per-feature reasons out.

Phase 2's classical half. The semantic signals stay the model's job; this
module only learns how much each signal and each deterministic flag should
move the final score, and reports signed per-feature contributions so every
verdict can name what fired.
"""

from __future__ import annotations

from typing import Dict, Iterable, List, Sequence, Tuple

from sklearn.linear_model import LogisticRegression

from .signals import SIGNAL_NAMES

__all__ = ["ALL_FLAG_CODES", "LogisticHead", "feature_vector"]

# Stable feature order for the flag half of the vector. Kept here (not in
# extract.py) so the combiner owns the contract it trains against.
ALL_FLAG_CODES: Tuple[str, ...] = (
    "reply_to_mismatch",
    "url_ip_literal",
    "url_punycode",
    "brand_lookalike_domain",
    "brand_in_subdomain",
    "display_name_brand_mismatch",
    "spf_fail",
    "dkim_fail",
)

_FEATURE_NAMES: Tuple[str, ...] = tuple(SIGNAL_NAMES) + ALL_FLAG_CODES


def feature_vector(signals: Dict[str, float], flags: Iterable[str]) -> List[float]:
    """Signals in SIGNAL_NAMES order, then one-hot flags in ALL_FLAG_CODES order."""
    flag_set = set(flags)
    vector = [float(signals.get(name, 0.0)) for name in SIGNAL_NAMES]
    vector.extend(1.0 if code in flag_set else 0.0 for code in ALL_FLAG_CODES)
    return vector


class LogisticHead:
    """Fitted logistic head over the composite feature vector."""

    def __init__(self) -> None:
        self.model = LogisticRegression(C=1.0, max_iter=1000)

    def fit(self, records: Sequence[dict]) -> "LogisticHead":
        """Train on [{signals, flags, label}] records (label 1 = phishing)."""
        if not records:
            raise ValueError("fit needs at least one record")
        X = [feature_vector(r["signals"], r["flags"]) for r in records]
        y = [int(r["label"]) for r in records]
        self.model.fit(X, y)
        return self

    def score(self, signals: Dict[str, float], flags: Iterable[str]) -> float:
        """Probability of phishing for one email's signals and flags."""
        return float(self.model.predict_proba([feature_vector(signals, flags)])[0][1])

    def reasons(self, signals: Dict[str, float], flags: Iterable[str],
                k: int = 3) -> List[Tuple[str, float]]:
        """Top-k firing reasons as (feature name, signed logit contribution).

        Contributions are coefficient * value in logit space: positive means
        the feature pushed the verdict towards phishing. Ordered strongest
        first; only positive contributions are reported as firing reasons.
        """
        vector = feature_vector(signals, flags)
        contributions = [
            (name, float(coef * value))
            for name, coef, value in zip(_FEATURE_NAMES, self.model.coef_[0], vector)
            if coef * value > 0
        ]
        contributions.sort(key=lambda item: item[1], reverse=True)
        return contributions[:k]

    def to_dict(self) -> dict:
        """Serialize coefficients for the evals artifact."""
        return {
            "feature_names": list(_FEATURE_NAMES),
            "coef": [float(c) for c in self.model.coef_[0]],
            "intercept": float(self.model.intercept_[0]),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "LogisticHead":
        """Rebuild a head from `to_dict` output without retraining.

        Raises ValueError when the artifact was trained against a different
        feature layout than this module's: a silent permutation mismatch
        would produce wrong scores with no error.
        """
        import numpy as np

        if data.get("feature_names") != list(_FEATURE_NAMES):
            raise ValueError(
                "artifact feature layout does not match this module's "
                "(signal or flag order changed); retrain before use"
            )
        head = cls.__new__(cls)
        head.model = LogisticRegression(C=1.0, max_iter=1000)
        head.model.classes_ = np.array([0, 1])
        head.model.coef_ = np.asarray([data["coef"]], dtype=float)
        head.model.intercept_ = np.asarray([data["intercept"]], dtype=float)
        head.model.n_features_in_ = len(data["coef"])
        return head
