"""Featurize prepared records: extract state, run the eight signals, cache.

Signal inference is the expensive step (~seconds per email on CPU), so every
result is cached by content hash and re-runs resume where they stopped.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from typing import Dict, List

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from laya_phishield import SIGNAL_QUESTIONS, extract_email_state, score_signals
from laya_phishield.combine import ALL_FLAG_CODES

__all__ = ["featurize_records", "record_hash", "questions_fingerprint"]

_CACHE_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "cache"
)


def questions_fingerprint() -> str:
    """Stable fingerprint of everything that changes featurized values.

    Signal wordings and the flag vocabulary both flow into feature values,
    so the cache key mixes their canonical JSON into the content hash: a
    wording change invalidates old entries instead of silently mixing old
    and new probabilities.
    """
    payload = json.dumps(
        {"questions": SIGNAL_QUESTIONS, "flags": ALL_FLAG_CODES},
        sort_keys=True, ensure_ascii=True,
    )
    return hashlib.sha1(payload.encode("utf-8")).hexdigest()[:12]


def record_hash(raw: str) -> str:
    return hashlib.sha1(
        (questions_fingerprint() + "\x00" + raw).encode("utf-8", "replace")
    ).hexdigest()


def _load_cache(cache_path: str) -> Dict[str, dict]:
    entries: Dict[str, dict] = {}
    if os.path.exists(cache_path):
        with open(cache_path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                entries[entry["hash"]] = entry
    return entries


def featurize_records(agent, records: List[dict], cache_path: str,
                      progress_every: int = 25) -> List[dict]:
    """[{raw, label, ...}] -> [{hash, signals, flags, label}] with caching.

    `agent` only sees records whose hash is missing from the cache, and each
    fresh entry is appended to the cache immediately, so interrupted runs
    resume instead of restarting from zero.
    """
    cache = _load_cache(cache_path)
    os.makedirs(os.path.dirname(cache_path), exist_ok=True)
    features: List[dict] = []
    fresh_count = 0
    with open(cache_path, "a", encoding="utf-8") as cache_fh:
        for i, record in enumerate(records):
            h = record_hash(record["raw"])
            entry = cache.get(h)
            if entry is None:
                email = extract_email_state(record["raw"])
                signals = score_signals(agent, email.state)
                entry = {"hash": h, "signals": signals, "flags": email.flag_codes}
                cache_fh.write(json.dumps(entry) + "\n")
                cache_fh.flush()
                cache[h] = entry
                fresh_count += 1
                if progress_every and (fresh_count % progress_every == 0):
                    print("featurized %d/%d (%d fresh)" % (i + 1, len(records), fresh_count),
                          flush=True)
            features.append({
                "hash": h,
                "signals": entry["signals"],
                "flags": entry["flags"],
                "label": record.get("label"),
            })
    return features


def default_cache_path(name: str) -> str:
    return os.path.join(_CACHE_DIR, name)
