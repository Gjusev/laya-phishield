"""MinHash near-duplicate detection for the eval datasets.

Near-duplicate leakage between train and test is the classic error of
phishing datasets: the same campaign email lands on both sides of the
split and every model looks better than it is. This module implements the
standard remedy — MinHash signatures with LSH banding — with the stdlib
only, and reports how much overlap it removed.
"""

from __future__ import annotations

import hashlib
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

__all__ = ["shingles", "signature", "jaccard_estimate", "dedup_records"]

_NUM_PERM = 128          # signature length
_BANDS = 32              # LSH bands
_ROWS = _NUM_PERM // _BANDS
_SHINGLE_K = 5           # words per shingle


def _hash32(data: str, seed: int) -> int:
    return int.from_bytes(
        hashlib.sha1(("%d\x00%s" % (seed, data)).encode("utf-8", "replace")).digest()[:4],
        "big",
    )


def shingles(text: str, k: int = _SHINGLE_K) -> Set[str]:
    """Lowercased word k-grams of a text."""
    words = [w for w in text.lower().split() if w.strip()]
    if len(words) < k:
        return {" ".join(words)} if words else set()
    return {" ".join(words[i:i + k]) for i in range(len(words) - k + 1)}


def signature(text: str) -> Tuple[int, ...]:
    """MinHash signature: for each of _NUM_PERM seeds, the minimum hash over shingles."""
    grams = shingles(text)
    if not grams:
        return (0,) * _NUM_PERM
    return tuple(min(_hash32(g, seed) for g in grams) for seed in range(_NUM_PERM))


def jaccard_estimate(text_a: str, text_b: str) -> float:
    """Estimated Jaccard similarity of two texts from their signatures."""
    sig_a, sig_b = signature(text_a), signature(text_b)
    equal = sum(1 for a, b in zip(sig_a, sig_b) if a == b)
    return equal / _NUM_PERM


def _bands(sig: Sequence[int]) -> Iterable[Tuple[int, ...]]:
    return (tuple(sig[i * _ROWS:(i + 1) * _ROWS]) for i in range(_BANDS))


def dedup_records(records: List[dict], text_key: str = "text",
                  min_jaccard: float = 0.5) -> Tuple[List[dict], Dict[str, int]]:
    """Drop near-duplicate records, keeping the first of each cluster.

    Records whose signatures collide in at least one LSH band are candidate
    duplicates; a candidate pair is merged only when its estimated Jaccard
    is at least `min_jaccard`. Records with no shingles at all (empty or
    body-less) never merge: they share no content, so they are unique by
    definition and must not collapse into one cluster. Returns (kept
    records, report with per-class and cross-class removal counts).
    """
    sigs: List[Optional[Tuple[int, ...]]] = [
        signature(r.get(text_key, "")) if shingles(r.get(text_key, "")) else None
        for r in records
    ]

    # Union-find over near-duplicate edges.
    parent = list(range(len(records)))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    buckets: Dict[Tuple[int, int, Tuple[int, ...]], List[int]] = {}
    for idx, sig in enumerate(sigs):
        if sig is None:
            continue
        for band_idx, band in enumerate(_bands(sig)):
            buckets.setdefault((band_idx, hash(band)), []).append(idx)
    for members in buckets.values():
        for i in range(1, len(members)):
            a, b = members[0], members[i]
            if find(a) == find(b):
                continue
            # Re-check with full-signature similarity: banding is only a filter.
            equal = sum(1 for x, y in zip(sigs[a], sigs[b]) if x == y)
            if equal / _NUM_PERM >= min_jaccard:
                parent[find(b)] = find(a)

    kept: List[dict] = []
    seen_roots: Set[int] = set()
    for idx, record in enumerate(records):
        root = find(idx)
        if root not in seen_roots:
            seen_roots.add(root)
            kept.append(record)

    # Removal attribution: within-class vs cross-class, from cluster shape.
    removed_within_phish = removed_within_legit = removed_cross_class = 0
    cluster_members: Dict[int, List[int]] = {}
    for idx in range(len(records)):
        cluster_members.setdefault(find(idx), []).append(idx)
    for members in cluster_members.values():
        labels = {records[m].get("label") for m in members}
        removed = len(members) - 1
        if removed <= 0:
            continue
        if len(labels) > 1:
            removed_cross_class += removed
        elif labels == {1}:
            removed_within_phish += removed
        else:
            removed_within_legit += removed

    report = {
        "input": len(records),
        "kept": len(kept),
        "removed": len(records) - len(kept),
        "clusters": len(kept),
        "removed_within_phish": removed_within_phish,
        "removed_within_legit": removed_within_legit,
        "removed_cross_class": removed_cross_class,
    }
    return kept, report
