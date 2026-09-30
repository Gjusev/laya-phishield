"""Prepare the eval datasets: Nazario phishing + Enron legitimate.

The heavy work (downloads, tar streaming) lives in `__main__`; everything
testable is a pure helper. Output is JSONL with one record per email:

    {"raw": <full RFC822 text>, "label": 0|1, "date": <iso or null>,
     "split": "train"|"test", "source": "nazario"|"enron"}

Pipeline: parse -> near-duplicate MinHash dedup (across classes: cross-class
duplicates leaking between train and test are the classic inflation bug) ->
per-class temporal split (oldest train_frac to train, newest to test;
undated records always go to train so the test side stays dated and the
split remains honest).

Run explicitly:

    python evals/prepare_data.py [--phish-per-class N] [--legit N]

Downloads data/raw/phishing2.mbox, phishing3.mbox and the Enron tarball if
missing (see URLS).
"""

from __future__ import annotations

import mailbox
import os
import random
import sys
import tarfile
from datetime import datetime, timezone
from typing import Iterable, List, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from minhash import dedup_records

__all__ = [
    "iter_mbox_messages",
    "parse_email_date",
    "sample_enron_from_tar",
    "temporal_split",
    "build_dataset",
]

RAW_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "raw")
PREPARED_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "prepared")

URLS = {
    "phishing2.mbox": "https://monkey.org/~jose/phishing/phishing2.mbox",
    "phishing3.mbox": "https://monkey.org/~jose/phishing/phishing3.mbox",
    "enron.tar.gz": "https://www.cs.cmu.edu/~enron/enron_mail_20150507.tar.gz",
}

# Enron folders worth sampling: correspondence, not calendar noise or contacts.
_ENRON_FOLDERS = ("/inbox/", "/sent/", "/sent_items/", "/_sent_mail/", "/deleted_items/")


def iter_mbox_messages(path: str) -> Iterable[str]:
    """Yield each raw message text from an mbox file.

    Splits on the mbox "From " line delimiter instead of re-serializing
    parsed messages: real corpora contain broken charsets
    ("iso-18899997-1") and malformed headers that make the email
    generator raise, while the raw text itself is exactly what the
    downstream extraction wants.
    """
    with open(path, encoding="utf-8", errors="replace") as fh:
        chunk: List[str] = []
        for line in fh:
            if line.startswith("From ") and chunk:
                yield "".join(chunk).strip() + "\n"
                chunk = []
                continue
            chunk.append(line)
        if chunk:
            yield "".join(chunk).strip() + "\n"


def parse_email_date(raw: str) -> Optional[datetime]:
    """RFC 2822 Date of a raw email as UTC, or None when absent/broken."""
    from email import message_from_string
    from email.utils import parsedate_to_datetime

    try:
        msg = message_from_string(raw)
        value = msg.get("Date")
        if not value:
            return None
        parsed = parsedate_to_datetime(str(value))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except Exception:
        return None


def sample_enron_from_tar(tar_path: str, max_emails: int,
                          rng: Optional[random.Random] = None) -> Iterable[str]:
    """Stream a maildir sample out of the Enron tar.gz without unpacking it.

    Only inbox/sent-style folders of each user's maildir are read; the whole
    tarball is streamed (423 MB compressed) and file bodies are yielded as
    text, capped at `max_emails`.
    """
    rng = rng or random.Random(1337)
    # Reservoir-sampled stream: keeps memory flat over ~500k members.
    reservoir: List[str] = []
    seen = 0
    with tarfile.open(tar_path, "r:gz") as tar:
        for member in tar:
            if not member.isfile() or member.size > 200_000:
                continue
            name = member.name.replace("\\", "/")
            if not name.startswith("maildir/") or not any(f in name for f in _ENRON_FOLDERS):
                continue
            handle = tar.extractfile(member)
            if handle is None:
                continue
            try:
                text = handle.read().decode("utf-8", "replace")
            except Exception:
                continue
            seen += 1
            if len(reservoir) < max_emails:
                reservoir.append(text)
            else:
                idx = rng.randrange(seen)
                if idx < max_emails:
                    reservoir[idx] = text
    return reservoir


def temporal_split(records: List[dict], train_frac: float = 0.7) -> Tuple[List[dict], List[dict]]:
    """Per-class temporal split: oldest `train_frac` to train, newest to test.

    Undated records always land in train: the test side stays strictly
    dated, which is what makes the temporal claim honest.
    """
    train, test = [], []
    for label in (0, 1):
        group = [r for r in records if r["label"] == label]
        dated = sorted(
            (r for r in group if r["date"] is not None),
            key=lambda r: r["date"],
        )
        undated = [r for r in group if r["date"] is None]
        cut = int(len(dated) * train_frac)
        train.extend(dated[:cut] + undated)
        test.extend(dated[cut:])
    for r in train:
        r["split"] = "train"
    for r in test:
        r["split"] = "test"
    return train, test


def _core_text(raw: str) -> str:
    """Subject plus decoded body text, walking nested multiparts.

    Used as MinHash input: it must reflect what a human would call the
    email's content, so payloads are transfer-decoded (base64/
    quoted-printable) and nested multipart/alternative trees are walked to
    their leaves instead of stringified as object reprs.
    """
    from email import message_from_string

    def _walk(part) -> List[str]:
        if part.is_multipart():
            return [t for sub in (part.get_payload() or []) for t in _walk(sub)]
        cte = (part.get("Content-Transfer-Encoding") or "").lower().strip()
        payload = part.get_payload()
        if payload is None:
            return []
        if cte in ("base64", "quoted-printable"):
            data = part.get_payload(decode=True) or b""
            charset = part.get_content_charset() or "utf-8"
            return [data.decode(charset, "replace")]
        return [payload if isinstance(payload, str) else str(payload)]

    try:
        msg = message_from_string(raw)
        subject = str(msg.get("Subject", "") or "")
        return subject + "\n" + "\n".join(_walk(msg))
    except Exception:
        return raw


def build_dataset(phish: List[str], legit: List[str], train_frac: float = 0.7
                  ) -> Tuple[List[dict], List[dict], dict]:
    """Label, dedup and split raw emails into train/test records.

    Records are date-sorted before dedup so the OLDEST variant of each
    near-duplicate cluster survives (deterministic w.r.t. time, not input
    order), and dedup runs over the combined corpus because near-duplicates
    across classes are exactly the leakage this exists to remove.
    """
    from datetime import datetime as _dt

    records = [
        {"raw": raw, "label": label, "date": parse_email_date(raw),
         "source": "nazario" if label == 1 else "enron", "text": _core_text(raw)}
        for label, group in ((1, phish), (0, legit)) for raw in group
    ]
    # Undated records sort last so a dated variant wins the keep slot.
    records.sort(key=lambda r: r["date"] or _dt.max.replace(tzinfo=timezone.utc))
    kept, dedup_report = dedup_records(records, text_key="text")
    kept_records = [
        {k: v for k, v in r.items() if k != "text"} for r in kept
    ]
    train, test = temporal_split(kept_records, train_frac=train_frac)
    report = {
        "dedup": dedup_report,
        "phish_in": len(phish), "legit_in": len(legit),
        "train": len(train), "test": len(test),
    }
    return train, test, report


def _download_if_missing(name: str) -> str:
    import urllib.request

    path = os.path.join(RAW_DIR, name)
    if os.path.exists(path) and os.path.getsize(path) > 0:
        return path
    os.makedirs(RAW_DIR, exist_ok=True)
    print("downloading %s ..." % URLS[name])
    urllib.request.urlretrieve(URLS[name], path)
    return path


def _reservoir_sample(items: Iterable[str], max_items: int,
                       rng: Optional[random.Random] = None) -> List[str]:
    """Uniform sample over a stream without holding the stream in memory."""
    rng = rng or random.Random(4242)
    reservoir: List[str] = []
    seen = 0
    for item in items:
        seen += 1
        if len(reservoir) < max_items:
            reservoir.append(item)
        else:
            idx = rng.randrange(seen)
            if idx < max_items:
                reservoir[idx] = item
    return reservoir


def main() -> int:
    import argparse
    import json

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--max-phish", type=int, default=3000)
    parser.add_argument("--max-legit", type=int, default=3000)
    parser.add_argument("--train-frac", type=float, default=0.7)
    args = parser.parse_args()

    all_phish: Iterable[str] = (
        message
        for mbox_name in ("phishing2.mbox", "phishing3.mbox")
        for message in iter_mbox_messages(_download_if_missing(mbox_name))
    )
    phish = _reservoir_sample(all_phish, args.max_phish)
    print("phishing loaded: %d" % len(phish))

    enron_path = _download_if_missing("enron.tar.gz")
    legit = sample_enron_from_tar(enron_path, max_emails=args.max_legit)
    print("legitimate sampled: %d" % len(legit))

    train, test, report = build_dataset(phish, legit, train_frac=args.train_frac)
    print("report: %s" % json.dumps(report))

    os.makedirs(PREPARED_DIR, exist_ok=True)
    for split_name, split_records in (("train", train), ("test", test)):
        path = os.path.join(PREPARED_DIR, "%s.jsonl" % split_name)
        with open(path, "w", encoding="utf-8") as fh:
            for record in split_records:
                fh.write(json.dumps({
                    "raw": record["raw"],
                    "label": record["label"],
                    "date": record["date"].isoformat() if record["date"] else None,
                    "split": record["split"],
                    "source": record["source"],
                }) + "\n")
        print("wrote %s (%d records)" % (path, len(split_records)))
    with open(os.path.join(PREPARED_DIR, "report.json"), "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
