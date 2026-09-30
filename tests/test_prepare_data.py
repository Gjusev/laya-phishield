"""Behavior tests for data-prep helpers (synthetic inputs, no network)."""

import io
import json
import tarfile
from datetime import datetime, timezone

from prepare_data import (
    build_dataset,
    iter_mbox_messages,
    parse_email_date,
    sample_enron_from_tar,
    temporal_split,
)


def _mbox_file(tmp_path, messages):
    path = tmp_path / "corpus.mbox"
    path.write_text("".join(m.replace("\n", "\r\n") if False else m for m in messages), encoding="utf-8")
    return str(path)


MSG_1 = """\
From: a@x.example
Date: Mon, 01 Jun 2026 10:00:00 +0000
Subject: one

body one
"""

MSG_2 = """\
From: b@y.example
Date: Tue, 02 Jun 2026 10:00:00 +0000
Subject: two

body two
"""


def test_iter_mbox_messages_yields_each_raw_email(tmp_path):
    # mbox format separates messages with a "From " line.
    mbox = "From a@x.example Mon Jun 01 10:00:00 2026\n" + MSG_1 + "\n" \
           "From b@y.example Tue Jun 02 10:00:00 2026\n" + MSG_2 + "\n"
    path = tmp_path / "c.mbox"
    path.write_text(mbox, encoding="utf-8")
    messages = list(iter_mbox_messages(str(path)))
    assert len(messages) == 2
    assert "Subject: one" in messages[0]
    assert "Subject: two" in messages[1]


def test_parse_email_date_reads_rfc2822_dates():
    assert parse_email_date(MSG_1) == datetime(2026, 6, 1, 10, 0, tzinfo=timezone.utc)


def test_parse_email_date_returns_none_for_garbage():
    assert parse_email_date("not an email at all") is None


def _enron_tar(tmp_path, entries):
    path = tmp_path / "enron.tar"
    with tarfile.open(str(path), "w:gz") as tar:
        for name, content in entries:
            data = content.encode("utf-8")
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return str(path)


def test_sample_enron_from_tar_reads_maildir_messages(tmp_path):
    tar = _enron_tar(tmp_path, [
        ("maildir/allen/inbox/1.", "From: allen@enron.example\nDate: Mon, 01 Jun 2001 10:00:00 +0000\nSubject: meeting\n\nsee you there\n"),
        ("maildir/allen/sent/2.", "From: allen@enron.example\nDate: Tue, 03 Jun 2001 10:00:00 +0000\nSubject: re: meeting\n\nok\n"),
        ("maildir/allen/contacts/3.", "From: allen@enron.example\nSubject: private\n\nx\n"),
        ("docs/README", "ignore me"),
    ])
    messages = list(sample_enron_from_tar(tar, max_emails=10))
    subjects = [m for m in messages if "Subject:" in m]
    assert len(subjects) == 2  # inbox + sent; contacts and docs skipped
    assert all("Subject: meeting" in m or "re: meeting" in m for m in subjects)


def test_sample_enron_from_tar_respects_the_cap(tmp_path):
    entries = [("maildir/u%d/inbox/%d." % (u, i),
                "From: u%d@enron.example\nSubject: s%d\n\nbody\n" % (u, i))
               for u in range(3) for i in range(4)]
    tar = _enron_tar(tmp_path, entries)
    messages = list(sample_enron_from_tar(tar, max_emails=5))
    assert len(messages) == 5


def test_temporal_split_puts_older_records_in_train_per_class():
    records = [
        {"id": "new-phish", "label": 1, "date": datetime(2026, 6, 1, tzinfo=timezone.utc)},
        {"id": "old-phish", "label": 1, "date": datetime(2005, 1, 1, tzinfo=timezone.utc)},
        {"id": "new-legit", "label": 0, "date": datetime(2006, 6, 1, tzinfo=timezone.utc)},
        {"id": "old-legit", "label": 0, "date": datetime(2001, 1, 1, tzinfo=timezone.utc)},
        # Undated records must not leak into the test side.
        {"id": "undated", "label": 1, "date": None},
    ]
    train, test = temporal_split(records, train_frac=0.6)
    assert {r["id"] for r in train} == {"old-phish", "old-legit", "undated"}
    assert {r["id"] for r in test} == {"new-phish", "new-legit"}


def test_build_dataset_dedups_and_splits_and_labels(tmp_path):
    phish = [
        "From: p@x.example\nDate: Mon, 01 Jan 2005 10:00:00 +0000\nSubject: phish\n\nconfirm your password now\n",
        # near-duplicate of the first (same body, tiny edit)
        "From: p2@x.example\nDate: Tue, 02 Jan 2005 10:00:00 +0000\nSubject: phish\n\nconfirm your password now please\n",
        "From: p3@x.example\nDate: Wed, 01 Jun 2005 10:00:00 +0000\nSubject: prize\n\nyou won a lottery send your details\n",
    ]
    legit = [
        "From: l@y.example\nDate: Mon, 01 Feb 2004 10:00:00 +0000\nSubject: notes\n\nrelease notes for the team\n",
        "From: l2@y.example\nDate: Tue, 01 Feb 2005 10:00:00 +0000\nSubject: lunch\n\ngrab lunch friday at the new place\n",
    ]
    train, test, report = build_dataset(phish, legit, train_frac=0.6)
    all_records = train + test
    assert all(r["label"] == 1 for r in all_records if "phish" in r["raw"] or "lottery" in r["raw"])
    assert report["dedup"]["removed"] >= 1
    assert {r["split"] for r in train} == {"train"}
    assert {r["split"] for r in test} == {"test"}


NESTED_MULTIPART = """\
From: p@x.example
Date: Mon, 01 Jan 2005 10:00:00 +0000
Subject: nested
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="OUT"

--OUT
Content-Type: multipart/alternative; boundary="IN"

--IN
Content-Type: text/plain; charset="utf-8"

confirm your password now
--IN
Content-Type: text/html; charset="utf-8"

<html><body>confirm your password now</body></html>
--IN--
--OUT--
"""


def test_core_text_walks_nested_multiparts_instead_of_object_reprs():
    from prepare_data import _core_text
    text = _core_text(NESTED_MULTIPART)
    assert "confirm your password now" in text
    assert "email.message.Message" not in text
    assert "nested" in text  # subject included


BASE64_BODY = """\
From: p@x.example
Subject: encoded
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"
Content-Transfer-Encoding: base64

Y29uZmlybSB5b3VyIHBhc3N3b3JkIG5vdw==
"""


def test_core_text_decodes_transfer_encoded_bodies():
    from prepare_data import _core_text
    assert "confirm your password now" in _core_text(BASE64_BODY)


def test_build_dataset_keeps_the_oldest_variant_of_a_cluster():
    phish_new_first = [
        # newer variant listed first; dedup must still keep the older one
        "From: p@x.example\nDate: Tue, 02 Jan 2005 10:00:00 +0000\nSubject: phish\n\nconfirm your password now please\n",
        "From: p2@x.example\nDate: Mon, 01 Jan 2005 10:00:00 +0000\nSubject: phish\n\nconfirm your password now\n",
    ]
    legit = [
        "From: l@y.example\nDate: Mon, 01 Feb 2004 10:00:00 +0000\nSubject: notes\n\nrelease notes for the team\n",
        "From: l2@y.example\nDate: Tue, 01 Feb 2005 10:00:00 +0000\nSubject: lunch\n\ngrab lunch friday at the new place\n",
    ]
    _, _, report = build_dataset(phish_new_first, legit, train_frac=0.6)
    # one cluster kept, and the kept record is the older variant
    assert report["dedup"]["removed"] == 1


def test_empty_body_emails_are_not_deduplicated_away():
    phish = [
        # SpamAssassin-wrapped mails with no extractable body at all
        'From: a@x.example\nDate: Mon, 01 Jan 2005 10:00:00 +0000\nSubject: (unknown one)\n\n',
        'From: b@x.example\nDate: Tue, 02 Jan 2005 10:00:00 +0000\nSubject: (unknown two)\n\n',
    ]
    legit = ["From: l@y.example\nDate: Mon, 01 Feb 2004 10:00:00 +0000\nSubject: notes\n\nrelease notes for the team\n"]
    _, _, report = build_dataset(phish, legit, train_frac=0.6)
    assert report["dedup"]["removed"] == 0
