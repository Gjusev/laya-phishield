"""Behavior tests for the batch CLI (agent injected, no checkpoint)."""

import json

from laya_phishield.cli import main, read_emails
from smoke_emails import CREDENTIAL_PHISH_EXEMPLAR, LEGIT_EMAILS, PHISHING_EMAILS


class FakeAgent:
    """Phishing-shaped states light up the signals; plain mail stays dark."""

    def system_one(self, state, questions):
        text = (state.get("subject", "") + " " + state.get("body_excerpt", "")).lower()
        phishy = "password" in text or "account has been" in text
        return {"answers": {qid: {"type": "noul", "noul": 0.85 if phishy else 0.08}
                            for qid in questions}}


def test_read_emails_handles_eml_mbox_and_jsonl(tmp_path):
    eml = tmp_path / "one.eml"
    eml.write_text(CREDENTIAL_PHISH_EXEMPLAR, encoding="utf-8")

    mbox = tmp_path / "batch.mbox"
    mbox.write_text(
        "From a@x.example Mon Jun 01 10:00:00 2026\n" + PHISHING_EMAILS[1] +
        "From b@y.example Tue Jun 02 10:00:00 2026\n" + LEGIT_EMAILS[0],
        encoding="utf-8")

    jsonl = tmp_path / "records.jsonl"
    jsonl.write_text(
        json.dumps({"raw": LEGIT_EMAILS[1]}) + "\n" +
        json.dumps({"raw": PHISHING_EMAILS[2]}) + "\n",
        encoding="utf-8")

    assert len(read_emails(str(eml))) == 1
    assert len(read_emails(str(mbox))) == 2
    assert len(read_emails(str(jsonl))) == 2


def test_cli_scans_files_and_prints_one_line_per_email(tmp_path, capsys):
    eml = tmp_path / "mail.eml"
    eml.write_text(CREDENTIAL_PHISH_EXEMPLAR, encoding="utf-8")
    code = main(["scan", str(eml)], agent=FakeAgent())
    out = capsys.readouterr().out
    assert code == 0
    assert "PHISHING" in out
    assert "1 email" in out


def test_cli_json_mode_emits_one_json_object_per_email(tmp_path, capsys):
    eml = tmp_path / "mail.eml"
    eml.write_text(CREDENTIAL_PHISH_EXEMPLAR, encoding="utf-8")
    other = tmp_path / "legit.eml"
    other.write_text(LEGIT_EMAILS[0], encoding="utf-8")
    code = main(["scan", str(eml), str(other), "--json"], agent=FakeAgent())
    lines = [json.loads(l) for l in capsys.readouterr().out.splitlines()]
    assert code == 0
    assert len(lines) == 2
    assert {l["label"] for l in lines} == {"phishing", "legitimate"}
    assert all("reasons" in l and "flags" in l for l in lines)


def test_cli_respects_the_limit_option(tmp_path, capsys):
    mbox = tmp_path / "batch.mbox"
    mbox.write_text(
        "From a@x.example Mon Jun 01 10:00:00 2026\n" + LEGIT_EMAILS[0] +
        "From b@y.example Tue Jun 02 10:00:00 2026\n" + LEGIT_EMAILS[1],
        encoding="utf-8")
    main(["scan", str(mbox), "--limit", "1", "--json"], agent=FakeAgent())
    assert len(capsys.readouterr().out.splitlines()) == 1
