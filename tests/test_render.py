"""Behavior tests for the demo's verdict rendering (no streamlit needed)."""

from laya_phishield.pipeline import scan_email
from laya_phishield.render import render_verdict_markdown
from smoke_emails import CREDENTIAL_PHISH_EXEMPLAR


class FakeAgent:
    def system_one(self, state, questions):
        text = (state.get("subject", "") + " " + state.get("body_excerpt", "")).lower()
        phishy = "password" in text
        return {"answers": {qid: {"type": "noul", "noul": 0.85 if phishy else 0.08}
                            for qid in questions}}


def test_rendered_markdown_names_the_verdict_and_readable_reasons():
    from laya_phishield.pipeline import load_head
    verdict = scan_email(FakeAgent(), load_head(), CREDENTIAL_PHISH_EXEMPLAR)
    text = render_verdict_markdown(verdict)
    assert "PHISHING" in text
    assert "**Why:**" in text
    # Flag codes render as human sentences, not snake_case.
    assert "display name claims a brand" in text
    assert "display_name_brand_mismatch" not in text.split("Deterministic")[1]
    assert "**Top signals:**" in text


def test_rendered_markdown_survives_a_clean_legit_email():
    from laya_phishield.pipeline import load_head
    from smoke_emails import LEGIT_EMAILS
    verdict = scan_email(FakeAgent(), load_head(), LEGIT_EMAILS[0])
    text = render_verdict_markdown(verdict)
    assert "LEGITIMATE" in text
    assert "**Top signals:**" in text
