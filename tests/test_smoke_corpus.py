"""Fast checks on the hand-written smoke corpus itself (no model involved)."""

from laya_phishield import extract_email_state
from smoke_emails import (
    CREDENTIAL_PHISH_EXEMPLAR,
    LEGIT_EMAILS,
    PHISHING_EMAILS,
)


def test_corpus_sizes_are_20_and_20():
    assert len(PHISHING_EMAILS) == 20
    assert len(LEGIT_EMAILS) == 20


def test_extraction_handles_every_corpus_email_without_raising():
    for raw in PHISHING_EMAILS + LEGIT_EMAILS:
        email = extract_email_state(raw)
        assert email.state["subject"], raw[:60]
        assert email.state["body_excerpt"], raw[:60]


def test_credential_phish_exemplar_carries_the_expected_deterministic_flags():
    email = extract_email_state(CREDENTIAL_PHISH_EXEMPLAR)
    assert email.state["first_url_host"] == "paypal-account-verify.example"
    assert "display_name_brand_mismatch" in email.flag_codes


def test_legit_emails_carry_their_expected_authentication_results():
    from laya_phishield import extract_email_state
    github = extract_email_state(LEGIT_EMAILS[3])
    assert "spf_fail" not in github.flag_codes
    amazon = extract_email_state(PHISHING_EMAILS[12])
    assert "spf_fail" in amazon.flag_codes
    assert "dkim_fail" in amazon.flag_codes
