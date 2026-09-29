"""Behavior tests for the deterministic pre-pass: raw email in, structured state out."""

from laya_phishield.extract import extract_email_state

PHISH_REPLY_MISMATCH = """\
From: "PayPal Support" <service@alert-center-paypal.com>
Reply-To: paypal.alerts@mail.example.net
To: victim@corp.example
Subject: URGENT: Your account has been limited
Date: Mon, 1 Jun 2026 10:00:00 +0000
Message-ID: <123@alert-center-paypal.com>
Content-Type: text/plain; charset="utf-8"

Dear customer,

We detected unusual activity. Click the link below to restore your account:
http://192.168.13.37/verify/login.php

If you do not act within 24 hours your account will be permanently closed.

Sincerely,
PayPal Security Team
"""

LEGIT_INTERNAL = """\
From: Alice Nguyen <alice.nguyen@acme-corp.com>
To: eng-team@acme-corp.com
Subject: Release notes 1.4.2
Content-Type: text/plain; charset="utf-8"

Hi all,

Release 1.4.2 is out. Highlights: faster sync, two crash fixes, updated docs.
See the changelog for details.

Best,
Alice
"""


def test_extracts_sender_domain_and_subject_from_headers():
    email = extract_email_state(PHISH_REPLY_MISMATCH)
    assert email.state["sender_domain"] == "alert-center-paypal.com"
    assert email.state["subject"] == "URGENT: Your account has been limited"
    assert email.state["sender_display"] == "PayPal Support"


def test_flags_reply_to_domain_different_from_sender_domain():
    email = extract_email_state(PHISH_REPLY_MISMATCH)
    assert email.state["reply_to_domain"] == "mail.example.net"
    assert "reply_to_mismatch" in email.flag_codes


def test_matching_reply_to_domain_is_not_flagged():
    email = extract_email_state(LEGIT_INTERNAL)
    assert "reply_to_mismatch" not in email.flag_codes


def test_body_excerpt_contains_the_core_message_text():
    email = extract_email_state(LEGIT_INTERNAL)
    assert "Release 1.4.2 is out" in email.state["body_excerpt"]


def test_first_url_host_is_extracted_from_the_body():
    email = extract_email_state(PHISH_REPLY_MISMATCH)
    assert email.state["first_url_host"] == "192.168.13.37"


def test_link_to_a_raw_ip_address_is_flagged():
    email = extract_email_state(PHISH_REPLY_MISMATCH)
    assert "url_ip_literal" in email.flag_codes


PUNYCODE_LINK = """\
From: "Microsoft 365" <security@m1crosoft-verify.example>
To: victim@corp.example
Subject: Action required: mailbox validation
Content-Type: text/plain; charset="utf-8"

Validate your mailbox at https://xn--m1crosoft-2ve.com/owa to keep access.
"""


def test_punycode_link_host_is_flagged():
    email = extract_email_state(PUNYCODE_LINK)
    assert email.state["first_url_host"] == "xn--m1crosoft-2ve.com"
    assert "url_punycode" in email.flag_codes


def _email_from_domain(display: str, sender: str, body: str = "Hello,\n\nSee you Monday.\n") -> str:
    return (
        f'From: "{display}" <{sender}>\n'
        "To: victim@corp.example\n"
        'Subject: Weekly update\n'
        'Content-Type: text/plain; charset="utf-8"\n\n'
        f"{body}\n"
    )


# Cyrillic "а" (U+0430) instead of ASCII "a" in the first syllable.
HOMOGLYPH_PAYPAL = "pаypal.com"


def test_sender_domain_with_brand_homoglyph_is_flagged():
    email = extract_email_state(_email_from_domain("PayPal Support", f"service@{HOMOGLYPH_PAYPAL}"))
    assert "brand_lookalike_domain" in email.flag_codes


def test_genuine_brand_sender_domain_is_not_flagged():
    email = extract_email_state(_email_from_domain("PayPal Support", "service@paypal.com"))
    assert email.flag_codes == []


def test_brand_domain_embedded_in_a_longer_host_is_flagged():
    email = extract_email_state(
        _email_from_domain(
            "Account Services",
            "no-reply@verify-login.example",
            body="Restore your account at https://paypal.com.verify-login.example/restore now.\n",
        )
    )
    assert "brand_in_subdomain" in email.flag_codes


def test_display_name_brand_that_sender_domain_is_not_is_flagged():
    email = extract_email_state(_email_from_domain("Microsoft Security", "security@m1crosoft-verify.example"))
    assert "display_name_brand_mismatch" in email.flag_codes


def test_display_name_brand_matching_sender_domain_is_not_flagged():
    email = extract_email_state(_email_from_domain("Microsoft Security", "security@microsoft.com"))
    assert "display_name_brand_mismatch" not in email.flag_codes


def test_display_name_brand_on_free_mail_is_not_flagged():
    # "Apple" can be a person's name on a personal account; do not cry wolf.
    email = extract_email_state(_email_from_domain("Apple Chen", "apple.chen@gmail.com"))
    assert "display_name_brand_mismatch" not in email.flag_codes


def test_every_flag_code_has_one_readable_sentence_in_the_state():
    email = extract_email_state(PHISH_REPLY_MISMATCH)
    readable = email.state["deterministic_flags"]
    assert len(readable) == len(email.flag_codes)
    assert all(isinstance(f, str) and len(f) > 10 for f in readable)


def test_reply_to_readable_flag_names_both_domains():
    email = extract_email_state(PHISH_REPLY_MISMATCH)
    reply_flag = email.state["deterministic_flags"][email.flag_codes.index("reply_to_mismatch")]
    assert "mail.example.net" in reply_flag
    assert "alert-center-paypal.com" in reply_flag


AUTH_RESULTS_FAIL = """\
From: "Security Team" <security@accounts-verify.example>
To: victim@corp.example
Subject: Unusual sign-in
Authentication-Results: mx.corp.example;
    spf=fail (sender IP is 203.0.113.9) smtp.mailfrom=accounts-verify.example;
    dkim=fail (body hash did not verify)
Content-Type: text/plain; charset="utf-8"

Confirm it was you.
"""


def test_failed_spf_and_dkim_are_flagged_when_authentication_results_present():
    email = extract_email_state(AUTH_RESULTS_FAIL)
    assert "spf_fail" in email.flag_codes
    assert "dkim_fail" in email.flag_codes


def test_absent_authentication_results_header_is_not_flagged():
    email = extract_email_state(LEGIT_INTERNAL)
    assert "spf_fail" not in email.flag_codes
    assert "dkim_fail" not in email.flag_codes


def test_garbage_input_never_raises():
    email = extract_email_state("\x00\xff\xff garbage \x80 without headers")
    assert isinstance(email.state["body_excerpt"], str)
    assert email.flag_codes == []


HTML_HREF_PHISH = """\
From: "PayPal Security" <no-reply@paypal-secure-alert.example>
To: victim@corp.example
Subject: Restore your account
MIME-Version: 1.0
Content-Type: text/html; charset="utf-8"

<html><body><p>Dear customer, unusual activity was detected.</p>
<p><a href="http://192.168.13.37/verify/login.php">Restore your account now</a></p>
</body></html>
"""


def test_html_href_url_is_extracted_and_flagged():
    email = extract_email_state(HTML_HREF_PHISH)
    assert email.state["first_url_host"] == "192.168.13.37"
    assert "url_ip_literal" in email.flag_codes
    assert "Restore your account now" in email.state["body_excerpt"]


MULTIPART_HTML_LINK = """\
From: "Microsoft" <security@m365-verify.example>
To: victim@corp.example
Subject: Validate your mailbox
MIME-Version: 1.0
Content-Type: multipart/alternative; boundary="BOUND"

--BOUND
Content-Type: text/plain; charset="utf-8"

This message requires HTML. Open it in a web browser.

--BOUND
Content-Type: text/html; charset="utf-8"

<html><body><a href="https://xn--m1crosoft-2ve.com/owa">Validate mailbox</a></body></html>
--BOUND--
"""


def test_links_only_present_in_the_html_part_are_still_found():
    email = extract_email_state(MULTIPART_HTML_LINK)
    assert email.state["first_url_host"] == "xn--m1crosoft-2ve.com"
    assert "url_punycode" in email.flag_codes


def test_bytes_input_never_raises():
    email = extract_email_state(b"From: a@b.example\r\n\r\nbody http://1.2.3.4/x")
    assert isinstance(email.state["body_excerpt"], str)


BINARY_SINGLE_PART = """\
From: a@b.example
To: c@d.example
Subject: data
MIME-Version: 1.0
Content-Type: application/octet-stream
Content-Transfer-Encoding: base64

aHR0cDovLzE5Mi4wLjIuODgvdHJhY2s=
"""


def test_non_text_single_part_body_is_empty_not_fatal():
    email = extract_email_state(BINARY_SINGLE_PART)
    assert email.state["body_excerpt"] == ""
    assert email.flag_codes == []


def test_trailing_punctuation_after_host_still_yields_the_host():
    email = extract_email_state(_email_from_domain(
        "Notice", "n@example.org",
        body="Click http://192.168.13.37, then enter your password.",
    ))
    assert email.state["first_url_host"] == "192.168.13.37"
    assert "url_ip_literal" in email.flag_codes


def test_ipv6_literal_link_is_flagged():
    email = extract_email_state(_email_from_domain(
        "Notice", "n@example.org",
        body="Fix it at http://[2001:db8::1]/verify now.",
    ))
    assert email.state["first_url_host"] == "2001:db8::1"
    assert "url_ip_literal" in email.flag_codes


def test_reply_to_on_a_subdomain_of_the_sender_domain_is_not_a_mismatch():
    email = extract_email_state(
        'From: "Google" <no-reply@accounts.google.example>\n'
        "Reply-To: noreply@google.example\n"
        'Subject: hi\n'
        'Content-Type: text/plain; charset="utf-8"\n\nhello\n'
    )
    assert "reply_to_mismatch" not in email.flag_codes


def test_reply_to_on_an_unrelated_domain_is_still_a_mismatch():
    email = extract_email_state(
        'From: "Google" <no-reply@accounts.google.example>\n'
        "Reply-To: noreply@mail.example.net\n"
        'Subject: hi\n'
        'Content-Type: text/plain; charset="utf-8"\n\nhello\n'
    )
    assert "reply_to_mismatch" in email.flag_codes


def test_genuine_brand_regional_domains_are_not_flagged():
    for genuine in ("google.com.au", "apple.com.cn", "amazon.com.mx", "amazon.co.uk"):
        email = extract_email_state(_email_from_domain("Store", f"noreply@{genuine}"))
        assert email.flag_codes == [], genuine


def test_brand_prefix_before_unrelated_domain_is_still_flagged():
    email = extract_email_state(_email_from_domain(
        "Notice", "n@example.org",
        body="Restore at https://paypal.com.verify-login.example/restore",
    ))
    assert "brand_in_subdomain" in email.flag_codes


FORWARDED_PHISH_INSIDE_LEGIT = """\
From: "Alice Nguyen" <alice.nguyen@acme-corp.example>
To: bob@acme-corp.example
Subject: Fwd: look at this
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="MIX"

--MIX
Content-Type: text/plain; charset="utf-8"

Forwarding below.

--MIX
Content-Type: message/rfc822

From: phish@evil.example
Subject: urgent
Content-Type: text/plain

Click http://10.0.0.1/x now.
--MIX--
"""


def test_forwarded_attachment_body_does_not_leak_into_the_cover_email():
    email = extract_email_state(FORWARDED_PHISH_INSIDE_LEGIT)
    assert email.state["body_excerpt"].startswith("Forwarding below.")
    assert email.state["first_url_host"] == ""
    assert email.flag_codes == []


def test_homoglyph_url_written_directly_in_the_body_is_detected():
    email = extract_email_state(_email_from_domain(
        "Notice", "n@example.org",
        # Cyrillic "a" inside the host, written as literal text.
        body="Confirm at http://pаypal.com/verify to keep access.",
    ))
    assert "brand_lookalike_domain" in email.flag_codes


def test_punycode_host_decoding_to_a_brand_is_flagged_as_lookalike():
    email = extract_email_state(_email_from_domain(
        "Notice", "n@example.org",
        body="Sign in at http://xn--80ak6aa92e.com/apple to continue.",
    ))
    assert "url_punycode" in email.flag_codes
    assert "brand_lookalike_domain" in email.flag_codes
