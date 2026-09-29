"""Deterministic pre-pass: parse a raw email into a structured state for the
semantic signals plus machine-readable flag codes.

This module never calls a model and never touches the network. It is pure
string/header work so it stays fast, hermetic and testable, and so every
obfuscated artifact (IP-literal URLs, punycode hosts, homoglyph domains) is
normalized into readable statements the decision model can actually weigh.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from email import message_from_string
from email.message import Message
from email.policy import default as default_policy
from email.utils import parseaddr
from typing import List, Optional, Tuple
from urllib.parse import urlsplit

__all__ = ["ExtractedEmail", "extract_email_state"]

_BODY_EXCERPT_MAX = 1500

# Trailing sentence punctuation is stripped from URL matches before parsing,
# so "click http://1.2.3.4, then..." still yields the bare host. Brackets are
# allowed so IPv6 literals parse; the closing "]" ends the match.
_URL_RE = re.compile(r"https?://[^\s<>\"')\]]+", re.IGNORECASE)
_URL_TRAILING_PUNCT = ".,;:!?\"'}]"
_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_TAG_RE = re.compile(r"<[^>]+>")
_HREF_RE = re.compile(r"""(?:href|src)\s*=\s*["']([^"']+)["']""", re.IGNORECASE)

# Frequently impersonated brands, token -> registrable domain.
BRAND_DOMAINS = {
    "paypal": "paypal.com",
    "microsoft": "microsoft.com",
    "apple": "apple.com",
    "amazon": "amazon.com",
    "google": "google.com",
    "netflix": "netflix.com",
    "facebook": "facebook.com",
    "instagram": "instagram.com",
    "whatsapp": "whatsapp.com",
    "linkedin": "linkedin.com",
    "dropbox": "dropbox.com",
    "adobe": "adobe.com",
    "dhl": "dhl.com",
    "fedex": "fedex.com",
    "ups": "ups.com",
    "bank of america": "bankofamerica.com",
    "wells fargo": "wellsfargo.com",
    "chase": "chase.com",
    "hsbc": "hsbc.com",
    "coinbase": "coinbase.com",
    "binance": "binance.com",
}

# Labels a brand itself may legitimately use beyond its .com: regional
# registrable domains (google.com.au, amazon.co.uk, dhl.de) and country
# codes. Conservative by design: it only accepts hosts whose every label
# after the brand token is a suffix-like label.
_SUFFIX_TOKENS = {"com", "org", "net", "edu", "gov", "mil", "co", "ac", "io"}

# Personal-mail providers where a brand word in the display name is more
# likely a person's name ("Apple Chen") than an impersonation.
FREE_MAIL_DOMAINS = {
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com",
    "msn.com", "yahoo.com", "icloud.com", "aol.com", "proton.me",
    "protonmail.com", "mail.ru", "yandex.ru", "gmx.de", "web.de",
}

# Cyrillic/Greek letters that render like ASCII ones; used to unmask
# homoglyph domains. Digit substitutions (1<->l, 0<->o) are deliberately
# not folded: too many legitimate domains contain digits.
_CONFUSABLES = str.maketrans({
    # Cyrillic lower-case
    "а": "a", "е": "e", "о": "o", "р": "p",
    "с": "c", "у": "y", "х": "x", "і": "i",
    "ѕ": "s", "ј": "j", "ӏ": "l", "ɑ": "a",
    # Greek lower-case
    "α": "a", "ι": "i", "κ": "k", "ο": "o",
    "ρ": "p", "τ": "t", "υ": "u", "ν": "v",
    # Cyrillic upper-case
    "А": "A", "В": "B", "Е": "E", "К": "K",
    "М": "M", "Н": "H", "О": "O", "Р": "P",
    "С": "C", "Т": "T", "У": "Y", "Х": "X",
    # Latin small script f / IPA g lookalikes
    "ɓ": "f", "ɡ": "g",
})


def _fold_confusables(host: str) -> str:
    """Fold Cyrillic/Greek lookalikes to ASCII for brand comparison."""
    return host.translate(_CONFUSABLES).lower()


def _domain(address: Optional[str]) -> Optional[str]:
    """Return the lowercased domain of an email address, or None."""
    if not address:
        return None
    _, addr = parseaddr(address)
    _, _, domain = addr.rpartition("@")
    return domain.strip().strip("[]").lower() or None


def _part_text(msg: Message) -> str:
    """Content of one part as text, or "" for parts that are not text.

    The payload is read undecoded for plain transfer encodings: with a str
    message input, `get_content()`/`get_payload(decode=True)` re-encode the
    payload through ASCII with backslash escapes, which silently turns a
    real Cyrillic homoglyph host into the literal text "\\u0430". Only
    base64 and quoted-printable parts round-trip through bytes.
    """
    if msg.get_content_maintype() != "text":
        return ""
    cte = (msg.get("Content-Transfer-Encoding") or "").lower().strip()
    try:
        if cte in ("base64", "quoted-printable"):
            data = msg.get_payload(decode=True) or b""
            charset = msg.get_content_charset() or "utf-8"
            return data.decode(charset, "replace")
        payload = msg.get_payload()
        return payload if isinstance(payload, str) else ""
    except Exception:
        return ""


def _body_text(msg: Message) -> str:
    """Plain-text rendering: prefer text/plain parts, strip tags from HTML.

    Attached messages (message/rfc822) are skipped: a forwarded email inside
    a cover message is a different email, not part of this one's body.
    """
    plain_parts, html_parts = [], []
    stack = [msg]
    while stack:
        part = stack.pop(0)
        if part.get_content_type() == "message/rfc822":
            continue
        if part.is_multipart():
            stack.extend(part.get_payload())
            continue
        text = _part_text(part)
        if not text:
            continue
        if part.get_content_type() == "text/plain":
            plain_parts.append(text)
        elif part.get_content_type() == "text/html":
            html_parts.append(_TAG_RE.sub(" ", text))
    if plain_parts:
        return "\n".join(plain_parts)
    return "\n".join(html_parts)


def _extract_urls(msg: Message) -> List[str]:
    """All http(s) URLs in the message, href/src attributes included.

    HTML phishes keep the hostile host in the href with benign anchor text,
    so attribute URLs are collected from raw HTML parts before tags are
    stripped; plain-text URLs are collected as written.
    """
    urls: List[str] = []
    stack = [msg]
    while stack:
        part = stack.pop(0)
        if part.get_content_type() == "message/rfc822":
            continue
        if part.is_multipart():
            stack.extend(part.get_payload())
            continue
        if part.get_content_type() == "text/html":
            raw = _part_text(part)
            urls.extend(u for u in _HREF_RE.findall(raw) if u.startswith(("http://", "https://")))
        elif part.get_content_maintype() == "text":
            text = _part_text(part)
            urls.extend(_URL_RE.findall(text))
    return urls


def _url_host(url: str) -> Optional[str]:
    """Return the lowercased host of a URL string, or None if unparseable."""
    url = url.rstrip(_URL_TRAILING_PUNCT)
    if url.count("[") == url.count("]") + 1:
        url += "]"  # regex cut at the closing bracket of an IPv6 literal
    try:
        host = urlsplit(url).hostname
    except ValueError:
        return None
    return host.strip(".").lower() if host else None


def _is_genuine_brand_host(host: str) -> bool:
    """True when the host is a known brand's own domain.

    Accepts the brand's registrable domain, its subdomains, and its regional
    domains (google.com.au, amazon.co.uk, dhl.de): every label after the
    brand token must be a suffix-like label.
    """
    for token, brand in BRAND_DOMAINS.items():
        if host == brand or host.endswith("." + brand):
            return True
        labels = host.split(".")
        if (
            labels[0] == token
            and len(labels) > 1
            and all(l in _SUFFIX_TOKENS or len(l) == 2 for l in labels[1:])
        ):
            return True
    return False


def _decoded_punycode(host: str) -> Optional[str]:
    """Host with xn-- labels decoded (unicode form), or None if none decode."""
    if "xn--" not in host:
        return None
    labels = []
    decoded_any = False
    for label in host.split("."):
        if label.startswith("xn--"):
            try:
                labels.append(label.encode("ascii").decode("idna"))
                decoded_any = True
                continue
            except (UnicodeError, ValueError):
                return None
        labels.append(label)
    return ".".join(labels) if decoded_any else None


def _host_findings(host: Optional[str]) -> List[Tuple[str, str]]:
    """(flag code, offending host) pairs for brand tricks on one hostname."""
    if not host or _is_genuine_brand_host(host):
        return []
    flags: List[Tuple[str, str]] = []
    folded = _fold_confusables(host)
    if _is_genuine_brand_host(folded):
        # The host only looks like the brand after unmasking lookalikes.
        return [("brand_lookalike_domain", host)]
    decoded = _decoded_punycode(host)
    if decoded and _is_genuine_brand_host(_fold_confusables(decoded)):
        # The punycode form decodes to a brand (homoglyph) domain.
        return [("brand_lookalike_domain", host)]
    if any(
        folded.startswith(brand + ".") or ("." + brand + ".") in folded
        for brand in BRAND_DOMAINS.values()
    ):
        # A brand domain embedded before the real one ("paypal.com.evil.net").
        return [("brand_in_subdomain", host)]
    return flags


def _display_name_findings(display: str, sender_domain: Optional[str]) -> List[Tuple[str, str]]:
    """(flag code, brand token) pairs for a display name claiming a foreign brand."""
    if not display or not sender_domain or sender_domain in FREE_MAIL_DOMAINS:
        return []
    for token, brand in BRAND_DOMAINS.items():
        if re.search(r"(?<!\w)%s(?!\w)" % re.escape(token), display, re.IGNORECASE):
            if not _is_genuine_brand_host(sender_domain):
                return [("display_name_brand_mismatch", token)]
    return []


def _punycode_decoded(host: str) -> Optional[str]:
    """Decode the first xn-- label of a host for humans, or None."""
    decoded = _decoded_punycode(host)
    if not decoded:
        return None
    return next(l for l in decoded.split(".") if l not in ("com", "org", "net"))


_FLAG_SENTENCES = {
    "url_ip_literal": "the first link points to a raw IP address instead of a domain name",
    "spf_fail": "the SPF check failed in the Authentication-Results header",
    "dkim_fail": "the DKIM check failed in the Authentication-Results header",
}


def _render_flag(code: str, detail: str, *, sender_domain: str, reply_to_domain: str) -> str:
    """One readable sentence per flag code; the model reads these verbatim."""
    if code == "reply_to_mismatch":
        return (
            f"the Reply-To domain {reply_to_domain} differs from the sender "
            f"domain {sender_domain}, so replies would go to another domain"
        )
    if code == "url_punycode":
        decoded = _punycode_decoded(detail)
        extra = f", which decodes to '{decoded}'" if decoded else ""
        return (
            f"a link host contains punycode ({detail}), commonly used to "
            f"disguise lookalike domains{extra}"
        )
    if code == "brand_lookalike_domain":
        return (
            f"the host '{detail}' imitates a well-known brand domain using "
            f"lookalike characters"
        )
    if code == "brand_in_subdomain":
        return (
            f"the host '{detail}' embeds a well-known brand domain in front "
            f"of an unrelated domain"
        )
    if code == "display_name_brand_mismatch":
        return (
            f"the sender display name claims the brand '{detail}' but the "
            f"sender domain does not belong to it"
        )
    return _FLAG_SENTENCES.get(code, code.replace("_", " "))


def _same_organization(domain_a: Optional[str], domain_b: Optional[str]) -> bool:
    """True when one domain is the other or a subdomain of it."""
    if not domain_a or not domain_b:
        return False
    return (
        domain_a == domain_b
        or domain_a.endswith("." + domain_b)
        or domain_b.endswith("." + domain_a)
    )


@dataclass
class ExtractedEmail:
    """Structured email state: what the semantic signals read, plus flag codes.

    `state` is the dict handed to the laya signals (readable strings only);
    `flag_codes` are the stable machine keys the Phase 2 combiner uses as
    features alongside the eight signal probabilities.
    """

    state: dict = field(default_factory=dict)
    flag_codes: List[str] = field(default_factory=list)


def extract_email_state(raw) -> ExtractedEmail:
    """Extract the structured state and deterministic flags from a raw email.

    Malformed input never raises: an unparseable email degrades to an
    almost-empty state with no flags rather than taking the pipeline down.
    """
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", "replace")
    raw = raw or ""

    try:
        msg = message_from_string(raw, policy=default_policy)
        from_header = msg.get("From", "")
        sender_display, sender_addr = parseaddr(str(from_header))
        sender_domain = _domain(sender_addr)
        reply_to_domain = _domain(str(msg.get("Reply-To", "")))
        subject = str(msg.get("Subject", "") or "").strip()
        auth_results = str(msg.get("Authentication-Results", "") or "")
        body = _body_text(msg).strip()
        urls = _extract_urls(msg)
    except Exception:
        # Header parsing itself failed; fall back to a bare-text reading.
        sender_display, sender_domain = "", None
        reply_to_domain, subject, auth_results = "", "", ""
        body = raw.strip()
        urls = _URL_RE.findall(body)

    hosts = [h for h in (_url_host(u) for u in urls) if h]
    first_url_host = hosts[0] if hosts else None

    findings: List[Tuple[str, str]] = []  # (flag code, detail) in report order

    def add(code: str, detail: str = "") -> None:
        if code not in (c for c, _ in findings):
            findings.append((code, detail))

    if sender_domain and reply_to_domain and not _same_organization(sender_domain, reply_to_domain):
        add("reply_to_mismatch")
    if first_url_host and (_IPV4_RE.match(first_url_host) or ":" in first_url_host):
        add("url_ip_literal", first_url_host)
    punycode_host = next(
        (h for h in hosts if "xn--" in h), None
    )
    if punycode_host:
        add("url_punycode", punycode_host)
    for host in [sender_domain] + hosts:
        for code, detail in _host_findings(host):
            add(code, detail)
    for code, detail in _display_name_findings(sender_display, sender_domain):
        add(code, detail)
    auth_lower = auth_results.lower()
    if "spf=fail" in auth_lower:
        add("spf_fail")
    if "dkim=fail" in auth_lower:
        add("dkim_fail")

    flag_codes = [code for code, _ in findings]
    readable_flags = [
        _render_flag(
            code,
            detail,
            sender_domain=sender_domain or "",
            reply_to_domain=reply_to_domain or "",
        )
        for code, detail in findings
    ]

    state = {
        "subject": subject,
        "sender_display": (sender_display or "").strip(),
        "sender_domain": sender_domain or "",
        "reply_to_domain": reply_to_domain or "",
        "first_url_host": first_url_host or "",
        "body_excerpt": body[:_BODY_EXCERPT_MAX],
        "deterministic_flags": readable_flags,
    }
    return ExtractedEmail(state=state, flag_codes=flag_codes)
