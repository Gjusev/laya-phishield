"""Human-facing rendering of a Verdict (markdown), shared by the demo UI."""

from __future__ import annotations

from typing import List, Tuple

__all__ = ["render_verdict_markdown"]

_REASON_LABELS = {
    "reply_to_mismatch": "Reply-To goes to a different domain",
    "url_ip_literal": "link points to a raw IP address",
    "url_punycode": "link host uses punycode",
    "brand_lookalike_domain": "lookalike brand domain",
    "brand_in_subdomain": "brand domain embedded in the link host",
    "display_name_brand_mismatch": "display name claims a brand it does not own",
    "spf_fail": "SPF check failed",
    "dkim_fail": "DKIM check failed",
}


def render_verdict_markdown(verdict) -> str:
    """Markdown block for one verdict: verdict line, reasons, signals, flags."""
    lines = ["**%s** — score %.3f" % (verdict.label.upper(), verdict.score)]
    lines.append("")
    lines.append("**Why:**")
    for name, value in verdict.reasons:
        label = _REASON_LABELS.get(name, name.replace("_", " "))
        lines.append("- %s (%.2f)" % (label, value))
    if verdict.flags:
        lines.append("")
        lines.append("**Deterministic checks that fired:**")
        for code in verdict.flags:
            lines.append("- %s" % _REASON_LABELS.get(code, code.replace("_", " ")))
    lines.append("")
    top = sorted(verdict.signals.items(), key=lambda kv: kv[1], reverse=True)[:3]
    lines.append("**Top signals:** " + ", ".join("%s %.2f" % kv for kv in top))
    return "\n".join(lines)
