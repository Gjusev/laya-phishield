"""Streamlit demo: paste an email, get the verdict with its reasons.

    uv run pip install -e ".[demo]"
    uv run streamlit run app.py

The model loads lazily on the first scan; the heavy imports (torch,
transformers) never happen until then.
"""

from __future__ import annotations

import sys

import streamlit as st

sys.path.insert(0, "src")

from laya_phishield.pipeline import load_head, scan_email  # noqa: E402
from laya_phishield.render import render_verdict_markdown  # noqa: E402

st.set_page_config(page_title="laya-phishield", page_icon="🛡️")
st.title("laya-phishield — explainable phishing detection")
st.caption("Eight atomic signals from a local decision model plus deterministic "
           "header/URL checks, combined by a logistic head. Every verdict names "
           "its reasons.")

EXAMPLE = """\
From: "PayPal Security" <no-reply@paypal-account-verify.example>
To: customer@corp.example
Subject: URGENT: Your account has been limited
Content-Type: text/plain; charset="utf-8"

Dear Customer,

We detected unusual activity on your account. Confirm your password at
https://paypal-account-verify.example/verify within 24 hours or your
account will be permanently closed.

PayPal Security Team
"""

raw = st.text_area("Paste a raw email (headers + body)", height=300, value=EXAMPLE)

if st.button("Scan", type="primary") and raw.strip():
    with st.spinner("Loading the local decision model on first scan..."):
        if "agent" not in st.session_state:
            import laya

            st.session_state.agent = laya.Agent()
        if "head" not in st.session_state:
            st.session_state.head = load_head()
    verdict = scan_email(st.session_state.agent, st.session_state.head, raw)
    if verdict.label == "phishing":
        st.error(render_verdict_markdown(verdict))
    else:
        st.success(render_verdict_markdown(verdict))
    with st.expander("All eight signals"):
        for name, value in sorted(verdict.signals.items(), key=lambda kv: -kv[1]):
            st.progress(min(value, 1.0), text="%s — %.2f" % (name, value))
