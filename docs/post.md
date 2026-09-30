# Explainable phishing detection: eight atomic signals from a local decision model, combined by a classical head

> Draft launch post. Every number below is measured and reproducible from
> the repo (`evals/results.json`); nothing is invented or projected.

When you ask a small decision model one wide question — "is this email
phishing or legitimate?" — you get the worst of both worlds: a shaky score
and no explanation. Wide questions are exactly where System 1-style models
are least reliable (their own docs carry the cautionary tale: asked about
"do NOT cancel", the model answers `cancel_account` with 0.9998), and a
bare phish/legit probability gives a fraud analyst nothing to act on.

So I built the opposite: **eight narrow yes/no questions** answered by a
local decision model in a single forward pass, plus a deterministic
pre-pass for what semantics can't see, combined by a logistic regression
that outputs a score *and its reasons*. The project is
[laya-phishield](https://github.com/Gjusev/laya-phishield), built on the
open-source [laya](https://github.com/NandhaKishorM/laya) System 1 decision
engine — CPU inference, ~35 ms per decision, no API bill.

## The eight signals

Each is one atomic noul over a structured email state (subject, sender
domains, first link host, body excerpt, readable deterministic flags):

- `asks_credentials` — confirm your password to restore access?
- `urgency_pressure` — act within hours or else?
- `payment_gift_request` — pay, wire, gift cards, crypto?
- `brand_impersonation` — borrows a brand whose domain isn't the sender?
- `requests_pii` — send ID numbers, card numbers, birth dates?
- `too_good_to_be_true` — lottery wins nobody entered?
- `suspicious_instructions` — keep it secret, bypass procedure?
- `external_link_risk` — link host unrelated to the claimed sender?

Deterministic checks feed the model readable statements instead of opaque
URLs: reply-to mismatches, IP-literal and punycode link hosts, homoglyph
brand domains (Cyrillic `pаypal.com`), brands embedded inside link hosts,
display-name/brand mismatches, SPF/DKIM failures. The exact per-signal
contract lives in the repo's `data/signals_schema.md`, including each
signal's out-of-scope boundaries and known hard negatives.

## Wording is an engineering surface

The interesting part of this project was discovering that question wording
is measurable infrastructure. Two examples:

- My first `asks_credentials` wording scored **0.59** on a textbook
  credential phish. Rewriting it to one short positively-phrased sentence
  (matching laya's own preset style, no criteria text, no field
  enumerations) brought it to **0.92** as the top reason — measured on a
  real checkpoint, in-batch, same state.
- The classic negation trap held up: an IT-security drill email saying
  "we never ask for your password by email" scores **0.11** on
  `asks_credentials`. A wording variant that chased a higher score on
  another email broke this hard negative to 0.70 — and was rejected.
  Positively-phrased narrow questions are not style, they're the fix for a
  documented failure mode.

## The eval (and the two bugs that matter in this field)

Dataset: Nazario phishing corpus vs a legitimate Enron sample. Two things
make phishing evals lie, so both are handled and reported:

1. **Near-duplicate leakage.** The same campaign email lands on both sides
   of the split and every model looks brilliant. MinHash + LSH dedup across
   classes removed **95 near-duplicates of 700** (92 within-phishing, 3
   within-legitimate, 0 cross-class) before the split.
2. **Accuracy on unbalanced classes.** Reported instead: AUC and FPR at 95%
   TPR, on a per-class **temporal** split (train on the oldest 70%, test on
   the newest 30% — undated records never leak into test).

Measured on the test split (n=183, temporal):

| | keyword | forced-choice laya | composite (8 signals + logit) |
|---|---|---|---|
| AUC | 0.5947 | 0.9444 | **0.9531** |
| Precision / Recall @ 0.5 | 1.000 / 0.051 | 0.902 / 0.590 | **0.913 / 0.808** |
| FPR @ 95% TPR | 1.000 | **0.124** | 0.210 |

The composite beats the forced-choice — same model, same checkpoint — by
**+0.9 pt AUC** and **+21.8 pt recall** at the operating point. And the
honest limit, because it matters more than the win: at the 95%-recall tail
the forced-choice ranks better (0.124 vs 0.210 FPR). If your product runs
at maximum recall, the wide question is still competitive there; at
practical thresholds, decomposition wins and hands you reasons for free.

Ablation (zero one signal, re-run 3-fold CV over n=605): no single signal
costs more than 0.4 pt AUC to remove. The architecture is redundant by
design — and the signals whose removal costs nothing at the ranking level
still earn their place by naming *why* in every verdict.

## Why this is the interesting pattern

The general shape — **semantic signals from a small local model as
features for a classical head** — transfers anywhere you need cheap,
explainable, per-item risk scores: support triage, content moderation,
payment review. The classical head gives you calibrated operating points
and per-feature attribution; the local model gives you the semantics at
CPU prices; the decomposition gives you auditability ("flagged for:
asks_credentials 0.93, reply-to mismatch, urgency 0.87") that neither an
LLM call nor a keyword regex can produce on its own.

Reproduce everything:

```bash
git clone https://github.com/Gjusev/laya-phishield
cd laya-phishield
uv venv && uv pip install -e ".[dev]"
pytest                    # fast suite, model mocked
uv run pytest -m slow     # real-checkpoint acceptance run
uv run laya-phishield scan your_inbox.mbox --json
```
