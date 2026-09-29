# laya-phishield

> Explainable phishing detection: eight atomic signals from a local decision model plus header/URL heuristics, combined by a classical head with per-signal reasons.

Status: early development. Built on [laya](https://github.com/NandhaKishorM/laya),
the open-source System 1 decision engine (Apache 2.0).

## Why

- A forced phish/legit choice is the wide question that System 1 models answer badly; eight narrow yes/no signals is the pattern the ecosystem's field lessons recommend, and it yields explanations for free.
- Every verdict names its reasons (per-signal probabilities plus deterministic flags), which is what risk and fraud teams actually need to operate.

## Roadmap

- [x] Deterministic pre-pass: header checks, reply-to mismatch, URL and punycode extraction, brand homoglyphs
- [x] Eight atomic signals (nouls) over a structured email state
- [ ] Logistic combination head trained on public data (Nazario phishing + Enron legitimate), with MinHash dedup and temporal split
- [ ] Eval: AUC and FPR at 95% TPR vs keyword baseline, forced-choice baseline and an LLM baseline (cost included)
- [ ] CLI for mbox/eml batches, HTTP API, and a paste-an-email demo

## How it works

1. **Deterministic pre-pass** (`laya_phishield/extract.py`): parses the raw
   email with the stdlib, extracts subject, sender display/domain, reply-to
   domain, first URL host and a plain-text body excerpt, and raises
   deterministic flags — reply-to mismatch, IP-literal or punycode link
   hosts, brand homoglyph domains, brand-in-subdomain hosts, display-name
   brand mismatch, SPF/DKIM failures. Flags become readable statements the
   model can weigh, so obfuscated artifacts are never lost as opaque URLs.
2. **Eight atomic signals** (`laya_phishield/signals.py`): one `system_one`
   call to the local laya decision model answers eight narrow yes/no
   questions over the structured state — `asks_credentials`,
   `urgency_pressure`, `payment_gift_request`, `brand_impersonation`,
   `requests_pii`, `too_good_to_be_true`, `suspicious_instructions`,
   `external_link_risk`. The exact per-signal contract lives in
   [`data/signals_schema.md`](data/signals_schema.md). Questions are phrased
   in the positive: negated/forced-choice prompts are the documented failure
   mode this decomposition avoids.

Phase 2 trains the logistic combination head over the eight probabilities
plus the flag codes, with reasons ordered by score contribution.

## Testing

`pytest` runs the fast suite only: the laya agent is mocked with a
deterministic fake, so no checkpoint is ever downloaded. The smoke run over
a fixed corpus of 20 phishing + 20 legitimate emails uses a real checkpoint
and is opt-in:

```bash
uv run pytest -m slow
```

## Development setup

Requires Python 3.10+ and [uv](https://docs.astral.sh/uv/) (or any venv + pip):

```bash
uv venv
uv pip install -e ".[dev]"
pytest
```

## License

Apache 2.0. See [LICENSE](LICENSE).
