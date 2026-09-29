# laya-phishield

> Explainable phishing detection: eight atomic signals from a local decision model plus header/URL heuristics, combined by a classical head with per-signal reasons.

Status: early development. Built on [laya](https://github.com/NandhaKishorM/laya),
the open-source System 1 decision engine (Apache 2.0).

## Why

- A forced phish/legit choice is the wide question that System 1 models answer badly; eight narrow yes/no signals is the pattern the ecosystem's field lessons recommend, and it yields explanations for free.
- Every verdict names its reasons (per-signal probabilities plus deterministic flags), which is what risk and fraud teams actually need to operate.

## Roadmap

- [ ] Deterministic pre-pass: header checks, reply-to mismatch, URL and punycode extraction, brand homoglyphs
- [ ] Eight atomic signals (nouls) over a structured email state
- [ ] Logistic combination head trained on public data (Nazario phishing + Enron legitimate), with MinHash dedup and temporal split
- [ ] Eval: AUC and FPR at 95% TPR vs keyword baseline, forced-choice baseline and an LLM baseline (cost included)
- [ ] CLI for mbox/eml batches, HTTP API, and a paste-an-email demo

## Development setup

Requires Python 3.10+ and [uv](https://docs.astral.sh/uv/) (or any venv + pip):

```bash
uv venv
uv pip install -e ".[dev]"
pytest
```

## License

Apache 2.0. See [LICENSE](LICENSE).
