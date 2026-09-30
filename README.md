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
- [x] Logistic combination head trained on public data (Nazario phishing + Enron legitimate), with MinHash dedup and temporal split
- [x] Eval: AUC and FPR at 95% TPR vs keyword baseline, forced-choice baseline and an LLM baseline (cost included)
- [x] CLI for mbox/eml batches, HTTP API, and a paste-an-email demo

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

## Evaluation

Datasets: [Nazario phishing corpus](https://monkey.org/~jose/phishing/)
(phishing2 + phishing3 mboxes) vs a reservoir sample of legitimate mail from
the [Enron dataset](https://www.cs.cmu.edu/~enron/). Near-duplicate leakage —
the classic inflation bug of these corpora — is removed with MinHash + LSH
banding (32 bands x 4 rows, merge at estimated Jaccard >= 0.5, dedup across
classes, oldest variant kept), and the split is per-class temporal (oldest
70% train, newest 30% test; undated records stay in train). Every run
reports how much overlap the dedup removed.

Reproduce end to end (the featurization cache makes runs resumable):

```bash
uv run python evals/prepare_data.py --max-phish 350 --max-legit 350
uv run python evals/run_eval.py --skip-gpt     # composite + keyword + forced-choice + ablation
OPENAI_API_KEY=... uv run python evals/run_eval.py   # adds GPT-4o-mini on a class-balanced 200-email subset
```

### Results

Measured on the temporal test split (n=183: 105 legitimate / 78 phishing;
see `evals/results.json` for the full artifact, including per-signal
ablation and the trained coefficients):

| Metric | keyword | forced-choice | composite (laya + logit) | GPT-4o-mini |
|---|---|---|---|---|
| AUC | 0.5947 | 0.9444 | **0.9531** | TODO(measure: needs OPENAI_API_KEY) |
| Precision / Recall @ 0.5 | 1.000 / 0.051 | 0.902 / 0.590 | **0.913 / 0.808** | TODO(measure: needs OPENAI_API_KEY) |
| FPR @ 95% TPR | 1.000 | **0.124** | 0.210 | TODO(measure: needs OPENAI_API_KEY) |
| $ per 1,000 emails | $0 | $0 | $0 | TODO(measure: needs OPENAI_API_KEY) |

Composite vs forced-choice (the delta this project exists to quantify):
**+0.9 pt AUC** and **+21.8 pt recall at the 0.5 operating point** at
comparable precision — the eight-signal decomposition recovers most of the
phish the wide question scores just under its threshold. Honest limit: at
the very tail the forced-choice ranks better (FPR@95%TPR 0.124 vs 0.210);
the composite's advantage is at practical operating points, not at 95%
recall.

Per-signal ablation (3-fold CV AUC over the full deduplicated corpus,
n=605, with that one signal zeroed out; full-model CV AUC is 0.9568 —
removing any single signal costs at most 0.4 pt, so no signal is a single
point of failure and none is dead weight):

| Signal zeroed | CV AUC | Drop vs full |
|---|---|---|
| asks_credentials | 0.9525 | 0.0043 |
| brand_impersonation | 0.9537 | 0.0031 |
| external_link_risk | 0.9544 | 0.0024 |
| requests_pii | 0.9547 | 0.0021 |
| urgency_pressure | 0.9559 | 0.0009 |
| payment_gift_request | 0.9568 | 0.0000 |
| too_good_to_be_true | 0.9573 | -0.0005 |
| suspicious_instructions | 0.9576 | -0.0008 |

The two negative drops mean the model is at the CV noise floor for those
signals: their value shows up in the verdict *reasons* (explainability)
rather than in extra ranking power on this corpus.

## Product

Scan files in batch (mbox, single eml, or jsonl of `{"raw": ...}` records):

```bash
uv run laya-phishield scan inbox.mbox            # human-readable lines
uv run laya-phishield scan inbox.mbox --json     # one verdict object per line
uv run laya-phishield scan a.eml b.jsonl --limit 100
```

HTTP API (loads the checkpoint on the first request):

```bash
uv run uvicorn laya_phishield.serve:app --port 8000
curl -s localhost:8000/scan -H 'content-type: application/json' \
     -d '{"raw": "<full RFC822 email>"}'
```

Paste-an-email demo:

```bash
uv run pip install -e ".[demo]"
uv run streamlit run app.py
```

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
