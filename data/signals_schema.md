# Signal schema

The eight atomic signals evaluated by the local laya decision model over the
structured email state. Each signal is one narrow yes/no question (`noul`
type) answered in a single forward pass; the value reported for each is the
model's calibrated `p(true)`.

Design rules that apply to every signal:

- **Positive phrasing.** Questions ask whether the email *does* the thing,
  never whether it is "not legitimate". Negated and forced-choice questions
  are the documented failure mode this decomposition exists to avoid
  (`do NOT cancel` style traps).
- **One behavior per signal.** A signal fires for exactly one manipulative
  behavior. Anything a signal does not cover is named in its *Out of scope*
  section, not silently absorbed.
- **House-style wording.** One short sentence, instructions only (no
  criteria text), matching the length and tone of laya's own question
  presets. Every wording below was validated against a real checkpoint
  over the smoke corpus; wordings that read well to a human but poorly to
  the model (long field enumerations, disjunctive criteria) were rejected
  by measurement.
- **The state is the only input.** Signals read the structured state
  produced by the deterministic pre-pass (`extract.py`), never the raw
  MIME. Obfuscated artifacts (IP-literal URLs, punycode hosts, homoglyph
  domains) reach the model as readable `deterministic_flags` statements.

Structured state fields:

| Field | Content |
|---|---|
| `subject` | Subject header, stripped |
| `sender_display` | Display name from the From header |
| `sender_domain` | Lowercased domain of the From address |
| `reply_to_domain` | Lowercased domain of Reply-To (empty if absent) |
| `first_url_host` | Host of the first http(s) URL found (href/src attributes of HTML parts included, then body text) |
| `body_excerpt` | Plain-text body (HTML parts tag-stripped), capped at 1500 chars |
| `deterministic_flags` | Readable statements, one per deterministic flag below |

Deterministic flag codes (stable keys; the readable sentence carries the
details into the state):

| Code | Raised when |
|---|---|
| `reply_to_mismatch` | Reply-To domain and sender domain belong to different organizations (a subdomain of the other is fine) |
| `url_ip_literal` | First body link points at a raw IPv4 or IPv6 address |
| `url_punycode` | A link host contains `xn--` labels (decoded form included) |
| `brand_lookalike_domain` | A host only matches a known brand after folding Cyrillic/Greek lookalikes, or its punycode form decodes to one |
| `brand_in_subdomain` | A brand domain is embedded before the real one (`paypal.com.evil.net`) |
| `display_name_brand_mismatch` | Display name claims a brand the (non-free-mail) sender domain does not own |
| `spf_fail` | `Authentication-Results` reports `spf=fail` (absent header never flags) |
| `dkim_fail` | `Authentication-Results` reports `dkim=fail` (absent header never flags) |

Brand genuineness is conservative in the no-false-positive direction: the
brand's registrable domain, its subdomains, and its regional domains
(`google.com.au`, `amazon.co.uk`, `dhl.de` — every label after the brand
token is a suffix-like label) all count as genuine.

---

## `asks_credentials`

"Does the email tell the recipient to confirm their password or account
login to restore or keep access?"

- **Fires for**: credential confirmation demands — on a linked page or by
  reply — framed as restoring or keeping access.
- **Example trigger**: "confirm your password within 24 hours to restore
  your account".
- **Out of scope**: personal identity data beyond logins (`requests_pii`),
  money movement (`payment_gift_request`), and who the sender claims to be
  (`brand_impersonation`).
- **Known hard negative**: a password-reset email the recipient just
  requested also answers yes — the trigger ("request from Chrome") is in
  the state, and separating requested from unsolicited resets is the
  Phase 2 combiner's job, not this signal's.

## `urgency_pressure`

"Does the email pressure the recipient to act immediately or within hours,
for example threatening consequences for delay?"

- **Fires for**: tight deadlines with threatened consequences; the threat
  is the typical case, not a required conjunction.
- **Example trigger**: "within 24 hours or your account will be permanently
  closed".
- **Out of scope**: ordinary calendar deadlines with no pressure ("expense
  reports due Friday"), and what the action itself is (the request-family
  signals).

## `payment_gift_request`

"Does the email ask for a payment, transfer, gift cards or cryptocurrency
to the sender or an account the sender names?"

- **Fires for**: any demand that money or gift cards move to a
  sender-named destination (including mule accounts the sender does not
  control).
- **Example trigger**: "buy 8 x $100 Apple gift cards and reply with the
  codes".
- **Out of scope**: purchase receipts and renewals already charged (no
  action demanded), and credential capture on a payment page
  (`asks_credentials`).

## `brand_impersonation`

"Does the email borrow the name or branding of a known company or bank
while `sender_domain` belongs to a different organization?"

- **Fires for**: claimed organizational identity and actual sending domain
  disagreeing — including every `brand_lookalike_domain` and
  `display_name_brand_mismatch` flag in the state.
- **Example trigger**: "PayPal Security" writing from
  `paypal-account-verify.example`.
- **Out of scope**: whether the *ask* is fraudulent (the other signals
  carry that); unknown non-brand senders (spam, not impersonation).

## `requests_pii`

"Does the email ask the recipient to send personal identity data such as an
ID number, card number or date of birth?"

- **Fires for**: collecting personal identity details from the recipient.
- **Example trigger**: "send your full name, date of birth and phone number
  to claim your winnings".
- **Out of scope**: passwords and codes (`asks_credentials`), and shipping
  addresses a customer knowingly gives a store they chose to buy from.

## `too_good_to_be_true`

"Does the email promise an unearned prize, lottery win, inheritance or
windfall?"

- **Fires for**: implausibly good rewards offered out of the blue.
- **Example trigger**: "You have won GBP 2,500,000.00 — your email was
  selected at random".
- **Out of scope**: earned credits (salary, refunds the recipient
  requested), and crypto "multiply your coins" mechanics that are really
  payment requests (`payment_gift_request`).

## `suspicious_instructions`

"Does the email ask the recipient to keep the request secret from
colleagues or bypass normal procedures?"

- **Fires for**: secrecy demands aimed at colleagues/management, and
  procedure-bypass instructions.
- **Example trigger**: "Do not discuss this with anyone in accounting yet…
  reply only to me".
- **Out of scope**: ordinary confidentiality footers aimed at unknown
  external parties, and the money a hidden request moves
  (`payment_gift_request`).

## `external_link_risk`

"Does the email send the recipient to click a link hosted on a domain
unrelated to the sender or the brand it claims?"

- **Fires for**: the structural mismatch between the link host
  (`first_url_host`) and the claimed sender or brand — raw IP links, links
  to a third-party host, links to a different lookalike domain than the
  sender's.
- **Does not fire for**: links that stay inside the sender's own domain,
  even when the email pushes a click.
- **Example trigger**: "PayPal" writing from `alert-center.example` and
  linking to `http://203.0.113.41/verify`.
- **Out of scope**: the click-baiting pressure itself (`urgency_pressure`),
  the credential ask behind the link (`asks_credentials`), and whether the
  sender identity is itself the lie (`brand_impersonation`).

---

## Combining (Phase 2)

Phase 1 orders reasons by signal probability (`rank_reasons`). Phase 2
trains a logistic head over the eight probabilities plus the deterministic
flag codes and re-derives per-signal score contributions for the verdict
text; the signal contract above does not change.
