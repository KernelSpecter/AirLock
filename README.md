<div align="center">

# 🔒 airlock

### The airlock between your terminal and the AI.

**Redacts secrets & PII _before_ they leak into an LLM.** Local-first. Zero network calls. One command.

[![License: MIT](https://img.shields.io/badge/License-MIT-black.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org)
[![Network calls: 0](https://img.shields.io/badge/network%20calls-0-brightgreen.svg)](#-private-by-design)
[![PRs welcome](https://img.shields.io/badge/PRs-welcome-orange.svg)](#-add-your-own-detector)

</div>

---

You hit a bug. You copy the stack trace, the `.env`, the failing request, and paste it into ChatGPT or Claude. Buried in there: an **AWS key**, a **database password**, a **customer's email**, a **live card number**. It's now sitting in a third party's logs — and you can't take it back.

`airlock` is the checkpoint in between. Pipe text through it (or let it guard your clipboard) and every secret comes out as a typed placeholder — `[AWS_ACCESS_KEY]`, `[CONNECTION_STRING]`, `[EMAIL]` — so the model still understands the shape of your problem, but the secret never leaves your machine.

<!-- 👉 Drop a recording here before launch — the demo GIF is what makes a repo spread.
     Record the block below with asciinema/vhs and save to docs/demo.gif
<p align="center"><img src="docs/demo.gif" alt="airlock demo" width="720"></p> -->

```console
$ cat staging.env | airlock
# staging config — pasting this to debug a 500
DATABASE_URL=[CONNECTION_STRING]/prod
AWS_ACCESS_KEY_ID=[AWS_ACCESS_KEY]
AWS_SECRET_ACCESS_KEY=[SECRET]
ANTHROPIC_API_KEY=[ANTHROPIC_KEY]
stripe_key = "[STRIPE_KEY]"
support_email = [EMAIL]
DEBUG = True
MAX_RETRIES = 3
card_on_file = [CREDIT_CARD]

airlock: 7 findings redacted        ← summary printed to stderr, so it never
  high   CONNECTION_STRING  post…5432    (line 2)     pollutes the piped output
  high   AWS_ACCESS_KEY     AKIA…MPLE    (line 3)
  medium SECRET             wJal…EKEY    (line 4)
  high   ANTHROPIC_KEY      sk-a…aaaa    (line 5)
  high   STRIPE_KEY         sk_l…5678    (line 6)
  low    EMAIL              jane….com    (line 7)
  high   CREDIT_CARD        4242…4242    (line 10)
```

Notice what *didn't* get touched: `DEBUG = True`, `MAX_RETRIES = 3`. A redactor that mangles your normal config is a redactor you uninstall. Keeping quiet on ordinary code is the whole design (see [below](#-why-it-wont-cry-wolf)).

## Install

Install straight from GitHub (not on PyPI yet):

```bash
# core CLI — zero dependencies
pip install "git+https://github.com/KernelSpecter/AirLock.git"

# ...or with the live clipboard guard
pip install "airlock[clipboard] @ git+https://github.com/KernelSpecter/AirLock.git"
```

Both put an `airlock` command on your PATH. Prefer isolation? Swap `pip install` for `pipx install`.

Or just clone and run — no install needed:

```bash
git clone https://github.com/KernelSpecter/AirLock.git && cd AirLock
python -m airlock.cli --help
```

## Use it

**Redact a file or stdin — the redacted text goes to stdout, the summary to stderr:**

```bash
cat error.log | airlock             # pipe anything through
airlock config.py .env              # scan files
airlock error.log | pbcopy          # redact straight into your clipboard (macOS)
airlock error.log | clip            # …or on Windows
```

**Guard your clipboard live** — anything you copy is scrubbed in place before you can paste it:

```bash
airlock --watch
#  airlock: watching clipboard — Ctrl-C to stop
#    >> redacted 2 (ANTHROPIC_KEY, EMAIL) from clipboard
```

**Just audit, don't rewrite:**

```bash
airlock --report error.log          # list findings only
airlock --json error.log            # machine-readable, for scripts/CI
airlock --all error.log             # also catch phones, IPs, SSNs (noisier)
```

**Use it as a guardrail.** `airlock` exits `1` when it finds anything, so it drops straight into a pre-commit hook or CI:

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/KernelSpecter/airlock
    rev: v0.1.0
    hooks:
      - id: airlock
```

## What it catches

Detection is **specific by default** — provider-anchored patterns and real validators, not a grab-bag of loose regexes.

| Category | Detects |
|---|---|
| **Cloud & API keys** | AWS, GCP, Anthropic, OpenAI, Stripe, Slack, SendGrid, Twilio, Google OAuth, npm |
| **Tokens** | GitHub PATs (classic + fine-grained), JWTs |
| **Credentials** | Private keys (`BEGIN … PRIVATE KEY`), `proto://user:pass@host` connection strings |
| **Generic secrets** | `API_KEY = "…"` style assignments — *gated by entropy* so `password="changeme"` is ignored |
| **PII** | Emails, credit cards (**Luhn-validated**) |
| **PII (opt-in `--all`)** | Phone numbers, IPv4 addresses, US SSNs |

## 🤫 Why it won't cry wolf

Most secret scanners are unusable because they flag everything. `airlock` is tuned the other way — **specificity over recall** for anything on by default:

- **Provider-anchored patterns.** `AKIA…`, `ghp_…`, `sk-ant-…` — matched by their real prefixes and lengths, not "any 32-char string."
- **Luhn-checked cards.** A 16-digit number only redacts if it's a mathematically valid card, so order IDs and timestamps stay put.
- **Entropy-gated generics.** The catch-all `secret = "…"` rule only fires when the value is actually high-entropy — `changeme` and `localhost` don't trip it.
- **The noisy stuff is opt-in.** Phone numbers, IPs and SSNs generate the most false positives, so they live behind `--all`.

## 🔐 Private by design

`airlock` makes **zero network calls, ever.** No telemetry, no cloud, no account. Your secrets are scanned and redacted entirely on your machine — which is rather the point of a tool whose job is to stop data from leaving it. It's a single small pure-Python package you can read top to bottom in a few minutes.

## How it works

1. **Scan** — every detector runs over the text; validators (Luhn, Shannon entropy) confirm candidate matches.
2. **Resolve overlaps** — when two detectors hit the same span, the higher-severity one wins, so nothing is redacted twice or mislabeled.
3. **Redact** — each finding's span is replaced with a typed, ASCII-safe placeholder. Repeats are numbered (`[EMAIL_1]`, `[EMAIL_2]`) so the model can still tell two distinct values apart.

## 🧩 Add your own detector

Detectors are plain data. Adding one is a few lines in `airlock/detectors.py`:

```python
Detector(
    kind="linear_key", category="secret", label="LINEAR_KEY", severity="high",
    pattern=re.compile(r"\blin_api_[A-Za-z0-9]{40}\b"),
)
```

Add a realistic fake key to `POSITIVES` and a look-alike to `NEGATIVES` in the tests, and you're done. PRs adding coverage for more providers are very welcome.

## Roadmap

- [ ] Config file for custom patterns & allowlists
- [ ] `git diff` mode (redact only what you're about to commit)
- [ ] Editor/shell integrations (a pre-paste hook)
- [ ] Reversible redaction (restore placeholders locally after the model replies)

## Contributing

Issues and PRs welcome — especially new provider patterns and false-positive reports (paste the text that tripped it). Run the tests before opening a PR:

```bash
python -m pytest        # or: python tests/run.py
```

## License

[MIT](LICENSE) © KernelSpecter
