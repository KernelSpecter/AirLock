"""Detection engine for airlock.

Design principle: *specificity over recall* for anything shown by default.
A tool that cries wolf gets uninstalled in a day. Provider-specific patterns
and validators (Luhn, entropy) keep false positives near zero. The noisy
heuristics (phones, IPs, loose SSNs) live behind ``--all``.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from typing import Callable, Optional, Pattern


# --------------------------------------------------------------------------- #
# Data types
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Finding:
    kind: str          # machine id, e.g. "aws_access_key"
    category: str      # "secret" | "pii"
    label: str         # redaction placeholder, e.g. "AWS_ACCESS_KEY"
    severity: str      # "high" | "medium" | "low"
    start: int
    end: int
    value: str

    @property
    def preview(self) -> str:
        """A safe, partially-masked look at the value for the summary line."""
        v = self.value
        if len(v) <= 8:
            return v[0] + "•" * (len(v) - 1) if v else ""
        return f"{v[:4]}…{v[-4:]}"


@dataclass(frozen=True)
class Detector:
    kind: str
    category: str
    label: str
    severity: str
    pattern: Pattern
    group: int = 0                                   # capture group holding the secret
    validate: Optional[Callable[[str], bool]] = None  # extra confirmation
    default: bool = True                              # off unless --all when False


# --------------------------------------------------------------------------- #
# Validators
# --------------------------------------------------------------------------- #
def shannon_entropy(s: str) -> float:
    """Bits of entropy per character. base64/hex secrets sit around 4-6."""
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def luhn_ok(candidate: str) -> bool:
    """Luhn checksum — the reason card detection barely ever false-positives."""
    digits = [int(c) for c in candidate if c.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    checksum = 0
    parity = len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def high_entropy(threshold: float = 3.5, min_len: int = 16) -> Callable[[str], bool]:
    def _check(value: str) -> bool:
        return len(value) >= min_len and shannon_entropy(value) >= threshold
    return _check


# --------------------------------------------------------------------------- #
# Detector registry
# --------------------------------------------------------------------------- #
# High-precision, provider-anchored patterns first. Order matters only for the
# summary; overlap resolution keeps the higher-severity / earlier match.
DETECTORS: list[Detector] = [
    # --- Private keys -------------------------------------------------------
    Detector(
        "private_key", "secret", "PRIVATE_KEY", "high",
        re.compile(
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----"
            r"[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----"
        ),
    ),
    # --- Cloud / provider tokens -------------------------------------------
    Detector("aws_access_key", "secret", "AWS_ACCESS_KEY", "high",
             re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA)[0-9A-Z]{16}\b")),
    Detector("gcp_api_key", "secret", "GCP_API_KEY", "high",
             re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    Detector("github_pat", "secret", "GITHUB_TOKEN", "high",
             re.compile(r"\bgh[posru]_[A-Za-z0-9]{36}\b")),
    Detector("github_fine_pat", "secret", "GITHUB_TOKEN", "high",
             re.compile(r"\bgithub_pat_[0-9a-zA-Z_]{82}\b")),
    Detector("anthropic_key", "secret", "ANTHROPIC_KEY", "high",
             re.compile(r"\bsk-ant-[A-Za-z0-9\-_]{20,}\b")),
    Detector("openai_key", "secret", "OPENAI_KEY", "high",
             re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9]{20,}\b")),
    Detector("stripe_key", "secret", "STRIPE_KEY", "high",
             re.compile(r"\b[rsp]k_(?:live|test)_[0-9a-zA-Z]{16,}\b")),
    Detector("slack_token", "secret", "SLACK_TOKEN", "high",
             re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")),
    Detector("slack_webhook", "secret", "SLACK_WEBHOOK", "high",
             re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/_+-]{40,}")),
    Detector("google_oauth", "secret", "GOOGLE_OAUTH_ID", "medium",
             re.compile(r"\b[0-9]+-[0-9a-z]{32}\.apps\.googleusercontent\.com\b")),
    Detector("sendgrid_key", "secret", "SENDGRID_KEY", "high",
             re.compile(r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b")),
    Detector("twilio_key", "secret", "TWILIO_KEY", "high",
             re.compile(r"\bSK[0-9a-fA-F]{32}\b")),
    Detector("npm_token", "secret", "NPM_TOKEN", "high",
             re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),
    Detector("jwt", "secret", "JWT", "medium",
             re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),

    # --- Generic assigned secret (entropy-gated) ---------------------------
    # Catches `API_KEY = "…"`, `password: '…'`, `secret_token="…"` etc.
    # The entropy validator kills matches like password="changeme".
    Detector(
        "generic_secret", "secret", "SECRET", "medium",
        re.compile(
            r"""(?ix)
            (?:api[_-]?key|secret|token|passwd|password|auth|access[_-]?key|
               client[_-]?secret|private[_-]?key|bearer)
            \s*[:=]\s*
            ['"]?(?P<val>[A-Za-z0-9+/=_\-.]{16,})['"]?
            """
        ),
        group=1,
        validate=high_entropy(threshold=3.2, min_len=16),
    ),

    # --- Credentials embedded in URLs (proto://user:pass@host) --------------
    # One of the most-pasted secrets there is: DB / broker connection strings.
    Detector("connection_string", "secret", "CONNECTION_STRING", "high",
             re.compile(r"\b[a-z][a-z0-9+.\-]*://[^\s:@/]+:[^\s:@/]+@[^\s/]+")),

    # --- PII (default on: only the low-FP ones) -----------------------------
    Detector("email", "pii", "EMAIL", "low",
             re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    Detector("credit_card", "pii", "CREDIT_CARD", "high",
             re.compile(r"\b(?:\d[ -]?){13,19}\b"), validate=luhn_ok),

    # --- PII (noisy: --all only) -------------------------------------------
    Detector("us_ssn", "pii", "SSN", "medium",
             re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"),
             default=False),
    Detector("phone", "pii", "PHONE", "low",
             re.compile(r"\b(?:\+?\d{1,3}[ .-]?)?\(?\d{3}\)?[ .-]?\d{3}[ .-]?\d{4}\b"),
             default=False),
    Detector("ipv4", "pii", "IP_ADDRESS", "low",
             re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"),
             default=False),
]


# --------------------------------------------------------------------------- #
# Scanning
# --------------------------------------------------------------------------- #
_SEVERITY_RANK = {"high": 3, "medium": 2, "low": 1}


def scan(text: str, *, include_all: bool = False) -> list[Finding]:
    """Return non-overlapping findings, earliest first.

    On overlap the higher-severity finding wins; ties break to the earlier /
    longer match. This stops (e.g.) a JWT and a generic-secret hit on the same
    span from both being redacted.
    """
    detectors = DETECTORS if include_all else [d for d in DETECTORS if d.default]
    raw: list[Finding] = []
    for det in detectors:
        for m in det.pattern.finditer(text):
            value = m.group(det.group)
            if not value:
                continue
            start, end = m.span(det.group)
            if det.validate and not det.validate(value):
                continue
            raw.append(Finding(det.kind, det.category, det.label, det.severity,
                               start, end, value))

    # Resolve overlaps: strongest finding wins its span. Sort by severity
    # (then length) so the winner is considered first, then greedily keep
    # any finding that doesn't collide with one already chosen.
    chosen: list[Finding] = []
    for f in sorted(raw, key=lambda f: (-_SEVERITY_RANK[f.severity],
                                        -(f.end - f.start), f.start)):
        if any(f.start < c.end and c.start < f.end for c in chosen):
            continue
        chosen.append(f)
    chosen.sort(key=lambda f: f.start)
    return chosen
