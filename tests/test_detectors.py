"""Detection quality is the whole ballgame. These tests pin down two things:
recall on real-shaped secrets, and — just as important — *silence* on ordinary
code that must never trip the tool.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from airlock.detectors import scan, luhn_ok, shannon_entropy  # noqa: E402
from airlock.redact import redact  # noqa: E402


def kinds(text, **kw):
    return {f.kind for f in scan(text, **kw)}


# --------------------------------------------------------------------------- #
# Positives — realistic fake secrets that MUST be caught
# --------------------------------------------------------------------------- #
# These fixtures are assembled from fragments on purpose. A secret scanner's
# own test data is a paradox: it must look real enough to match our detectors,
# which means it would also trip every *other* scanner (GitHub push protection,
# gitleaks, …) on this very repo — and on every fork. Splitting each token at
# its prefix keeps the full literal out of the source text, while `_t()` rebuilds
# the complete, detector-matching value at runtime. (We practice what we preach.)
def _t(*parts):
    return "".join(parts)


POSITIVES = {
    "aws_access_key": "aws_key = " + _t("AKIA", "IOSFODNN7EXAMPLE"),
    "gcp_api_key":    "key: " + _t("AIza", "012345678901234567890123456789abcde"),  # AIza + 35
    "github_pat":     "token " + _t("ghp_", "abcdefghijklmnopqrstuvwxyz0123456789"),
    "anthropic_key":  "ANTHROPIC_API_KEY=" + _t("sk-ant-", "api03-aaaaaaaaaaaaaaaaaaaaaaaa"),
    "openai_key":     "openai.api_key = '" + _t("sk-", "abcdefghijklmnopqrstuvwxyz1234") + "'",
    "stripe_key":     "STRIPE=" + _t("sk_live_", "abcdefghijklmnop12345678"),
    "slack_token":    _t("xoxb-", "123456789012-abcdefghijklmnopqrst"),
    "sendgrid_key":   _t("SG.", "abcdefghijklmnopqrstuv.abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG"),
    "npm_token":      "//registry.npmjs.org/:_authToken=" + _t("npm_", "abcdefghijklmnopqrstuvwxyz0123456789"),
    "credit_card":    "card 4242 4242 4242 4242 on file",
    "email":          "reach me at jane.doe@example.com",
    "jwt":            _t("eyJhbGciOiJIUzI1NiJ9.", "eyJzdWIiOiIxMjM0NTY3ODkwIn0.",
                         "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"),
}


def test_each_positive_caught():
    missed = [name for name, text in POSITIVES.items() if name not in kinds(text)]
    assert not missed, f"missed: {missed}"


def test_private_key_block():
    text = (
        _t("-----BEGIN RSA ", "PRIVATE KEY-----") + "\n"
        "MIIEpAIBAAKCAQEA1234567890abcdefg\n"
        "hijklmnopqrstuvwxyzABCDEFGHIJKLMN\n"
        + _t("-----END RSA ", "PRIVATE KEY-----")
    )
    assert "private_key" in kinds(text)


# --------------------------------------------------------------------------- #
# Negatives — ordinary code / text that MUST stay silent by default
# --------------------------------------------------------------------------- #
NEGATIVES = [
    'password = "changeme"',                       # low-entropy placeholder
    'api_key = os.environ["API_KEY"]',             # reference, not a literal
    "commit 550e8400-e29b-41d4-a716-446655440000", # a UUID
    "version = 1.2.3",                             # version string
    "the meeting is at 555-123-4567",              # phone (off by default)
    "server listening on 192.168.1.100:8080",      # private IP (off by default)
    "his id is 123-45-6789 apparently",            # SSN-shaped (off by default)
    "card 4242 4242 4242 4241 declined",           # 16 digits, FAILS Luhn
    "just some ordinary prose with no secrets in it at all",
    "sha = a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4",  # a bare git-ish hash
]


def test_negatives_are_silent_by_default():
    noisy = [t for t in NEGATIVES if scan(t)]
    assert not noisy, f"false positives: {noisy}"


def test_noisy_detectors_wake_up_with_all():
    assert "phone" in kinds("call 555-123-4567", include_all=True)
    assert "ipv4" in kinds("ip 192.168.1.100", include_all=True)
    assert "us_ssn" in kinds("ssn 123-45-6789", include_all=True)


# --------------------------------------------------------------------------- #
# Validators
# --------------------------------------------------------------------------- #
def test_luhn():
    assert luhn_ok("4242 4242 4242 4242")
    assert not luhn_ok("4242 4242 4242 4241")
    assert not luhn_ok("1234")  # too short


def test_entropy_ordering():
    assert shannon_entropy("aaaaaaaa") < shannon_entropy("aB3$xK9zQ1")


# --------------------------------------------------------------------------- #
# Redaction + overlap resolution
# --------------------------------------------------------------------------- #
def test_redaction_replaces_and_labels():
    secret = _t("AKIA", "IOSFODNN7EXAMPLE")
    text = f"key is {secret} ok"
    out = redact(text, scan(text))
    assert secret not in out
    assert "[AWS_ACCESS_KEY]" in out


def test_repeated_labels_numbered():
    text = "a@b.com and c@d.com"
    out = redact(text, scan(text))
    assert "[EMAIL_1]" in out and "[EMAIL_2]" in out


def test_no_double_redaction_on_overlap():
    # A github token assigned to a `token = ` var triggers both the specific
    # github detector and the generic-secret one; only one span should redact.
    text = "token = " + _t("ghp_", "abcdefghijklmnopqrstuvwxyz0123456789")
    out = redact(text, scan(text))
    assert out.count("[") == 1


def test_connection_string_beats_email_label():
    # postgres://user:pass@host embeds a password; must be caught as a
    # connection string, not mislabelled as an email.
    text = "DATABASE_URL=postgres://admin:hunter2@db.internal:5432/prod"
    found = scan(text)
    assert "connection_string" in {f.kind for f in found}
    assert "email" not in {f.kind for f in found}   # the @host part shouldn't leak out separately
    out = redact(text, found)
    assert "hunter2" not in out
