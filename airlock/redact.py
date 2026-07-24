"""Turn findings into redacted text."""

from __future__ import annotations

from .detectors import Finding


def redact(text: str, findings: list[Finding]) -> str:
    """Replace each finding's span with a typed placeholder [LABEL].

    Findings must be non-overlapping (as returned by ``scan``). Multiple hits of
    the same label get numbered so a reader can tell two distinct secrets apart:
    [EMAIL_1], [EMAIL_2], …

    Placeholders are pure ASCII on purpose: this text gets pasted into the LLM,
    so it must survive every terminal, editor, and copy buffer unchanged.
    """
    if not findings:
        return text

    # Number repeated labels for disambiguation.
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.label] = counts.get(f.label, 0) + 1
    seen: dict[str, int] = {}

    out: list[str] = []
    cursor = 0
    for f in sorted(findings, key=lambda x: x.start):
        out.append(text[cursor:f.start])
        if counts[f.label] > 1:
            seen[f.label] = seen.get(f.label, 0) + 1
            out.append(f"[{f.label}_{seen[f.label]}]")
        else:
            out.append(f"[{f.label}]")
        cursor = f.end
    out.append(text[cursor:])
    return "".join(out)
