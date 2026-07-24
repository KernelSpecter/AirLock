"""airlock command-line interface.

    cat secrets.txt | airlock            # redacted text -> stdout, summary -> stderr
    airlock file1.py file2.env           # scan files
    airlock --report app.log             # just list findings, don't print text
    airlock --json app.log               # findings as JSON
    airlock --watch                      # guard the clipboard live

Exit code is 1 when anything is found (so it doubles as a CI / pre-commit
check), 0 when clean, 2 on error.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time

from . import __version__
from .detectors import Finding, scan
from .redact import redact


# --------------------------------------------------------------------------- #
# Colour (auto-off when not a tty, or NO_COLOR set)
# --------------------------------------------------------------------------- #
def _use_colour(stream) -> bool:
    return stream.isatty() and os.environ.get("NO_COLOR") is None


class _C:
    def __init__(self, on: bool):
        self.on = on

    def __call__(self, code: str, text: str) -> str:
        return f"\033[{code}m{text}\033[0m" if self.on else text


_SEV_COLOUR = {"high": "1;31", "medium": "33", "low": "2;37"}


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _summary(findings: list[Finding], text: str, stream) -> None:
    c = _C(_use_colour(stream))
    if not findings:
        print(c("32", "airlock: clean — nothing sensitive found"), file=stream)
        return
    n = len(findings)
    head = f"airlock: {n} finding{'s' if n != 1 else ''} redacted"
    print(c("1;36", head), file=stream)
    for f in findings:
        sev = c(_SEV_COLOUR[f.severity], f"{f.severity:<6}")
        print(f"  {sev} {f.label:<18} {f.preview:<12} (line {_line_of(text, f.start)})",
              file=stream)


# --------------------------------------------------------------------------- #
# Sources
# --------------------------------------------------------------------------- #
def _gather(files: list[str]) -> list[tuple[str, str]]:
    """Return [(name, text)]. No files → read stdin."""
    if not files:
        return [("<stdin>", sys.stdin.read())]
    out = []
    for path in files:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            out.append((path, fh.read()))
    return out


# --------------------------------------------------------------------------- #
# Clipboard guard
# --------------------------------------------------------------------------- #
def _watch(include_all: bool) -> int:
    try:
        import pyperclip
    except ImportError:
        print("airlock: --watch needs pyperclip  (pip install pyperclip)",
              file=sys.stderr)
        return 2

    c = _C(_use_colour(sys.stderr))
    print(c("1;36", "airlock: watching clipboard — Ctrl-C to stop"), file=sys.stderr)
    last = None
    try:
        while True:
            try:
                current = pyperclip.paste()
            except Exception:
                current = None
            if current and current != last:
                findings = scan(current, include_all=include_all)
                if findings:
                    cleaned = redact(current, findings)
                    pyperclip.copy(cleaned)
                    last = cleaned
                    labels = ", ".join(sorted({f.label for f in findings}))
                    print(c("1;31", f"  >> redacted {len(findings)} "
                                     f"({labels}) from clipboard"), file=sys.stderr)
                else:
                    last = current
            time.sleep(0.4)
    except KeyboardInterrupt:
        print(c("2;37", "\nairlock: stopped"), file=sys.stderr)
        return 0


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="airlock",
        description="The airlock between your terminal and the AI. "
                    "Redacts secrets + PII before they leak into an LLM.",
    )
    p.add_argument("files", nargs="*", help="files to scan (default: stdin)")
    p.add_argument("-a", "--all", action="store_true",
                   help="enable noisy detectors (phone, IP, SSN)")
    p.add_argument("-r", "--report", action="store_true",
                   help="list findings only; do not print redacted text")
    p.add_argument("-j", "--json", action="store_true",
                   help="emit findings as JSON")
    p.add_argument("-q", "--quiet", action="store_true",
                   help="suppress the stderr summary")
    p.add_argument("-w", "--watch", action="store_true",
                   help="guard the system clipboard live")
    p.add_argument("--version", action="version",
                   version=f"airlock {__version__}")
    return p


def _force_utf8() -> None:
    # The redacted text may contain any Unicode from the user's input; a legacy
    # cp1252 stdout would raise UnicodeEncodeError. UTF-8 everywhere is safe.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass


def main(argv: list[str] | None = None) -> int:
    _force_utf8()
    args = build_parser().parse_args(argv)

    if args.watch:
        return _watch(args.all)

    if not args.files and sys.stdin.isatty():
        build_parser().print_help(sys.stderr)
        return 2

    try:
        sources = _gather(args.files)
    except OSError as e:
        print(f"airlock: {e}", file=sys.stderr)
        return 2

    all_findings: list[Finding] = []
    for name, text in sources:
        findings = scan(text, include_all=args.all)
        all_findings.extend(findings)

        if args.json:
            payload = {
                "source": name,
                "findings": [
                    {"kind": f.kind, "category": f.category, "label": f.label,
                     "severity": f.severity, "line": _line_of(text, f.start),
                     "start": f.start, "end": f.end}
                    for f in findings
                ],
            }
            print(json.dumps(payload, indent=2))
        elif not args.report:
            sys.stdout.write(redact(text, findings))

        if not args.quiet and not args.json:
            if len(sources) > 1:
                print(f"\n-- {name} --", file=sys.stderr)
            _summary(findings, text, sys.stderr)

    return 1 if all_findings else 0


if __name__ == "__main__":
    sys.exit(main())
