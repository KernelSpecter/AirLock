"""airlock — the airlock between your terminal and the AI.

Detects and redacts secrets + PII in text before it leaves your machine
into an LLM. Local-first, zero network calls.
"""

from .detectors import Detector, Finding, scan
from .redact import redact

__version__ = "0.1.0"
__all__ = ["Detector", "Finding", "scan", "redact", "__version__"]
