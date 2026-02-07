"""Output filtering to prevent sensitive data leakage."""

from __future__ import annotations

import logging
import re
from typing import List

logger = logging.getLogger(__name__)


class OutputFilter:
    """Sanitize LLM output before sending to end users."""

    def __init__(self) -> None:
        """Build data leakage regex rules."""
        self._rules: List[tuple[re.Pattern[str], str]] = [
            (re.compile(r"sk-[A-Za-z0-9]{20,}", re.IGNORECASE), "[REDACTED_API_KEY]"),
            (re.compile(r"BEGIN\s+PRIVATE\s+KEY.*?END\s+PRIVATE\s+KEY", re.IGNORECASE | re.DOTALL), "[REDACTED_PRIVATE_KEY]"),
            (re.compile(r"password\s*[:=]\s*\S+", re.IGNORECASE), "password=[REDACTED]"),
            (re.compile(r"token\s*[:=]\s*\S+", re.IGNORECASE), "token=[REDACTED]"),
            (re.compile(r"aws_secret_access_key\s*[:=]\s*\S+", re.IGNORECASE), "aws_secret_access_key=[REDACTED]"),
        ]

    def sanitize(self, output_text: str) -> str:
        """Sanitize potentially sensitive output text.

        Args:
            output_text: Raw model output.

        Returns:
            Redacted output string.
        """
        try:
            sanitized = output_text
            for pattern, replacement in self._rules:
                sanitized = pattern.sub(replacement, sanitized)
            logger.info("Output sanitization complete")
            return sanitized
        except Exception as exc:  # pragma: no cover - defensive runtime path
            logger.exception("Output filter failed: %s", exc)
            return "[Output blocked due to sanitization error]"

