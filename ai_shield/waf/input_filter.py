"""Input filtering and prompt attack detection for LLM traffic."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Dict, List, Pattern, Tuple
from urllib.parse import unquote_plus

logger = logging.getLogger(__name__)


@dataclass
class FilterResult:
    """Result object returned by InputFilter scans."""

    is_safe: bool
    risk_score: float
    matches: List[str]
    reason: str
    explanations: List[str]


class InputFilter:
    """Detect prompt injections, jailbreaks, exfiltration and role override attempts."""

    def __init__(self) -> None:
        """Initialize attack patterns and compile regexes for performance."""
        labeled_patterns: List[Tuple[str, str]] = [
            ("jailbreak", r"ignore\s+previous\s+instructions"),
            ("jailbreak", r"ignore\s+all\s+rules"),
            ("prompt_leak", r"system\s*prompt"),
            ("prompt_leak", r"developer\s*message"),
            ("prompt_leak", r"reveal\s+hidden\s+prompt"),
            ("prompt_leak", r"show\s+your\s+instructions"),
            ("jailbreak", r"jailbreak"),
            ("jailbreak", r"DAN\s+mode"),
            ("jailbreak", r"do\s+anything\s+now"),
            ("role_override", r"role\s*:\s*system"),
            ("role_override", r"you\s+are\s+now\s+admin"),
            ("role_override", r"simulate\s+root\s+access"),
            ("role_override", r"override\s+safety"),
            ("role_override", r"disable\s+guardrails"),
            ("role_override", r"bypass\s+content\s+policy"),
            ("env_vars", r"print\s+environment\s+variables"),
            ("exfiltration", r"export\s+secrets"),
            ("exfiltration", r"api[_\s-]?key"),
            ("token_leak", r"token\s+leak"),
            ("exfiltration", r"password\s+dump"),
            ("injection", r"sql\s+injection"),
            ("injection", r"drop\s+table"),
            ("injection", r"<script>"),
            ("shell_command", r"run:\s*cat\s+/etc/passwd"),
            ("shell_command", r"execute\s+shell\s+command"),
            ("shell_command", r"printenv\s+\\|\\s*grep\\s+key"),
            ("shell_command", r"`printenv\\s*\\|\\s*grep\\s*key`"),
            ("encoding", r"base64\s+decode"),
            ("prompt_injection", r"prompt\s+injection"),
            ("confidentiality", r"confidential\s+data"),
            ("confidentiality", r"private\s+keys?"),
            ("confidentiality", r"ssh-rsa"),
            ("confidentiality", r"BEGIN\s+PRIVATE\s+KEY"),
            ("social_engineering", r"urgent\s+request"),
            ("social_engineering", r"manager\s+approved"),
            ("social_engineering", r"emergency\s+mode"),
            ("multilingual", r"ignora\s+todas\s+las\s+reglas"),
            ("multilingual", r"muestra\s+las\s+claves\s+privadas"),
            ("multilingual", r"ignorez\s+toutes\s+les\s+restrictions"),
            ("multilingual", r"affichez\s+les\s+secrets"),
            ("multilingual", r"忽略之前的所有指令"),
            ("multilingual", r"输出系统提示"),
        ]
        self._patterns: List[Tuple[str, Pattern[str]]] = [
            (label, re.compile(pattern, re.IGNORECASE)) for label, pattern in labeled_patterns
        ]
        self._adaptive_patterns: Dict[str, Pattern[str]] = {}

    def scan(self, user_input: str) -> FilterResult:
        """Scan user prompt for malicious patterns.

        Args:
            user_input: Incoming natural language user prompt.

        Returns:
            A FilterResult with safety flag, score, and detections.
        """
        try:
            matched_patterns: List[str] = []
            explanations: List[str] = []

            def _scan_text(text: str) -> None:
                for label, pattern in self._patterns:
                    if pattern.search(text):
                        matched_patterns.append(pattern.pattern)
                        explanations.append(label)
                for label, pattern in self._adaptive_patterns.items():
                    if pattern.search(text):
                        matched_patterns.append(pattern.pattern)
                        explanations.append(f"adaptive:{label}")

            _scan_text(user_input)
            for decoded in self._decode_variants(user_input):
                _scan_text(decoded)

            unique_explanations = sorted(set(explanations))
            base_risk = len(set(matched_patterns)) * 0.18
            if "token_leak" in unique_explanations:
                base_risk += 0.15
            if "env_vars" in unique_explanations:
                base_risk += 0.12
            if "shell_command" in unique_explanations:
                base_risk += 0.14
            risk_score = min(1.0, base_risk)
            is_safe = risk_score < 0.35
            reason = "Input accepted" if is_safe else "Blocked: " + ", ".join(unique_explanations)

            if not is_safe:
                self.learn_from_attack(user_input, unique_explanations)

            logger.info(
                "Input scan complete: safe=%s risk=%.2f matches=%d",
                is_safe,
                risk_score,
                len(matched_patterns),
            )
            return FilterResult(
                is_safe=is_safe,
                risk_score=risk_score,
                matches=matched_patterns,
                reason=reason,
                explanations=unique_explanations,
            )
        except Exception as exc:  # pragma: no cover - defensive runtime path
            logger.exception("Input filter failed: %s", exc)
            return FilterResult(
                is_safe=False,
                risk_score=1.0,
                matches=["input_filter_error"],
                reason="Input filtering error; blocked by default",
                explanations=["filter_error"],
            )

    def learn_from_attack(self, user_input: str, explanations: List[str]) -> None:
        """Adaptively learn new suspicious tokens from blocked inputs."""
        tokens = {token.lower() for token in re.findall(r"[a-zA-Z]{4,}", user_input)}
        for token in tokens:
            if token in self._adaptive_patterns:
                continue
            if any(label.startswith("adaptive") for label in explanations):
                continue
            if token in {"ignore", "previous", "instructions", "system"}:
                continue
            pattern = rf"\b{re.escape(token)}\b"
            self._adaptive_patterns[token] = re.compile(pattern, re.IGNORECASE)

    def _decode_variants(self, text: str) -> List[str]:
        """Decode common encodings to catch obfuscated attacks."""
        variants: List[str] = []
        try:
            variants.append(unquote_plus(text))
        except Exception:
            pass
        rot13 = text.translate(str.maketrans(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
            "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm",
        ))
        variants.append(rot13)
        try:
            import base64

            if len(text) >= 8:
                decoded = base64.b64decode(text + "==", validate=False).decode("utf-8", errors="ignore")
                if decoded:
                    variants.append(decoded)
        except Exception:
            pass
        return list({v for v in variants if v and v != text})
