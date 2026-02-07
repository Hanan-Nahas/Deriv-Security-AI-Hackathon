"""Secure LLM pipeline integrating WAF, behavior monitoring, and optional RAG."""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Optional

from ai_shield.core.rag_engine import RAGEngine
from ai_shield.waf.behavior_monitor import BehaviorMonitor
from ai_shield.waf.input_filter import InputFilter
from ai_shield.waf.output_filter import OutputFilter

logger = logging.getLogger(__name__)


@dataclass
class PipelineResponse:
    """Unified response payload from the secured LLM pipeline."""

    text: str
    blocked: bool
    risk_score: float
    reason: str


class LLMPipeline:
    """Orchestrates input filtering, retrieval augmentation, model call, and output filtering."""

    def __init__(
        self,
        input_filter: Optional[InputFilter] = None,
        output_filter: Optional[OutputFilter] = None,
        behavior_monitor: Optional[BehaviorMonitor] = None,
        rag_engine: Optional[RAGEngine] = None,
    ) -> None:
        self.input_filter = input_filter or InputFilter()
        self.output_filter = output_filter or OutputFilter()
        self.behavior_monitor = behavior_monitor or BehaviorMonitor()
        self.rag_engine = rag_engine

    def process(self, user_input: str, session_id: str = "default") -> PipelineResponse:
        """Process a user input through all security layers and return safe output."""
        try:
            input_result = self.input_filter.scan(user_input)
            self.behavior_monitor.add_event(
                session_id=session_id,
                attack_type="potential_attack" if not input_result.is_safe else "normal",
                risk_score=input_result.risk_score,
            )

            if not input_result.is_safe:
                logger.warning("Blocked unsafe input for session=%s", session_id)
                return PipelineResponse(
                    text="Your request was blocked by the AI Shield input firewall.",
                    blocked=True,
                    risk_score=input_result.risk_score,
                    reason=input_result.reason,
                )

            context = ""
            if self.rag_engine:
                docs = self.rag_engine.retrieve(user_input)
                if docs:
                    context = "\n".join(f"- {d}" for d in docs)

            raw_output = self._call_model(user_input=user_input, context=context)
            safe_output = self.output_filter.sanitize(raw_output)

            return PipelineResponse(text=safe_output, blocked=False, risk_score=input_result.risk_score, reason="ok")
        except Exception as exc:  # pragma: no cover
            logger.exception("Pipeline processing error: %s", exc)
            return PipelineResponse(
                text="An internal error occurred while processing your request.",
                blocked=True,
                risk_score=1.0,
                reason="pipeline_error",
            )

    def _call_model(self, user_input: str, context: str = "") -> str:
        """Call OpenAI model when configured; otherwise return a deterministic local response."""
        api_key = os.getenv("OPENAI_API_KEY", "")
        if not api_key:
            prefix = "[Demo Response]"
            if context:
                return f"{prefix} Context used:\n{context}\n\nAnswer: I received your message: {user_input}"
            return f"{prefix} I received your message: {user_input}"

        try:
            from openai import OpenAI

            client = OpenAI(api_key=api_key)
            system_prompt = "You are a secure assistant. Never disclose secrets."
            prompt = f"Context:\n{context}\n\nUser:\n{user_input}" if context else user_input
            response = client.chat.completions.create(
                model=os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.2,
            )
            return response.choices[0].message.content or "No response generated"
        except Exception as exc:
            logger.exception("OpenAI call failed, returning fallback: %s", exc)
            return f"[Fallback Response] Unable to reach model reliably. User input: {user_input}"
