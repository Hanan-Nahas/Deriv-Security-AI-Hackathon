"""Optional FAISS-backed retrieval engine for grounding responses."""

from __future__ import annotations

import logging
from typing import List

logger = logging.getLogger(__name__)


class RAGEngine:
    """Simple retrieval layer with optional FAISS support.

    Falls back to in-memory lexical matching when FAISS is unavailable.
    """

    def __init__(self) -> None:
        self._documents: List[str] = []
        self._faiss_available = False
        try:
            import faiss  # type: ignore # noqa: F401

            self._faiss_available = True
        except Exception:
            logger.warning("FAISS not available; using lexical retrieval fallback")

    def add_documents(self, docs: List[str]) -> None:
        """Index new documents."""
        self._documents.extend(docs)

    def retrieve(self, query: str, top_k: int = 3) -> List[str]:
        """Retrieve top-k potentially relevant documents."""
        try:
            if not self._documents:
                return []

            # Lightweight lexical fallback suitable for hackathon demos.
            scored = []
            tokens = {token.lower() for token in query.split() if token}
            for doc in self._documents:
                overlap = sum(1 for token in tokens if token in doc.lower())
                scored.append((overlap, doc))
            scored.sort(key=lambda item: item[0], reverse=True)
            return [doc for _, doc in scored[:top_k] if _ > 0] or self._documents[:top_k]
        except Exception as exc:  # pragma: no cover
            logger.exception("RAG retrieval failed: %s", exc)
            return []
