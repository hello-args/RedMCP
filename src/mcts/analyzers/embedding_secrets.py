"""Optional semantic credential detection (MCTS-M-025 / MCTS-T-1022)."""

from __future__ import annotations

import re
from typing import Any

from mcts.analyzers.base import BaseAnalyzer
from mcts.analyzers.data_leakage import SECRET_PATTERNS
from mcts.mcp.models import MCPServerInfo
from mcts.reporting.models import Finding, Severity, SourceLocation

CREDENTIAL_KEYWORDS: tuple[str, ...] = (
    "api_key",
    "api key",
    "secret_key",
    "secret key",
    "access_token",
    "auth_token",
    "password",
    "credential",
    "private_key",
    "bearer",
)

SEMANTIC_REFERENCE_PHRASES: tuple[str, ...] = (
    "store your openai api key here",
    "include the secret token",
    "paste your credentials",
    "send the password to",
    "load environment secrets",
)

_OBFUSCATED_SECRET = re.compile(r"(?i)(sk-[a-z0-9-]{10,}|ghp_[a-z0-9]{20,}|AKIA[0-9A-Z]{12,})")


class EmbeddingSecretsAnalyzer(BaseAnalyzer):
    """Detect credential-like content using regex + optional semantic similarity."""

    name = "embedding_secrets"

    def __init__(self, semantic_secrets: bool = False, semantic_threshold: float = 0.75) -> None:
        self.semantic_secrets = semantic_secrets
        self.semantic_threshold = semantic_threshold

    def analyze(self, server: MCPServerInfo) -> list[Finding]:
        findings: list[Finding] = []
        for tool in server.tools:
            corpus = _tool_corpus(tool)
            if _regex_credential_hit(corpus):
                findings.append(_finding(tool, "regex_credential", 0.9))
                continue
            if self.semantic_secrets and _semantic_credential_hit(corpus, self.semantic_threshold):
                findings.append(_finding(tool, "semantic_credential", 0.8))
        return findings


def _tool_corpus(tool: Any) -> str:
    parts = [tool.name, tool.description]
    if isinstance(tool.input_schema, dict):
        parts.append(str(tool.input_schema))
    if tool.handler_snippet:
        parts.append(tool.handler_snippet)
    return "\n".join(parts)


def _regex_credential_hit(text: str) -> bool:
    for _, pattern, _ in SECRET_PATTERNS:
        if pattern.search(text):
            return True
    if _OBFUSCATED_SECRET.search(text):
        return True
    lowered = text.lower()
    return sum(1 for keyword in CREDENTIAL_KEYWORDS if keyword in lowered) >= 2


def _semantic_credential_hit(text: str, threshold: float) -> bool:
    lowered = text.lower()
    if any(phrase in lowered for phrase in SEMANTIC_REFERENCE_PHRASES):
        return True

    try:
        import numpy as np
        from sentence_transformers import SentenceTransformer
    except ImportError:
        return False

    model = SentenceTransformer("all-MiniLM-L6-v2")
    text_embedding = model.encode([text], normalize_embeddings=True)[0]
    ref_embeddings = model.encode(list(SEMANTIC_REFERENCE_PHRASES), normalize_embeddings=True)
    similarities = np.dot(ref_embeddings, text_embedding)
    return bool((similarities >= threshold).any())


def _finding(tool: Any, mode: str, confidence: float) -> Finding:
    return Finding(
        id=f"embed-secret-{tool.name}",
        analyzer="embedding_secrets",
        title=f"Credential-like content in {tool.name}",
        description="Tool metadata resembles embedded secrets or credential harvesting instructions.",
        severity=Severity.HIGH,
        tool=tool.name,
        recommendation="Remove secrets from tool metadata; sanitize embeddings before storage (MCTS-M-025).",
        technique_id="MCTS-T-1022",
        confidence=confidence,
        location=SourceLocation(file=tool.source_file or "", line=tool.source_line),
        evidence={"mode": mode},
    )
