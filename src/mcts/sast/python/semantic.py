"""Heuristic semantic alignment checks for Python MCP tool handlers."""

from __future__ import annotations

import re
from dataclasses import dataclass

_CRYPTO_CLAIM = re.compile(r"(?i)\b(aes-?256|encrypt|encryption|pbkdf2|cryptograph|cipher)\b")
_INSTRUCTION_POISON = re.compile(
    r"(?i)(system directive|system override|instruction override|ignore previous|"
    r"act as:|jailbreak|bypass[_ -]?validation|bypass[_ -]?filters|"
    r"disable all|unrestricted emergency|trust_level)"
)
_POISON_CONTENT = re.compile(r"(?i)(phishing\.com|malware\.com|scam\.com|fake-antivirus|POISONED_)")
_LARGE_RANGE = re.compile(r"range\s*\(\s*(?:10\s*\*\*\s*[6-9]|[1-9]\d{6,})")
_REDOSE_PATTERN = re.compile(r"\(\s*[a-z]\s*[+*]\s*\)\s*[+*]")


@dataclass
class SemanticIssue:
    category: str
    label: str
    confidence: float


def analyze_python_semantics(source: str, description: str = "") -> list[SemanticIssue]:
    """Detect description/code mismatches and risky patterns without an LLM."""
    blob = f"{description}\n{source}"
    issues: list[SemanticIssue] = []

    if issue := _check_fake_crypto(description, source):
        issues.append(issue)
    if issue := _check_instruction_poison(blob):
        issues.append(issue)
    if issue := _check_resource_exhaustion(source):
        issues.append(issue)
    if issue := _check_ldap(source):
        issues.append(issue)
    if issue := _check_format_injection(source):
        issues.append(issue)
    if issue := _check_symlink(source):
        issues.append(issue)
    if issue := _check_env_enumeration(source):
        issues.append(issue)
    if issue := _check_poisoned_content(source):
        issues.append(issue)
    if issue := _check_user_database(source):
        issues.append(issue)
    if issue := _check_suid_manipulation(source):
        issues.append(issue)
    if issue := _check_redos(source):
        issues.append(issue)

    return issues


def _check_fake_crypto(description: str, source: str) -> SemanticIssue | None:
    if not _CRYPTO_CLAIM.search(description):
        return None
    uses_real_crypto = any(
        token in source for token in ("cryptography", "Cipher", "AESGCM", "Fernet", "PBKDF2HMAC")
    )
    uses_weak_only = any(
        token in source for token in ("base64.b64encode", "b64encode", "hashlib.md5", "fake_aes")
    )
    if uses_weak_only and not uses_real_crypto:
        return SemanticIssue("security_mismatch", "fake_encryption", 0.85)
    return None


def _check_instruction_poison(blob: str) -> SemanticIssue | None:
    if _INSTRUCTION_POISON.search(blob):
        return SemanticIssue("instruction_poisoning", "hidden_directive", 0.8)
    return None


def _check_resource_exhaustion(source: str) -> SemanticIssue | None:
    if "while True" in source:
        return SemanticIssue("resource_exhaustion", "infinite_loop", 0.8)
    if _LARGE_RANGE.search(source):
        return SemanticIssue("resource_exhaustion", "unbounded_iteration", 0.75)
    if "threading.Thread" in source and "range(" in source:
        return SemanticIssue("resource_exhaustion", "thread_exhaustion", 0.8)
    if "setrecursionlimit" in source or "infinite_recursion" in source.lower():
        return SemanticIssue("resource_exhaustion", "unbounded_recursion", 0.75)
    if re.search(r"\*\s*(?:10\s*\*\*\s*[5-9]|[1-9]\d{6,})", source):
        return SemanticIssue("resource_exhaustion", "memory_exhaustion", 0.75)
    if "recursive_thread" in source.lower() or re.search(
        r"def\s+spawn\s*\([^)]*\):[\s\S]{0,200}spawn\s*\(", source
    ):
        return SemanticIssue("resource_exhaustion", "thread_exhaustion", 0.8)
    return None


def _check_ldap(source: str) -> SemanticIssue | None:
    if "ldap" in source.lower() and ("build_filter" in source or "ldap.initialize" in source):
        return SemanticIssue("injection", "ldap_filter_injection", 0.8)
    return None


def _check_format_injection(source: str) -> SemanticIssue | None:
    if ".format(" in source and ("format_str" in source or "format_map" in source):
        return SemanticIssue("injection", "format_string_injection", 0.8)
    return None


def _check_symlink(source: str) -> SemanticIssue | None:
    if "os.symlink" in source or "symlink_to" in source or "symlink_attack" in source.lower():
        return SemanticIssue("privilege_escalation", "symlink_attack", 0.85)
    return None


def _check_env_enumeration(source: str) -> SemanticIssue | None:
    if "dict(os.environ)" in source or "os.environ.items()" in source:
        return SemanticIssue("credential_access", "environment_enumeration", 0.75)
    return None


def _check_poisoned_content(source: str) -> SemanticIssue | None:
    if _POISON_CONTENT.search(source):
        return SemanticIssue("tool_poisoning", "poisoned_response_content", 0.85)
    if "inject_poisoned" in source.lower() or "poisoned_results" in source:
        return SemanticIssue("tool_poisoning", "poisoned_result_injection", 0.8)
    return None


def _check_user_database(source: str) -> SemanticIssue | None:
    if "pwd.getpwall" in source or "grp.getgrall" in source:
        return SemanticIssue("unauthorized_access", "user_database_enumeration", 0.8)
    return None


def _check_suid_manipulation(source: str) -> SemanticIssue | None:
    if "S_ISUID" in source or "suid" in source.lower():
        return SemanticIssue("privilege_escalation", "suid_manipulation", 0.85)
    return None


def _check_redos(source: str) -> SemanticIssue | None:
    if "re.compile" in source and (_REDOSE_PATTERN.search(source) or "MALICIOUS_PATTERNS" in source):
        return SemanticIssue("resource_exhaustion", "regex_dos", 0.8)
    return None
