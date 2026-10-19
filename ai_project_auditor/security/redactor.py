"""
Secret Protection and Redaction Engine for AI Project Auditor V2.
Mandatory security boundary: prevents credentials from leaking to LLMs or reports.
"""

import re
from typing import List, Tuple

# Compiled regex patterns for credential detection and replacement
SECRET_PATTERNS: List[Tuple[re.Pattern, str]] = [
    # Private Keys (PEM, SSH, RSA)
    (
        re.compile(
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
            re.MULTILINE,
        ),
        "[REDACTED_PRIVATE_KEY]",
    ),
    # Anthropic API Keys
    (re.compile(r"sk-ant-[a-zA-Z0-9_\-]{20,}"), "[REDACTED_ANTHROPIC_KEY]"),
    # OpenAI API Keys
    (re.compile(r"sk-(?:proj-)?[a-zA-Z0-9_\-]{20,}"), "[REDACTED_OPENAI_KEY]"),
    # Google API Keys
    (re.compile(r"AIza[0-9A-Za-z\-_]{35}"), "[REDACTED_GOOGLE_API_KEY]"),
    # GitHub Tokens
    (
        re.compile(r"(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{50,}"),
        "[REDACTED_GITHUB_TOKEN]",
    ),
    # AWS Access Key IDs
    (re.compile(r"(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}"), "[REDACTED_AWS_KEY_ID]"),
    # Slack Tokens
    (re.compile(r"xox[baprs]-[0-9a-zA-Z\-]{10,}"), "[REDACTED_SLACK_TOKEN]"),
    # Hugging Face Tokens
    (re.compile(r"hf_[a-zA-Z0-9]{34,}"), "[REDACTED_HF_TOKEN]"),
    # Stripe Keys
    (re.compile(r"(?:sk|pk)_(?:test|live)_[0-9a-zA-Z]{24,}"), "[REDACTED_STRIPE_KEY]"),
    # Database connection URIs with passwords
    (
        re.compile(r"((?:postgres|postgresql|mysql|mongodb|redis|amqp):\/\/[^:\s]+:)([^@\s]+)(@)", re.IGNORECASE),
        r"\1[REDACTED_PASSWORD]\3",
    ),
    # Authorization header tokens
    (
        re.compile(r"((?:Bearer|Basic)\s+)[a-zA-Z0-9_\-\.~+/]{16,}=*", re.IGNORECASE),
        r"\1[REDACTED_TOKEN]",
    ),
    # Generic key-value secret assignments in configs/code (skip already redacted tokens)
    (
        re.compile(
            r"""((?:password|passwd|secret|api_key|apikey|access_token|client_secret|secret_key|auth_token)\s*[:=]\s*["'])(?!\[REDACTED_)([^"'\n\r]{4,})(["'])""",
            re.IGNORECASE,
        ),
        r"\1[REDACTED_SECRET]\3",
    ),
]


class SecretRedactor:
    """Provides methods to sanitize code, evidence, and prompts before external exposure."""

    @classmethod
    def redact(cls, text: str) -> str:
        """
        Redact all detected secrets, tokens, passwords, and private keys from the provided text.
        Safe for use on source snippets, prompt contexts, logs, and report content.
        """
        if not text:
            return ""

        sanitized = text
        for pattern, replacement in SECRET_PATTERNS:
            sanitized = pattern.sub(replacement, sanitized)
        return sanitized

    @classmethod
    def redact_finding(cls, finding) -> None:
        """
        In-place redaction of all sensitive textual fields within a Finding object.
        Ensures reports and logs never contain plaintext credentials.
        """
        finding.evidence = cls.redact(finding.evidence)
        finding.title = cls.redact(finding.title)
        finding.description = cls.redact(finding.description)
        finding.impact = cls.redact(finding.impact)
        finding.recommendation = cls.redact(finding.recommendation)
        if finding.ai_remediation:
            finding.ai_remediation = cls.redact(finding.ai_remediation)
