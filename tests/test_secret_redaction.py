"""
Tests for Secret Protection and Redaction Engine.
Ensures zero credentials leak into prompts, reports, or logs.
"""

import pytest
from ai_project_auditor.security.redactor import SecretRedactor
from ai_project_auditor.models.finding import Finding, FindingSeverity, FindingConfidence, DetectionMethod


def test_redact_anthropic_key():
    raw = 'ANTHROPIC_API_KEY = "sk-ant-api03-abcdef1234567890abcdef1234567890"'
    clean = SecretRedactor.redact(raw)
    assert "sk-ant-" not in clean
    assert "[REDACTED_ANTHROPIC_KEY]" in clean


def test_redact_openai_key():
    raw = 'OPENAI_KEY = "sk-proj-abcde1234567890fghij1234567890"'
    clean = SecretRedactor.redact(raw)
    assert "sk-proj-" not in clean
    assert "[REDACTED_OPENAI_KEY]" in clean


def test_redact_github_token():
    raw = 'token = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"'
    clean = SecretRedactor.redact(raw)
    assert "ghp_" not in clean
    assert "[REDACTED_GITHUB_TOKEN]" in clean


def test_redact_aws_key():
    raw = 'aws_access = "AKIA1234567890ABCDEF"'
    clean = SecretRedactor.redact(raw)
    assert "AKIA" not in clean
    assert "[REDACTED_AWS_KEY_ID]" in clean


def test_redact_database_password():
    raw = "DATABASE_URL = 'postgresql://admin:super_secret_password_123@db.internal:5432/production'"
    clean = SecretRedactor.redact(raw)
    assert "super_secret_password_123" not in clean
    assert "[REDACTED_PASSWORD]" in clean


def test_redact_private_key():
    raw = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Y3b+X1b...
-----END RSA PRIVATE KEY-----"""
    clean = SecretRedactor.redact(raw)
    assert "BEGIN RSA PRIVATE KEY" not in clean
    assert "[REDACTED_PRIVATE_KEY]" in clean


def test_redact_generic_secret_assignment():
    raw = 'api_secret = "mysupersecretkey123456"'
    clean = SecretRedactor.redact(raw)
    assert "mysupersecretkey123456" not in clean
    assert "[REDACTED_SECRET]" in clean


def test_redact_finding_in_place():
    f = Finding(
        finding_id="FIND-001",
        check_id="SEC-001",
        title="Hardcoded API key sk-ant-api03-abcdef1234567890abcdef",
        category="Security",
        severity=FindingSeverity.CRITICAL,
        confidence=FindingConfidence.HIGH,
        file="config.py",
        line=10,
        evidence='api_key = "sk-ant-api03-abcdef1234567890abcdef"',
        description="Leaked sk-ant-api03-abcdef1234567890abcdef in config",
        impact="Compromised sk-ant-api03-abcdef1234567890abcdef",
        recommendation="Revoke sk-ant-api03-abcdef1234567890abcdef immediately",
    )
    SecretRedactor.redact_finding(f)
    assert "sk-ant-" not in f.title
    assert "sk-ant-" not in f.evidence
    assert "sk-ant-" not in f.description
    assert "sk-ant-" not in f.impact
    assert "sk-ant-" not in f.recommendation
    assert "[REDACTED_ANTHROPIC_KEY]" in f.evidence
