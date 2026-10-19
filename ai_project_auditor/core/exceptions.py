"""
Custom exception hierarchy for AI Project Auditor V2.
"""


class AuditorError(Exception):
    """Base class for expected, user-facing auditor failures."""
    exit_code: int = 1


# Backwards-compatible name used by the first V2 modules.  New code should
# inherit from AuditorError so the CLI has a single predictable boundary.
AuditorBaseError = AuditorError


class ConfigurationError(AuditorError):
    """Raised when application configuration is invalid."""
    exit_code = 2


class ChecklistError(AuditorError):
    """Raised when a checklist cannot be loaded or validated."""
    exit_code = 3


class ChecklistNotFoundError(ChecklistError):
    """Raised when the Excel checklist file cannot be found or opened."""
    exit_code = 3


class RepositoryError(AuditorError):
    """Raised when a repository cannot be accessed or cloned."""
    exit_code = 4


class InvalidProjectPathError(RepositoryError):
    """Raised when the local project path does not exist or is not accessible."""
    exit_code = 2


class InvalidGitHubURLError(RepositoryError):
    """Raised when a GitHub URL fails validation."""
    exit_code = 4


class ProviderError(AuditorError):
    """Raised when a configured LLM provider cannot complete a request."""
    exit_code = 5


class LLMProviderError(ProviderError):
    """Raised when an LLM provider fails and the error is non-recoverable."""
    exit_code = 5


class AuditError(AuditorError):
    """Raised when the audit pipeline cannot complete."""


class ReportError(AuditorError):
    """Raised when a requested report cannot be generated."""
    """Raised when a report output file cannot be created."""
    exit_code = 6


class ReportGenerationError(ReportError):
    """Compatibility name for report generation failures."""
