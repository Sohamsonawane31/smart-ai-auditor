"""
Tests for GitHub client safety, URL validation, and workspace isolation.
"""

import pytest
from ai_project_auditor.github.client import GitHubSafetyClient
from ai_project_auditor.core.exceptions import InvalidGitHubURLError


def test_validate_valid_github_urls():
    valid_cases = [
        ("https://github.com/fastapi/fastapi", "fastapi", "fastapi"),
        ("https://github.com/torvalds/linux.git", "torvalds", "linux"),
        ("http://www.github.com/psf/requests/", "psf", "requests"),
        ("github.com/langchain-ai/langchain", "langchain-ai", "langchain"),
    ]
    for url, exp_owner, exp_repo in valid_cases:
        is_val, owner, repo = GitHubSafetyClient.validate_url(url)
        assert is_val is True
        assert owner == exp_owner
        assert repo == exp_repo


def test_validate_invalid_github_urls():
    invalid_cases = [
        "https://gitlab.com/user/project",
        "https://bitbucket.org/user/repo",
        "https://github.com/",
        "ftp://github.com/test/test",
        "",
        "not_a_url",
    ]
    for url in invalid_cases:
        is_val, _, _ = GitHubSafetyClient.validate_url(url)
        assert is_val is False


def test_clone_isolated_raises_on_invalid_url():
    with pytest.raises(InvalidGitHubURLError):
        with GitHubSafetyClient.clone_isolated("https://invalid.com/bad/repo"):
            pass
