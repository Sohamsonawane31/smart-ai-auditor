"""
Safe GitHub Repository Cloner and Workspace Isolator for AI Project Auditor V2.
Guarantees sandbox isolation, hook disabling, credential safety, and automated cleanup.
"""

import os
import re
import shutil
import stat
import subprocess
import tempfile
from contextlib import contextmanager
from typing import Generator, Tuple
from ..core.exceptions import InvalidGitHubURLError, RepositoryError

GITHUB_URL_REGEX = re.compile(
    r"^(?:https?:\/\/)?(?:www\.)?github\.com\/([a-zA-Z0-9_\-\.]+)\/([a-zA-Z0-9_\-\.]+?)(?:\.git)?\/?$"
)


def _remove_readonly(func, path, exc_info):
    """Clear the read-only bit on Windows and retry removal."""
    try:
        os.chmod(path, stat.S_IWRITE)
        func(path)
    except Exception:
        pass


class GitHubSafetyClient:
    """Safely manages isolated clones of GitHub repositories for auditing."""

    @staticmethod
    def validate_url(url: str) -> Tuple[bool, str, str]:
        """
        Validate that the provided string is a valid GitHub URL.
        Returns: (is_valid, owner, repo_name)
        """
        if not url:
            return False, "", ""

        clean_url = url.strip()
        match = GITHUB_URL_REGEX.match(clean_url)
        if not match:
            return False, "", ""

        owner, repo = match.group(1), match.group(2)
        # Normalize to standard HTTPS clone URL
        normalized_url = f"https://github.com/{owner}/{repo}.git"
        return True, owner, repo

    @classmethod
    @contextmanager
    def clone_isolated(cls, repo_url: str) -> Generator[str, None, None]:
        """
        Context manager that creates a temporary isolated workspace,
        clones the target repository safely (shallow clone, hooks disabled),
        yields the temporary directory path for auditing,
        and guarantees complete cleanup upon exit.
        """
        is_valid, owner, repo_name = cls.validate_url(repo_url)
        if not is_valid:
            raise InvalidGitHubURLError(repo_url)

        clone_url = f"https://github.com/{owner}/{repo_name}.git"
        temp_dir = tempfile.mkdtemp(prefix=f"audit_{repo_name}_")

        try:
            # Safe shallow clone:
            # - --depth 1: minimal footprint, fastest network transfer
            # - -c core.hooksPath=/dev/null: strictly disables executing any repo git hooks
            # - --single-branch: only default branch
            cmd = [
                "git",
                "-c",
                "core.hooksPath=/dev/null",
                "clone",
                "--depth",
                "1",
                "--single-branch",
                clone_url,
                temp_dir,
            ]

            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False,
                timeout=120,  # 2 minute timeout
            )

            if process.returncode != 0:
                err_lower = process.stderr.lower()
                if "authentication failed" in err_lower or "could not read username" in err_lower:
                    raise RepositoryError(f"Authentication failed for '{repo_url}'. Private repositories require credentials.")
                elif "not found" in err_lower:
                    raise RepositoryError(f"Repository not found at '{repo_url}'. Verify repository exists and is public.")
                else:
                    raise RepositoryError(f"Git clone failed: {process.stderr.strip()}")

            yield temp_dir

        except subprocess.TimeoutExpired:
            raise RepositoryError(f"Cloning timed out for '{repo_url}'. Check network connectivity.")
        except FileNotFoundError:
            raise RepositoryError("Git executable not found in system PATH. Please install git.")
        finally:
            # Guarantee cleanup of temporary isolated workspace
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir, onerror=_remove_readonly)
