"""
Interactive Console Interface for AI Project Auditor V2.
Provides guided terminal menus for local projects and GitHub repository auditing.
"""

import sys
import os
from ..core.engine import AuditEngine
from ..core.exceptions import AuditorError
from ..core.config import AuditorConfig
from ..github.client import GitHubSafetyClient
from ..providers import get_provider
from ..utils.console import (
    print_banner,
    print_step,
    print_success,
    print_error,
    print_finding_summary_line,
    Colors,
)
from ..utils.logger import setup_logger


def run_interactive() -> int:
    """Launch the interactive terminal wizard."""
    setup_logger(verbose=False)
    AuditorConfig.load_env()
    print_banner()

    while True:
        print("\nChoose audit source:")
        print("1. Local Project")
        print("2. GitHub Repository")
        print("3. Exit")

        try:
            choice = input(f"\n{Colors.BOLD}Select an option (1-3): {Colors.RESET}").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nExiting.")
            return 0

        if choice == "1":
            return _handle_local_audit()
        elif choice == "2":
            return _handle_github_audit()
        elif choice in ("3", "q", "exit", "quit"):
            print("Exiting AI Project Auditor. Goodbye!")
            return 0
        else:
            print_error("Invalid selection. Please choose 1, 2, or 3.")


def _handle_local_audit() -> int:
    """Prompt for local path and run audit."""
    try:
        path = input(f"\n{Colors.BOLD}Enter project folder path: {Colors.RESET}").strip().strip("'\"")
    except (KeyboardInterrupt, EOFError):
        return 0

    if not path:
        print_error("Path cannot be empty.")
        return 1

    if not os.path.exists(path):
        print_error(f"Directory not found: '{path}'")
        return 1

    provider_name = _prompt_provider()
    formats = _prompt_formats()

    try:
        print_step(f"Starting audit for: {path}")
        provider = get_provider(provider_name)
        if provider and not provider.is_available():
            key_name = "NVIDIA_API_KEY" if provider_name == "nvidia" else "OPENCODE_API_KEY"
            print_error(f"{key_name} is missing or invalid. Select Offline / No LLM to continue without an API key.")
            return 1
        engine = AuditEngine(
            project_path=path,
            provider=provider,
            formats=formats,
        )
        report, report_files = engine.run()
        _display_interactive_results(report, report_files)
        return 0

    except AuditorError as e:
        print_error(str(e))
        return e.exit_code
    except Exception as e:
        print_error(f"Audit failed: {e}")
        return 1


def _handle_github_audit() -> int:
    """Prompt for GitHub URL and safely audit in isolated workspace."""
    try:
        url = input(f"\n{Colors.BOLD}Enter GitHub repository URL (e.g., https://github.com/owner/repo): {Colors.RESET}").strip()
    except (KeyboardInterrupt, EOFError):
        return 0

    if not url:
        print_error("URL cannot be empty.")
        return 1

    is_valid, _, _ = GitHubSafetyClient.validate_url(url)
    if not is_valid:
        print_error(f"Invalid GitHub URL format: '{url}'. Please enter a valid URL like 'https://github.com/user/repo'.")
        return 1

    provider_name = _prompt_provider()
    formats = _prompt_formats()

    try:
        print_step(f"Preparing isolated workspace and cloning repository: {url}")
        with GitHubSafetyClient.clone_isolated(url) as temp_workspace:
            print_success("Repository cloned into isolated sandbox.")
            provider = get_provider(provider_name)
            if provider and not provider.is_available():
                key_name = "NVIDIA_API_KEY" if provider_name == "nvidia" else "OPENCODE_API_KEY"
                print_error(f"{key_name} is missing or invalid. Select Offline / No LLM to continue without an API key.")
                return 1
            engine = AuditEngine(
                project_path=temp_workspace,
                provider=provider,
                formats=formats,
                audit_source="GitHub repository",
            )
            report, report_files = engine.run()

        print_success("Temporary isolated workspace safely destroyed.")
        _display_interactive_results(report, report_files)
        return 0

    except AuditorError as e:
        print_error(str(e))
        return e.exit_code
    except Exception as e:
        print_error(f"GitHub audit failed: {e}")
        return 1


def _prompt_provider() -> str:
    """Optionally ask user for LLM provider or default to deterministic."""
    print(f"\n{Colors.DIM}Choose LLM Provider:")
    print("1. Offline / No LLM (static audit; no API key required)")
    print("2. NVIDIA (requires NVIDIA_API_KEY in .env)")
    print("3. OpenCode Zen (requires OPENCODE_API_KEY in .env)")
    try:
        ans = input("Select provider [1-3, Default=1]: ").strip()
    except (KeyboardInterrupt, EOFError):
        return "offline"

    if ans == "2":
        return "nvidia"
    elif ans == "3":
        return "opencode"
    return "offline"


def _prompt_formats() -> list:
    """Return report formats list."""
    return ["markdown", "json", "excel", "pdf"]


def _display_interactive_results(report, report_files) -> None:
    """Print results banner and report links."""
    risk = report.risk_summary
    print("\n" + "=" * 70)
    print(f" AUDIT COMPLETE: {report.project_name}")
    print("=" * 70)
    print(f" Primary Language : {report.technology_profile.primary_language}")
    print(f" Total Files      : {report.statistics.total_files} ({report.statistics.scanned_files} scanned)")
    print(f" Active Checks    : {len(report.executed_check_ids)}")
    print(f" Risk Assessment  : {risk.risk_level.upper()} (Risk Score: {risk.risk_score} / 100)")
    print(
        f" Severity Counts  : Critical: {risk.critical} | High: {risk.high} | "
        f"Medium: {risk.medium} | Low: {risk.low} | Info: {risk.info}"
    )

    if report.findings:
        print(f"\n Key Findings ({min(8, len(report.findings))} of {len(report.findings)}):")
        for f in report.findings[:8]:
            print_finding_summary_line(f)
        if len(report.findings) > 8:
            print(f"  ... plus {len(report.findings) - 8} more in full reports.")
    else:
        print_success("No issues or vulnerabilities detected!")

    print("\n Generated Reports:")
    for fmt, p in report_files.items():
        print(f"  [OK] {fmt.upper()}: {p}")
    print("=" * 70 + "\n")
