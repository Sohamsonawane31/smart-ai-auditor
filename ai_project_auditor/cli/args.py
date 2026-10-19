"""
Advanced Command Line Interface parser and runner for AI Project Auditor V2.
"""

import argparse
import sys
import os
from typing import List, Optional

from ..core.engine import AuditEngine
from ..core.exceptions import AuditorError
from ..core.config import AuditorConfig
from ..github.client import GitHubSafetyClient
from ..providers import get_provider
from ..utils.logger import setup_logger
from ..utils.console import (
    print_banner,
    print_step,
    print_success,
    print_error,
    print_finding_summary_line,
    Colors,
)

VERSION = "2.0.0"


def build_parser() -> argparse.ArgumentParser:
    """Build and configure the command-line argument parser."""
    parser = argparse.ArgumentParser(
        prog="audit.py",
        description="AI Project Auditor V2 - Deterministic & AI-Powered Software Architecture Auditor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python audit.py --repo "D:\\Projects\\MyApp"
  python audit.py --github "https://github.com/user/repository"
  python audit.py --repo "D:\\Projects\\MyApp" --provider offline
  python audit.py --repo "D:\\Projects\\MyApp" --provider nvidia
  python audit.py --repo "D:\\Projects\\MyApp" --provider opencode
  python audit.py --repo "D:\\Projects\\MyApp" --checklist custom.xlsx
  python audit.py --repo "D:\\Projects\\MyApp" --format json,markdown
  python audit.py --repo "D:\\Projects\\MyApp" --verbose
""",
    )

    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--repo",
        "-r",
        metavar="PATH",
        type=str,
        help="Path to local software project to audit",
    )
    group.add_argument(
        "--github",
        "-g",
        metavar="URL",
        type=str,
        help="GitHub repository URL to clone and audit in an isolated workspace",
    )

    parser.add_argument(
        "--provider",
        "-p",
        choices=["offline", "nvidia", "opencode"],
        default="offline",
        help="LLM mode: offline (no API key), nvidia (NVIDIA_API_KEY), or opencode (OPENCODE_API_KEY)",
    )
    parser.add_argument(
        "--checklist",
        "-c",
        metavar="FILE",
        type=str,
        default=None,
        help="Path to custom audit checklist Excel file (.xlsx)",
    )
    parser.add_argument(
        "--format",
        "-f",
        default="markdown,json,excel,pdf",
        help="Comma-separated report formats: json, markdown, excel, pdf, all (default: all)",
    )
    parser.add_argument(
        "--output",
        "-o",
        metavar="DIR",
        default="reports",
        help="Directory to save generated reports (default: reports)",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable detailed debug logging",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"AI Project Auditor V2 - Version {VERSION}",
    )

    return parser


def run_cli(argv: Optional[List[str]] = None) -> int:
    """Parse CLI arguments and execute the audit."""
    parser = build_parser()
    args = parser.parse_args(argv)

    setup_logger(verbose=args.verbose)
    AuditorConfig.load_env()

    # If no source provided, return -1 indicating interactive mode should run
    if not args.repo and not args.github:
        return -1

    print_banner()

    formats = [fmt.strip().lower() for fmt in args.format.split(",") if fmt.strip()]
    provider = get_provider(args.provider)
    if provider and not provider.is_available():
        key_name = "NVIDIA_API_KEY" if args.provider == "nvidia" else "OPENCODE_API_KEY"
        print_error(f"{key_name} is missing or invalid. Add it to .env, or use --provider offline for static auditing.")
        return 5

    try:
        if args.repo:
            print_step(f"Auditing Local Project: {args.repo}")
            engine = AuditEngine(
                project_path=args.repo,
                checklist_path=args.checklist,
                provider=provider,
                output_dir=args.output,
                formats=formats,
            )
            report, report_files = engine.run()

        elif args.github:
            print_step(f"Cloning and Auditing GitHub Repository: {args.github}")
            with GitHubSafetyClient.clone_isolated(args.github) as temp_workspace:
                engine = AuditEngine(
                    project_path=temp_workspace,
                    checklist_path=args.checklist,
                    provider=provider,
                    output_dir=args.output,
                    formats=formats,
                    audit_source="GitHub repository",
                )
                report, report_files = engine.run()

        # Display summary results in terminal
        _display_cli_summary(report, report_files)
        return 0

    except AuditorError as e:
        print_error(str(e))
        return e.exit_code
    except KeyboardInterrupt:
        print_error("\nAudit interrupted by user.")
        return 130
    except Exception as e:
        print_error(f"Unexpected error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


def _display_cli_summary(report, report_files) -> None:
    """Print clean results summary to stdout."""
    risk = report.risk_summary
    print("\n" + "=" * 70)
    print(f" AUDIT COMPLETE: {report.project_name}")
    print("=" * 70)
    print(f" Primary Language : {report.technology_profile.primary_language}")
    print(f" Discovered Files : {report.statistics.total_files} ({report.statistics.scanned_files} scanned)")
    print(f" Checks Evaluated : {len(report.executed_check_ids)} active")
    print(f" Overall Risk     : {risk.risk_level.upper()} (Score: {risk.risk_score}/100)")
    print(
        f" Severity Breakdown: Critical: {risk.critical} | High: {risk.high} | "
        f"Medium: {risk.medium} | Low: {risk.low} | Info: {risk.info}"
    )

    if report.findings:
        print(f"\n Key Findings ({min(10, len(report.findings))} of {len(report.findings)} shown):")
        for f in report.findings[:10]:
            print_finding_summary_line(f)
        if len(report.findings) > 10:
            print(f"  ... and {len(report.findings) - 10} more in full reports.")

    print("\n Generated Reports:")
    for fmt, p in report_files.items():
        print(f"  [OK] [{fmt.upper()}]: {p}")
    print("=" * 70 + "\n")
