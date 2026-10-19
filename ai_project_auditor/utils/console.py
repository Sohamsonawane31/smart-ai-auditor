"""
Console formatting, terminal banners, and colored output helpers.
Safe across Windows CP1252 and UTF-8 terminals.
"""

import sys
import os

# Enable UTF-8 streams and ANSI on Windows where supported
if sys.platform == "win32":
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    if hasattr(sys.stderr, "reconfigure"):
        try:
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    os.system("")  # Activates VT100 in Windows cmd/powershell


class Colors:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"


def print_banner() -> None:
    banner = f"""
{Colors.CYAN}{Colors.BOLD}======================================================================
                     AI PROJECT AUDITOR V2
        Deterministic & AI-Powered Software Architecture Auditor
======================================================================{Colors.RESET}"""
    print(banner)


def print_step(title: str) -> None:
    print(f"\n{Colors.BOLD}{Colors.BLUE}[>] {title}{Colors.RESET}")


def print_success(message: str) -> None:
    print(f"{Colors.GREEN}[+] {message}{Colors.RESET}")


def print_warning(message: str) -> None:
    print(f"{Colors.YELLOW}[!] {message}{Colors.RESET}")


def print_error(message: str) -> None:
    print(f"{Colors.RED}[X] {message}{Colors.RESET}")


def severity_color(sev: str) -> str:
    s = str(sev).lower()
    if s == "critical":
        return Colors.RED + Colors.BOLD
    elif s == "high":
        return Colors.YELLOW + Colors.BOLD
    elif s == "medium":
        return Colors.YELLOW
    elif s == "low":
        return Colors.BLUE
    return Colors.DIM


def print_finding_summary_line(finding) -> None:
    sev = finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity)
    color = severity_color(sev)
    loc = f"{finding.file}:{finding.line}" if finding.line else finding.file
    print(
        f"  [{color}{sev.upper():<8}{Colors.RESET}] "
        f"{Colors.BOLD}{finding.check_id:<8}{Colors.RESET} "
        f"{finding.title[:45]:<45} "
        f"{Colors.DIM}({loc}){Colors.RESET}"
    )
