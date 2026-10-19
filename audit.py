#!/usr/bin/env python3
"""
AI Project Auditor V2
Root entrypoint for Interactive and Advanced CLI auditing.
"""

import sys
from ai_project_auditor.cli.args import run_cli
from ai_project_auditor.cli.interactive import run_interactive


def main() -> None:
    """Main application dispatcher."""
    # If no arguments provided, start interactive CLI
    if len(sys.argv) == 1:
        code = run_interactive()
        sys.exit(code)

    # Otherwise, execute advanced CLI
    code = run_cli()
    if code == -1:
        # User provided non-execution flags, or no target repo/github specified
        code = run_interactive()
    sys.exit(code)


if __name__ == "__main__":
    main()
