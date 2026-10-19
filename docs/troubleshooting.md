# Troubleshooting

## Environment

If Python or Streamlit resolves to another installation, activate `.venv` and
use `python -m streamlit`, not a globally installed executable. Run
`python -m pip check` after installing dependencies.

## Targets and reports

A GitHub URL must be entered as a GitHub URL, not a local path. For manual
imports select one compatible JSON report file; a report directory is only for
discovery. Managed runs always add JSON for automatic import.

## Provider failures

Set the matching key in `.env` and restart the process. Authentication errors,
rate limits, timeouts, malformed provider replies, and unavailable networks are
reported as failures; use offline mode if an external provider is unavailable.

## Recovery

After an interruption, retry a failed or interrupted run from the UI. Do not
delete a lock or mark an unknown run interrupted unless you have confirmed its
execution stopped.
