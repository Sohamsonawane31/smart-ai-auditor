"""
Tests for CLI execution and argument handling.
"""

import tempfile
import os
from pathlib import Path
from ai_project_auditor.cli.args import run_cli


def test_cli_help():
    assert run_cli([]) == -1  # Triggers interactive mode when no args given


def test_cli_audit_local_repo():
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        (tmp_path / "main.py").write_text("import os\nprint('hello world')", encoding="utf-8")
        (tmp_path / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")

        out_dir = os.path.join(tmp_dir, "test_reports")
        exit_code = run_cli([
            "--repo", tmp_dir,
            "--format", "json,markdown",
            "--output", out_dir,
        ])
        assert exit_code == 0
        assert os.path.exists(out_dir)
        assert any(f.endswith(".json") for f in os.listdir(out_dir))
        assert any(f.endswith(".md") for f in os.listdir(out_dir))


def test_cli_invalid_repo_path():
    exit_code = run_cli([
        "--repo", "non_existent_folder_xyz_12345",
    ])
    assert exit_code == 2  # InvalidProjectPathError code
