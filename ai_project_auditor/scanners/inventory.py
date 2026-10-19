"""
Project inventory — discovers and categorizes all files in the audited project.
"""

import os
from pathlib import Path
from typing import Dict, List, Set

_SKIP_DIRS: Set[str] = {
    ".git", ".venv", "venv", "env", "__pycache__", "node_modules",
    ".pytest_cache", "dist", "build", ".tox", ".mypy_cache", ".eggs",
}

_SKIP_EXTENSIONS: Set[str] = {
    ".pyc", ".pyo", ".pyd", ".so", ".dll", ".exe", ".bin",
    ".jpg", ".jpeg", ".png", ".gif", ".svg", ".ico", ".woff", ".woff2",
    ".ttf", ".eot", ".mp4", ".mp3", ".zip", ".tar", ".gz", ".bz2",
    ".pdf", ".xlsx", ".xls", ".doc", ".docx",
}

_MAX_FILE_SIZE = 2 * 1024 * 1024  # 2 MB


class ProjectInventory:
    """Walks the project directory and categorizes all discovered files."""

    def __init__(self, project_path: str) -> None:
        self.root = Path(project_path).resolve()
        self.all_files: List[Path] = []
        self.source_files: List[Path] = []
        self.config_files: List[Path] = []
        self.test_files: List[Path] = []
        self.doc_files: List[Path] = []
        self.total_lines: int = 0
        self.skipped_files: int = 0
        self.extension_breakdown: Dict[str, int] = {}

    def discover(self) -> "ProjectInventory":
        """Walk the project tree and populate categorized file lists."""
        for root, dirs, fnames in os.walk(self.root):
            dirs[:] = [d for d in dirs if d not in _SKIP_DIRS and not d.startswith(".")]
            for fname in fnames:
                fpath = Path(root) / fname
                ext = fpath.suffix.lower()

                if ext in _SKIP_EXTENSIONS:
                    self.skipped_files += 1
                    continue

                try:
                    if fpath.stat().st_size > _MAX_FILE_SIZE:
                        self.skipped_files += 1
                        continue
                except OSError:
                    continue

                self.all_files.append(fpath)
                self.extension_breakdown[ext] = self.extension_breakdown.get(ext, 0) + 1

                # Categorize
                rel = str(fpath.relative_to(self.root))
                rel_low = rel.lower()

                if self._is_test_file(fpath, rel_low):
                    self.test_files.append(fpath)
                elif self._is_config_file(fpath, rel_low):
                    self.config_files.append(fpath)
                elif self._is_doc_file(ext, rel_low):
                    self.doc_files.append(fpath)
                elif ext in (".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".sql", ".sh"):
                    self.source_files.append(fpath)

        # Count lines of code
        self.total_lines = self._count_lines(self.source_files)
        return self

    # Compatibility views for scanners retained from the pre-V2 inventory.
    # They intentionally return root-relative strings because those scanners
    # call read_file(), while the V2 scanners use the Path collections above.
    @property
    def root_path(self) -> str:
        return str(self.root)

    def _relative_matching(self, suffixes: tuple[str, ...]) -> List[str]:
        return [str(path.relative_to(self.root)) for path in self.all_files if path.suffix.lower() in suffixes]

    @property
    def python_files(self) -> List[str]:
        return self._relative_matching((".py",))

    @property
    def js_ts_files(self) -> List[str]:
        return self._relative_matching((".js", ".jsx", ".ts", ".tsx"))

    @property
    def docker_files(self) -> List[str]:
        return [str(path.relative_to(self.root)) for path in self.all_files if path.name.lower() in ("dockerfile", "docker-compose.yml", "docker-compose.yaml")]

    @property
    def ci_files(self) -> List[str]:
        return [str(path.relative_to(self.root)) for path in self.all_files if ".github" in path.parts]

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #

    def _is_test_file(self, path: Path, rel_low: str) -> bool:
        parts = path.parts
        return (
            "tests" in parts
            or "test" in parts
            or path.name.startswith("test_")
            or path.name.endswith("_test.py")
            or path.name.endswith(".spec.ts")
            or path.name.endswith(".spec.js")
            or path.name.endswith(".test.ts")
            or path.name.endswith(".test.js")
        )

    def _is_config_file(self, path: Path, rel_low: str) -> bool:
        config_names = {
            "requirements.txt", "pyproject.toml", "setup.py", "setup.cfg",
            "package.json", "package-lock.json", "yarn.lock",
            "dockerfile", "docker-compose.yml", "docker-compose.yaml",
            ".env", ".env.example", ".gitignore", ".gitattributes",
            "makefile", ".editorconfig", "tox.ini", "pytest.ini",
            "tsconfig.json", "jsconfig.json", ".eslintrc.json",
            ".eslintrc.js", ".prettierrc",
        }
        ext = path.suffix.lower()
        return (
            path.name.lower() in config_names
            or ext in (".toml", ".cfg", ".ini", ".yaml", ".yml")
            or ".github" in path.parts
        )

    def _is_doc_file(self, ext: str, rel_low: str) -> bool:
        return ext in (".md", ".rst", ".txt") and "readme" not in rel_low.split("/")[-1]

    def _count_lines(self, files: List[Path]) -> int:
        total = 0
        for fpath in files:
            try:
                content = fpath.read_bytes()
                total += content.count(b"\n")
            except OSError:
                pass
        return total

    def read_source_file(self, path: Path) -> str:
        """Safely read a source file, returning empty string on error."""
        try:
            return path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return ""

    def read_file(self, relative_path: str) -> str:
        """Read a root-relative file for legacy deterministic scanners."""
        return self.read_source_file(self.root / relative_path)
