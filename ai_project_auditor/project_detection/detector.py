"""
Project and technology stack detector.

Uses file extensions, dependency files, configuration files and source
imports to build a TechnologyProfile for the audited repository.
"""

import os
import re
from pathlib import Path
from typing import List, Set

from ai_project_auditor.models.technology import TechnologyProfile

# Directories to skip during detection
_SKIP_DIRS: Set[str] = {
    ".git", ".venv", "venv", "env", "__pycache__", "node_modules",
    ".pytest_cache", "dist", "build", ".tox", ".mypy_cache",
}

# File names / patterns to skip during import scanning
_SKIP_TEST_PATTERNS = re.compile(r"(^test_|_test\.py$|spec\.(js|ts)$)", re.IGNORECASE)


class ProjectDetector:
    """Detects the technology stack of a software project."""

    def __init__(self, project_path: str) -> None:
        self.root = Path(project_path).resolve()

    def detect(self) -> TechnologyProfile:
        profile = TechnologyProfile()

        all_files = self._collect_files()
        extensions = {f.suffix.lower() for f in all_files}
        filenames = {f.name.lower() for f in all_files}
        all_text_files = [
            f for f in all_files
            if f.suffix.lower() in (".py", ".js", ".ts", ".jsx", ".tsx", ".java",
                                     ".txt", ".toml", ".yaml", ".yml", ".json", ".env", ".cfg", ".ini")
        ]

        # ------------------------------------------------------------------ #
        # Language detection
        # ------------------------------------------------------------------ #
        if ".py" in extensions:
            profile.python = True
            profile.primary_language = "Python"

        if ".java" in extensions:
            profile.java = True
            if not profile.python:
                profile.primary_language = "Java"

        if any(ext in extensions for ext in (".js", ".jsx", ".cjs", ".mjs")):
            profile.javascript = True
            if not profile.python and not profile.java:
                profile.primary_language = "JavaScript"

        if any(ext in extensions for ext in (".ts", ".tsx")):
            profile.typescript = True
            if not profile.python and not profile.java:
                profile.primary_language = "TypeScript"

        if any(ext in extensions for ext in (".sql",)):
            profile.sql = True

        # ------------------------------------------------------------------ #
        # Dependency file analysis
        # ------------------------------------------------------------------ #
        reqs_text = self._read_file(self.root / "requirements.txt")
        pyproject_text = self._read_file(self.root / "pyproject.toml")
        setup_text = self._read_file(self.root / "setup.py") + self._read_file(self.root / "setup.cfg")
        pkg_json = self._read_file(self.root / "package.json")

        dep_text = reqs_text + pyproject_text + setup_text + pkg_json

        # Python frameworks
        if re.search(r"\bfastapi\b", dep_text, re.IGNORECASE):
            profile.fastapi = True
            profile.detected_frameworks.append("FastAPI")
        if re.search(r"\bflask\b", dep_text, re.IGNORECASE):
            profile.flask = True
            profile.detected_frameworks.append("Flask")
        if re.search(r"\bdjango\b", dep_text, re.IGNORECASE):
            profile.django = True
            profile.detected_frameworks.append("Django")

        # JS / Node frameworks
        if re.search(r'"next"', pkg_json, re.IGNORECASE):
            profile.nextjs = True
            profile.react = True
            profile.nodejs = True
            if "Next.js" not in profile.detected_frameworks:
                profile.detected_frameworks.append("Next.js")
            if "React" not in profile.detected_frameworks:
                profile.detected_frameworks.append("React")

        if re.search(r'"react"', pkg_json, re.IGNORECASE) and not profile.nextjs:
            profile.react = True
            if "React" not in profile.detected_frameworks:
                profile.detected_frameworks.append("React")

        if re.search(r'"react-native"', pkg_json, re.IGNORECASE):
            profile.react_native = True
            if "React Native" not in profile.detected_frameworks:
                profile.detected_frameworks.append("React Native")

        if any(f in filenames for f in ("package.json", "package-lock.json", "yarn.lock", ".nvmrc")):
            profile.nodejs = True

        # ML / AI
        if re.search(r"\btorch\b|\bpytorch\b", dep_text, re.IGNORECASE):
            profile.pytorch = True
            profile.machine_learning = True
        if re.search(r"\btensorflow\b|\bkeras\b", dep_text, re.IGNORECASE):
            profile.tensorflow = True
            profile.machine_learning = True
        if re.search(r"\bopencv\b|cv2\b", dep_text, re.IGNORECASE):
            profile.opencv = True
            profile.machine_learning = True
        if re.search(r"\bscikit.learn\b|\bsklearn\b|xgboost|lightgbm|catboost", dep_text, re.IGNORECASE):
            profile.machine_learning = True

        # LLM
        if re.search(r"\bopenai\b|\banthropologic\b|\banthropic\b|\blangchain\b|\bllm\b|\bllamaindex\b|\bgroq\b|\bmistral\b|\bcohere\b|\bgemini\b", dep_text, re.IGNORECASE):
            profile.llm = True
        # RAG
        if re.search(r"\bchromadb\b|\bpinecone\b|\bweaviate\b|\bqdrant\b|\bmilvus\b|\bfaiss\b|\bvector\b|\bpgvector\b", dep_text, re.IGNORECASE):
            profile.rag = True
            profile.vector_databases = True
        # Embeddings
        if re.search(r"\bsentence.transformers\b|\bembedding\b|\bhugging.face\b|\btransformers\b", dep_text, re.IGNORECASE):
            profile.embeddings = True
        # Agents
        if re.search(r"\bcrewai\b|\bautogen\b|\bmetagpt\b|\bagent\b|\blangchain.agents\b", dep_text, re.IGNORECASE):
            profile.agents = True

        # ------------------------------------------------------------------ #
        # Source import scanning
        # ------------------------------------------------------------------ #
        py_files = [f for f in all_text_files if f.suffix == ".py"
                    and not self._is_test_file(f)]
        js_ts_files = [f for f in all_text_files
                       if f.suffix.lower() in (".js", ".jsx", ".ts", ".tsx")
                       and not self._is_test_file(f)]

        combined_py_src = self._read_files(py_files, max_bytes=200_000)

        # FastAPI / Flask / Django from imports
        if re.search(r"from fastapi|import fastapi", combined_py_src, re.IGNORECASE):
            profile.fastapi = True
            if "FastAPI" not in profile.detected_frameworks:
                profile.detected_frameworks.append("FastAPI")
        if re.search(r"from flask|import flask", combined_py_src, re.IGNORECASE):
            profile.flask = True
            if "Flask" not in profile.detected_frameworks:
                profile.detected_frameworks.append("Flask")
        if re.search(r"from django|import django", combined_py_src, re.IGNORECASE):
            profile.django = True
            if "Django" not in profile.detected_frameworks:
                profile.detected_frameworks.append("Django")

        # LLM patterns in Python source
        if re.search(r"import openai|from openai|anthropic|langchain|llamaindex|groq|mistral|cohere|gemini|call_llm|llm\.", combined_py_src, re.IGNORECASE):
            profile.llm = True
        # RAG patterns
        if re.search(r"chromadb|pinecone|weaviate|qdrant|milvus|faiss|vector_store|VectorStore|pgvector", combined_py_src, re.IGNORECASE):
            profile.rag = True
            profile.vector_databases = True
        # Embeddings
        if re.search(r"sentence_transformers|SentenceTransformer|embedding|embed_query|get_embedding", combined_py_src, re.IGNORECASE):
            profile.embeddings = True
        # Agents / tool calling
        if re.search(r"@tool|from crewai|Agent\(|autogen|metagpt|function_call|tool_call", combined_py_src, re.IGNORECASE):
            profile.agents = True
            profile.tool_calling = True

        # React / Next.js in JS/TS files only
        combined_js_src = self._read_files(js_ts_files, max_bytes=100_000)
        if re.search(r"from ['\"]react['\"]|require\(['\"]react['\"]\)|import React", combined_js_src):
            profile.react = True
            if "React" not in profile.detected_frameworks:
                profile.detected_frameworks.append("React")
        if re.search(r"from ['\"]next|next/", combined_js_src):
            profile.nextjs = True
            if "Next.js" not in profile.detected_frameworks:
                profile.detected_frameworks.append("Next.js")

        # ------------------------------------------------------------------ #
        # DevOps / infra
        # ------------------------------------------------------------------ #
        if any(f.name in ("Dockerfile", "docker-compose.yml", "docker-compose.yaml", ".dockerignore")
               for f in all_files):
            profile.docker = True
            if "Docker" not in profile.detected_frameworks:
                profile.detected_frameworks.append("Docker")

        gh_actions_dir = self.root / ".github" / "workflows"
        if gh_actions_dir.is_dir() and any(gh_actions_dir.iterdir()):
            profile.github_actions = True
            if "GitHub Actions" not in profile.detected_frameworks:
                profile.detected_frameworks.append("GitHub Actions")

        # SQL patterns in source
        if re.search(r"SELECT\s+|INSERT INTO|CREATE TABLE|\.execute\(", combined_py_src, re.IGNORECASE):
            profile.sql = True

        return profile

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #

    def _collect_files(self) -> List[Path]:
        """Walk the project tree and return all files, skipping ignored dirs."""
        files: List[Path] = []
        for root, dirs, fnames in os.walk(self.root):
            # Prune skip dirs in-place
            dirs[:] = [d for d in dirs if d not in _SKIP_DIRS and not d.startswith(".")]
            for fname in fnames:
                files.append(Path(root) / fname)
        return files

    def _read_file(self, path: Path) -> str:
        if not path.exists():
            return ""
        try:
            return path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return ""

    def _read_files(self, paths: List[Path], max_bytes: int = 200_000) -> str:
        parts = []
        total = 0
        for p in paths:
            try:
                text = p.read_text(encoding="utf-8", errors="ignore")
                parts.append(text)
                total += len(text)
                if total >= max_bytes:
                    break
            except OSError:
                continue
        return "\n".join(parts)

    def _is_test_file(self, path: Path) -> bool:
        """Return True if this file appears to be a test file (skip for tech detection)."""
        parts = path.parts
        if "tests" in parts or "test" in parts:
            return True
        return bool(_SKIP_TEST_PATTERNS.search(path.name))
