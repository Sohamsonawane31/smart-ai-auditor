"""
Tests for Project and Technology Detection Engine.
"""

import tempfile
import os
from pathlib import Path
from ai_project_auditor.project_detection.detector import ProjectDetector


def test_detect_python_fastapi_docker():
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        (tmp_path / "main.py").write_text("from fastapi import FastAPI\napp = FastAPI()", encoding="utf-8")
        (tmp_path / "requirements.txt").write_text("fastapi==0.110.0\nuvicorn>=0.28.0\n", encoding="utf-8")
        (tmp_path / "Dockerfile").write_text("FROM python:3.11-slim\nUSER appuser", encoding="utf-8")

        detector = ProjectDetector(tmp_dir)
        profile = detector.detect()

        assert profile.python is True
        assert profile.fastapi is True
        assert profile.docker is True
        assert profile.primary_language == "Python"
        assert "FastAPI" in profile.detected_frameworks
        assert profile.has_api is True


def test_detect_ai_llm_rag_stack():
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        (tmp_path / "agent.py").write_text(
            "import openai\nimport chromadb\nfrom crewai import Agent\n\n@tool\ndef search(): pass",
            encoding="utf-8",
        )
        (tmp_path / "requirements.txt").write_text(
            "openai>=1.12.0\nchromadb==0.4.22\ncrewai==0.28.8\ntorch>=2.0.0\n", encoding="utf-8"
        )

        detector = ProjectDetector(tmp_dir)
        profile = detector.detect()

        assert profile.llm is True
        assert profile.rag is True
        assert profile.vector_databases is True
        assert profile.agents is True
        assert profile.tool_calling is True
        assert profile.pytorch is True
        assert profile.machine_learning is True
        assert profile.has_ai is True
        assert profile.has_rag_or_agents is True


def test_detect_javascript_react_stack():
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        (tmp_path / "App.jsx").write_text("import React from 'react'; export default function App(){}", encoding="utf-8")
        (tmp_path / "package.json").write_text('{"dependencies": {"react": "^18.2.0", "next": "^14.0.0"}}', encoding="utf-8")

        detector = ProjectDetector(tmp_dir)
        profile = detector.detect()

        assert profile.javascript is True
        assert profile.react is True
        assert profile.nextjs is True
        assert profile.nodejs is True
