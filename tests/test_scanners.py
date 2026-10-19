"""
Tests for deterministic static scanners (Security, AI, Dependency, DevOps, Code Quality).
"""

import tempfile
from pathlib import Path
from ai_project_auditor.scanners.inventory import ProjectInventory
from ai_project_auditor.scanners.security_scanner import SecurityScanner
from ai_project_auditor.scanners.ai_scanner import AISecurityScanner
from ai_project_auditor.scanners.dependency_scanner import DependencyScanner
from ai_project_auditor.scanners.devops_scanner import DevOpsScanner
from ai_project_auditor.scanners.code_quality import CodeQualityScanner


def test_security_scanner_detects_flaws():
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        bad_code = """
import hashlib
import subprocess

def handler(user_input):
    api_key = "abcdef1234567890abcdef1234567890"
    eval(user_input)
    subprocess.run("ls " + user_input, shell=True)
    h = hashlib.md5(user_input.encode()).hexdigest()
"""
        (tmp_path / "vulnerable.py").write_text(bad_code, encoding="utf-8")
        inv = ProjectInventory(tmp_dir).discover()

        scanner = SecurityScanner(inv)
        findings = scanner.scan()

        check_ids = {f.check_id for f in findings}
        assert "SEC-001" in check_ids  # Hardcoded key
        assert "SEC-004" in check_ids  # eval / shell=True
        assert "SEC-010" in check_ids  # md5


def test_security_scanner_does_not_treat_regex_compile_as_code_execution():
    with tempfile.TemporaryDirectory() as tmp_dir:
        source = """import re\npattern = re.compile(r'^safe$')\neval(user_input)\nexec(user_input)\n"""
        (Path(tmp_dir) / "patterns.py").write_text(source, encoding="utf-8")
        findings = SecurityScanner(ProjectInventory(tmp_dir).discover()).scan()
        dynamic_execution = [item for item in findings if item.check_id == "SEC-004"]

        assert len(dynamic_execution) == 2
        assert {"eval", "exec"} == {item.title.split(": ")[1].removesuffix("()") for item in dynamic_execution}
        assert all("re.compile" not in item.evidence for item in dynamic_execution)


def test_ai_scanner_detects_ai_vulnerabilities():
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        ai_code = """
def generate_answer(query):
    # Prompt injection vector
    prompt = f"Answer user query: {query}"
    response = call_llm(prompt)

    # Unsafe direct execution of model output
    eval(response)

    # Missing schema validation
    data = json.loads(response)
"""
        (tmp_path / "ai_service.py").write_text(ai_code, encoding="utf-8")
        inv = ProjectInventory(tmp_dir).discover()

        scanner = AISecurityScanner(inv)
        findings = scanner.scan()

        check_ids = {f.check_id for f in findings}
        assert "AI-002" in check_ids  # Prompt injection
        assert "AI-004" in check_ids  # Direct execution of LLM output
        assert "AI-005" in check_ids  # Unvalidated JSON parsing


def test_dependency_scanner_detects_unpinned_and_vulnerable():
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        reqs = """
# Unpinned
requests
# Vulnerable
jinja2==3.0.1
# Secure
pytest==8.0.0
"""
        (tmp_path / "requirements.txt").write_text(reqs, encoding="utf-8")
        inv = ProjectInventory(tmp_dir).discover()

        scanner = DependencyScanner(inv)
        findings = scanner.scan()

        check_ids = {f.check_id for f in findings}
        assert "DEP-003" in check_ids  # Unpinned
        assert "DEP-002" in check_ids  # Known vulnerable jinja2==3.0.1


def test_devops_scanner_detects_root_dockerfile():
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        df = """FROM python:latest
WORKDIR /app
COPY . .
CMD ["python", "main.py"]
"""
        (tmp_path / "Dockerfile").write_text(df, encoding="utf-8")
        inv = ProjectInventory(tmp_dir).discover()

        scanner = DevOpsScanner(inv)
        findings = scanner.scan()

        check_ids = {f.check_id for f in findings}
        assert "OPS-002" in check_ids  # Root user / unpinned image
