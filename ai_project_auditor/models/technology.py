"""
Technology profile model — output of project detection.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import List


@dataclass
class TechnologyProfile:
    """Describes the detected technology stack of the audited project."""

    # Languages
    python: bool = False
    javascript: bool = False
    typescript: bool = False
    java: bool = False

    # Web frameworks
    fastapi: bool = False
    flask: bool = False
    django: bool = False
    react: bool = False
    nextjs: bool = False
    react_native: bool = False
    nodejs: bool = False

    # Data / Database
    sql: bool = False

    # DevOps
    docker: bool = False
    github_actions: bool = False

    # AI / ML
    machine_learning: bool = False
    pytorch: bool = False
    tensorflow: bool = False
    opencv: bool = False
    llm: bool = False
    rag: bool = False
    embeddings: bool = False
    vector_databases: bool = False
    agents: bool = False
    tool_calling: bool = False

    # Meta
    primary_language: str = "Unknown"
    detected_frameworks: List[str] = field(default_factory=list)

    # Computed properties
    @property
    def has_api(self) -> bool:
        return any([self.fastapi, self.flask, self.django, self.nodejs, self.react, self.nextjs])

    @property
    def has_ai(self) -> bool:
        return any([
            self.machine_learning, self.pytorch, self.tensorflow,
            self.llm, self.rag, self.embeddings, self.vector_databases,
            self.agents, self.tool_calling,
        ])

    @property
    def has_rag_or_agents(self) -> bool:
        return any([self.rag, self.agents, self.tool_calling, self.vector_databases])

    def to_dict(self) -> dict:
        return {
            "python": self.python,
            "javascript": self.javascript,
            "typescript": self.typescript,
            "java": self.java,
            "fastapi": self.fastapi,
            "flask": self.flask,
            "django": self.django,
            "react": self.react,
            "nextjs": self.nextjs,
            "react_native": self.react_native,
            "nodejs": self.nodejs,
            "sql": self.sql,
            "docker": self.docker,
            "github_actions": self.github_actions,
            "machine_learning": self.machine_learning,
            "pytorch": self.pytorch,
            "tensorflow": self.tensorflow,
            "opencv": self.opencv,
            "llm": self.llm,
            "rag": self.rag,
            "embeddings": self.embeddings,
            "vector_databases": self.vector_databases,
            "agents": self.agents,
            "tool_calling": self.tool_calling,
            "primary_language": self.primary_language,
            "detected_frameworks": self.detected_frameworks,
            "has_api": self.has_api,
            "has_ai": self.has_ai,
            "has_rag_or_agents": self.has_rag_or_agents,
        }

    def summary_markdown(self) -> str:
        """Render the detected profile for the human-readable report."""
        rows = [
            ("Python", self.python), ("JavaScript", self.javascript), ("TypeScript", self.typescript),
            ("FastAPI", self.fastapi), ("React", self.react), ("Docker", self.docker),
            ("AI/ML", self.has_ai), ("LLM", self.llm), ("RAG", self.rag),
        ]
        return "\n".join(["| Technology | Detected |", "|:---|:---:|"] + [f"| {name} | {'✓' if value else '✗'} |" for name, value in rows])
