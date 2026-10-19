"""Local, dependency-free persistence for the optional audit-management UI."""

from __future__ import annotations

import json
import os
import socket
import threading
import hashlib
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from uuid import uuid4


class ManagementValidationError(ValueError):
    """Raised when management data is incomplete or inconsistent."""


class ManagementAuditError(RuntimeError):
    """Raised when a managed Smart AI Auditor run cannot complete safely."""


class AuditManagementService:
    """Store project, assessment, imported-finding, and action records safely.

    Scanner report content is stored as an immutable import snapshot. Human
    validation and remediation state live in separate management fields.
    """

    SCHEMA_VERSION = 1
    MAX_REPORT_BYTES = 20 * 1024 * 1024
    _active_run_ids: set[str] = set()
    _active_run_lock = threading.RLock()

    def __init__(self, storage_path: str | Path) -> None:
        self.storage_path = Path(storage_path)
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)
        self._ensure_store()

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _new_id(prefix: str) -> str:
        return f"{prefix}_{uuid4().hex}"

    def _empty_store(self) -> Dict[str, Any]:
        return {
            "schema_version": self.SCHEMA_VERSION,
            "projects": [], "audits": [], "reports": [], "findings": [], "corrective_actions": [], "migrations": [],
            "audit_runs": [],
        }

    def _ensure_store(self) -> None:
        if not self.storage_path.exists():
            self._write(self._empty_store())
            return
        data = self._load()
        if self._recover_interrupted_runs_in_data(data):
            self._write(data)

    def _load(self) -> Dict[str, Any]:
        try:
            with self.storage_path.open("r", encoding="utf-8") as handle:
                data = json.load(handle)
        except (OSError, json.JSONDecodeError) as exc:
            raise ManagementValidationError(f"Management storage is unreadable: {exc}") from exc
        if not isinstance(data, dict) or data.get("schema_version") != self.SCHEMA_VERSION:
            raise ManagementValidationError("Unsupported audit-management storage schema.")
        for key in ("projects", "audits", "reports", "findings", "corrective_actions", "migrations"):
            if not isinstance(data.get(key), list):
                raise ManagementValidationError(f"Management storage field '{key}' must be a list.")
        # Added after the first management-store version. Existing user data is
        # read compatibly and written with this field on its next safe update.
        if "audit_runs" not in data:
            data["audit_runs"] = []
        if not isinstance(data["audit_runs"], list):
            raise ManagementValidationError("Management storage field 'audit_runs' must be a list.")
        return data

    def _write(self, data: Dict[str, Any]) -> None:
        temporary = self.storage_path.with_suffix(self.storage_path.suffix + ".tmp")
        with temporary.open("w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2, ensure_ascii=False)
        os.replace(temporary, self.storage_path)

    @classmethod
    def _register_active_run(cls, run_id: str) -> None:
        with cls._active_run_lock:
            cls._active_run_ids.add(run_id)

    @classmethod
    def _unregister_active_run(cls, run_id: str) -> None:
        with cls._active_run_lock:
            cls._active_run_ids.discard(run_id)

    @classmethod
    def _is_registered_active_run(cls, run_id: str) -> bool:
        with cls._active_run_lock:
            return run_id in cls._active_run_ids

    def _project_lock_path(self, project_id: str) -> Path:
        return self.storage_path.parent / f".smart_audit_{project_id}.lock"

    def _acquire_project_lock(self, project_id: str, run_id: str) -> Path:
        lock_path = self._project_lock_path(project_id)
        try:
            descriptor = os.open(str(lock_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError as exc:
            raise ManagementAuditError("An audit is already running or awaiting recovery for this project.") from exc
        try:
            os.write(descriptor, json.dumps({"run_id": run_id, "pid": os.getpid(), "host": socket.gethostname()}).encode("utf-8"))
        finally:
            os.close(descriptor)
        return lock_path

    @staticmethod
    def _release_project_lock(lock_path: Optional[Path]) -> None:
        if lock_path is None:
            return
        try:
            lock_path.unlink(missing_ok=True)
        except OSError:
            # A leftover lock is evaluated conservatively during the next recovery.
            pass

    @staticmethod
    def _pid_is_running(pid: Any) -> Optional[bool]:
        """Return False only for a confirmed dead local process; None is unknown."""
        if not isinstance(pid, int) or pid <= 0:
            return None
        if os.name == "nt":
            # `os.kill(pid, 0)` returns WinError 87 for a missing PID, which is
            # not portable enough to distinguish from other OSErrors.
            import ctypes

            process_query_limited_information = 0x1000
            handle = ctypes.windll.kernel32.OpenProcess(process_query_limited_information, False, pid)
            if handle:
                ctypes.windll.kernel32.CloseHandle(handle)
                return True
            error = ctypes.windll.kernel32.GetLastError()
            if error == 87:  # ERROR_INVALID_PARAMETER: no such process
                return False
            return None
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return None
        except OSError:
            return None
        return True

    def _recover_interrupted_runs_in_data(self, data: Dict[str, Any]) -> bool:
        """Recover only runs whose recorded local execution is confirmed absent."""
        changed = False
        for run in data["audit_runs"]:
            if run.get("status") != "Running":
                continue
            # If importing completed just before an interruption, preserve the
            # already imported report and complete the run instead of retrying it.
            report_id = run.get("report_id")
            if report_id and any(item.get("id") == report_id for item in data["reports"]):
                run.update({"status": "Completed", "completed_at": self._now(),
                            "recovery_note": "Recovered completed state from an already imported report."})
                self._release_project_lock(self._project_lock_path(run["project_id"]))
                changed = True
                continue
            if self._is_registered_active_run(run.get("id", "")):
                continue
            execution = run.get("execution", {})
            host = execution.get("host")
            pid = execution.get("pid")
            # A live PID cannot prove it is this audit after an application
            # restart, so retain the lock rather than creating a duplicate run.
            is_dead = host == socket.gethostname() and self._pid_is_running(pid) is False
            if is_dead:
                run.update({"status": "Interrupted", "interrupted_at": self._now(),
                            "error": f"Recovered after restart: recorded execution process {pid} is no longer running."})
                self._release_project_lock(self._project_lock_path(run["project_id"]))
                changed = True
        return changed

    def recover_interrupted_runs(self) -> List[Dict[str, Any]]:
        """Recover confirmed-abandoned runs and return the runs changed."""
        data = self._load()
        before = {item["id"]: item.get("status") for item in data["audit_runs"]}
        if self._recover_interrupted_runs_in_data(data):
            self._write(data)
        return [item for item in data["audit_runs"] if before.get(item["id"]) != item.get("status")]

    def list_projects(self) -> List[Dict[str, Any]]:
        return list(self._load()["projects"])

    @staticmethod
    def _normalize_github_url(value: str) -> Optional[str]:
        """Return the safe canonical GitHub URL, or None for a non-GitHub value."""
        from ai_project_auditor.github.client import GitHubSafetyClient

        valid, owner, repository = GitHubSafetyClient.validate_url(value.strip())
        return f"https://github.com/{owner}/{repository}.git" if valid else None

    def _project_remote_url(self, project: Dict[str, Any]) -> Optional[str]:
        value = str(project.get("repository_url") or project.get("repository_path") or "").strip()
        return self._normalize_github_url(value) if value else None

    @staticmethod
    def _git_revision(repository: Path) -> Optional[str]:
        """Best-effort revision capture; never executes repository code."""
        try:
            result = subprocess.run(["git", "-C", str(repository), "rev-parse", "HEAD"],
                                    capture_output=True, text=True, timeout=10, check=False)
        except (OSError, subprocess.TimeoutExpired):
            return None
        return result.stdout.strip() if result.returncode == 0 and result.stdout.strip() else None

    def _read_report_file(self, report_path: str | Path) -> tuple[Path, Dict[str, Any], str]:
        source = Path(report_path).expanduser().resolve()
        if source.is_dir():
            raise ManagementValidationError("Report import requires a specific JSON report file. Select a file from the reports directory.")
        if not source.exists() or not source.is_file():
            raise ManagementValidationError("Report file does not exist or is not a regular file.")
        if source.suffix.lower() != ".json":
            raise ManagementValidationError("Only Smart AI Auditor JSON reports can be imported.")
        try:
            raw = source.read_bytes()
        except PermissionError as exc:
            raise ManagementValidationError("Report file cannot be read due to permissions. Choose a readable JSON report file.") from exc
        except OSError as exc:
            raise ManagementValidationError("Report file could not be read.") from exc
        if len(raw) > self.MAX_REPORT_BYTES:
            raise ManagementValidationError("Report file is too large to import safely.")
        try:
            report_data = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ManagementValidationError("Report file is not valid UTF-8 JSON.") from exc
        if not isinstance(report_data, dict) or not isinstance(report_data.get("project_name"), str):
            raise ManagementValidationError("The JSON file is not a supported Smart AI Auditor report.")
        if not isinstance(report_data.get("findings"), list):
            raise ManagementValidationError("The report has no valid findings list.")
        if "risk_summary" in report_data and not isinstance(report_data["risk_summary"], dict):
            raise ManagementValidationError("The report has an invalid risk summary.")
        if "check_results" in report_data and not isinstance(report_data["check_results"], list):
            raise ManagementValidationError("The report has invalid check results.")
        if not all(isinstance(item, dict) for item in report_data["findings"]):
            raise ManagementValidationError("The report contains malformed finding records.")
        for finding in report_data["findings"]:
            if not isinstance(finding.get("finding_id", ""), str) or not isinstance(finding.get("title", ""), str):
                raise ManagementValidationError("The report contains findings with invalid identifiers or titles.")
            if "severity" in finding and not isinstance(finding["severity"], str):
                raise ManagementValidationError("The report contains a finding with invalid severity.")
        return source, report_data, hashlib.sha256(raw).hexdigest()

    def discover_report_files(self, location: str | Path) -> List[str]:
        """Return validated JSON report files from an explicit report directory."""
        directory = Path(location).expanduser().resolve()
        if not directory.exists() or not directory.is_dir():
            raise ManagementValidationError("Reports directory does not exist or is not a directory.")
        candidates = []
        try:
            files = sorted(directory.glob("*_audit_report.json"), key=lambda item: item.stat().st_mtime, reverse=True)
        except OSError as exc:
            raise ManagementValidationError("Reports directory could not be read.") from exc
        for candidate in files:
            try:
                self._read_report_file(candidate)
            except ManagementValidationError:
                continue
            candidates.append(str(candidate))
        return candidates

    def migrate_legacy_json(self, source_directory: str | Path) -> Dict[str, int]:
        """Copy legacy `projects.json` / `audits.json` without changing them.

        A resolved source path is recorded after a successful import, making the
        operation safely repeatable. Existing project IDs are retained where
        possible; records with an ID collision are skipped rather than replaced.
        """
        source = Path(source_directory).resolve()
        key = str(source)
        data = self._load()
        if any(item.get("source") == key for item in data["migrations"]):
            raise ManagementValidationError("This legacy directory has already been imported.")

        def read_list(filename: str) -> List[Dict[str, Any]]:
            try:
                with (source / filename).open("r", encoding="utf-8") as handle:
                    value = json.load(handle)
            except (OSError, json.JSONDecodeError) as exc:
                raise ManagementValidationError(f"Could not read legacy {filename}: {exc}") from exc
            if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
                raise ManagementValidationError(f"Legacy {filename} must contain a JSON list of records.")
            return value

        legacy_projects, legacy_audits = read_list("projects.json"), read_list("audits.json")
        existing_project_ids = {item["id"] for item in data["projects"]}
        imported_projects = 0
        for legacy in legacy_projects:
            project_id = str(legacy.get("id") or self._new_id("project"))
            if project_id in existing_project_ids:
                continue
            now = self._now()
            data["projects"].append({"id": project_id, "name": str(legacy.get("name") or "Untitled Project"),
                "client": str(legacy.get("client") or ""), "technology": str(legacy.get("tech") or ""),
                "status": str(legacy.get("status") or "Active"), "created_at": legacy.get("created_at") or now,
                "updated_at": legacy.get("updated_at") or now})
            existing_project_ids.add(project_id)
            imported_projects += 1
        project_names = {item["id"]: item["name"] for item in data["projects"]}
        imported_audits = 0
        for legacy in legacy_audits:
            project_id = str(legacy.get("project_id") or "")
            if project_id not in project_names:
                continue
            status = str(legacy.get("status") or "Pass")
            score = legacy.get("score", {"Pass": 100, "Partial": 60, "Fail": 20, "Not Applicable": 100}.get(status, 0))
            data["audits"].append({"id": self._new_id("assessment"), "project_id": project_id,
                "project_name": str(legacy.get("project_name") or project_names[project_id]),
                "category": str(legacy.get("category") or "General"), "checkpoint": str(legacy.get("checkpoint") or "General Review"),
                "status": status, "severity": str(legacy.get("severity") or "Medium"),
                "remarks": str(legacy.get("remark") or legacy.get("remarks") or ""), "score": score,
                "created_at": legacy.get("date") or legacy.get("created_at") or self._now()})
            imported_audits += 1
        data["migrations"].append({"source": key, "migrated_at": self._now(), "projects": imported_projects, "audits": imported_audits})
        self._write(data)
        return {"projects": imported_projects, "audits": imported_audits}

    def create_project(self, name: str, client: str = "", technology: str = "", repository_path: str = "") -> Dict[str, Any]:
        if not name or not name.strip():
            raise ManagementValidationError("Project name is required.")
        data = self._load()
        normalized = name.strip().casefold()
        if any(item["name"].casefold() == normalized for item in data["projects"]):
            raise ManagementValidationError("A project with this name already exists.")
        location = repository_path.strip()
        remote_url = self._normalize_github_url(location) if location else None
        if location and not remote_url:
            candidate = Path(location).expanduser()
            if not candidate.is_dir():
                raise ManagementValidationError("Repository path must be an existing local directory, or provide a valid GitHub repository URL.")
            location = str(candidate.resolve())
        now = self._now()
        project = {"id": self._new_id("project"), "name": name.strip(), "client": client.strip(),
                   "technology": technology.strip(), "repository_path": "" if remote_url else location,
                   "repository_url": remote_url or "",
                   "status": "Active", "created_at": now, "updated_at": now}
        data["projects"].append(project)
        self._write(data)
        return project

    def set_project_repository_path(self, project_id: str, repository_path: str) -> Dict[str, Any]:
        """Store a project repository path after verifying it is an existing directory."""
        if self._normalize_github_url(repository_path):
            raise ManagementValidationError("This is a GitHub URL, not a local path. Configure it as a remote repository instead.")
        candidate = Path(repository_path).expanduser()
        if not repository_path.strip() or not candidate.is_dir():
            raise ManagementValidationError("Repository path must be an existing directory.")
        data = self._load()
        project = next((item for item in data["projects"] if item["id"] == project_id), None)
        if not project:
            raise ManagementValidationError("The selected project does not exist.")
        project.update({"repository_path": str(candidate.resolve()), "repository_url": "", "updated_at": self._now()})
        self._write(data)
        return project

    def set_project_repository_url(self, project_id: str, repository_url: str) -> Dict[str, Any]:
        normalized = self._normalize_github_url(repository_url)
        if not normalized:
            raise ManagementValidationError("Remote repositories currently support valid public GitHub URLs only.")
        data = self._load()
        project = next((item for item in data["projects"] if item["id"] == project_id), None)
        if not project:
            raise ManagementValidationError("The selected project does not exist.")
        project.update({"repository_path": "", "repository_url": normalized, "updated_at": self._now()})
        self._write(data)
        return project

    def create_assessment(self, project_id: str, category: str, checkpoint: str, status: str,
                          severity: str, remarks: str = "") -> Dict[str, Any]:
        if status not in {"Pass", "Partial", "Fail", "Not Applicable"}:
            raise ManagementValidationError("Invalid assessment status.")
        if severity not in {"Low", "Medium", "High", "Critical"}:
            raise ManagementValidationError("Invalid assessment severity.")
        data = self._load()
        project = next((item for item in data["projects"] if item["id"] == project_id), None)
        if not project:
            raise ManagementValidationError("The selected project does not exist.")
        if not category.strip() or not checkpoint.strip():
            raise ManagementValidationError("Category and checkpoint are required.")
        score = {"Pass": 100, "Partial": 60, "Fail": 20, "Not Applicable": 100}[status]
        audit = {"id": self._new_id("assessment"), "project_id": project_id, "project_name": project["name"],
                 "category": category.strip(), "checkpoint": checkpoint.strip(), "status": status,
                 "severity": severity, "remarks": remarks.strip(), "score": score, "created_at": self._now()}
        data["audits"].append(audit)
        self._write(data)
        return audit

    def list_audits(self, project_id: Optional[str] = None) -> List[Dict[str, Any]]:
        audits = self._load()["audits"]
        return [item for item in audits if project_id is None or item["project_id"] == project_id]

    def list_audit_runs(self, project_id: Optional[str] = None) -> List[Dict[str, Any]]:
        runs = self._load()["audit_runs"]
        return [item for item in runs if project_id is None or item["project_id"] == project_id]

    def run_project_audit(
        self,
        project_id: str,
        provider_name: str = "offline",
        formats: Optional[List[str]] = None,
        output_root: str | Path | None = None,
        engine_factory=None,
    ) -> Dict[str, Any]:
        """Run the established audit engine for a registered project and import JSON.

        Each managed run gets a unique output directory, so existing CLI reports
        are not overwritten. JSON is always requested because import depends on
        the established JSON report contract.
        """
        selected_formats = ["all"] if formats is None else formats
        requested_formats = [item.strip().lower() for item in selected_formats if item.strip()]
        allowed_formats = {"all", "json", "markdown", "md", "excel", "xlsx", "pdf"}
        if not requested_formats or any(item not in allowed_formats for item in requested_formats):
            raise ManagementValidationError("Unsupported report format selection.")
        if "all" not in requested_formats and "json" not in requested_formats:
            requested_formats.append("json")

        self.recover_interrupted_runs()
        data = self._load()
        project = next((item for item in data["projects"] if item["id"] == project_id), None)
        if not project:
            raise ManagementValidationError("The selected project does not exist.")
        remote_url = self._project_remote_url(project)
        repository_path = str(project.get("repository_path", "")).strip()
        repository = Path(repository_path).expanduser() if not remote_url else None
        if not remote_url and (not repository_path or repository is None or not repository.is_dir()):
            raise ManagementValidationError("Configure an existing local repository directory or a valid GitHub repository URL for this project.")
        if any(item["project_id"] == project_id and item["status"] == "Running" for item in data["audit_runs"]):
            raise ManagementAuditError("An audit is already running for this project.")

        from ai_project_auditor.core.engine import AuditEngine
        from ai_project_auditor.providers import get_provider

        try:
            provider = get_provider(provider_name)
        except ValueError as exc:
            raise ManagementValidationError(str(exc)) from exc
        if provider and not provider.is_available():
            key_name = "NVIDIA_API_KEY" if provider_name == "nvidia" else "OPENCODE_API_KEY"
            raise ManagementValidationError(f"{key_name} is missing or the selected provider is unavailable.")

        run_id = self._new_id("run")
        root = Path(output_root) if output_root is not None else self.storage_path.parent / "audit_runs"
        run_output = root / project_id / run_id
        lock_path = self._acquire_project_lock(project_id, run_id)
        run = {"id": run_id, "project_id": project_id, "project_name": project["name"],
               "repository_path": str(repository.resolve()) if repository else "", "repository_url": remote_url or "",
               "target_kind": "github" if remote_url else "local", "provider": provider_name, "formats": requested_formats,
               "output_dir": str(run_output), "status": "Running", "created_at": self._now(), "started_at": self._now(),
               "execution": {"host": socket.gethostname(), "pid": os.getpid(), "mode": "in_process_background"}}
        try:
            # Re-read after acquiring the filesystem lock to avoid a check/write race.
            data = self._load()
            if any(item["project_id"] == project_id and item["status"] == "Running" for item in data["audit_runs"]):
                raise ManagementAuditError("An audit is already running for this project.")
            data["audit_runs"].append(run)
            self._write(data)
            self._register_active_run(run_id)

            def execute_engine(target: Path):
                revision = self._git_revision(target)
                if revision:
                    snapshot = self._load()
                    active = next(item for item in snapshot["audit_runs"] if item["id"] == run_id)
                    active["target_revision"] = revision
                    self._write(snapshot)
                engine = (engine_factory or AuditEngine)(project_path=str(target), provider=provider,
                                                          output_dir=str(run_output), formats=requested_formats)
                result = engine.run()
                if provider and provider.last_error:
                    raise ManagementAuditError(
                        f"{provider.name} failed; no management report was imported. {provider.last_error}"
                    )
                return result

            if remote_url:
                from ai_project_auditor.github.client import GitHubSafetyClient
                with GitHubSafetyClient.clone_isolated(remote_url) as clone_path:
                    _, generated_files = execute_engine(Path(clone_path).resolve())
            else:
                _, generated_files = execute_engine(repository.resolve())
            json_path = generated_files.get("json")
            if not json_path or not Path(json_path).is_file():
                raise ManagementAuditError("The audit completed without a generated JSON report to import.")
            data = self._load()
            active_run = next(item for item in data["audit_runs"] if item["id"] == run_id)
            active_run.update({"report_path": str(Path(json_path).resolve()), "report_generated_at": self._now()})
            self._write(data)
            imported = self.import_report(project_id, json_path, source_type="Generated")
            data = self._load()
            active_run = next(item for item in data["audit_runs"] if item["id"] == run_id)
            active_run["report_id"] = imported["id"]
            self._write(data)
        except Exception as exc:
            data = self._load()
            failed_run = next((item for item in data["audit_runs"] if item["id"] == run_id), None)
            if failed_run:
                failed_run.update({"status": "Failed", "completed_at": self._now(), "error": str(exc)})
                self._write(data)
            if isinstance(exc, ManagementAuditError):
                raise
            raise ManagementAuditError(f"Audit failed: {exc}") from exc
        else:
            data = self._load()
            completed_run = next(item for item in data["audit_runs"] if item["id"] == run_id)
            completed_run.update({"status": "Completed", "completed_at": self._now()})
            self._write(data)
            return {"run": completed_run, "report": imported}
        finally:
            self._unregister_active_run(run_id)
            self._release_project_lock(lock_path)

    def mark_run_interrupted(self, run_id: str, reason: str) -> Dict[str, Any]:
        """Explicitly release an unverifiable run after an operator confirms it stopped."""
        if not reason.strip():
            raise ManagementValidationError("Provide a recovery reason before marking a run interrupted.")
        data = self._load()
        run = next((item for item in data["audit_runs"] if item["id"] == run_id), None)
        if not run:
            raise ManagementValidationError("Audit run does not exist.")
        if run.get("status") != "Running":
            raise ManagementValidationError("Only a running audit can be marked interrupted.")
        if self._is_registered_active_run(run_id):
            raise ManagementAuditError("This audit is active in the current application and cannot be interrupted manually.")
        run.update({"status": "Interrupted", "interrupted_at": self._now(),
                    "error": f"Manually interrupted after operator confirmation: {reason.strip()}"})
        self._write(data)
        self._release_project_lock(self._project_lock_path(run["project_id"]))
        return run

    def retry_audit_run(self, run_id: str, engine_factory=None) -> Dict[str, Any]:
        """Retry a failed/interrupted run with a fresh run ID and output directory."""
        self.recover_interrupted_runs()
        data = self._load()
        run = next((item for item in data["audit_runs"] if item["id"] == run_id), None)
        if not run:
            raise ManagementValidationError("Audit run does not exist.")
        if run.get("status") not in {"Failed", "Interrupted"}:
            raise ManagementValidationError("Only failed or interrupted audits can be retried.")
        source_output = Path(run["output_dir"])
        result = self.run_project_audit(run["project_id"], run.get("provider", "offline"), run.get("formats"),
                                        source_output.parent.parent, engine_factory)
        result["run"]["retry_of"] = run_id
        data = self._load()
        retried = next(item for item in data["audit_runs"] if item["id"] == result["run"]["id"])
        retried["retry_of"] = run_id
        self._write(data)
        return {"run": retried, "report": result["report"]}

    def import_report(self, project_id: str, report_path: str | Path, source_type: str = "Imported") -> Dict[str, Any]:
        data = self._load()
        if not any(item["id"] == project_id for item in data["projects"]):
            raise ManagementValidationError("The selected project does not exist.")
        source, report_data, fingerprint = self._read_report_file(report_path)
        source_key = str(source)
        if any(item.get("source_path") == source_key or item.get("report_fingerprint") == fingerprint for item in data["reports"]):
            raise ManagementValidationError("This report has already been imported.")
        report = {"id": self._new_id("report"), "project_id": project_id, "source_path": source_key,
                  "project_name": report_data.get("project_name", "Unknown"),
                  "risk_summary": report_data.get("risk_summary", {}), "imported_at": self._now(),
                  "finding_count": len(report_data["findings"]), "check_results": report_data.get("check_results", []),
                  "llm_findings_rejected": report_data.get("llm_findings_rejected", 0),
                  "report_fingerprint": fingerprint, "source_type": source_type}
        data["reports"].append(report)
        for source_finding in report_data["findings"]:
            data["findings"].append({"id": self._new_id("finding"), "report_id": report["id"],
                "project_id": project_id, "source_finding_id": source_finding.get("finding_id", ""),
                "snapshot": source_finding, "decision": "Pending", "decision_note": "", "decided_at": None})
        self._write(data)
        return report

    def list_findings(self, project_id: Optional[str] = None) -> List[Dict[str, Any]]:
        findings = self._load()["findings"]
        return [item for item in findings if project_id is None or item["project_id"] == project_id]

    def list_reports(self, project_id: Optional[str] = None) -> List[Dict[str, Any]]:
        reports = self._load()["reports"]
        return [item for item in reports if project_id is None or item["project_id"] == project_id]

    def list_corrective_actions(self, project_id: Optional[str] = None) -> List[Dict[str, Any]]:
        actions = self._load()["corrective_actions"]
        return [item for item in actions if project_id is None or item["project_id"] == project_id]

    def update_corrective_action_status(self, action_id: str, status: str, note: str = "") -> Dict[str, Any]:
        if status not in {"Open", "In Progress", "Resolved", "Closed"}:
            raise ManagementValidationError("Invalid corrective-action status.")
        data = self._load()
        action = next((item for item in data["corrective_actions"] if item["id"] == action_id), None)
        if not action:
            raise ManagementValidationError("Corrective action does not exist.")
        action.update({"status": status, "status_note": note.strip(), "updated_at": self._now()})
        self._write(data)
        return action

    def report_check_results(self, report_id: str) -> List[Dict[str, Any]]:
        """Return report check outcomes without changing the source report contract."""
        report = next((item for item in self._load()["reports"] if item["id"] == report_id), None)
        if not report:
            raise ManagementValidationError("Report does not exist.")
        rows = []
        for item in report.get("check_results", []):
            status = item.get("status", "ERROR")
            notes = item.get("notes", "")
            display_status = "NOT APPLICABLE" if status == "SKIPPED" and "not applicable" in notes.lower() else status
            rows.append({"check_id": item.get("check_id", ""), "category": item.get("category", ""),
                         "check": item.get("check_name", ""), "method": item.get("method", ""),
                         "status": display_status, "notes": notes})
        return rows

    def history(self, project_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Return persisted assessment, report, and corrective-action events."""
        events = []
        for item in self.list_audits(project_id):
            events.append({"type": "Assessment", "timestamp": item["created_at"], "summary": item["checkpoint"], "status": item["status"]})
        for item in self.list_reports(project_id):
            events.append({"type": "Report imported", "timestamp": item["imported_at"], "summary": item["project_name"], "status": "Available"})
        for item in self.list_audit_runs(project_id):
            events.append({"type": "Smart AI audit", "timestamp": item.get("completed_at", item["started_at"]),
                           "summary": item.get("repository_url") or item.get("repository_path", ""), "status": item["status"]})
        for item in self.list_corrective_actions(project_id):
            events.append({"type": "Corrective action", "timestamp": item.get("updated_at", item["created_at"]), "summary": item["action"], "status": item["status"]})
        return sorted(events, key=lambda item: item["timestamp"], reverse=True)

    def decide_finding(self, finding_id: str, decision: str, note: str = "") -> Dict[str, Any]:
        if decision not in {"Validated", "Rejected", "Pending"}:
            raise ManagementValidationError("Invalid finding decision.")
        data = self._load()
        finding = next((item for item in data["findings"] if item["id"] == finding_id), None)
        if not finding:
            raise ManagementValidationError("Finding does not exist.")
        finding.update({"decision": decision, "decision_note": note.strip(), "decided_at": self._now()})
        self._write(data)
        return finding

    def create_corrective_action(self, finding_id: str, action: str, owner: str = "", due_date: str = "") -> Dict[str, Any]:
        if not action or not action.strip():
            raise ManagementValidationError("Corrective action text is required.")
        data = self._load()
        finding = next((item for item in data["findings"] if item["id"] == finding_id), None)
        if not finding:
            raise ManagementValidationError("Finding does not exist.")
        item = {"id": self._new_id("action"), "finding_id": finding_id, "project_id": finding["project_id"],
                "action": action.strip(), "owner": owner.strip(), "due_date": due_date, "status": "Open", "created_at": self._now()}
        data["corrective_actions"].append(item)
        self._write(data)
        return item
