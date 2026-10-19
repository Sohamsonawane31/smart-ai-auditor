import json
import os
import socket
from contextlib import contextmanager
from pathlib import Path

import pytest

from ai_project_auditor.management import AuditManagementService, ManagementAuditError, ManagementValidationError


def _report(path):
    path.write_text(json.dumps({"project_name": "Demo", "risk_summary": {"risk_score": 10}, "llm_findings_rejected": 2,
        "check_results": [{"check_id": "SEC-1", "category": "Security", "check_name": "Secrets", "method": "Static", "status": "FAIL", "notes": "One finding."},
                          {"check_id": "API-1", "category": "API", "check_name": "Endpoints", "method": "Static", "status": "SKIPPED", "notes": "Not applicable to detected technology."}],
        "findings": [{"finding_id": "SEC-1", "title": "Issue", "severity": "High", "evidence": "actual evidence", "ai_remediation": "specific fix"}]}), encoding="utf-8")


def test_management_links_immutable_report_findings_to_actions(tmp_path):
    service = AuditManagementService(tmp_path / "management.json")
    project = service.create_project("Demo", "Client", "Python")
    assessment = service.create_assessment(project["id"], "Security", "Review secrets", "Fail", "High")
    report_path = tmp_path / "report.json"
    _report(report_path)
    report = service.import_report(project["id"], report_path)
    finding = service.list_findings(project["id"])[0]
    service.decide_finding(finding["id"], "Validated", "Confirmed by reviewer")
    action = service.create_corrective_action(finding["id"], "Rotate exposed credential", "Security", "2026-12-01")
    updated = service.update_corrective_action_status(action["id"], "In Progress", "Assigned")

    assert assessment["score"] == 20
    assert report["finding_count"] == 1
    assert service.list_findings()[0]["snapshot"]["finding_id"] == "SEC-1"
    assert updated["status"] == "In Progress"
    assert service.report_check_results(report["id"])[1]["status"] == "NOT APPLICABLE"
    assert service.history(project["id"])[0]["type"] in {"Corrective action", "Report imported", "Assessment"}


def test_management_rejects_bad_input_and_duplicate_report_import(tmp_path):
    service = AuditManagementService(tmp_path / "management.json")
    with pytest.raises(ManagementValidationError):
        service.create_project(" ")
    project = service.create_project("Demo")
    report_path = tmp_path / "report.json"
    _report(report_path)
    service.import_report(project["id"], report_path)
    with pytest.raises(ManagementValidationError):
        service.import_report(project["id"], report_path)


def test_report_directory_discovery_and_file_validation(tmp_path):
    service = AuditManagementService(tmp_path / "management.json")
    project = service.create_project("Demo")
    reports = tmp_path / "reports"
    reports.mkdir()
    valid = reports / "demo_audit_report.json"
    _report(valid)
    (reports / "broken_audit_report.json").write_text("not json", encoding="utf-8")

    assert service.discover_report_files(reports) == [str(valid.resolve())]
    with pytest.raises(ManagementValidationError, match="specific JSON report file"):
        service.import_report(project["id"], reports)
    imported = service.import_report(project["id"], valid)
    assert imported["source_type"] == "Imported"
    copied = reports / "copied_audit_report.json"
    copied.write_bytes(valid.read_bytes())
    with pytest.raises(ManagementValidationError, match="already been imported"):
        service.import_report(project["id"], copied)


def test_project_distinguishes_local_directory_from_github_url(tmp_path):
    repository = tmp_path / "repository"
    repository.mkdir()
    service = AuditManagementService(tmp_path / "management.json")
    local = service.create_project("Local", repository_path=str(repository))
    remote = service.create_project("Remote", repository_path="https://github.com/example/demo.git")

    assert local["repository_path"] == str(repository.resolve())
    assert local["repository_url"] == ""
    assert remote["repository_path"] == ""
    assert remote["repository_url"] == "https://github.com/example/demo.git"
    with pytest.raises(ManagementValidationError, match="GitHub URL"):
        service.set_project_repository_path(local["id"], remote["repository_url"])


def test_managed_audit_uses_safe_isolated_clone_for_github_project(tmp_path, monkeypatch):
    clone = tmp_path / "isolated_clone"
    clone.mkdir()
    service = AuditManagementService(tmp_path / "management.json")
    project = service.create_project("Remote", repository_path="https://github.com/example/demo")

    @contextmanager
    def fake_clone(url):
        assert url == "https://github.com/example/demo.git"
        yield str(clone)

    monkeypatch.setattr("ai_project_auditor.github.client.GitHubSafetyClient.clone_isolated", fake_clone)
    result = service.run_project_audit(project["id"], engine_factory=_SuccessfulEngine)

    assert result["run"]["target_kind"] == "github"
    assert result["run"]["repository_url"] == "https://github.com/example/demo.git"
    assert result["report"]["source_type"] == "Generated"


def test_legacy_migration_copies_without_mutating_source_and_is_repeat_safe(tmp_path):
    source = tmp_path / "legacy"
    source.mkdir()
    projects = [{"id": "legacy-1", "name": "Legacy", "client": "Client", "tech": "Python", "status": "Active"}]
    audits = [{"project_id": "legacy-1", "category": "Security", "checkpoint": "Secrets", "status": "Fail", "severity": "High"}]
    (source / "projects.json").write_text(json.dumps(projects), encoding="utf-8")
    (source / "audits.json").write_text(json.dumps(audits), encoding="utf-8")
    projects_before = (source / "projects.json").read_text(encoding="utf-8")

    service = AuditManagementService(tmp_path / "management.json")
    assert service.migrate_legacy_json(source) == {"projects": 1, "audits": 1}
    assert (source / "projects.json").read_text(encoding="utf-8") == projects_before
    assert service.list_audits()[0]["project_id"] == "legacy-1"
    with pytest.raises(ManagementValidationError):
        service.migrate_legacy_json(source)


class _SuccessfulEngine:
    def __init__(self, project_path, provider, output_dir, formats):
        self.project_path = project_path
        self.output_dir = Path(output_dir)
        self.formats = formats

    def run(self):
        self.output_dir.mkdir(parents=True, exist_ok=True)
        report = self.output_dir / "target_audit_report.json"
        _report(report)
        return object(), {"json": str(report)}


def test_managed_audit_runs_selected_project_and_imports_report(tmp_path):
    repository = tmp_path / "target_repository"
    repository.mkdir()
    service = AuditManagementService(tmp_path / "management.json")
    project = service.create_project("Target", repository_path=str(repository))

    result = service.run_project_audit(project["id"], "offline", ["markdown"], tmp_path / "runs", _SuccessfulEngine)
    reopened = AuditManagementService(tmp_path / "management.json")

    assert result["run"]["status"] == "Completed"
    assert result["run"]["repository_path"] == str(repository.resolve())
    assert result["run"]["formats"] == ["markdown", "json"]
    assert result["report"]["project_id"] == project["id"]
    assert len(reopened.list_reports(project["id"])) == 1
    assert len(reopened.list_findings(project["id"])) == 1
    assert any(item["type"] == "Smart AI audit" and item["status"] == "Completed" for item in reopened.history(project["id"]))


def test_managed_offline_audit_uses_real_engine_and_persists_lifecycle(tmp_path, monkeypatch):
    """Exercise the actual engine through the management service, not a stub."""
    repository = tmp_path / "target_repository"
    repository.mkdir()
    (repository / "app.py").write_text("def hello(name):\n    return f'hello {name}'\n", encoding="utf-8")
    monkeypatch.chdir(Path(__file__).resolve().parents[1])
    service = AuditManagementService(tmp_path / "management.json")
    project = service.create_project("Real target", repository_path=str(repository))

    result = service.run_project_audit(project["id"], "offline", ["json"], tmp_path / "runs")
    reopened = AuditManagementService(tmp_path / "management.json")

    assert result["run"]["status"] == "Completed"
    assert Path(result["run"]["report_path"]).is_file()
    assert len(reopened.list_reports(project["id"])) == 1
    assert len(reopened.list_findings(project["id"])) == result["report"]["finding_count"]
    assert any(event["status"] == "Completed" for event in reopened.history(project["id"]))


def test_managed_audit_rejects_invalid_repository_path(tmp_path):
    service = AuditManagementService(tmp_path / "management.json")
    with pytest.raises(ManagementValidationError, match="existing local directory"):
        service.create_project("Missing", repository_path=str(tmp_path / "does-not-exist"))
    assert service.list_projects() == []


def test_managed_audit_rejects_empty_or_unsupported_format_selection(tmp_path):
    repository = tmp_path / "target_repository"
    repository.mkdir()
    service = AuditManagementService(tmp_path / "management.json")
    project = service.create_project("Target", repository_path=str(repository))

    with pytest.raises(ManagementValidationError, match="Unsupported report format"):
        service.run_project_audit(project["id"], formats=[], engine_factory=_SuccessfulEngine)
    with pytest.raises(ManagementValidationError, match="Unsupported report format"):
        service.run_project_audit(project["id"], formats=["word"], engine_factory=_SuccessfulEngine)


def test_managed_audit_records_failure_without_importing_report(tmp_path):
    repository = tmp_path / "target_repository"
    repository.mkdir()

    class FailingEngine:
        def __init__(self, **_kwargs):
            pass

        def run(self):
            raise RuntimeError("scanner failure")

    service = AuditManagementService(tmp_path / "management.json")
    project = service.create_project("Target", repository_path=str(repository))
    with pytest.raises(ManagementAuditError, match="scanner failure"):
        service.run_project_audit(project["id"], engine_factory=FailingEngine)

    assert service.list_reports(project["id"]) == []
    assert service.list_audit_runs(project["id"])[0]["status"] == "Failed"


def test_managed_audit_does_not_import_report_when_selected_provider_fails(tmp_path, monkeypatch):
    repository = tmp_path / "target_repository"
    repository.mkdir()

    class FailedProvider:
        name = "NVIDIA (test)"
        last_error = None
        def is_available(self): return True

    provider = FailedProvider()
    monkeypatch.setattr("ai_project_auditor.providers.get_provider", lambda _name: provider)

    class ProviderFailureEngine(_SuccessfulEngine):
        def run(self):
            result = super().run()
            provider.last_error = "NVIDIA API authentication failed (HTTP 401)."
            return result

    service = AuditManagementService(tmp_path / "management.json")
    project = service.create_project("Target", repository_path=str(repository))
    with pytest.raises(ManagementAuditError, match="authentication failed"):
        service.run_project_audit(project["id"], "nvidia", engine_factory=ProviderFailureEngine)

    assert service.list_reports(project["id"]) == []
    assert service.list_audit_runs(project["id"])[0]["status"] == "Failed"


@pytest.mark.parametrize("engine_factory", [
    type("MissingJsonEngine", (), {"__init__": lambda self, **_kwargs: None, "run": lambda self: (object(), {})}),
])
def test_managed_audit_rejects_missing_json_report(tmp_path, engine_factory):
    repository = tmp_path / "target_repository"
    repository.mkdir()
    service = AuditManagementService(tmp_path / "management.json")
    project = service.create_project("Target", repository_path=str(repository))

    with pytest.raises(ManagementAuditError, match="without a generated JSON"):
        service.run_project_audit(project["id"], engine_factory=engine_factory)
    assert service.list_reports(project["id"]) == []


def test_managed_audit_rejects_malformed_json_and_duplicate_running_submission(tmp_path):
    repository = tmp_path / "target_repository"
    repository.mkdir()
    service = AuditManagementService(tmp_path / "management.json")
    project = service.create_project("Target", repository_path=str(repository))

    class MalformedEngine:
        def __init__(self, output_dir, **_kwargs):
            self.output_dir = Path(output_dir)

        def run(self):
            self.output_dir.mkdir(parents=True, exist_ok=True)
            report = self.output_dir / "broken.json"
            report.write_text("not json", encoding="utf-8")
            return object(), {"json": str(report)}

    with pytest.raises(ManagementAuditError, match="not valid UTF-8 JSON"):
        service.run_project_audit(project["id"], engine_factory=MalformedEngine)
    assert service.list_reports(project["id"]) == []

    class DuplicateSubmissionEngine(_SuccessfulEngine):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.duplicate_error = None

        def run(self):
            try:
                service.run_project_audit(project["id"], engine_factory=_SuccessfulEngine)
            except ManagementAuditError as exc:
                self.duplicate_error = str(exc)
            assert self.duplicate_error == "An audit is already running for this project."
            return super().run()

    result = service.run_project_audit(project["id"], engine_factory=DuplicateSubmissionEngine)
    assert result["run"]["status"] == "Completed"


def _insert_running_run(service, project, run_id="run_abandoned", pid=999999, status="Running"):
    output = service.storage_path.parent / "runs" / project["id"] / run_id
    data = service._load()
    data["audit_runs"].append({
        "id": run_id, "project_id": project["id"], "project_name": project["name"],
        "repository_path": project["repository_path"], "provider": "offline", "formats": ["json"],
        "output_dir": str(output), "status": status, "created_at": "2020-01-01T00:00:00+00:00",
        "started_at": "2020-01-01T00:00:00+00:00",
        "execution": {"host": socket.gethostname(), "pid": pid, "mode": "in_process_background"},
    })
    service._write(data)
    return output


def test_startup_recovers_confirmed_abandoned_run_and_releases_project(tmp_path):
    repository = tmp_path / "target_repository"
    repository.mkdir()
    service = AuditManagementService(tmp_path / "management.json")
    project = service.create_project("Target", repository_path=str(repository))
    _insert_running_run(service, project)
    service._project_lock_path(project["id"]).write_text("old lock", encoding="utf-8")

    reopened = AuditManagementService(service.storage_path)
    run = reopened.list_audit_runs(project["id"])[0]

    assert run["status"] == "Interrupted"
    assert "no longer running" in run["error"]
    assert not reopened._project_lock_path(project["id"]).exists()
    result = reopened.run_project_audit(project["id"], engine_factory=_SuccessfulEngine)
    assert result["run"]["status"] == "Completed"


def test_active_local_run_is_not_incorrectly_interrupted(tmp_path):
    repository = tmp_path / "target_repository"
    repository.mkdir()
    service = AuditManagementService(tmp_path / "management.json")
    project = service.create_project("Target", repository_path=str(repository))
    _insert_running_run(service, project, run_id="run_live", pid=os.getpid())

    reopened = AuditManagementService(service.storage_path)
    assert reopened.list_audit_runs(project["id"])[0]["status"] == "Running"
    with pytest.raises(ManagementAuditError, match="already running"):
        reopened.run_project_audit(project["id"], engine_factory=_SuccessfulEngine)


def test_retry_creates_fresh_run_and_output_without_changing_failed_history(tmp_path):
    repository = tmp_path / "target_repository"
    repository.mkdir()

    class FailingEngine:
        def __init__(self, **_kwargs):
            pass

        def run(self):
            raise RuntimeError("intentional failure")

    service = AuditManagementService(tmp_path / "management.json")
    project = service.create_project("Target", repository_path=str(repository))
    with pytest.raises(ManagementAuditError):
        service.run_project_audit(project["id"], engine_factory=FailingEngine)
    failed = service.list_audit_runs(project["id"])[0]

    retried = service.retry_audit_run(failed["id"], _SuccessfulEngine)
    all_runs = service.list_audit_runs(project["id"])

    assert len(all_runs) == 2
    assert failed["status"] == "Failed"
    assert retried["run"]["id"] != failed["id"]
    assert retried["run"]["output_dir"] != failed["output_dir"]
    assert retried["run"]["retry_of"] == failed["id"]
    assert len(service.list_reports(project["id"])) == 1


def test_recovery_preserves_already_imported_report_without_duplicate_import(tmp_path):
    repository = tmp_path / "target_repository"
    repository.mkdir()
    service = AuditManagementService(tmp_path / "management.json")
    project = service.create_project("Target", repository_path=str(repository))
    report_path = tmp_path / "existing_report.json"
    _report(report_path)
    imported = service.import_report(project["id"], report_path)
    _insert_running_run(service, project, run_id="run_imported")
    data = service._load()
    run = next(item for item in data["audit_runs"] if item["id"] == "run_imported")
    run["report_id"] = imported["id"]
    service._write(data)

    reopened = AuditManagementService(service.storage_path)
    recovered = reopened.list_audit_runs(project["id"])[0]

    assert recovered["status"] == "Completed"
    assert len(reopened.list_reports(project["id"])) == 1
    with pytest.raises(ManagementValidationError, match="Only failed or interrupted"):
        reopened.retry_audit_run(recovered["id"], _SuccessfulEngine)


def test_concurrent_retry_attempt_is_rejected_safely(tmp_path):
    repository = tmp_path / "target_repository"
    repository.mkdir()

    class FailingEngine:
        def __init__(self, **_kwargs):
            pass

        def run(self):
            raise RuntimeError("intentional failure")

    service = AuditManagementService(tmp_path / "management.json")
    project = service.create_project("Target", repository_path=str(repository))
    with pytest.raises(ManagementAuditError):
        service.run_project_audit(project["id"], engine_factory=FailingEngine)
    failed = service.list_audit_runs(project["id"])[0]

    class RetryDuplicateEngine(_SuccessfulEngine):
        def run(self):
            with pytest.raises(ManagementAuditError, match="already running"):
                service.retry_audit_run(failed["id"], _SuccessfulEngine)
            return super().run()

    result = service.retry_audit_run(failed["id"], RetryDuplicateEngine)
    assert result["run"]["status"] == "Completed"
