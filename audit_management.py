"""Optional Streamlit Audit Management module for Smart AI Auditor.

Run with: streamlit run audit_management.py
The existing `python audit.py ...` command is unchanged.
"""

from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

import streamlit as st

from ai_project_auditor.management import AuditManagementService, ManagementAuditError, ManagementValidationError


ROOT = Path(__file__).resolve().parent
STORE = ROOT / "management_data" / "audit_management.json"
CHECKPOINTS = {
    "Code Quality": ["Proper folder structure", "Readable and clean code", "Meaningful variable names"],
    "Security": ["Input validation implemented", "Authentication present", "No hardcoded secrets"],
}
AUDIT_EXECUTOR = ThreadPoolExecutor(max_workers=2, thread_name_prefix="smart-audit")


def service() -> AuditManagementService:
    return AuditManagementService(STORE)


def choose_project(items):
    return st.selectbox("Project", items, format_func=lambda item: item["name"]) if items else None


def show_dashboard(api: AuditManagementService) -> None:
    projects, assessments, findings, actions = api.list_projects(), api.list_audits(), api.list_findings(), api.list_corrective_actions()
    runs = api.list_audit_runs()
    cols = st.columns(5)
    cols[0].metric("Projects", len(projects))
    cols[1].metric("Assessments", len(assessments))
    cols[2].metric("Imported findings", len(findings))
    cols[3].metric("Open actions", sum(item["status"] == "Open" for item in actions))
    cols[4].metric("Audit runs", len(runs))
    if projects and not runs:
        st.info("Projects are registered, but no audit has been run or imported yet. Use Run audit to generate and register findings; the dashboard will then populate from persisted results.")
    if assessments:
        st.subheader("Assessment status")
        counts = {}
        for item in assessments:
            counts[item["status"]] = counts.get(item["status"], 0) + 1
        st.bar_chart(counts)
    st.subheader("Recent activity")
    activity = sorted(assessments + api.list_reports(), key=lambda item: item.get("created_at", item.get("imported_at", "")), reverse=True)[:10]
    st.dataframe(activity, use_container_width=True, hide_index=True)


def show_projects(api: AuditManagementService) -> None:
    st.subheader("Projects")
    with st.form("project"):
        name = st.text_input("Project name")
        client = st.text_input("Client")
        technology = st.text_input("Technology stack")
        repository_location = st.text_input("Repository location (optional: local folder or public GitHub URL)")
        if st.form_submit_button("Create project"):
            try:
                api.create_project(name, client, technology, repository_location)
                st.success("Project created.")
            except ManagementValidationError as exc:
                st.error(str(exc))
    st.dataframe(api.list_projects(), use_container_width=True, hide_index=True)
    with st.expander("Import legacy management data"):
        source = st.text_input("Legacy application directory", key="legacy_source")
        if st.button("Copy legacy projects and audits"):
            try:
                result = api.migrate_legacy_json(source)
                st.success(f"Copied {result['projects']} projects and {result['audits']} assessments. Source files were not modified.")
            except ManagementValidationError as exc:
                st.error(str(exc))


def show_assessments(api: AuditManagementService) -> None:
    st.subheader("Checklist assessment")
    project = choose_project(api.list_projects())
    if not project:
        st.info("Create a project before recording an assessment.")
        return
    with st.form("assessment"):
        category = st.selectbox("Category", list(CHECKPOINTS))
        checkpoint = st.selectbox("Checkpoint", CHECKPOINTS[category])
        status = st.selectbox("Status", ["Pass", "Partial", "Fail", "Not Applicable"])
        severity = st.selectbox("Severity", ["Low", "Medium", "High", "Critical"], index=1)
        remarks = st.text_area("Remarks")
        if st.form_submit_button("Save assessment"):
            try:
                api.create_assessment(project["id"], category, checkpoint, status, severity, remarks)
                st.success("Assessment saved.")
            except ManagementValidationError as exc:
                st.error(str(exc))
    st.dataframe(api.list_audits(project["id"]), use_container_width=True, hide_index=True)


def show_run_audit(api: AuditManagementService) -> None:
    st.subheader("Run Smart AI Auditor")
    active_future = st.session_state.get("managed_audit_future")
    if active_future is not None:
        if not active_future.done():
            st.info("An audit is running in the background. You can navigate to other pages and return here to check its status.")
            if st.button("Refresh audit status"):
                st.rerun()
            return
        del st.session_state["managed_audit_future"]
        try:
            result = active_future.result()
        except (ManagementValidationError, ManagementAuditError) as exc:
            st.error(str(exc))
        except Exception as exc:
            st.error(f"Unexpected audit failure: {exc}")
        else:
            st.success(f"Audit completed. Imported {result['report']['finding_count']} findings into this project.")

    project = choose_project(api.list_projects())
    if not project:
        st.info("Create a project and configure its repository path before running an audit.")
        return

    runs = api.list_audit_runs(project["id"])
    if runs:
        st.subheader("Audit runs")
        st.dataframe(runs, use_container_width=True, hide_index=True)
        unresolved = [item for item in runs if item["status"] == "Running"]
        for item in unresolved:
            with st.expander(f"Recovery required: {item['id']}"):
                st.warning("This run could not be verified as stopped automatically. Confirm that it is no longer executing before releasing it.")
                reason = st.text_input("Recovery reason", key=f"recover_reason_{item['id']}")
                confirmed_stop = st.checkbox("I confirm this audit execution has stopped.", key=f"recover_confirm_{item['id']}")
                if st.button("Mark interrupted", key=f"interrupt_{item['id']}"):
                    if not confirmed_stop:
                        st.error("Confirmation is required before releasing this run.")
                    else:
                        try:
                            api.mark_run_interrupted(item["id"], reason)
                            st.success("Run marked interrupted. It can now be retried.")
                            st.rerun()
                        except (ManagementValidationError, ManagementAuditError) as exc:
                            st.error(str(exc))

        retryable = [item for item in runs if item["status"] in {"Failed", "Interrupted"}]
        if retryable:
            retry = st.selectbox("Retry a failed or interrupted run", retryable,
                                 format_func=lambda item: f"{item['status']}: {item['id']}")
            if st.button("Retry selected run"):
                st.session_state["managed_audit_future"] = AUDIT_EXECUTOR.submit(api.retry_audit_run, retry["id"])
                st.info("Retry started in the background with a new run ID and output directory.")
                return

    configured_location = project.get("repository_url") or project.get("repository_path", "")
    default_kind = "GitHub URL" if project.get("repository_url") or str(configured_location).startswith(("http://", "https://", "github.com/")) else "Local directory"
    with st.form("run_audit"):
        target_kind = st.radio("Repository type", ["Local directory", "GitHub URL"], index=0 if default_kind == "Local directory" else 1)
        repository_location = st.text_input("Repository location", value=configured_location,
                                            help="Local directories are audited in place. Public GitHub URLs are shallow-cloned into a temporary isolated workspace.")
        provider = st.selectbox("AI provider", ["offline", "nvidia", "opencode"], help="Uses the same supported providers and environment configuration as the CLI.")
        formats = st.multiselect("Report formats", ["all", "json", "markdown", "excel", "pdf"], default=["all"], help="JSON is always generated for safe management import.")
        confirmed = st.checkbox("I confirm this is the selected project's repository.")
        submitted = st.form_submit_button("Run audit", disabled=st.session_state.get("audit_in_progress", False))
    if not submitted:
        return
    if not confirmed:
        st.error("Confirm the repository location before starting the audit.")
        return

    try:
        if target_kind == "GitHub URL":
            if not project.get("repository_url") and repository_location == project.get("repository_path"):
                st.info("Recognized an older project record containing a GitHub URL in the local-path field. It will be normalized without changing the URL.")
            if repository_location != configured_location or not project.get("repository_url"):
                project = api.set_project_repository_url(project["id"], repository_location)
        elif repository_location != configured_location or project.get("repository_url"):
            project = api.set_project_repository_path(project["id"], repository_location)
        st.session_state["audit_in_progress"] = True
        st.session_state["managed_audit_future"] = AUDIT_EXECUTOR.submit(
            api.run_project_audit, project["id"], provider, formats
        )
        st.info("Audit started in the background. Return to this page to view completion status.")
    except (ManagementValidationError, ManagementAuditError) as exc:
        st.error(str(exc))
    finally:
        st.session_state["audit_in_progress"] = False


def show_reports(api: AuditManagementService) -> None:
    st.subheader("Import Smart AI Auditor report")
    project = choose_project(api.list_projects())
    if not project:
        st.info("Create a project before importing a report.")
        return
    path = st.text_input("JSON report file or reports directory", value=str(ROOT / "reports"))
    selected_path = path
    try:
        candidate = Path(path).expanduser()
        if candidate.is_dir():
            options = api.discover_report_files(candidate)
            if options:
                selected_path = st.selectbox("Select report file", options, format_func=lambda value: Path(value).name)
            else:
                st.info("No valid Smart AI Auditor JSON reports were found. Run an audit with JSON output, then select its report file.")
    except ManagementValidationError as exc:
        st.error(str(exc))
    if st.button("Import report"):
        try:
            imported = api.import_report(project["id"], selected_path)
            st.success(f"Imported {imported['finding_count']} findings without changing the source report.")
        except ManagementValidationError as exc:
            st.error(str(exc))
    reports = api.list_reports(project["id"])
    st.dataframe(reports, use_container_width=True, hide_index=True)
    if reports:
        selected = st.selectbox("Imported report", reports, format_func=lambda item: f"{item['project_name']} — {item['imported_at']}")
        check_results = api.report_check_results(selected["id"])
        st.caption(f"LLM findings rejected during source analysis: {selected.get('llm_findings_rejected', 0)}. Individual rejected LLM responses are not emitted by the core report contract.")
        if check_results:
            st.subheader("Checklist outcomes")
            st.dataframe(check_results, use_container_width=True, hide_index=True)


def show_findings(api: AuditManagementService) -> None:
    st.subheader("Findings and corrective actions")
    project = choose_project(api.list_projects())
    if not project:
        st.info("Create a project and import a report first.")
        return
    findings = api.list_findings(project["id"])
    if not findings:
        st.info("No imported findings for this project.")
        return
    selected = st.selectbox("Finding", findings, format_func=lambda item: f"{item['snapshot'].get('severity', 'Info')}: {item['snapshot'].get('title', item['source_finding_id'])}")
    st.json(selected["snapshot"])
    with st.form("decision"):
        decision = st.selectbox("Review decision", ["Pending", "Validated", "Rejected"], index=["Pending", "Validated", "Rejected"].index(selected["decision"]))
        note = st.text_area("Decision note", value=selected["decision_note"])
        if st.form_submit_button("Save decision"):
            api.decide_finding(selected["id"], decision, note)
            st.success("Decision saved.")
    with st.form("action"):
        action = st.text_area("Corrective action")
        owner = st.text_input("Owner")
        due_date = st.date_input("Due date")
        if st.form_submit_button("Create corrective action"):
            try:
                api.create_corrective_action(selected["id"], action, owner, str(due_date))
                st.success("Corrective action created.")
            except ManagementValidationError as exc:
                st.error(str(exc))
    actions = api.list_corrective_actions(project["id"])
    if actions:
        action_item = st.selectbox("Corrective action", actions, format_func=lambda item: f"{item['status']}: {item['action']}")
        with st.form("action_status"):
            current = ["Open", "In Progress", "Resolved", "Closed"]
            action_status = st.selectbox("Action status", current, index=current.index(action_item["status"]))
            status_note = st.text_area("Status note", value=action_item.get("status_note", ""))
            if st.form_submit_button("Update action status"):
                api.update_corrective_action_status(action_item["id"], action_status, status_note)
                st.success("Corrective action updated.")
    st.dataframe(actions, use_container_width=True, hide_index=True)


def show_history(api: AuditManagementService) -> None:
    st.subheader("Audit history")
    project = choose_project(api.list_projects())
    if not project:
        st.info("Create or import a project to view history.")
        return
    st.dataframe(api.history(project["id"]), use_container_width=True, hide_index=True)


def main() -> None:
    st.set_page_config(page_title="Smart AI Auditor — Audit Management", layout="wide")
    st.title("Smart AI Auditor")
    st.caption("Audit Management — projects, assessments, imported technical findings, and corrective actions")
    api = service()
    page = st.sidebar.radio("Module", ["Dashboard", "Projects", "Run audit", "Assessments", "Reports", "Findings & actions", "History"])
    {"Dashboard": show_dashboard, "Projects": show_projects, "Assessments": show_assessments,
     "Run audit": show_run_audit, "Reports": show_reports, "Findings & actions": show_findings,
     "History": show_history}[page](api)


if __name__ == "__main__":
    main()
