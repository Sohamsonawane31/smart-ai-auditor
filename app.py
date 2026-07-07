import math
from collections import Counter
from datetime import datetime, timedelta, timezone
from io import BytesIO
from typing import Any, Dict, List, Optional, Tuple

import plotly.graph_objects as go
import streamlit as st
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.pdfgen import canvas
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from database.db import (
    authenticate_user,
    create_project,
    create_user,
    get_user_by_email,
    get_user_by_username,
    has_users,
    init_db,
    list_audits,
    list_projects,
    list_users,
    save_audit,
)

CHECKPOINTS = {
    "Code Quality": [
        "Proper folder structure",
        "Readable and clean code",
        "Meaningful variable names",
    ],
    "Security": [
        "Input validation implemented",
        "Authentication present",
        "No hardcoded secrets",
    ],
}

PAGE_ACCESS = {
    "Admin": ["📊 Dashboard", "➕ Create Project", "📋 View Projects", "🧪 Run Audit", "🕘 Audit History", "👤 Manage Users"],
    "Auditor": ["📊 Dashboard", "📋 View Projects", "🧪 Run Audit", "🕘 Audit History"],
}


def _status_to_score(status: str) -> int:
    mapping = {
        "Pass": 100,
        "Partial": 60,
        "Fail": 20,
        "Not Applicable": 100,
    }
    return mapping.get(status, 0)


def _initialize_app() -> None:
    try:
        init_db()
    except Exception as exc:
        st.error(f"Unable to initialize storage: {exc}")


def _format_date(value: str) -> str:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).strftime("%Y-%m-%d")
    except (TypeError, ValueError):
        return str(value)[:10]


def _render_badge(status: str) -> str:
    colors = {
        "Pass": "#2ecc71",
        "Partial": "#f39c12",
        "Fail": "#e74c3c",
        "Not Applicable": "#95a5a6",
    }
    color = colors.get(status, "#34495e")
    return f"<span style='background-color:{color}; color:white; padding:4px 10px; border-radius:999px; font-size:0.8rem;'>{status}</span>"


def _initialize_session_state() -> None:
    defaults = {
        "authenticated": False,
        "user": None,
        "role": None,
        "username": None,
        "display_name": None,
        "auth_mode": "login",
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value


def _logout() -> None:
    st.session_state.authenticated = False
    st.session_state.user = None
    st.session_state.role = None
    st.session_state.username = None
    st.session_state.display_name = None
    st.session_state.auth_mode = "login"


def _render_register_page() -> None:
    st.header("📝 Create Account")
    st.caption("Register a new account to access the audit workspace")

    with st.form("register_form"):
        full_name = st.text_input("Full Name")
        username = st.text_input("Username")
        email = st.text_input("Email")
        password = st.text_input("Password", type="password")
        confirm_password = st.text_input("Confirm Password", type="password")
        submitted = st.form_submit_button("Register")

    if submitted:
        if not full_name or not username or not email or not password or not confirm_password:
            st.error("Please complete all fields")
            return

        if password != confirm_password:
            st.error("Passwords do not match")
            return

        if get_user_by_username(username):
            st.error("Username already exists")
            return

        if get_user_by_email(email):
            st.error("Email already exists")
            return

        try:
            create_user({"full_name": full_name, "username": username, "email": email, "password": password})
            st.success("Account created successfully. Please sign in.")
            st.session_state.auth_mode = "login"
            st.rerun()
        except Exception as exc:
            st.error(str(exc))

    st.markdown("---")
    if st.button("Already have an account? Sign In"):
        st.session_state.auth_mode = "login"
        st.rerun()


def _render_login_page() -> None:
    st.header("🔐 Sign In")
    st.caption("Access the audit workspace securely")

    with st.form("login_form"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Login")

    if submitted:
        user = authenticate_user(username, password)
        if user:
            st.session_state.authenticated = True
            st.session_state.user = user
            st.session_state.role = user.get("role", "Auditor")
            st.session_state.username = user.get("username")
            st.session_state.display_name = user.get("full_name") or user.get("username")
            st.success(f"Welcome back, {st.session_state.display_name}!")
            st.rerun()
        else:
            st.error("Invalid username or password")

    st.markdown("---")
    if st.button("Create an account"):
        st.session_state.auth_mode = "register"
        st.rerun()


def _render_dashboard(projects: List[Dict[str, Any]], audits: List[Dict[str, Any]]) -> None:
    total_projects = len(projects)
    total_audits = len(audits)
    average_score = round(sum(item.get("score", 0) for item in audits) / total_audits, 1) if audits else 0
    high_risk_findings = sum(
        1
        for audit in audits
        if audit.get("severity") in {"High", "Critical"} and audit.get("status") in {"Fail", "Partial"}
    )

    st.markdown("### Dashboard Overview")
    st.caption("A concise view of project health and recent audit activity")

    metric_cols = st.columns(4)
    metric_cols[0].metric("Total Projects", total_projects)
    metric_cols[1].metric("Total Audits", total_audits)
    metric_cols[2].metric("Average Health Score", f"{average_score}%")
    metric_cols[3].metric("High Risk Findings", high_risk_findings)

    chart_cols = st.columns(2)

    category_counts = Counter(audit.get("category", "General") for audit in audits)
    chart_cols[0].markdown("#### Audit Volume by Category")
    category_labels = list(category_counts.keys())
    category_values = list(category_counts.values())
    category_fig = go.Figure(data=[go.Bar(x=category_labels, y=category_values, marker_color="#4f46e5")])
    category_fig.update_layout(
        template="plotly_white",
        margin=dict(l=20, r=20, t=10, b=10),
        xaxis_title="Category",
        yaxis_title="Audit Count",
    )
    chart_cols[0].plotly_chart(category_fig, use_container_width=True)

    severity_counts = Counter(audit.get("severity", "Medium") for audit in audits)
    chart_cols[1].markdown("#### Risk Distribution")
    severity_labels = list(severity_counts.keys())
    severity_values = list(severity_counts.values())
    severity_fig = go.Figure(data=[go.Pie(labels=severity_labels, values=severity_values, hole=0.4)])
    severity_fig.update_layout(template="plotly_white", margin=dict(l=20, r=20, t=10, b=10))
    chart_cols[1].plotly_chart(severity_fig, use_container_width=True)

    st.markdown("#### Recent Audit Activity")
    recent_audits = sorted(audits, key=lambda item: item.get("created_at") or item.get("date", ""), reverse=True)[:8]

    if recent_audits:
        table_rows = []
        for audit in recent_audits:
            table_rows.append(
                {
                    "Project": audit.get("project_name", "Unknown"),
                    "Category": audit.get("category", "General"),
                    "Status": audit.get("status", "Pass"),
                    "Severity": audit.get("severity", "Medium"),
                    "Date": _format_date(audit.get("date", "")),
                }
            )
        st.dataframe(table_rows, use_container_width=True, hide_index=True)
    else:
        st.info("No audit activity yet. Run an audit to populate this section.")

    with st.expander("How audit scores are calculated"):
        st.write("- Pass: 100%")
        st.write("- Partial: 60%")
        st.write("- Fail: 20%")
        st.write("- Not Applicable: 100%")


def _render_project_form() -> None:
    st.header("Create New Project")
    name = st.text_input("Project Name")
    client = st.text_input("Client Name")
    tech = st.text_input("Technology Stack")

    if st.button("Create Project"):
        project = {
            "id": datetime.now().strftime("%Y%m%d%H%M%S"),
            "name": name,
            "client": client,
            "tech": tech,
            "status": "Active",
        }

        try:
            create_project(project)
            st.success("✅ Project created successfully")
        except Exception as exc:
            st.error(f"Unable to save project: {exc}")


def _render_project_list() -> None:
    st.header("Project List")
    projects = list_projects()

    if not projects:
        st.info("No projects found")
    else:
        for project in projects:
            st.markdown(
                f"<div style='padding:12px 14px; border:1px solid #e5e7eb; border-radius:10px; margin-bottom:10px;'>"
                f"<strong>{project['name']}</strong><br>"
                f"Client: {project['client']}<br>"
                f"Technology: {project['tech']}<br>"
                f"Status: {project['status']}</div>",
                unsafe_allow_html=True,
            )


def _render_audit_form() -> None:
    st.header("Run Project Audit")

    projects = list_projects()
    if not projects:
        st.warning("Create a project first")
        return

    project_names = {project["name"]: project["id"] for project in projects}
    selected_project = st.selectbox("Select Project", list(project_names.keys()))
    project_id = project_names[selected_project]

    category = st.selectbox("Audit Category", list(CHECKPOINTS.keys()))
    checkpoint = st.selectbox("Checkpoint", CHECKPOINTS[category])

    status = st.radio("Status", ["Pass", "Fail", "Partial", "Not Applicable"])
    severity = st.selectbox("Severity", ["Low", "Medium", "High", "Critical"])
    remark = st.text_area("Remarks")

    if st.button("Save Audit"):
        audit = {
            "project_id": project_id,
            "project_name": selected_project,
            "category": category,
            "checkpoint": checkpoint,
            "status": status,
            "severity": severity,
            "remark": remark,
            "auditor": st.session_state.display_name or st.session_state.username or "System",
            "date": str(datetime.now()),
            "score": _status_to_score(status),
        }

        try:
            save_audit(audit)
            st.success("✅ Audit saved successfully")
        except Exception as exc:
            st.error(f"Unable to save audit: {exc}")


def _render_manage_users() -> None:
    st.header("Manage Users")
    st.caption("Create local access accounts for auditors and administrators")

    with st.form("create_user_form"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        role = st.selectbox("Role", ["Auditor", "Admin"])
        submitted = st.form_submit_button("Create User")

    if submitted:
        try:
            create_user({"username": username, "password": password, "role": role})
            st.success(f"User {username} created successfully")
            st.rerun()
        except Exception as exc:
            st.error(str(exc))

    st.markdown("#### Existing Users")
    users = list_users()
    if users:
        st.dataframe(
            [{"Username": user.get("username"), "Role": user.get("role"), "Created": _format_date(user.get("created_at", ""))} for user in users],
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.info("No users have been created yet")


def _parse_audit_date(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is not None:
            parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
        return parsed.replace(tzinfo=None)
    except (TypeError, ValueError):
        return None


def _build_audit_history_rows(audits: List[Dict[str, Any]], projects_by_id: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    enriched_audits: List[Dict[str, Any]] = []
    for audit in audits:
        project = projects_by_id.get(audit.get("project_id"), {})
        enriched_audits.append(
            {
                **audit,
                "client": project.get("client", "Unknown"),
                "technology": project.get("tech", "Unknown"),
                "auditor": audit.get("auditor") or "System",
                "date_label": _format_date(audit.get("date", "")),
            }
        )
    return sorted(
        enriched_audits,
        key=lambda item: (_parse_audit_date(item.get("date")) or datetime.min).replace(tzinfo=None),
        reverse=True,
    )


def _filter_audits(
    audits: List[Dict[str, Any]],
    search_query: str,
    project_filter: str,
    status_filter: str,
    severity_filter: str,
    category_filter: str,
    date_range: Tuple[Optional[datetime], Optional[datetime]],
) -> List[Dict[str, Any]]:
    query = search_query.strip().lower()
    start_date, end_date = date_range
    filtered: List[Dict[str, Any]] = []

    for audit in audits:
        searchable_text = " ".join(
            [
                str(audit.get("project_name", "")),
                str(audit.get("client", "")),
                str(audit.get("category", "")),
                str(audit.get("checkpoint", "")),
                str(audit.get("remark", "")),
                str(audit.get("auditor", "")),
            ]
        ).lower()

        if query and query not in searchable_text:
            continue
        if project_filter != "All" and audit.get("project_name") != project_filter:
            continue
        if status_filter != "All" and audit.get("status") != status_filter:
            continue
        if severity_filter != "All" and audit.get("severity") != severity_filter:
            continue
        if category_filter != "All" and audit.get("category") != category_filter:
            continue

        audit_date = _parse_audit_date(audit.get("date"))
        if start_date and audit_date and audit_date.date() < start_date.date():
            continue
        if end_date and audit_date and audit_date.date() > end_date.date():
            continue

        filtered.append(audit)

    return filtered


def _build_pdf_report(audits: List[Dict[str, Any]], projects_by_id: Dict[str, Dict[str, Any]], title: str) -> bytes:
    if not audits:
        return b""

    buffer = BytesIO()
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("report_title", parent=styles["Heading1"], fontSize=18, leading=22, textColor=colors.HexColor("#0f172a"))
    section_style = ParagraphStyle("report_section", parent=styles["Heading2"], fontSize=12, leading=14, textColor=colors.HexColor("#1d4ed8"), spaceBefore=10)
    body_style = styles["BodyText"]

    def _draw_footer(canvas_obj: canvas.Canvas, doc: SimpleDocTemplate) -> None:  # type: ignore[name-defined]
        canvas_obj.saveState()
        canvas_obj.setFont("Helvetica", 9)
        canvas_obj.setFillColor(colors.grey)
        canvas_obj.drawString(inch, 0.5 * inch, "Audit Management System")
        canvas_obj.drawRightString(letter[0] - inch, 0.5 * inch, f"Page {canvas_obj.getPageNumber()}")
        canvas_obj.restoreState()

    story: List[Any] = []
    story.append(Paragraph("Audit Management System", title_style))
    story.append(Paragraph("Enterprise Audit Report", styles["Heading2"]))
    story.append(Paragraph(f"Generated on {datetime.now().strftime('%Y-%m-%d %H:%M')}", body_style))
    story.append(Spacer(1, 0.2 * inch))

    project_group = {}
    for audit in audits:
        project = projects_by_id.get(audit.get("project_id"), {})
        project_name = audit.get("project_name") or project.get("name", "Unknown Project")
        project_group.setdefault(project_name, []).append(audit)

    story.append(Paragraph(title, section_style))
    story.append(Spacer(1, 0.1 * inch))

    if project_group:
        project_summary_rows = [["Project", "Client", "Technology", "Audit Count"]]
        for project_name, project_audits in sorted(project_group.items()):
            project = projects_by_id.get(next((audit.get("project_id") for audit in project_audits if audit.get("project_id")), "") or "", {})
            project_summary_rows.append(
                [
                    project_name,
                    project.get("client", "Unknown"),
                    project.get("tech", "Unknown"),
                    str(len(project_audits)),
                ]
            )
        project_table = Table(project_summary_rows, repeatRows=1, hAlign="LEFT")
        project_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 9),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.whitesmoke, colors.white]),
                ]
            )
        )
        story.append(project_table)
        story.append(Spacer(1, 0.2 * inch))

    status_summary = Counter(audit.get("status", "Pass") for audit in audits)
    severity_summary = Counter(audit.get("severity", "Medium") for audit in audits)
    average_score = round(sum(audit.get("score", 0) for audit in audits) / len(audits), 1) if audits else 0

    summary_rows = [["Metric", "Value"], ["Total Audits", str(len(audits))], ["Average Health Score", f"{average_score}%"], ["Status Summary", str(dict(status_summary))], ["Severity Summary", str(dict(severity_summary))]]
    summary_table = Table(summary_rows, repeatRows=1, hAlign="LEFT")
    summary_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1d4ed8")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.whitesmoke, colors.white]),
            ]
        )
    )
    story.append(Paragraph("Audit Summary", section_style))
    story.append(summary_table)
    story.append(Spacer(1, 0.2 * inch))

    detail_rows = [["Date", "Project", "Category", "Checkpoint", "Status", "Severity", "Auditor", "Remarks"]]
    for audit in audits:
        detail_rows.append(
            [
                _format_date(audit.get("date", "")),
                audit.get("project_name", "Unknown"),
                audit.get("category", "General"),
                audit.get("checkpoint", "General Review"),
                audit.get("status", "Pass"),
                audit.get("severity", "Medium"),
                audit.get("auditor") or "System",
                (audit.get("remark") or "No remarks provided")[:120],
            ]
        )
    detail_table = Table(detail_rows, repeatRows=1, hAlign="LEFT")
    detail_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.whitesmoke, colors.white]),
            ]
        )
    )
    story.append(Paragraph("Audit Details", section_style))
    story.append(detail_table)

    document = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=0.75 * inch, leftMargin=0.75 * inch, topMargin=0.75 * inch, bottomMargin=0.75 * inch)
    document.build(story, onFirstPage=_draw_footer, onLaterPages=_draw_footer)
    buffer.seek(0)
    return buffer.getvalue()


def _render_audit_history() -> None:
    st.header("Audit History")
    st.caption("Search, filter, sort, and inspect completed audits")

    projects = list_projects()
    projects_by_id = {project.get("id"): project for project in projects}
    audits = list_audits()
    enriched_audits = _build_audit_history_rows(audits, projects_by_id)

    if "audit_history_search" not in st.session_state:
        st.session_state.audit_history_search = ""
    if "audit_history_project" not in st.session_state:
        st.session_state.audit_history_project = "All"
    if "audit_history_status" not in st.session_state:
        st.session_state.audit_history_status = "All"
    if "audit_history_severity" not in st.session_state:
        st.session_state.audit_history_severity = "All"
    if "audit_history_category" not in st.session_state:
        st.session_state.audit_history_category = "All"
    if "audit_history_start_date" not in st.session_state:
        st.session_state.audit_history_start_date = None
    if "audit_history_end_date" not in st.session_state:
        st.session_state.audit_history_end_date = None
    if "audit_history_pdf_bytes" not in st.session_state:
        st.session_state.audit_history_pdf_bytes = None
    if "audit_history_pdf_name" not in st.session_state:
        st.session_state.audit_history_pdf_name = "audit-report.pdf"

    col1, col2 = st.columns([2, 1])
    with col1:
        search_query = st.text_input(
            "Search",
            key="audit_history_search",
            placeholder="Project, category, checkpoint, remarks, auditor",
        )
    with col2:
        if st.button("Reset Filters"):
            st.session_state.audit_history_search = ""
            st.session_state.audit_history_project = "All"
            st.session_state.audit_history_status = "All"
            st.session_state.audit_history_severity = "All"
            st.session_state.audit_history_category = "All"
            st.session_state.audit_history_start_date = None
            st.session_state.audit_history_end_date = None
            st.rerun()

    project_options = ["All", *sorted({audit.get("project_name", "Unknown") for audit in enriched_audits})]
    status_options = ["All", "Pass", "Fail", "Partial", "Not Applicable"]
    severity_options = ["All", "Low", "Medium", "High", "Critical"]
    category_options = ["All", *sorted({audit.get("category", "General") for audit in enriched_audits})]

    filter_cols = st.columns(4)
    with filter_cols[0]:
        project_filter = st.selectbox("Project", project_options, key="audit_history_project")
    with filter_cols[1]:
        status_filter = st.selectbox("Status", status_options, key="audit_history_status")
    with filter_cols[2]:
        severity_filter = st.selectbox("Severity", severity_options, key="audit_history_severity")
    with filter_cols[3]:
        category_filter = st.selectbox("Category", category_options, key="audit_history_category")

    date_value = st.session_state.audit_history_start_date, st.session_state.audit_history_end_date
    if None in date_value and not any(date_value):
        date_value = None

    date_range = st.date_input(
        "Date Range",
        value=date_value,
        key="audit_history_date_range",
    )
    if isinstance(date_range, tuple) and len(date_range) == 2:
        start_date, end_date = date_range
    else:
        start_date, end_date = None, None
    st.session_state.audit_history_start_date = start_date
    st.session_state.audit_history_end_date = end_date

    filtered_audits = _filter_audits(
        enriched_audits,
        search_query,
        project_filter,
        status_filter,
        severity_filter,
        category_filter,
        (start_date, end_date),
    )

    page_size = 10
    total_pages = max(1, math.ceil(len(filtered_audits) / page_size)) if filtered_audits else 1
    current_page = st.number_input("Page", min_value=1, max_value=total_pages, value=1, step=1, key="audit_history_page")
    start_index = (current_page - 1) * page_size
    end_index = start_index + page_size
    paged_audits = filtered_audits[start_index:end_index]

    st.caption(f"Showing {len(paged_audits)} of {len(filtered_audits)} audits")

    if not paged_audits:
        st.info("No audits match the current search and filters")
        return

    table_rows = []
    for audit in paged_audits:
        table_rows.append(
            {
                "Date": audit.get("date_label", _format_date(audit.get("date", ""))),
                "Project": audit.get("project_name", "Unknown"),
                "Category": audit.get("category", "General"),
                "Checkpoint": audit.get("checkpoint", "General Review"),
                "Status": audit.get("status", "Pass"),
                "Severity": audit.get("severity", "Medium"),
                "Auditor": audit.get("auditor") or "System",
                "Remarks": (audit.get("remark") or "No remarks provided")[:80],
            }
        )

    selected_audit = None
    table = st.dataframe(table_rows, use_container_width=True, hide_index=True, selection_mode="single-row", on_select="rerun")
    if getattr(table, "selection", None) and getattr(table.selection, "rows", None):
        selected_row_index = table.selection.rows[0]
        if 0 <= selected_row_index < len(paged_audits):
            selected_audit = paged_audits[selected_row_index]

    if selected_audit:
        st.markdown("#### Selected Audit Details")
        st.write(f"**Project:** {selected_audit.get('project_name', 'Unknown')}")
        st.write(f"**Category:** {selected_audit.get('category', 'General')}")
        st.write(f"**Checkpoint:** {selected_audit.get('checkpoint', 'General Review')}")
        st.write(f"**Status:** {selected_audit.get('status', 'Pass')}")
        st.write(f"**Severity:** {selected_audit.get('severity', 'Medium')}")
        st.write(f"**Auditor:** {selected_audit.get('auditor') or 'System'}")
        st.write(f"**Date:** {selected_audit.get('date_label', _format_date(selected_audit.get('date', '')))}")
        st.write(f"**Score:** {selected_audit.get('score', 0)}")
        st.write(f"**Remarks:** {selected_audit.get('remark') or 'No remarks provided'}")
    else:
        st.info("Select a row in the table to view the full audit details")

    st.markdown("---")
    st.subheader("Generate PDF Report")
    report_scope = st.selectbox("Report Type", ["Filtered audit report", "Single audit report", "Entire project audit report"])

    if report_scope == "Single audit report":
        audit_options = {
            f"{audit.get('project_name', 'Unknown')} • {audit.get('category', 'General')} • {audit.get('checkpoint', 'General Review')}": audit
            for audit in filtered_audits
        }
        selected_report_key = st.selectbox("Audit", list(audit_options.keys())) if audit_options else st.empty()
        selected_report_audit = audit_options.get(selected_report_key) if audit_options else None
    elif report_scope == "Entire project audit report":
        project_names = [audit.get("project_name", "Unknown") for audit in filtered_audits]
        project_choice = st.selectbox("Project", sorted(set(project_names))) if project_names else st.empty()
        selected_report_audit = None
        selected_project_name = project_choice if project_names else None
    else:
        selected_report_audit = None
        selected_project_name = None

    if st.button("Generate PDF Report"):
        if report_scope == "Single audit report" and selected_report_audit:
            pdf_bytes = _build_pdf_report([selected_report_audit], projects_by_id, "Single Audit Report")
            st.session_state.audit_history_pdf_bytes = pdf_bytes
            st.session_state.audit_history_pdf_name = f"{selected_report_audit.get('project_name', 'audit')}-report.pdf"
            st.success("PDF report generated successfully")
        elif report_scope == "Entire project audit report" and selected_project_name:
            project_audits = [audit for audit in filtered_audits if audit.get("project_name") == selected_project_name]
            if project_audits:
                pdf_bytes = _build_pdf_report(project_audits, projects_by_id, f"Project Report: {selected_project_name}")
                st.session_state.audit_history_pdf_bytes = pdf_bytes
                st.session_state.audit_history_pdf_name = f"{selected_project_name}-project-report.pdf"
                st.success("PDF report generated successfully")
            else:
                st.warning("No audits found for the selected project")
        else:
            pdf_bytes = _build_pdf_report(filtered_audits, projects_by_id, "Filtered Audit Report")
            st.session_state.audit_history_pdf_bytes = pdf_bytes
            st.session_state.audit_history_pdf_name = "filtered-audit-report.pdf"
            if pdf_bytes:
                st.success("PDF report generated successfully")
            else:
                st.warning("No audits available for PDF generation")

    if st.session_state.audit_history_pdf_bytes:
        st.download_button(
            "Download PDF",
            data=st.session_state.audit_history_pdf_bytes,
            file_name=st.session_state.audit_history_pdf_name,
            mime="application/pdf",
        )


_initialize_app()

st.set_page_config(page_title="Audit Management System", layout="wide")
st.markdown(
    """
    <style>

    /* Main App */
    .stApp {
        background-color: #f8fafc;
    }

    /* Main Container */
    .block-container {
        padding-top: 1.5rem;
        padding-bottom: 2rem;
        padding-left: 2rem;
        padding-right: 2rem;
    }

    /* Sidebar */
    section[data-testid="stSidebar"] {
        background-color: #0f172a;
    }

    /* Sidebar title */
    section[data-testid="stSidebar"] h1,
    section[data-testid="stSidebar"] h2,
    section[data-testid="stSidebar"] h3,
    section[data-testid="stSidebar"] label {
        color: white !important;
        font-weight: 600;
    }

    /* Radio option text */
    section[data-testid="stSidebar"] .stRadio label {
        color: white !important;
        font-size: 16px;
        font-weight: 500;
    }

    /* Radio circles */
    section[data-testid="stSidebar"] .stRadio div[role="radiogroup"] {
        color: white !important;
    }

    /* Small text */
    section[data-testid="stSidebar"] p {
        color: #cbd5e1 !important;
    }

    /* Hover */
    section[data-testid="stSidebar"] label:hover {
        color: #60a5fa !important;
    }

    /* Metric Cards */
    div[data-testid="metric-container"] {
        background: white;
        border-radius: 12px;
        padding: 15px;
        border: 1px solid #e5e7eb;
        box-shadow: 0 2px 8px rgba(0,0,0,0.05);
    }

    /* Tables */
    .stDataFrame {
        border-radius: 10px;
        overflow: hidden;
    }

    </style>
    """,
    unsafe_allow_html=True,
)

st.title("🛠 Project Audit Management System")
st.caption("AI-powered software audit platform for modern engineering teams")

_initialize_session_state()

if not st.session_state.authenticated:
    if st.session_state.auth_mode == "register" or not has_users():
        _render_register_page()
    else:
        _render_login_page()
else:
    sidebar_name = st.session_state.display_name or st.session_state.username or "User"
    st.sidebar.markdown(f"### 👤 {sidebar_name}")
    st.sidebar.caption(st.session_state.role)
    if st.sidebar.button("Logout"):
        _logout()
        st.rerun()

    st.sidebar.divider()
    accessible_pages = PAGE_ACCESS.get(st.session_state.role, ["📊 Dashboard"])
    menu = st.sidebar.radio("Navigation", accessible_pages, index=0)

    projects = list_projects()
    audits = list_audits()

    if menu == "➕ Create Project":
        _render_project_form()
    elif menu == "📋 View Projects":
        _render_project_list()
    elif menu == "🧪 Run Audit":
        _render_audit_form()
    elif menu == "🕘 Audit History":
        _render_audit_history()
    elif menu == "👤 Manage Users":
        _render_manage_users()
    else:
        _render_dashboard(projects, audits)
