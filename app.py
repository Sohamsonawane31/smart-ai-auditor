import streamlit as st
from collections import Counter
from datetime import datetime
from typing import Any, Dict, List

import plotly.graph_objects as go

from database.db import create_project, init_db, list_audits, list_projects, save_audit

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
    category_fig = go.Figure(
        data=[go.Bar(x=category_labels, y=category_values, marker_color="#4f46e5")]
    )
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
    severity_fig = go.Figure(
        data=[go.Pie(labels=severity_labels, values=severity_values, hole=0.4)]
    )
    severity_fig.update_layout(template="plotly_white", margin=dict(l=20, r=20, t=10, b=10))
    chart_cols[1].plotly_chart(severity_fig, use_container_width=True)

    st.markdown("#### Recent Audit Activity")
    recent_audits = sorted(
        audits,
        key=lambda item: item.get("created_at") or item.get("date", ""),
        reverse=True,
    )[:8]

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
            "date": str(datetime.now()),
            "score": _status_to_score(status),
        }

        try:
            save_audit(audit)
            st.success("✅ Audit saved successfully")
        except Exception as exc:
            st.error(f"Unable to save audit: {exc}")


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

menu = st.sidebar.radio(
    "Navigation",
    ["📊 Dashboard", "➕ Create Project", "📋 View Projects", "🧪 Run Audit"],
    index=0,
)

projects = list_projects()
audits = list_audits()

if menu == "➕ Create Project":
    _render_project_form()
elif menu == "📋 View Projects":
    _render_project_list()
elif menu == "🧪 Run Audit":
    _render_audit_form()
else:
    _render_dashboard(projects, audits)
