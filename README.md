# Local Audit Management System

## Overview
This project is a local audit management system designed to replace Excel-based software audits.
It allows users to create projects, define audit checkpoints, execute audits, and store results persistently using local storage.
The system also demonstrates the use of AI through prompt engineering to assist in code quality analysis and audit reporting.

---

## Problem Statement
Manual audit tracking using Excel sheets leads to:
- Manual data entry errors
- Lack of standardization
- No centralized audit history
- Limited reporting and analysis

This project provides a structured, scalable alternative using a local software solution.

---

## System Architecture
- Command Line Interface (CLI)
- Python-based application
- Local JSON files used as NoSQL-style storage
- AI used externally through prompt engineering for analysis and summarization

---

## Technology Stack
- Programming Language: Python
- Storage: JSON files (Local NoSQL-style storage)
- Development Tool: Visual Studio Code
- AI Tool: ChatGPT (for prompt-based assistance)

---

## Database Design
The system uses two JSON files:

## projects.json
Stores project details:
- id
- project name
- client name
- technology stack
- status

## audits.json
Stores audit results:
- project id
- audit category
- checkpoint
- status
- severity
- remarks
- timestamp

---

## Features
- Create and manage projects
- Predefined audit categories and checkpoints
- Execute audits using structured checkpoints
- Persist audit data locally
- Generate sample audit reports
- AI-assisted audit summary and recommendations

---

## Setup & Run Instructions
1. Install Python (version 3.x)
2. Open the project folder in VS Code
3. Install required dependency:
   pip install streamlit
4. Run the application:
   streamlit run app.py
5. Use the interactive UI to create projects and perform audits

Note: The initial CLI-based version is available in main.py for reference.

---

## AI & Prompt Engineering Usage
AI is used through well-defined prompts for:
- Code quality review
- Security audit
- Improvement suggestions
- Audit report summarization

Prompts are documented separately in the Prompt Design Document.

---

## Sample Output
A sample audit report is provided in: sample_audit_report.md

## Assumptions & Limitations
- This is a local, single-user system
- No real client project code is included
- JSON storage is used instead of a full database
- AI is used as an assistant, not an automated decision-maker

---

## Future Enhancements
- Automated report generation
- Risk scoring system
- Audit history and versioning
- Role-based access control
- PDF report export

---

## User Interface
The project includes a Streamlit-based interactive UI (`app.py`)
that allows users to:
- Create projects using forms
- Perform audits using dropdowns and buttons
- Store audit results locally without terminal interaction

---

## Conclusion
This project demonstrates logical problem-solving, structured audit design, and effective use of AI through prompt engineering to enhance software quality audits.