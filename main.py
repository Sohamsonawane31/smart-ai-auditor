import json
from datetime import datetime

CHECKPOINTS = {
    "Code Quality": [
        "Proper folder structure",
        "Readable and clean code",
        "Meaningful variable names"
    ],
    "Security": [
        "Input validation implemented",
        "Authentication present",
        "No hardcoded secrets"
    ]
}

def load_data(file):
    try:
        with open(file, "r") as f:
            return json.load(f)
    except:
        return []

def save_data(file, data):
    with open(file, "w") as f:
        json.dump(data, f, indent=4)

def create_project():
    name = input("Project Name: ")
    client = input("Client Name: ")
    tech = input("Technology Stack: ")
    
    project = {
        "id": datetime.now().strftime("%Y%m%d%H%M%S"),
        "name": name,
        "client": client,
        "tech": tech,
        "status": "Active"
    }
    
    projects = load_data("projects.json")
    projects.append(project)
    save_data("projects.json", projects)
    print("✅ Project created successfully")

def view_projects():
    projects = load_data("projects.json")
    for p in projects:
        print(p["id"], "-", p["name"], "-", p["client"])

def run_audit():
    projects = load_data("projects.json")
    if not projects:
        print("No projects found")
        return

    print("Select Project ID:")
    for p in projects:
        print(p["id"], "-", p["name"])

    pid = input("Enter Project ID: ")

    for category, items in CHECKPOINTS.items():
        print(f"\nAuditing {category}")
        for checkpoint in items:
            status = input(f"{checkpoint} (Pass/Fail/Partial/NA): ")
            severity = input("Severity (Low/Medium/High): ")
            remark = input("Remark: ")

            audit = {
                "project_id": pid,
                "category": category,
                "checkpoint": checkpoint,
                "status": status,
                "severity": severity,
                "remark": remark
            }

            audits = load_data("audits.json")
            audits.append(audit)
            save_data("audits.json", audits)


while True:
    print("\n1. Create Project")
    print("2. View Projects")
    print("3. Run Audit")
    print("4. Exit")

    choice = input("Choose option: ")

    if choice == "1":
        create_project()
    elif choice == "2":
        view_projects()
    elif choice == "3":
        run_audit()
    elif choice == "4":
        break
    else:
        print("Invalid option")

