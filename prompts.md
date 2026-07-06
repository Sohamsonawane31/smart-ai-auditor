# AI Prompt Design Document

# Prompt 1: Code Quality Review
Purpose: Used during audit review and report generation
to assist auditors with quality and security analysis.


Prompt:
You are a senior software auditor.  
Please review the following code for:  
- Code structure  
- Naming conventions  
- Readability  

List each issue found with:  
- Description of the problem  
- Severity level (Low, Medium, High)  
- Suggested improvements  

Here is the code:

def calculate_total(items):
    total = 0
    for i in range(len(items)):
        total += items[i]
    return total

password = "123456"


---

# Prompt 2: Security Audit
Purpose: Used during audit review and report generation
to assist auditors with quality and security analysis.


**Prompt:**
You are a security expert reviewing code.  
Analyze the following code for potential security issues, including but not limited to:  
- Input validation  
- Authentication mechanisms  
- Presence of hardcoded secrets or passwords  

List any security risks found with explanations.  

Code snippet:  

def calculate_total(items):
    total = 0
    for i in range(len(items)):
        total += items[i]
    return total

password = "123456"


---

# Prompt 3: Audit Summary
Purpose: Used during audit review and report generation
to assist auditors with quality and security analysis.


**Prompt:**
You are an auditor preparing a report for management.  
Summarize the audit results below into a clear, concise, and easy-to-understand report highlighting:  
- Key findings  
- Areas of concern  
- Suggested next steps  

Audit data:  

[
    {
        "category": "Code Quality",
        "checkpoint": "Proper folder structure",
        "status": "Fail",
        "severity": "High",
        "remark": "Multiple files are misplaced."
    },
    {
        "category": "Security",
        "checkpoint": "Input validation implemented",
        "status": "Partial",
        "severity": "Medium",
        "remark": "Some inputs are validated, but not all."
    }
]

## Prompt Usage Note
Prompts are designed to be reusable and UI-independent.
They can be invoked from the Streamlit UI or during offline analysis
to improve audit quality and reporting clarity.
