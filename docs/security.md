# Security notes

- Do not commit `.env`, management data, generated audit reports, target
  repositories, or credentials.
- Offline mode does not transmit source code to an LLM. NVIDIA and OpenCode
  modes send only redacted, bounded context; obtain client authorization first.
- The auditor statically examines a target and does not execute its project
  code. Findings still require qualified human review.
- The management UI is local and single-user. Use filesystem permissions and
  secure backups to protect `management_data/`.
- Public GitHub targets are cloned into temporary isolated workspaces. Private
  repository credentials are not managed by this application.
