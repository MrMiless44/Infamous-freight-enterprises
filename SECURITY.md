# Security & Compliance

Our security posture follows least privilege, org-level data isolation, audited access, and secure secret management. All CI workflows enforce least-privilege GITHUB_TOKEN permissions. We maintain audit logs for key actions and design toward SOC2 readiness via dependency monitoring, CI enforcement, and change management.

## Security Posture

- **Data Isolation**: Per-organization data boundaries
- **Least Privilege**: Minimized tokens and permissions in CI/CD
- **Secret Management**: Environment-scoped secrets, no secrets in VCS
- **Auditability**: CI logs + decision records for sensitive actions
- **Dependency Security**: Dependabot + weekly updates

## Reporting Security Issues

For detailed security policies and vulnerability reporting, see:

➡️ [docs/security.md](docs/security.md)
