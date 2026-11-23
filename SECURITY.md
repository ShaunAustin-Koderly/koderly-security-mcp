# Security policy

## Reporting a vulnerability

Please do not report security vulnerabilities through public issues.

Use the hosting platform's private vulnerability reporting feature instead (for example, GitHub's **Security → Report a vulnerability**) if it is enabled for this repository. Otherwise, email the maintainers at support@koder.ly.

Please include:

- a description of the issue and its impact
- steps to reproduce it, or a proof of concept
- the affected version or commit

We aim to acknowledge reports within five working days.

## Scope and design principles

This server is intended to be **read-only**. We are particularly interested in reports of:

- any path by which a tool can modify tenant state
- query or script injection into the KQL queries or the PowerShell script the server builds
- credential, token, or certificate exposure
- tools returning more data than their documented bounds

Please never commit secrets, tenant IDs, subscription IDs, or other environment-specific identifiers to this repository. All configuration is supplied through environment variables.
