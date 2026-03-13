# Cyber Triage

Cyber Triage is an agentless endpoint triage tool that pushes a collection agent to remote Windows endpoints, gathers volatile and file system data, and analyzes it for indicators of compromise — including data exfiltration, lateral movement, remote access, and malware.

## What does this pack do?

This pack provides the **CyberTriage** integration, which allows you to:

- Initiate remote forensic triage collections on Windows endpoints directly from Cortex XSOAR.
- Send collected file hashes to external malware analysis services.
- Optionally upload suspicious files for deeper sandbox analysis.
- Retrieve session identifiers for tracking collection jobs in the Cyber Triage client.

## Use Cases

- **Breach Notification** — Rapidly investigate the scope of alerts to determine breach severity.
- **Incident Response** — Prioritize and triage endpoints during active security incidents.
- **Malware Analysis** — Detect malware using 40+ scanning tools and sandbox services.
- **Phishing** — Assess post-phishing endpoint compromise.
- **Ransomware** — Investigate ransomware deployment and lateral movement.
- **Threat Hunting** — Proactively assess endpoints for suspicious activity.

## Requirements

- Cyber Triage **Team** version (>= 3.16.0). The Standalone desktop version is not supported.
- A Windows administrative account with privileges on target endpoints.
- The Cyber Triage REST API key (found in Options → Deployment Mode → REST API Key).
