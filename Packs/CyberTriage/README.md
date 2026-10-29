# Cyber Triage

Cyber Triage is an automated investigation platform that imports data from existing telemetry and has its own collector for additional artifacts. It scores the data to help you quickly identify what happened on an endpoint, with a focus on lateral movement, data exfiltration, and remote access.

## What does this pack do?

This pack provides the **CyberTriage** integration, which allows you to:

- Initiate remote forensic triage collections on Windows endpoints directly from Cortex XSOAR.
- That data is sent back into Cyber Triage, which will then analyze it using malware analysis, threat intelligence, and other heuristics to identify the relevant artifacts.

## Use Cases

- **Breach Notification** — Rapidly investigate the scope of alerts to determine breach severity.
- **Incident Response** — Prioritize and triage endpoints during active security incidents.
- **Malware Analysis** — Detect malware using 40+ scanning tools and sandbox services.
- **Phishing** — Assess post-phishing endpoint compromise.
- **Ransomware** — Investigate ransomware deployment and lateral movement.
- **Threat Hunting** — Proactively assess endpoints for suspicious activity.

## Requirements

- Cyber Triage **Team** version (>= 4.0). The Standalone desktop version is not supported.
- The public API enabled in Cyber Triage (Options → Team Settings → Enable the public API).
- A Windows administrative account with privileges on target endpoints.
- The Cyber Triage API authentication token (found in Options → User Accounts → api-user → View Details).

## Contact Info

- Support: support@sleuthkitlabs.com
- Sales: sales@sleuthkitlabs.com
