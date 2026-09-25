# XSOAR Incident Exporter

Export Cortex XSOAR 6 or XSOAR 8 incidents to Cortex XSIAM using push or pull workflows.

## Pack Contents

### Integrations

- **Xporter (XSIAM Alert Pusher)** — Runs on XSOAR 6 or 8. Pushes incidents to XSIAM as parsed alerts via the Insert Parsed Alerts API. Supports bulk push, single incident push, and incremental sync.
- **XSOAR Incident Collector** — Runs on XSIAM. Fetches incidents from a remote XSOAR 6 or XSOAR 8 instance using fetch-incidents.

### Scripts

- **CloseFromXSOAR** — Extracts close reason and notes from an XSOAR-sourced alert and closes the XSIAM case accordingly.
- **SyncXSOARCloseStatus** — Scheduled job script that queries open XSOAR-sourced alerts and closes resolved ones in bulk.

### Playbooks

- **Close XSIAM Case From XSOAR** — Trigger playbook for XSOAR-sourced alerts. Runs CloseFromXSOAR to sync close status.

## XSOAR Version Compatibility

Both integrations support XSOAR 6 (on-prem) and XSOAR 8 (cloud). The version is auto-detected based on whether an API Key ID is provided:

| | XSOAR 6 | XSOAR 8 |
|---|---|---|
| **Server URL** | `https://{server-ip}` | `https://api-{tenant}.xdr.us.paloaltonetworks.com` |
| **API Key ID** | Leave blank | Required |
| **Auth** | API Key only | API Key + Key ID |

## Setup

### Push Workflow (XSOAR → XSIAM)

1. Install the pack on XSOAR by uploading `Xporter.yml` as a custom integration.
2. Configure the integration instance with your XSOAR and XSIAM API credentials.
3. For XSOAR 8, fill in the **XSOAR API Key ID** field.
4. Run `!xsiam-push-incidents` for bulk push or `!xsiam-sync-new-incidents` for incremental sync.

### Pull Workflow (XSIAM fetches from XSOAR)

1. Install the pack on XSIAM via the Marketplace.
2. Configure the XSOAR Incident Collector with your remote XSOAR API credentials.
3. For XSOAR 8 sources, fill in the **XSOAR API Key ID** field.
4. Enable fetch incidents to begin pulling incidents automatically.
