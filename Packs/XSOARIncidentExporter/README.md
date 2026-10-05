# XSOAR Incident Exporter

Push Cortex XSOAR 6 or XSOAR 8 incidents to Cortex XSIAM as parsed alerts via the Insert Parsed Alerts API.

## Pack Contents

### Integrations

- **Xporter (XSIAM Alert Pusher)** — Pushes incidents to XSIAM as parsed alerts. Supports bulk push, single incident push, and incremental sync with automatic state tracking. Full incident context including labels, custom fields, and raw JSON. Compatible with XSOAR 6 and XSOAR 8.

### Scripts

- **CloseFromXSOAR** — Extracts close reason and notes from an XSOAR-sourced alert and closes the XSIAM case accordingly.
- **SyncXSOARCloseStatus** — Scheduled job script that queries open XSOAR-sourced alerts and closes resolved ones in bulk.

### Playbooks

- **Close XSIAM Case From XSOAR** — Trigger playbook for XSOAR-sourced alerts. Runs CloseFromXSOAR to sync close status.

## XSOAR Version Compatibility

The integration supports XSOAR 6 (on-prem) and XSOAR 8 (cloud). The version is auto-detected based on whether an API Key ID is provided:

| | XSOAR 6 | XSOAR 8 |
|---|---|---|
| **Server URL** | `https://{server-ip}` | `https://api-{tenant}.xdr.us.paloaltonetworks.com` |
| **API Key ID** | Leave blank | Required |
| **Auth** | API Key only | API Key + Key ID |

## Setup

1. Upload `Xporter.yml` to your XSOAR instance via **Settings > Integrations > Upload Integration**.
2. Configure the integration instance with your XSOAR and XSIAM API credentials.
3. For XSOAR 8, fill in the **XSOAR API Key ID** field.
4. Run `!xsiam-push-incidents` for bulk push or `!xsiam-sync-new-incidents` for incremental sync.
