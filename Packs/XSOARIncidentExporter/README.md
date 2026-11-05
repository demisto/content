# XSOAR Incident Exporter

Export Cortex XSOAR 6 or Cortex XSOAR 8 incidents to Cortex XSIAM using the Insert Parsed Alerts API.

## Pack Contents

### Integrations

- **XSOAR Incident Exporter** — Runs on Cortex XSOAR 6 or 8. Pushes incidents to Cortex XSIAM as parsed alerts. Supports bulk push, single incident push, incremental sync, and close status sync.

### Scripts

- **CloseFromXSOAR** — Extracts close reason and notes from a Cortex XSOAR-sourced alert and closes the Cortex XSIAM case accordingly.

### Playbooks

- **Close XSIAM Case From XSOAR** — Trigger playbook for Cortex XSOAR-sourced alerts. Runs CloseFromXSOAR to sync close status.

## Cortex XSOAR Version Compatibility

The integration supports Cortex XSOAR 6 (on-prem) and Cortex XSOAR 8 (cloud). The version is auto-detected based on whether an API Key ID is provided:

| | Cortex XSOAR 6 | Cortex XSOAR 8 |
|---|---|---|
| **Server URL** | `https://{server-ip}` | `https://api-{tenant}.xdr.us.paloaltonetworks.com` |
| **API Key ID** | Leave blank | Required |
| **Auth** | API Key only | API Key + Key ID |

## Setup

1. Install the pack on Cortex XSOAR.
2. Configure the XSOAR Incident Exporter integration instance with your Cortex XSOAR and Cortex XSIAM API credentials.
3. For Cortex XSOAR 8, fill in the **Cortex XSOAR API Key ID** field.
4. Run `!xsoar-exporter-push-incidents` for bulk push or `!xsoar-exporter-sync-new-incidents` for incremental sync.
5. Run `!xsoar-exporter-sync-close-status` to resolve Cortex XSIAM alerts whose source incidents are closed.
