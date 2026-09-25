# XSOAR Incident Exporter

Export Cortex XSOAR 6 incidents to Cortex XSIAM using push or pull workflows.

## Pack Contents

### Integrations

- **Xporter (XSIAM Alert Pusher)** — Runs on XSOAR 6. Pushes incidents to XSIAM as parsed alerts via the Insert Parsed Alerts API. Supports bulk push, single incident push, and incremental sync.
- **XSOAR 6 Incident Collector** — Runs on XSIAM. Fetches incidents from a remote XSOAR 6 instance using fetch-incidents.

### Scripts

- **CloseFromXSOAR** — Extracts close reason and notes from an XSOAR-sourced alert and closes the XSIAM case accordingly.
- **SyncXSOARCloseStatus** — Scheduled job script that queries open XSOAR-sourced alerts and closes resolved ones in bulk.

### Playbooks

- **Close XSIAM Case From XSOAR** — Trigger playbook for XSOAR-sourced alerts. Runs CloseFromXSOAR to sync close status.

## Setup

### Push Workflow (XSOAR 6 → XSIAM)

1. Install the pack on XSOAR 6 by uploading `Xporter.yml` as a custom integration.
2. Configure the integration instance with your XSOAR 6 and XSIAM API credentials.
3. Run `!xsiam-push-incidents` for bulk push or `!xsiam-sync-new-incidents` for incremental sync.

### Pull Workflow (XSIAM fetches from XSOAR 6)

1. Install the pack on XSIAM via the Marketplace.
2. Configure the XSOAR 6 Incident Collector with your remote XSOAR 6 API credentials.
3. Enable fetch incidents to begin pulling incidents automatically.
