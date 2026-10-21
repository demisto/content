## XSOAR Incident Exporter

This integration pushes Cortex XSOAR 6 or Cortex XSOAR 8 incidents to Cortex XSIAM as parsed alerts using the [Insert Parsed Alerts API](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-API-Reference/Insert-Parsed-Alerts).

### Prerequisites

- A Cortex XSIAM API key with permissions to insert parsed alerts.
- The Cortex XSIAM API Key ID associated with the API key.
- The Cortex XSIAM API base URL for your tenant.

### How It Works

1. The integration queries Cortex XSOAR for incidents matching a configurable filter.
2. Each incident is mapped to the Cortex XSIAM parsed alert schema, including severity, name, description, and timestamp.
3. The mapped alerts are sent to Cortex XSIAM via the Insert Parsed Alerts endpoint.
4. Alerts appear in Cortex XSIAM with product **XSOAR** and vendor **Palo Alto Networks**.

### Usage

- **Manual push**: Run `!xsoar-exporter-push-incidents` or `!xsoar-exporter-push-incident incident_id=<ID>` from the War Room.
- **Scheduled push**: Create a playbook that calls `xsoar-exporter-push-incidents` with appropriate date filters, then attach it to a recurring job to continuously forward incidents.
- **Filtered push**: Use the `query` parameter (instance-level or per-command) to push only specific incident types (e.g., `type:Phishing`).
- **Close status sync**: Run `!xsoar-exporter-sync-close-status` to resolve Cortex XSIAM alerts whose source Cortex XSOAR incidents have been closed.
