# ThreatMon Integration

## Overview

The ThreatMon integration enables Cortex XSOAR to retrieve threat intelligence data from the ThreatMon API and update incidents automatically based on the incoming threat context.

This integration is designed to help security teams streamline incident enrichment and response by leveraging real-time intelligence from ThreatMon’s extensive threat database.

---

## Use Cases

- Enrich incidents in XSOAR with actionable threat intelligence from ThreatMon.
- Automatically pull threat data and update incidents accordingly.
- Support analyst decision-making with contextual threat data from an external source.

---

## Key Features

- Real-time threat data ingestion from the ThreatMon API.
- Automated incident updates using custom playbooks or scheduled jobs.
- Flexible command-based data retrieval (on-demand or automated).
- Supports indicators such as IP addresses, domains, and file hashes.

---

## Requirements

- A valid ThreatMon API key (can be obtained from your ThreatMon dashboard).
- IP based access permission to Threatmon API
- Internet connectivity from your XSOAR instance to the ThreatMon API endpoint.

---

## Configuration

1. Navigate to **Settings > Integrations > Servers & Services**.
2. Search for **ThreatMon**.
3. Click **Add instance** to create and configure a new integration instance:
    - **Name:** `ThreatMon`
    - **API Key:** Your ThreatMon API key
    - **Base URL:** `https://external.threatmonit.io` *(or your custom endpoint)*
4. Click **Test** to validate the connection.
5. Click **Save**.

---

## Commands

| Command | Description |
|--------|-------------|
| `fetch-incidents` | Retrieves threat intelligence data for a specified indicator or time range. |
| `threatmon_update_incident_status` | Updates the current incident with contextual threat intelligence. |

> **Note:** Full command usage details and argument structures are available within the integration settings in XSOAR.

---

## Troubleshooting

- Make sure the API key is valid and not expired.
- Ensure the integration instance has network access to `https://external.threatmonit.io`.
- Review Cortex XSOAR logs for additional error context.

---

## Support

This is a **community-supported integration**. For issues or feature requests:

- Contact the ThreatMon team at [integration@threatmonit.io](mailto:integration@threatmonit.io).

---

## Author

ThreatMon Security Intelligence Team  
Website: [https://www.threatmon.io](https://www.threatmon.io)  
Support: [integration@threatmonit.io](mailto:integration@threatmonit.io)
