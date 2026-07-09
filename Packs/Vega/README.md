This pack provides an end-to-end integration with the Vega security platform, allowing analysts to fetch, map, and mirror Vega alerts and incidents directly in Cortex XSOAR.

## Real-Life Context

Security Operations Centers (SOCs) often need to track alerts and incidents originating from the Vega platform. Manually syncing comments, statuses, and events between Vega and Cortex XSOAR can be tedious and prone to human error. This pack automates the bidirectional syncing of Vega incidents and alerts into Cortex XSOAR, streamlining the incident response lifecycle.

## What does this pack do?

- **Ingest Vega Alerts and Incidents:** Automatically fetch and map alerts and incidents from Vega into Cortex XSOAR.
- **Bidirectional Mirroring:** Sync comments, verdict reasoning, and status updates between Vega and XSOAR in real-time.
- **Update Alerts and Incidents:** Provides commands like `vega-update-alert` and `vega-update-incident` to update Vega records from XSOAR playbooks.
- **Fetch Alert Events:** Retrieve rich contextual alert events directly into the XSOAR layout for deep analysis.
- **Custom Layouts:** Includes customized layouts for Vega Alerts and Incidents, providing a tailored view of all critical fields, including MITRE ATT&CK techniques, Verdicts, and Recommended Actions.
