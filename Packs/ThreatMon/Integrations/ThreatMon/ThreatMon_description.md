## Threatmon Integration

The Threatmon integration allows Cortex XSOAR to connect with the Threatmon platform to automatically retrieve and update incident data. This integration is designed to help security teams streamline incident management workflows by synchronizing Threatmon alarms and their status directly into XSOAR.

### Use Cases
- Automatically fetch and ingest Threatmon alarms as XSOAR incidents.
- Update the status of Threatmon incidents from within XSOAR.
- Maintain a consistent incident lifecycle between Threatmon and XSOAR.

### Key Features
- Fetch Threatmon alarms into Cortex XSOAR.
- Update the status of existing Threatmon incidents (e.g., Open, In Progress, Resolved).
- Supports automated playbooks for streamlined response.

### Commands
- **threatmon-update-incident-status**  
  - Update the status of a specific Threatmon incident using its unique ID.

### Requirements
- Threatmon API credentials (API key).
- Access to Threatmon’s incident management endpoints.

### Additional Information
Threatmon is a threat intelligence and monitoring platform that provides actionable alerts to security teams. Integrating Threatmon with XSOAR enables more efficient triage, faster response times, and better visibility into your security operations.

For more information about Threatmon, visit: [https://www.threatmon.io](https://www.threatmon.io)

---

**Support**
For support, please contact the Threatmon team at: [integration@threatmonit.io](mailto:integration@threatmonit.io)
