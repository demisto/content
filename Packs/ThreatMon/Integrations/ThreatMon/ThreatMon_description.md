## Threatmon Integration

The Threatmon integration allows Cortex XSOAR to connect with the Threatmon platform to automatically retrieve and update incident data. This integration is designed to help security teams streamline incident management workflows by synchronizing Threatmon alarms and their status directly into XSOAR.

### Use Cases
- Automatically fetch and ingest Threatmon alarms as XSOAR incidents.
- Update the status of Threatmon incidents from within XSOAR.
- Submit takedown requests for eligible findings (Phishing Domains, Rogue Mobile Apps, Fake Social Media Accounts).
- Request data removal for Black Market Monitoring findings directly from XSOAR playbooks.
- Maintain a consistent incident lifecycle between Threatmon and XSOAR.

### Key Features
- Fetch Threatmon alarms into Cortex XSOAR.
- Update the status of existing Threatmon incidents (e.g., Open, In Progress, Resolved).
- Submit takedown requests for eligible threat findings.
- Submit Black Market Monitoring data removal requests — checks company credit rights and returns an appropriate error if the quota is exceeded.
- Query all CVEs monitored by ThreatMon, including CVSS v2, v3, v3.1, and v4 scores.
- Query CVEs affecting products the company is subscribed to.
- Supports automated playbooks for streamlined response.

### Commands
- **threatmon_update_incident_status** — Update the status of a specific Threatmon incident using its unique ID.
- **threatmon_request_takedown** — Submit a takedown request for an eligible Threatmon finding.
- **threatmon_request_data_removal** — Submit a Black Market Monitoring data removal request for a specific finding.
- **threatmon_list_cves** — Retrieve a paginated list of all CVEs monitored by ThreatMon.
- **threatmon_list_subscribed_cves** — Retrieve CVEs affecting products the company is subscribed to.

### Requirements
- Threatmon API credentials (API key).
- Access to Threatmon’s external API endpoints.
- For data removal: the authenticated company must have remaining Black Market Data Removal credits.

### Additional Information
Threatmon is a threat intelligence and monitoring platform that provides actionable alerts to security teams. Integrating Threatmon with XSOAR enables more efficient triage, faster response times, and better visibility into your security operations.

For more information about Threatmon, visit: [https://www.threatmon.io](https://www.threatmon.io)

---

**Support**
For support, please contact the Threatmon team at: [integration@threatmonit.io](mailto:integration@threatmonit.io)