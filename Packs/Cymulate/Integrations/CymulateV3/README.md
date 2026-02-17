# Cymulate v3

Cymulate is a Multi-Vector Cyber Attack, Breach and Attack Simulation (BAS) platform that continuously validates security posture by simulating real-world threats across multiple security controls.

This integration was integrated and tested with Cymulate API v2 (Assessment-based).

The Cymulate v3 integration for Cortex XSOAR enables users to:

- Fetch findings from completed Cymulate assessments as Cortex XSOAR incidents.
- Filter fetched findings by category: **All** (all "Not Prevented" findings) or **Threat Feed IOCs** (only findings tagged as Threat Feed IOC).
- Automatically paginate through assessments and their findings.
- Continuously monitor security control effectiveness.

Each finding in Cymulate represents a validated exposure or security weakness discovered through simulation. When fetched, these findings are transformed into Cortex XSOAR incidents, enabling:

- Triage and enrichment through playbooks.
- Automated response workflows.
- SOC visibility and tracking.
- Centralized reporting alongside other security tools.

The integration includes transient error handling for network issues, ensuring stable ingestion even under temporary connectivity issues.

---

## Configure Cymulate v3 in Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for **Cymulate v3**.
3. Click **Add instance**.
4. Configure the parameters below.
5. Click **Test** to validate connectivity.
6. Click **Save & exit**.

### Instance Parameters

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| API token | Cymulate API token used for authentication (sent as `x-token`). | False |
| Base URL | Cymulate API base URL (for example: `https://api.app.cymulate.com`). | False |
| Fetch incidents | When enabled, fetches Cymulate assessment findings as Cortex XSOAR incidents. | False |
| Fetch category | **All** fetches all "Not Prevented" findings. **Threat Feed IOCs** fetches only findings tagged as Threat Feed IOC. Default: All. | False |
| First fetch timestamp (number and time unit, e.g., `12 hours`, `7 days`) | First time to fetch incidents from. | False |
| Max Fetch | Maximum number of incidents to return per fetch run. Default: 25. | False |
| Trust any certificate (not secure) | If checked, SSL certificate verification is disabled. | False |
| Use system proxy settings | Use the system proxy settings for HTTP/S requests. | False |