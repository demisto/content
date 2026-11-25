## ThreatMon Incident Management

Fetches ThreatMon alarms as **ThreatMon Alert** incidents, mirrors their status between ThreatMon and Cortex, submits takedown and data removal requests, and enriches CVEs and files with ThreatMon intelligence.

### Get the API key
1. Sign in to the ThreatMon dashboard.
2. Go to **Settings > Integrations > Settings** and copy the **External API Key**.

If IP whitelisting is enabled for your ThreatMon account, send the public IP address of the Cortex server or engine to [support@threatmonit.io](mailto:support@threatmonit.io).

### Fetching
- Changes are followed by change time, so alarms that are approved later and alarms that move to a fetched status are fetched as well. Alarms that already exist are never created again.
- **Alarm Statuses to Fetch** defaults to *Open* and *In Progress*.
- **Attach Screenshots** adds the screenshots of the findings to the incident.
- Leak findings can contain passwords. **Mask Secrets in Findings** shortens them before they are stored.

### Mirroring (Cortex XSOAR)
Set **Incident Mirroring Direction** to mirror the alarm status:
- **Incoming**: status changes in ThreatMon update the **ThreatMon Status** field. Select **Close Mirrored Cortex Incident** to close incidents when the alarm is set to Resolved or Ignore.
- **Outgoing**: changing **ThreatMon Status** sets the alarm status. Select **Close Mirrored ThreatMon Alarm** to set the alarm to Resolved (or Ignore for False Positive and Duplicate) when the incident is closed.

### Modules
CVE enrichment needs the Vulnerability Knowledge module, the sandbox needs the Sandbox module, and MSSP customer management needs the External API Key of the MSSP administrator account.

### MSSP
Enter the exact sub company name in **Customer Name (MSSP)**. A name that does not match is rejected by ThreatMon like a wrong API key. ThreatMon currently rejects sub company names that contain a space.
