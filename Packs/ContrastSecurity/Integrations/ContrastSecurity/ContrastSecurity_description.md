## Contrast Security

### Authorization

The Contrast Security username, API key, service key, and organization ID can be found in the Contrast Security platform by clicking on the profile icon.

### Instance Configuration

1. Configure a Contrast Security integration instance with valid credentials.
2. Click **Test** to validate the connection between Cortex XSOAR and the Contrast Security platform.
3. To fetch Contrast Security Incidents and Issues as Cortex XSOAR incidents, select **Fetch incidents**, select the **Event Type**, and configure the fetch parameters.
4. To keep Cortex XSOAR and Contrast Security in sync, configure the **Incident Mirroring Direction** and **Issue Mirroring Direction**.

The following table provides detailed information about each configuration parameter of the integration instance:

| **Parameter** | **Description** |
| --- | --- |
| Contrast Security Server URL | Server URL of the Contrast Security platform. |
| Contrast Security Username (Email) | Username used for Contrast Security platform. Email address is used as the username. |
| Contrast Security Service Key | Service key used for Contrast Security platform authentication. |
| Contrast Security API Key | API key used for secure communication with Contrast Security platform. |
| Contrast Security Organization ID | The organization ID used for the Contrast Security platform. |
| Event Type | Select the event type to fetch from Contrast Security platform. Contrast Security recommends selecting "Contrast Incident" as the event type to fetch. |
| First Fetch Time | The date or relative timestamp from which to begin fetching Contrast Security Incidents and Issues. Default is 3 days.<br/>Supported formats: 2 minutes, 2 hours, 2 days, 2 weeks, 2 months, 2 years, yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ.<br/>For example: 01 Oct 2026, 01 Oct 2026 04:45:33, 2026-10-01T14:05:44Z. |
| Max Fetch | The maximum number of Contrast Security Incidents or Issues to fetch per run. Default is 25.<br/>Note: The maximum value is 200. |
| Incident Statuses | Select Contrast Security Incident statuses to fetch as incidents. Default is Open.<br/>Note: Applies only when Event Type is set to "Contrast Incident". |
| Incident Severity Levels | Select Contrast Security Incident severity levels to fetch as incidents. Default is all.<br/>Note: Applies only when Event Type is set to "Contrast Incident". |
| Issue Statuses | Select Contrast Security Issue statuses to fetch as incidents. Default is Open.<br/>Note: Applies only when Event Type is set to "Contrast Issue". |
| Issue Severity Levels | Select Contrast Security Issue severity levels to fetch as incidents. Default is all.<br/>Note: Applies only when Event Type is set to "Contrast Issue". |
| Incident Mirroring Direction | The mirroring direction in which to mirror the incident details. |
| Issue Mirroring Direction | The mirroring direction in which to mirror the Issue details. |
| Mirror Tag for Notes | Tag value used to mirror Cortex XSOAR notes back to Contrast Security as issue or incident comments. |
| Reopen Incident in XSOAR When Status Changes to 'Open' in Contrast Security Incident | If selected, closed incidents will be reopened in Cortex XSOAR when the incident status in Contrast Security incident changes to 'Open'.<br/>Note: This parameter is only used when the incident mirroring direction is set to 'Incoming' or 'Incoming and Outgoing'. |
| Close Incident in XSOAR When Status Changes to 'Closed' in Contrast Security Incident | If selected, active incidents will be closed in Cortex XSOAR when the incident status in Contrast Security incident changes to 'Closed'.<br/>Note: This parameter is only used when the incident mirroring direction is set to 'Incoming' or 'Incoming and Outgoing'. |
| Trust any certificate (not secure) | Trust any certificate, including self-signed certificates. Not recommended for production environments. |
| Use system proxy settings | Use system proxy settings for network communication. |