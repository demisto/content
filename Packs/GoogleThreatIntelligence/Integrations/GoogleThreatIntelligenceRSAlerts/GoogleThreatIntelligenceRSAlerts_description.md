## Google Threat Intelligence - RS Alerts Help

To use the integration, an API Key and Project ID will be required from your Google Threat Intelligence account.

### Authorization

Your API key can be found in your Google Threat Intelligence account **user menu**, by clicking your **avatar**.
Your API key carries all your privileges, so keep it secure and don't share it with anyone.

### Instance Configuration

1. Configure a Google Threat Intelligence - RS Alerts integration instance with valid API Key and Project ID.
2. Click **Test** to validate the connection.
3. To fetch RS Alerts as incidents in Cortex XSOAR, select the option `Fetches incidents` and follow the table to update configuration parameters.

| **Parameter** | **Description** |
| --- | --- |
| Server URL | URL of the GTI platform. |
| API Key | Provide the API key for authentication. |
| Project ID | Specify the ID of the project. |
| Incident type | Select Incident type as "Google Threat Intelligence RS Alert". |
| First Fetch Time | The date or relative timestamp from which to begin fetching RS Alerts. Default value is '3 days'.<br/><br/>Supported formats: 2 minutes, 2 hours, 2 days, 2 weeks, 2 months, 2 years, yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ.<br/><br/>For example: 01 May 2026, 01 May 2026 04:45:33, 2026-05-17T14:05:44Z. |
| Max Fetch | The maximum number of Alerts to fetch each time. Default value is 100. The maximum is 200.<br/><br/>If the value is greater than 200, it will be considered as 200. |
| Relevance Level | Filter the alerts by the relevance level. |
| Severity Level | Filter the alerts by the severity level. |
| Priority Level | Filter the alerts by the priority level. |
| Status | Filter the alerts by the status. |
| Threat Scenarios | Filter the alerts by the threat scenarios. |
| Mirroring Direction | The mirroring direction in which to mirror the alert. You can mirror 'Incoming' \(from GTI to XSOAR\), 'Outgoing' \(from XSOAR to GTI\), or in both directions. |
| Reopen Incident for Open Alert Status | Whether to reopen the incident when the Alert status is 'Read', 'Triaged', or 'Escalated'.<br/><br/>Note: This parameter is only used when the mirroring direction is set to 'Incoming' or 'Incoming And Outgoing'. |
| Close Incident for Close Alert Status | Whether to close the incident when the Alert status is 'False Positive', 'Resolved', 'Duplicate', 'Benign', 'Not Actionable', or 'Tracked Externally'.<br/><br/>Note: This parameter is only used when the mirroring direction is set to 'Incoming' or 'Incoming And Outgoing'. |
| Alert Status for Incident Reopen | Alert Status set in GTI when reopening incidents in XSOAR. Default value is 'Escalated'.<br/><br/>Note: This parameter is only used when the mirroring direction is set to 'Outgoing' or 'Incoming And Outgoing'. |
| Alert Status for Incident Closure | Alert Status set in GTI when closing incidents in XSOAR. Default value is 'Resolved'.<br/><br/>Note: This parameter is only used when the mirroring direction is set to 'Outgoing' or 'Incoming And Outgoing'. |
