## Cyberhaven Integration - Help

Configure this integration to pull DLP incidents from Cyberhaven into XSOAR.
This integration was integrated and tested with version 2 of Cyberhaven API.

### Prerequisites

- Your Cyberhaven tenant URL (e.g. `https://example.cyberhaven.io`)
- A Cyberhaven refresh token (generated in your Cyberhaven tenant under API settings)
  - For Fetches incidents: API Token has to carry `incident__read` permission.
  - For Outgoing Mirroring(XSOAR -> Cyberhaven), API Token has to carry `incident__update` permission.

### Instance Configuration

1. Configure a Cyberhaven integration instance with valid **Server URL** and **Refresh Token**.
2. Click **Test** to validate the connection.
3. To fetch DLP incidents as incidents in XSOAR, select the option `Fetches incidents` and follow the table to update configuration parameters.

| **Parameter** | **Description** |
| --- | --- |
| Incident type | Select Incident type as "Cyberhaven Incident". |
| Mapper (incoming) | Select "Cyberhaven - Incoming Mapper". |
| First fetch time | The date or relative timestamp from which to begin fetching DLP Incidents. Default value is '3 days'. The maximum is '30 days'.<br/><br/>If the value is greater than '30 days', it will be considered as '30 days'.<br/><br/>Supported formats: 2 minutes, 2 hours, 2 days, 2 weeks, 2 months, 2 years, yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ.<br/><br/>For example: 01 May 2026, 01 May 2026 04:45:33, 2026-05-17T14:05:44Z. |
| Max Fetch | The maximum number of DLP Incidents to fetch each time. Default value is 100. The maximum is 200.<br/><br/>If the value is greater than 200, it will be considered as 200. |
| Status of incidents to fetch | Filter the DLP incidents by Status. Default value is 'Open'. |
| Severity of incidents to fetch | Filter the DLP incidents by Severity. Default value is 'Informational, Low, Medium, High, Critical'. |
| Enable Outgoing Mirroring (from XSOAR to Cyberhaven) | When enabled, updates to the following fields in XSOAR are synchronized to Cyberhaven: Status, Owner, Close Reason, and Close Notes. |
| Incidents Fetch Interval | The interval in minutes to fetch incidents. The default is 5 minute. |
| Trust any certificate (not secure) | Whether to allow connections without verifying SSL certificates validity. |
| Use system proxy settings | Whether to use XSOAR's system proxy settings to connect to the API. |
