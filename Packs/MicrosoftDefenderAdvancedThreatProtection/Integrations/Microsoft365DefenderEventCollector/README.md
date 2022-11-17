Microsoft 365 Defender event collector integration for Cortex XSIAM.

## Configure Microsoft 365 Defender Event Collector on Cortex XSIAM

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Microsoft 365 Defender Event Collector.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Endpoint URI | The United States: api-us.security.microsoft.com<br/>Europe: api-eu.security.microsoft.com<br/>The United Kingdom: api-uk.security.microsoft.co | True |
    | Client (Application) ID | The client \(application\) ID to use to connect. | True |
    | Client Secret |  | True |
    | Tenant ID |  | True |
    | First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, for example 12 hours, 7 days) |  | False |
    | Fetch alerts timeout | The time limit in seconds for fetch alerts to run. Leave this empty to cancel the timeout limit. | False |
    | Number of alerts for each fetch. | Due to API limitations, the maximum is 10,000. | False |
    | Fetch events |  | False |
    | Verify SSL Certificate |  | False |
    | Use system proxy settings |  | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### microsoft-365-defender-get-events
***
Returns a list of alerts


#### Base Command

`microsoft-365-defender-get-events`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of alerts per fetch. Default is 10000. | Optional | 
| first_fetch | The first fetch time (&lt;number&gt; &lt;time unit&gt;, for example 12 hours, 1 day, 3 months). Default is 3 days. | Optional | 


#### Context Output

There is no context output for this command.

#### Context Example
```json
{
    "Microsoft365Defender": {
            "alerts": [
                {
                    "classification": null, 
                    "investigationState": "TerminatedBySystem", 
                    "computerDnsName": "computer-name", 
                    "evidence": [], 
                    "aadTenantId": "00000000-0000-0000-0000-000000000000", 
                    "id": "aa000000000000000000_000000000", 
                    "category": "SuspiciousActivity", 
                    "threatFamilyName": null, 
                    "lastUpdateTime": "2022-05-12T07:29:45.1466667Z", 
                    "lastEventTime": "2022-05-12T01:19:11.7046854Z", 
                    "firstEventTime": "2022-05-12T01:19:11.7046854Z", 
                    "threatName": null, 
                    "comments": [], 
                    "assignedTo": null, 
                    "detectorId": "00000000-0000-0000-0000-000000000000", 
                    "detectionSource": "AutomatedInvestigation", 
                    "resolvedTime": null, 
                    "alertCreationTime": "2022-05-12T01:19:11.8059246Z", 
                    "status": "New", 
                    "description": "MS description", 
                    "loggedOnUsers": [], 
                    "determination": null, 
                    "severity": "Informational", 
                    "mitreTechniques": [], 
                    "machineId": "abc1234567890987654321234567890987654xyz", 
                    "title": "Automated investigation started manually", 
                    "investigationId": 0000, 
                    "relatedUser": null, 
                    "rbacGroupName": "UnassignedGroup", 
                    "incidentId": 0000
                }
            ]
    }
}
```
