Microsoft Defender for Endpoint Alerts integration for Cortex XSIAM (Deprecated).

## Deprecation Announcement
Following [this](https://learn.microsoft.com/en-us/defender-endpoint/configure-siem) announcement by Microsoft about migrating from the deprecated SIEM API to the Graph API, this Event Collector is now deprecated.

### Replacement Option:
In XSIAM `Office 365` Data Source, select `Microsoft Graph API` -> `Alerts`, and select `Use Microsoft Graph API V2`.

***
This is the default integration for this content pack when configured by the Data Onboarder in Cortex XSIAM.

## Configure Microsoft Defender for Endpoint Alerts on Cortex XSIAM

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Microsoft Defender for Endpoint Alerts.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter**                                                                          | **Description**                                                                                                                                                        | **Required** |
    |----------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------|
    | Endpoint Type                                                                          | The endpoint for accessing Microsoft Defender for Endpoint. See table below.                                                                                           | True         |
    | Client (Application) ID                                                                | The client \(application\) ID to use to connect.                                                                                                                       | True         |
    | Client Secret                                                                          |                                                                                                                                                                        | True         |
    | Tenant ID                                                                              |                                                                                                                                                                        | True         |
    | First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, for example 12 hours, 7 days) |                                                                                                                                                                        | False        |
    | Fetch alerts timeout                                                                   | The time limit in seconds for fetch alerts to run. Leave this empty to cancel the timeout limit.                                                                       | False        |
    | Number of alerts for each fetch.                                                       | Due to API limitations, the maximum is 10,000.                                                                                                                         | False        |
    | Fetch events                                                                           |                                                                                                                                                                        | False        |
    | Verify SSL Certificate                                                                 |                                                                                                                                                                        | False        |
    | Use system proxy settings                                                              |                                                                                                                                                                        | False        |
    | Server URL                                                                             | The United States: api-us.security.microsoft.com<br/>Europe: api-eu.security.microsoft.com<br/>The United Kingdom: api-uk.security.microsoft.com<br/> See table below. | True         |

4. Endpoint Type options

    | Endpoint Type    | Description                                                                            |
    |------------------|----------------------------------------------------------------------------------------|
    | Worldwide        | The publicly accessible Microsoft Defender for Endpoint                                |
    | EU Geo Proximity | Microsoft Defender for Endpoint Geo proximity end point for the UK customers.          |
    | UK Geo Proximity | Microsoft Defender for Endpoint Geo proximity end point for the UK customers.          |
    | US Geo Proximity | Microsoft Defender for Endpoint Geo proximity end point  for the US customers.         |
    | US GCC           | Microsoft Defender for Endpoint for the USA Government Cloud Community (GCC)           |
    | US GCC-High      | Microsoft Defender for Endpoint for the USA Government Cloud Community High (GCC-High) |
    | DoD              | Microsoft Defender for Endpoint for the USA Department of Defense (DoD)                |
    | Custom           | Custom endpoint configuration to the Microsoft Defender for Endpoint. See note below.  |
   
   - Note: In most cases setting Endpoint type is preferred to setting Server URL. Only use it in cases where a custom URL is required for accessing a national cloud or for cases of self-deployment.

5. Click **Test** to validate the URLs, token, and connection.

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


### microsoft-365-defender-auth-reset

***
Run this command if for some reason you need to rerun the authentication process.

#### Base Command

`microsoft-365-defender-auth-reset`

#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.
