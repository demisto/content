Microsoft Defender for Cloud Apps Event Collector integration.

This is the default integration for this content pack when configured by the Data Onboarder in Cortex XSIAM.

## Configure Microsoft Defender for Cloud Apps Event Collector in Cortex


| **Parameter**                                                                    | **Description**                                                                                                                                  | **Required** |
|----------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------|--------------|
| Endpoint Type                                                                    | The endpoint for accessing Microsoft Defender for Cloud Applications (MCAS), see table below.                                                    | Worldwide    |   
| Endpoint URI                                                                     | The United States: api-us.security.microsoft.com<br/>Europe: api-eu.security.microsoft.com<br/>The United Kingdom: api-uk.security.microsoft.com | True         |
| Client (Application) ID                                                          | The Client \(Application\) ID to use to connect.                                                                                                 | True         |
| Client Secret                                                                    |                                                                                                                                                  | True         |
| Tenant ID                                                                        |                                                                                                                                                  | True         |
| Scope                                                                            |                                                                                                                                                  | True         |
| First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days) |                                                                                                                                                  | False        |
| Number of alerts for each fetch.                                                 | Due to API limitations, the maximum is 10,000.                                                                                                   | False        |
| Fetch events                                                                     |                                                                                                                                                  | False        |
| Verify SSL Certificate                                                           |                                                                                                                                                  | False        |
| Use system proxy settings                                                        |                                                                                                                                                  | False        |
| Event types to fetch |  | True |

    Endpoint Type options

| Endpoint Type | Description                                                                                      |
|---------------|--------------------------------------------------------------------------------------------------|
| Worldwide     | The publicly accessible Microsoft Defender for Cloud Applications                                |
| US GCC        | Microsoft Defender for Cloud Applications for the USA Government Cloud Community (GCC)           |
| US GCC-High   | Microsoft Defender for Cloud Applications for the USA Government Cloud Community High (GCC-High) |
   

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### microsoft-defender-cloud-apps-get-events

***
Returns a list of alerts.


#### Base Command

`microsoft-defender-cloud-apps-get-events`

#### Input

| **Argument Name** | **Description**                                                                                                    | **Required** |
|-------------------|--------------------------------------------------------------------------------------------------------------------|--------------|
| limit             | The maximum number of alerts per fetch. Default is 10000.                                                          | Optional     | 
| after             | The first fetch time (&lt;number&gt; &lt;time unit&gt;, for example 12 hours, 1 day, 3 months). Default is 3 days. | Optional     | 
| push_to_xsiam     | Whether to push the fetched event to XSIAM or not. Possible values are: false, true. Default is false.             | Optional     | 


#### Context Output

There is no context output for this command.


### microsoft-defender-cloud-apps-auth-reset

***
Run this command if for some reason you need to rerun the authentication process.

#### Base Command

`microsoft-defender-cloud-apps-auth-reset`

#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.