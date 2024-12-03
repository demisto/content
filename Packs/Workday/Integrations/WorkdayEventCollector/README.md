Use Workday Event Collector integration to get activity loggings from Workday.
This integration was integrated and tested with API v1.

This is the default integration for this content pack when configured by the Data Onboarder in Cortex XSIAM.

## Configure Workday Event Collector in Cortex

    
| **Parameter**                                                                    | **Description**                                                                                                                | **Required** |
|----------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------|--------------|
| Server URL (e.g. https://WORKDAY-HOST/ccx/api/privacy/v1/TENANT_NAME)                   | REST API Endpoint of Workday server. Can be obtained from View API Clients report in Workday application                       | True         |
| Token endpoint (e.g. https://WORKDAY-HOST/ccx/oauth2/TENANT_NAME/token)          | Token endpoint of the Workday server. Can be obtained from View API Clients report in Workday application.                     | True         |
| Client ID                                                                        | Copy the Client ID and Secret from the Register API Client for Integrations stage at Workday.                                  | True         |
| Client Secret                                                                    |                                                                                                                                | True         |
| Refresh Token                                                                    | Non-expiry Workday API refresh token.                                                                                          | True         |
| Trust any certificate (not secure)                                               |                                                                                                                                | False        |
| Use system proxy settings                                                        |                                                                                                                                | False        |
| First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days) |                                                                                                                                | False        |
| Max events per fetch                                                             | The maximum number of audit logs to retrieve for each event type. For more information about event types see the help section. | False        |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### workday-get-activity-logging

***
Returns activity loggings extracted from Workday.

#### Base Command

`workday-get-activity-logging`

#### Input

| **Argument Name** | **Description**                                                                                                                                                                                                                 | **Required** |
| --- |---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------| --- |
| limit | The maximum number of loggings to return.. Default is 1000.                                                                                                                                               | Optional | 
| offset | The zero-based index of the first object in a response collection. Default is 0.                                                                                                                                                | Optional | 
| from_date | The date and time of the earliest log entry. The default timezone is UTC/GMT. The time format is "{yyyy}-{mm}-{dd}T{hh}:{mm}:{ss}Z". Example: "2021-05-18T13:45:14Z" indicates May 18, 2021, 1:45PM UTC. Possible values are: . | Required | 
| to_date | The time format is "{yyyy}-{mm}-{dd}T{hh}:{mm}:{ss}Z". Example: "2021-05-18T13:45:14Z" indicates May 18, 2021, 1:45PM UTC. Possible values are: .                                                                               | Required | 


#### Context Output

There is no context output for this command.

#### Command example

```!workday-get-activity-logging limit=4 from_date=2023-04-24T07:00:00Z to_date=2023-04-24T08:00:00Z```


#### Human Readable Output

### Activity Logging List:

|Activity Action|Device Type|Ip Address|Request Time|Session Id|System Account|Target|Task Display Name|Task Id|User Activity Entry Count|User Agent|
|---|---|---|---|---|---|---|---|--|---|---|
| test_action | test_device | 1.1.1.1 | 2023-04-24T07:00:00Z | test_session_id | 123 | id: 1234<br>descriptor: test_descriptor<br>href: test_href | test_display | 1 | 1234 | test_agent |
| test_action | test_device | 1.1.1.1 | 2023-04-24T07:00:00Z | test_session_id | 123 | id: 1234<br>descriptor: test_descriptor<br>href: test_href | test_display | 2 | 1234 | test_agent |
| test_action | test_device | 1.1.1.1 | 2023-04-24T07:00:00Z | test_session_id | 123 | id: 1234<br>descriptor: test_descriptor<br>href: test_href | test_display | 3 | 1234 | test_agent |
| test_action | test_device | 1.1.1.1 | 2023-04-24T07:00:00Z | test_session_id | 123 | id: 1234<br>descriptor: test_descriptor<br>href: test_href | test_display | 4 | 1234 | test_agent |