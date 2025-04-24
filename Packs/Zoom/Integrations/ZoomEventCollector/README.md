This is the Zoom event collector integration for Cortex XSIAM.
This integration was integrated and tested with version 2.0.0 of Zoom

This is the default integration for this content pack when configured by the Data Onboarder in Cortex XSIAM.

## Configure Zoom Event Collector in Cortex


| **Parameter** | **Required** |
|--------| --- |
| Server URL (e.g., 'https://api.zoom.us/v2/')                                                             | True   |
| Account ID (OAuth)                                                                                       | True   |
| Client ID (OAuth)                                                                                        | True   |
| Client Secret (OAuth)                                                                                    | True   |
| First fetch time (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days) - within the last six months | False  |
| Trust any certificate (not secure)                                                                       | False  |
| Use system proxy settings                                                                                | False  |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### zoom-get-events

***
Gets events from Zoom.

#### Base Command

`zoom-get-events`

#### Input

| **Argument Name**  | **Description**                                                                                                                   | **Required** |
|--------------------|-----------------------------------------------------------------------------------------------------------------------------------|--------------|
| should_push_events | If true, the command will create events, otherwise it will only display them. Possible values are: true, false. Default is false. | Required     | 
| limit              | Maximum results to return.  The maximum is 300.                                                                                   | Optional     | 

#### Context Output

There is no context output for this command.

#### Command Example

```!zoom-get-events should_push_events=true limit=1```

#### Human Readable Output

### operationlogs Events

| action | category_type | operation_detail                | operator            | time                 |
|--------|---------------|---------------------------------|---------------------|----------------------|
| Delete | User          | Delete User example@example.com | example@example.com | 2023-01-16T09:51:59Z |

### activities Events

| client_type | email               | ip_address | time                 | type    | version |
|-------------|---------------------|------------|----------------------|---------|---------|
| Browser     | example@example.com | 8.8.8.8    | 2023-01-19T14:44:23Z | Sign in | -       |



### Rate Limits
To prevent abuse and ensure service stability, all API requests are rate limited. Rate limits specify the maximum number of API calls that can be made in a minute period. The exact number of calls that your application can make per minute varies based on company plan. 
For more information, please refer to the Zoom API documentation on [Rate limits by account type](https://developers.zoom.us/docs/api/rest/rate-limits/#rate-limits-by-account-type).