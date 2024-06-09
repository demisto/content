Use this integration to fetch audit logs from ServiceNow as Cortex XSIAM events.
This integration was integrated and tested with Vancouver version of ServiceNow API.

## Configure ServiceNow Event Collector on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for ServiceNow Event Collector.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description**                                                                          | **Required** |
    | --- |------------------------------------------------------------------------------------------| --- |
    | ServiceNow URL | ServiceNow URL in the format https://company.service-now.com/                            | True |
    | Username |                                                                                          | True |
    | Password |                                                                                          | True |
    | Client ID |                                                                                          | False |
    | Client Secret |                                                                                          | False |
    | ServiceNow API Version (e.g. 'v1') |                                                                                          | False |
    | Use OAuth Login | Select this checkbox to use OAuth 2.0 authentication. See \(?\) for more information. | False |
    | Maximum number of events per fetch | Default value is 1000                                                                    | False |
    | Events Fetch Interval |                                                                                          | False |
    | Trust any certificate (not secure) |                                                                                          | False |
    | Use system proxy settings |                                                                                          | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSIAM CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### service-now-get-audit-logs

***
Returns audit logs events extracted from ServiceNow. This command is used for developing/debugging and is to be used with caution, as it can create events, leading to event duplication and exceeding the API request limitation.

#### Base Command

`service-now-get-audit-logs`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | Set this argument to True in order to create events, otherwise the command will only display them. Possible values are: True, False. Default is False. | Required | 
| limit | The maximum number of events to return. Default is 1000. | Optional | 
| from_date | The date and time of the earliest event. The time format is "{yyyy}-{mm}-{dd} {hh}:{mm}:{ss}". Example: "2021-05-18 13:45:14" indicates May 18, 2021, 1:45PM. | Optional | 
| offset | Starting record index from which to begin retrieving records. | Optional | 

#### Context Output

There is no context output for this command.

### Human Readable

>### Audit Logs List:
>|Time|Documentkey|Fieldname|Newvalue|Record Checkpoint|Sys Created On|Sys Id|Tablename|
>|---|---|---|---|---|---|---|---|
>| 2024-01-28T13:21:43Z | 3 | DELETED | DELETED | -1 | 2024-01-28 13:21:43 | 3 | test_table |
>| 2024-01-28T13:21:43Z | 3 | DELETED | DELETED | -1 | 2024-01-28 13:21:43 | 3 | test_table |
>| 2024-01-28T13:21:43Z | 3 | DELETED | DELETED | -1 | 2024-01-28 13:21:43 | 3 | test_table |
>| 2024-01-28T13:21:43Z | 3 | DELETED | DELETED | -1 | 2024-01-28 13:21:43 | 3 | test_table |
