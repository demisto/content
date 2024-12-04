Use this integration to fetch audit and syslog transactions logs from ServiceNow as Cortex XSIAM events.
This integration was integrated and tested with Vancouver version of ServiceNow API.

## Configure ServiceNow Event Collector in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| ServiceNow URL, in the format https://company.service-now.com/ |  | True |
| Username |  | True |
| Password |  | True |
| Client ID |  | False |
| Client Secret |  | False |
| ServiceNow API Version (e.g., 'v1') |  | False |
| Use OAuth Login | Select this checkbox to use OAuth 2.0 authentication. | False |
| Event Types To Fetch | Event types to fetch. Defaults to 'Audit' if no type is specified. | False |
| Maximum audit events to fetch | Maximum number of audit events per fetch. | False |
| Maximum syslog transactions events to fetch | Maximum number of syslog transactions events per fetch. | False |
| Events Fetch Interval |  | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### service-now-get-audit-logs

***
Returns events extracted from ServiceNow. This command is used for developing/debugging and is to be used with caution, as it can create events, leading to event duplication and exceeding the API request limitation.

#### Base Command

`service-now-get-audit-logs`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | Set this argument to True in order to create events, otherwise the command will only display them. Possible values are: True, False. Default is False. | Required | 
| limit | Maximum audit events to fetch. Default is 1000. | Optional | 
| from_date | The date and time of the earliest event. The time format is "{yyyy}-{mm}-{dd} {hh}:{mm}:{ss}". Example: "2021-05-18 13:45:14" indicates May 18, 2021, 1:45PM. | Optional | 
| offset | Starting record index from which to begin retrieving records. | Optional | 

#### Context Output

There is no context output for this command.

### Human Readable

>### Audit Events
>|_time|documentkey|fieldname|newvalue|record_checkpoint|sys_created_on|sys_id|tablename|
>|---|---|---|---|---|---|---|---|
>| 2024-01-28T13:21:43Z | 3 | DELETED | DELETED | -1 | 2024-01-28 13:21:43 | 3 | audit |
>| 2024-01-28T13:21:43Z | 3 | DELETED | DELETED | -1 | 2024-01-28 13:21:43 | 3 | audit |
>| 2024-01-28T13:21:43Z | 3 | DELETED | DELETED | -1 | 2024-01-28 13:21:43 | 3 | audit |
>| 2024-01-28T13:21:43Z | 3 | DELETED | DELETED | -1 | 2024-01-28 13:21:43 | 3 | audit |

### service-now-get-syslog-transactions

***
Returns syslog transactions events extracted from ServiceNow. This command is used for developing/debugging and is to be used with caution, as it can create events, leading to event duplication and exceeding the API request limitation.

#### Base Command

`service-now-get-syslog-transactions`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | Set this argument to True in order to create events, otherwise the command will only display them. Possible values are: True, False. Default is False. | Required | 
| max_fetch_syslog_transactions | Maximum syslog transactions events to fetch. Default is 1000. | Optional | 
| from_date | The date and time of the earliest event. The time format is "{yyyy}-{mm}-{dd} {hh}:{mm}:{ss}". Example: "2021-05-18 13:45:14" indicates May 18, 2021, 1:45PM. | Optional | 
| offset | Starting record index from which to begin retrieving records. | Optional | 

#### Context Output

There is no context output for this command.

### Human Readable

>### Syslog Transactions Events
>|_time|acl_time|business_rule_count|client_transaction|cpu_time|sys_created_on|sys_id|source_log_type|
>|---|---|---|---|---|---|---|---|
>| 2024-01-28T13:21:43Z | 3 | DELETED | DELETED | -1 | 2024-01-28 13:21:43 | 3 | test_table |
>| 2024-01-28T13:21:43Z | 3 | DELETED | DELETED | -1 | 2024-01-28 13:21:43 | 3 | test_table |
>| 2024-01-28T13:21:43Z | 3 | DELETED | DELETED | -1 | 2024-01-28 13:21:43 | 3 | test_table |
>| 2024-01-28T13:21:43Z | 3 | DELETED | DELETED | -1 | 2024-01-28 13:21:43 | 3 | test_table |
