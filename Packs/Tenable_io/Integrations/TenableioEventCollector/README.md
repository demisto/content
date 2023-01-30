Tenable.io Event Collector integration.
This integration was integrated and tested with version 1.0 of Tenable.io

## Configure Tenable.io Event Collector on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Tenable.io Event Collector.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Access Key | Tenable API access key. | True |
    | Secret Key | Tenable API secret key. | True |
    | Vulnerabilities Fetch Interval | Fetch interval in minutes. | True |
    | Severity | The severity of the vulnerabilities to include in the export. | False |
    | First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days) |  | False |
    | Max Fetch | The maximum number of audit logs to retrieve for each event type. For more information about event types see the help section. | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### tenable-get-audit-logs
***
Returns audit logs extracted from Tenable io.


#### Base Command

`tenable-get-audit-logs`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | Set this argument to True in order to create events, otherwise the command will only display the events. Possible values are: true, false. Default is false. | Required | 
| limit | The maximum number of alerts to return (maximum value - 5000). | Optional | 
| from_date | Return events that occurred after the specified date.  | Optional | 
| to_date | Return events that occurred before the specified date. | Optional | 
| actor_id | Return events that contain the specified actor UUID. | Optional | 
| target_id | Return events matching the specified target UUID. | Optional | 


#### Context Output

There is no context output for this command.

#### Command example
```!tenable-get-audit-logs limit=1```


#### Human Readable Output

>### Audit Logs List:
>|Action| Actor    | Crud | Description | Fields                                                                                                                                                  | Id  |Is Anonymous|Is Failure|Received| Target                                              |
>|----------|------|-------------|---------------------------------------------------------------------------------------------------------------------------------------------------------|-----|---|---|---|-----------------------------------------------------|---|
>| user.create | id: test | c    |             | {'key': 'X-Access-Type', 'value': 'apikey'},<br>{'key': 'X-Forwarded-For', 'value': '1.2.3.4'},<br>{'key': 'X-Request-Uuid', 'value': '12:12:12:12:12'} | 12  | true | false | 2022-05-18T16:33:02Z | id: 12-1-1-1-1<br>name: test@test.com<br>type: User |


### tenable-get-vulnerabilities
***
Returns vulnerabilities extracted from Tenable io.


#### Base Command

`tenable-get-vulnerabilities`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | Set this argument to True in order to create events, otherwise the command will only display the events. Possible values are: true, false. Default is false. | Required | 
| last_found | Returns vulnerabilities that were last found between the specified date (in Unix time) and now. | Optional | 
| num_assets | The severity of the vulnerabilities to include in the export. | Optional | 
| hide_polling_output | Whether to hide the polling output. | Optional | 


#### Context Output

There is no context output for this command.


#### Human Readable Output

>## Vulnerabilities List:
>| Asset |First Found|Indexed|Last Found|Output|Plugin|Port|Scan|Severity|Severity Default Id|Severity Id|Severity Modification Type|State|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| test     | 2022-08-14T14:53:18.852Z | 2022-08-14T14:53:53.627Z | 2022-08-14T14:53:18.852Z | Port 465/tcp was found to be open | checks_for_default | info | 0 | 0 | NONE | OPEN |
