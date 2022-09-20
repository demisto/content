Tenable.io Event Collector integration.
This integration was integrated and tested with version 1.0 of Tenable.io Event Collector

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
    | Max Fetch | The maximum amount of audit logs to retrieve for each event type. For more information about event types see the help section. | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### tenable-get-audit-logs
***
Returns events extracted from SaaS traffic and or logs.


#### Base Command

`tenable-get-audit-logs`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | Set this argument to True in order to create events, otherwise the command will only display the events. Possible values are: true, false. Default is false. | Required | 
| limit | The maximum number of alerts to return (maximum value - 5000). | Optional | 
| from_date | Date to return events that occurred after. | Optional | 
| to_date | Date to return events that occurred before. | Optional | 
| actor_id | Return events contains given actor UUID. | Optional | 
| target_id | Return events matching given target UUID. | Optional | 


#### Context Output

There is no context output for this command.
#### Command example
```!tenable-get-audit-logs limit=1```
#### Context Example
```json
{
    "Tenable": {
        "AuditLogs": [
            {
              "id": "1234",
              "action": "user.create",
              "crud": "c",
              "actor": {
                "id": "1234",
                "name": "teste@tenatestble.admin"
              },
              "target": {
                "id": "1234",
                "name": "test@test.com",
                "type": "User"
              },
              "description": "None",
              "is_anonymous": "True",
              "is_failure": "False",
              "fields": [
                {"key": "X-Access-Type", "value": "apikey"},
                {"key": "X-Forwarded-For", "value": "1.3.2.1"},
                {"key": "X-Request-Uuid", "value": "1.2.3.4"}],
              "received": "2022-05-18T16:33:02Z"}
        ]
    }
}
```

#### Human Readable Output

### Audit Logs List:
>|Action| Actor    |Crud|Description| Fields                                                                                                                                                  | Id  |Is Anonymous|Is Failure|Received| Target                                              |
>|----------|---|---|---------------------------------------------------------------------------------------------------------------------------------------------------------|-----|---|---|---|-----------------------------------------------------|---|
>| user.create | id: test | c |  | {'key': 'X-Access-Type', 'value': 'apikey'},<br>{'key': 'X-Forwarded-For', 'value': '1.2.3.4'},<br>{'key': 'X-Request-Uuid', 'value': '12:12:12:12:12'} | 12  | true | false | 2022-05-18T16:33:02Z | id: 12-1-1-1-1<br>name: test@test.com<br>type: User |
