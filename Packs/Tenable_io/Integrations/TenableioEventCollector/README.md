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
    | Max Fetch | The maximum amount of audit logs to retrieve for each event type. For more information about event types see the help section. | False |
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
| hide_polling_output | Hide polling output. | Optional | 


#### Context Output

There is no context output for this command.

#### Context Example
```json
{
  "Tenable": {
    "Vulnerabilities": [
      {
        "asset": {
          "device_type": "general-purpose",
          "fqdn": "test.net",
          "hostname": "test.net",
          "uuid": "1234",
          "ipv4": "1.2.3.4",
          "last_unauthenticated_results": "2022-08-14T14:53:02Z",
          "operating_system": [
            "Linux Kernel 2.6"
          ],
          "network_id": "00000000-0000-0000-0000-000000000000",
          "tracked": True
        },
        "output": "test",
        "plugin": {
          "checks_for_default_account": False,
          "checks_for_malware": False,
          "cvss3_base_score": 0.0,
          "cvss3_temporal_score": 0.0,
          "cvss_base_score": 0.0,
          "cvss_temporal_score": 0.0,
          "description": "This plugin is a SYN half-open",
          "exploit_available": False,
          "exploit_framework_canvas": False,
          "exploit_framework_core": False,
          "exploit_framework_d2_elliot": False,
          "exploit_framework_exploithub": False,
          "exploit_framework_metasploit": False,
          "exploited_by_malware": False,
          "exploited_by_nessus": False,
          "family": "Port scanners",
          "family_id": 1,
          "has_patch": False,
          "id": 1,
          "in_the_news": False,
          "name": "test",
          "modification_date": "2022-07-19T00:00:00Z",
          "publication_date": "2009-02-04T00:00:00Z",
          "risk_factor": "None",
          "see_also": [
            ""
          ],
          "solution": "test",
          "synopsis": "test",
          "type": "remote",
          "unsupported_by_vendor": False,
          "version": "1"
        },
        "port": {
          "port": 1,
          "protocol": "TCP",
          "service": "smtp"
        },
        "scan": {
          "completed_at": "2022-08-14T14:53:18.852Z",
          "schedule_uuid": "1234",
          "started_at": "2022-08-14T14:22:51.230Z",
          "uuid": "1234"
        },
        "severity": "info",
        "severity_id": 0,
        "severity_default_id": 0,
        "severity_modification_type": "NONE",
        "first_found": "2022-08-14T14:53:18.852Z",
        "last_found": "2022-08-14T14:53:18.852Z",
        "state": "OPEN",
        "indexed": "2022-08-14T14:53:53.627Z"
      }
    ]
  }
}
```

#### Human Readable Output

>## Vulnerabilities List:
>| Asset |First Found|Indexed|Last Found|Output|Plugin|Port|Scan|Severity|Severity Default Id|Severity Id|Severity Modification Type|State|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| test     | 2022-08-14T14:53:18.852Z | 2022-08-14T14:53:53.627Z | 2022-08-14T14:53:18.852Z | Port 465/tcp was found to be open | checks_for_default | info | 0 | 0 | NONE | OPEN |
