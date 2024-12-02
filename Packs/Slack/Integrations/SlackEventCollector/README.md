Slack logs event collector integration for XSIAM.
This integration was integrated and tested with version v1 of Slack Audit Logs API.

This is the default integration for this content pack when configured by the Data Onboarder in Cortex XSIAM.

## Configure Slack Event Collector in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL |  | True |
| User Token |  | True |
| The maximum number of audit logs to fetch |  | False |
| First fetch time interval | Data is not available prior to March 2018. | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### slack-get-events
***
Gets audit log events from Slack.


#### Base Command

`slack-get-events`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | If true, the command will create events, otherwise it will only display them. Possible values are: true, false. Default is false. | Required | 
| limit | Number of results to return, maximum is 9999. Default is 10. | Optional | 
| oldest | Occurrence time of the least recent audit event to include (inclusive). Data is not available prior to March 2018. Default is 3 days. | Optional | 
| latest | Occurrence time of the most recent audit event to include (inclusive). | Optional | 
| action | Name of the action. | Optional | 
| actor | ID of the user who initiated the action. | Optional | 
| entity | ID of the target entity of the action (such as a channel, workspace, organization, file). | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` !slack-get-events action=user_login oldest="15 months ago" limit=1 ```

#### Context Example
```json
{
    "SlackEvents": [
      {
         "id":"0123a45b-6c7d-8900-e12f-3456789gh0i1",
         "date_create":1521214343,
         "action":"user_login",
         "actor":{
            "type":"user",
            "user":{
               "id":"W123AB456",
               "name":"Charlie Parker",
               "email":"bird@slack.com"
            }
         },
         "entity":{
            "type":"user",
            "user":{
               "id":"W123AB456",
               "name":"Charlie Parker",
               "email":"bird@slack.com"
            }
         },
         "context":{
            "location":{
               "type":"enterprise",
               "id":"E1701NCCA",
               "name":"Birdland",
               "domain":"birdland"
            },
            "ua":"Mozilla\/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit\/537.36 (KHTML, like Gecko) Chrome\/64.0.3282.186 Safari\/537.36",
            "session_id": "847288190092",
            "ip_address":"1.23.45.678"
        }
      }
    ]
}
```

#### Human Readable Output

>### Slack Audit Logs
>|action|actor|context|date_create|entity|id|
>|---|---|---|---|---|---|
>| user_login | type: user<br/>user: {"id": "W123AB456", "name": "Charlie Parker", "email": "bird@slack.com"} | location: {"type": "enterprise", "id": "E1701NCCA", "name": "Birdland", "domain": "birdland"}<br/>ua: Mozilla\/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit\/537.36 (KHTML, like Gecko) Chrome\/64.0.3282.186 Safari\/537.36<br/>session_id: 847288190092<br/>ip_address: 1.23.45.678 | 1970-01-18 14:33:34 | type: user<br/>user: {"id": "W123AB456", "name": "Charlie Parker", "email": "bird@slack.com"} | 0123a45b-6c7d-8900-e12f-3456789gh0i2 |
