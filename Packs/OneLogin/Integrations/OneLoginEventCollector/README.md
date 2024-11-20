Simple customer authentication and streamlined workforce identity operations.

## Configure OneLogin Event Collector in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Your server URL |  | True |
| Client Id | The client ID. | True |
| Client Secret | The client secret. | True |
| The maximum number of events per fetch |  | False |
| First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days) |  | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### onelogin-get-events
***
Manual command to fetch events from OneLogin and display them.


#### Base Command

`onelogin-get-events`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | If true, the command will create events, otherwise it will only display them. Possible values are: true, false. Default is false. | Required | 
| limit | Number of results to return. Maximum is 2000. Default is 10. | Optional | 
| cursor | A string pointing at the next page of results. The cursor can be found within the response_metadata field, as part of the raw response of the OneLogin Events API call. | Optional | 
| since | Occurrence time of the least recent event to include (inclusive). Default is 3 days. | Optional | 
| until | Occurrence time of the most recent event to include (inclusive). | Optional | 
| event_type_id | A comma-separated list of type IDs of events to include. | Optional | 


#### Context Output

There is no context output for this command.