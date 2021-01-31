This is an integration for using xMatters.
This integration was integrated and tested with version 1 of xMatters
## Configure xMatters on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for xMatters.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| instance | Your xmatters instance base URL. \(i.e. acme.xmatters.com\) | True |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |
| username | Username for your xMatters instance. | True |
| password | Password for your xMatters instance. | True |
| url | URL of an HTTP trigger in a flow. | True |
| fetch_type |  | True |
| status | Fetch alerts with status \(ACTIVE, SUSPENDED\) | False |
| priority | Priority of events to fetch | False |
| isFetch | Fetch incidents | False |
| incidentType | Incident type | False |
| property_name |  | False |
| property_value |  | False |
| first_fetch | First fetch timestamp \(&amp;lt;number&amp;gt; &amp;lt;time unit&amp;gt;, e.g., 12 hours, 7 days\) | False |
| max_fetch |  | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### xm-trigger-workflow
***
sends the event to xMatters


#### Base Command

`xm-trigger-workflow`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| recipients | Recipients of the xMatters Message | Required | 
| subject | Subject of the xMatters Message | Optional | 
| body | Body of the xMatters Message | Optional | 
| incident_id | Incident ID of Incident referenced | Optional | 
| close_task_id | Id of task to close in playbook. Requires an incident_id as the investigation id. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| request_id | string | Request ID from xMatters | 


#### Command Example
```!xm-trigger-workflow recipients="Joey" subject="Major Emu Issue" body="The emu has escaped!"```

#### Context Example
```json
{
    "request_id": "93e6b331-2108-424d-872b-8200b476907b"
}
```

#### Human Readable Output

>Successfully sent a message to xMatters.

### xm-get-events
***
Get events from xMatters.


#### Base Command

`xm-get-events`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| request_id | The UUID returned from triggering a workflow. | Optional | 
| status | Status of the event. | Optional | 
| priority | Priority of the event. | Optional | 
| from | A date in UTC format that represents the start of the time range you want to search. | Optional | 
| to | A date in UTC format that represents the end of the time range you want to search. | Optional | 
| workflow | The name of the workflow the event is tied to. | Optional | 
| form | The name of the form the event is tied to. | Optional | 
| property_name | An event property name to filter the events | Optional | 
| property_value | An event property value to filter the events | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Events | unknown | Events from xMatters. | 


#### Command Example
```!xm-get-events status=ACTIVE```

#### Context Example
```json
{
    "Events": [
        {
            "Created": "2020-10-13T21:35:07.725+0000",
            "FormName": "Incident",
            "Incident": "7a63abc3-5abf-41ca-969b-80eb678fbf72",
            "Name": "Major Emu Issue\n",
            "PlanName": "Cortex XSOAR",
            "Prioity": "MEDIUM",
            "Properties": null,
            "Status": "ACTIVE",
            "SubmitterName": "admin",
            "Terminated": null
        },
        {
            "Created": "2020-10-13T21:33:58.444+0000",
            "FormName": "Incident",
            "Incident": "388884f1-410b-4eb8-a38e-4973e7151b89",
            "Name": "Major Emu Issue\n",
            "PlanName": "Cortex XSOAR",
            "Prioity": "MEDIUM",
            "Properties": null,
            "Status": "ACTIVE",
            "SubmitterName": "admin",
            "Terminated": null
        }
    ]
}
```

#### Human Readable Output

>Retrieved Events from xMatters.

### xm-get-event
***
Get a single event from xMatters.


#### Base Command

`xm-get-event`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| event_id | Unique identifier of the event | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Event | unknown | Event from xMatters. | 


#### Command Example
```!xm-get-event event_id=33999001```

#### Context Example
```json
{
    "Event": {
        "Created": "2020-10-13T20:50:24.520+0000",
        "FormName": "Integration Builder: Integration Problem",
        "Incident": "99a7692b-30df-40c4-9a20-edc495ae91f9",
        "Name": "Your xMatters integration has a problem",
        "PlanName": "Integration Builder Notifications",
        "Prioity": "MEDIUM",
        "Properties": null,
        "Status": "ACTIVE",
        "SubmitterName": "xm-support",
        "Terminated": null
    }
}
```

#### Human Readable Output

>Retrieved Event from xMatters.
