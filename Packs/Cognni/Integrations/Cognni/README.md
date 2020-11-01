Cognni Integration
This integration was integrated and tested with version xx of Cognni
## Configure Cognni on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Cognni.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | Server URL | True |
| isFetch | Fetch incidents | False |
| incidentType | Incident type | False |
| max_fetch | Maximum number of events per fetch | False |
| apikey | API Key | True |
| min_severity | Minimum severity of alerts to fetch | True |
| first_fetch | First fetch time | False |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### cognni-ping
***
Ping command - check ping.


#### Base Command

`cognni-ping`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cognni.ping | String | Should be "ok". | 


#### Command Example
```!cognni-ping```

#### Context Example
```json
{
    "Cognni": {
        "ping": {}
    }
}
```

#### Human Readable Output

>## ping: pong

### cognni-get-event
***
Fetch a single event by ID


#### Base Command

`cognni-get-event`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| event_id | The event ID | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cognni.Event.id | String | id | 
| Cognni.Event.date | Date | date | 
| Cognni.Event.description | String | description | 
| Cognni.Event.severity | Number | severity | 
| Cognni.Event.sourceApplication | String | The source of the event | 


#### Command Example
```!cognni-get-event event_id="9ba7fb56-8ace-4b3d-a1e9-08c466668e57"```

#### Context Example
```json
{
    "Cognni": {
        "event": {
            "date": "2020-10-07T14:55:59.000Z",
            "description": "N/A",
            "id": "9ba7fb56-8ace-4b3d-a1e9-08c466668e57",
            "sourceApplication": "exchange"
        }
    }
}
```

#### Human Readable Output

>### Cognni event 9ba7fb56-8ace-4b3d-a1e9-08c466668e57
>|date|description|id|sourceApplication|
>|---|---|---|---|
>| 2020-10-07T14:55:59.000Z | N/A | 9ba7fb56-8ace-4b3d-a1e9-08c466668e57 | exchange |


### cognni-get-insight
***
Fetch a single insight by ID


#### Base Command

`cognni-get-insight`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| insight_id | The insight ID | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cognni.insight.id | String | ID | 
| Cognni.insight.name | String | name | 
| Cognni.insight.description | String | description | 
| Cognni.insight.severity | Number | severity | 


#### Command Example
```!cognni-get-insight insight_id="74a53ab3-3e75-4444-9e7c-0be1e1bc26a9"```

#### Context Example
```json
{
    "Cognni": {
        "insight": {
            "description": "High Sensitive, Shared to Personal Address",
            "id": "74a53ab3-3e75-4444-9e7c-0be1e1bc26a9",
            "name": "High Sensitive Shared to Personal Address",
            "severity": 3
        }
    }
}
```

#### Human Readable Output

>### Cognni event 74a53ab3-3e75-4444-9e7c-0be1e1bc26a9
>|description|id|name|severity|
>|---|---|---|---|
>| High Sensitive, Shared to Personal Address | 74a53ab3-3e75-4444-9e7c-0be1e1bc26a9 | High Sensitive Shared to Personal Address | 3 |


### cognni-fetch-insights
***
Fetch insights


#### Base Command

`cognni-fetch-insights`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| min_severity | Minimum severity of insights to fetch | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cognni.insights.id | String | id | 
| Cognni.insights.name | String | name | 
| Cognni.insights.description | String | description | 
| Cognni.insights.severity | Number | severity | 


#### Command Example
```!cognni-fetch-insights min_severity=2```

#### Context Example
```json
{
    "Cognni": {
        "insights": {
            "description": "High Sensitive, Shared to Personal Address",
            "id": "74a53ab3-3e75-4444-9e7c-0be1e1bc26a9",
            "name": "High Sensitive Shared to Personal Address",
            "severity": 3
        }
    }
}
```

#### Human Readable Output

>### Cognni 1 insights
>|description|id|name|severity|
>|---|---|---|---|
>| High Sensitive, Shared to Personal Address | 74a53ab3-3e75-4444-9e7c-0be1e1bc26a9 | High Sensitive Shared to Personal Address | 3 |


### cognni-fetch-incidents
***
Fetch incidents


#### Base Command

`cognni-fetch-incidents`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| from_date | Fetch incidents starting from that date | Optional | 
| min_severity | Minimum severity of incidents to fetch | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!cognni-fetch-incidents min_severity=1```

#### Context Example
```json
{
    "Cognni": {
        "incidents": [
            {
                "details": "N/A",
                "name": null,
                "occurred": "2020-10-07T14:55:59.000Z",
                "rawJSON": "{\"eventId\": \"7c43bf89-d116-42e1-b474-f7da5346adac\", \"fileName\": null, \"fileId\": \"2aa0b002-a714-ba37-c7f1-360abe72fe96\", \"name\": null, \"eventType\": \"Attachment\", \"description\": \"N/A\", \"date\": \"2020-10-07T14:55:59.000Z\", \"severity\": 1, \"sourceApplication\": \"exchange\"}",
                "severity": 1
            }
        ]
    }
}
```

#### Human Readable Output

>### Cognni 1 incidents
>|details|name|occurred|rawJSON|severity|
>|---|---|---|---|---|
>| N/A |  | 2020-10-07T14:55:59.000Z | {"eventId": "7c43bf89-d116-42e1-b474-f7da5346adac", "fileName": null, "fileId": "2aa0b002-a714-ba37-c7f1-360abe72fe96", "name": null, "eventType": "Attachment", "description": "N/A", "date": "2020-10-07T14:55:59.000Z", "severity": 1, "sourceApplication": "exchange"} | 1 |

