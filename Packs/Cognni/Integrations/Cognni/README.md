The Cognni connector offers a quick and simple integration with Demisto 
in order to provide ongoing insights into how your important information is used. 
With Cognni, you can autonomously detect information-specific incidents 
based on contextual factors, and automatically compile insights to investigate 
how incidents occur. This intelligence provides the details you need to remediate 
incidents, fast enough to make a difference.

This integration was integrated and tested with version 1.0 of Cognni

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
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### cognni-get-event
***
Fetch a single event by ID


#### Base Command

`cognni-get-event`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| event_id | The event ID. | Required | 


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
{}
```

#### Human Readable Output

>### Cognni event 9ba7fb56-8ace-4b3d-a1e9-08c466668e57
>**No entries.**


### cognni-get-insight
***
Fetch a single insight by ID


#### Base Command

`cognni-get-insight`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| insight_id | The insight ID. | Required | 


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
{}
```

#### Human Readable Output

>### Cognni event 74a53ab3-3e75-4444-9e7c-0be1e1bc26a9
>**No entries.**


### cognni-fetch-insights
***
Fetch insights


#### Base Command

`cognni-fetch-insights`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| min_severity | Minimum severity of insights to fetch. Default is 2. | Required | 


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
        "insights": [
            {
                "description": null,
                "id": "4539ff6d-c58b-4a2a-a509-f121edbe97d7",
                "name": "High sensitive Anonymous share",
                "severity": 3
            },
            {
                "description": null,
                "id": "0875799c-6077-4f5f-b276-0e7baa2b89ab",
                "name": "High sensitive content Shared inside the organization Anomaly",
                "severity": 2
            },
            {
                "description": null,
                "id": "169b10e0-0970-430b-9709-61ccc312fdd0",
                "name": "High Sensitive content Shared Outside the organization Anomaly",
                "severity": 3
            },
            {
                "description": null,
                "id": "4cf8297f-b311-4cfa-9e8e-935606907e5f",
                "name": "High Sensitive content Shared to private email address",
                "severity": 3
            },
            {
                "description": null,
                "id": "537aa700-0eed-4998-b253-f809e1eacc00",
                "name": "High sensitive content Shared to private email Address Anomaly",
                "severity": 3
            },
            {
                "description": null,
                "id": "df061da3-13c1-4a59-8501-4d26bacd5b83",
                "name": "Low Sensitive content Anonymous Share",
                "severity": 2
            },
            {
                "description": null,
                "id": "c7723427-b075-4259-8fbc-19dab3861b92",
                "name": "Low sensitive content Shared to private email address Anomaly",
                "severity": 2
            },
            {
                "description": null,
                "id": "846c753b-1feb-4d21-ae43-ec81b9725636",
                "name": "Medium sensitivity content, Anonymous share",
                "severity": 3
            },
            {
                "description": null,
                "id": "f964659c-9cc3-4833-b535-0402cd953376",
                "name": "Medium sensitivity content Shared outside the organization Anomaly",
                "severity": 2
            },
            {
                "description": null,
                "id": "c24405d5-49f5-48b8-b15c-1a1aba540979",
                "name": "Medium sensitivity content, Shared to private email address",
                "severity": 2
            },
            {
                "description": null,
                "id": "c925372e-c2d5-4b61-b37e-399263ad58f9",
                "name": "Medium sensitivity content Shared to private email Address Anomaly",
                "severity": 3
            }
        ]
    }
}
```

#### Human Readable Output

>### Cognni 11 insights
>|description|id|name|severity|
>|---|---|---|---|
>|  | 4539ff6d-c58b-4a2a-a509-f121edbe97d7 | High sensitive Anonymous share | 3 |
>|  | 0875799c-6077-4f5f-b276-0e7baa2b89ab | High sensitive content Shared inside the organization Anomaly | 2 |
>|  | 169b10e0-0970-430b-9709-61ccc312fdd0 | High Sensitive content Shared Outside the organization Anomaly | 3 |
>|  | 4cf8297f-b311-4cfa-9e8e-935606907e5f | High Sensitive content Shared to private email address | 3 |
>|  | 537aa700-0eed-4998-b253-f809e1eacc00 | High sensitive content Shared to private email Address Anomaly | 3 |
>|  | df061da3-13c1-4a59-8501-4d26bacd5b83 | Low Sensitive content Anonymous Share | 2 |
>|  | c7723427-b075-4259-8fbc-19dab3861b92 | Low sensitive content Shared to private email address Anomaly | 2 |
>|  | 846c753b-1feb-4d21-ae43-ec81b9725636 | Medium sensitivity content, Anonymous share | 3 |
>|  | f964659c-9cc3-4833-b535-0402cd953376 | Medium sensitivity content Shared outside the organization Anomaly | 2 |
>|  | c24405d5-49f5-48b8-b15c-1a1aba540979 | Medium sensitivity content, Shared to private email address | 2 |
>|  | c925372e-c2d5-4b61-b37e-399263ad58f9 | Medium sensitivity content Shared to private email Address Anomaly | 3 |

