Cloud-based SIEM 
This integration was integrated and tested with version xx of rapid7_insightidr
## Configure rapid7_insightidr on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for rapid7_insightidr.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| region | Insight cloud server region \(i.e EU\) | True |
| apiKey | InsightIDR API key | True |
| isFetch | Fetch incidents | False |
| fetch_time | First Fetch Time | False |
| max_fetch | Fetch Limit | False |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### rapid7-insight-idr-list-investigations
***
List open/closed investigations


#### Base Command

`rapid7-insight-idr-list-investigations`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| time_range | An optional time range string (ie 1 week, 1 day) | Optional | 
| start_time | An optional ISO formatted timestamp. Only investigations whose createTime is after this date will be returned by the api. If this parameter is omitted investigations with any create_time may be returned - Use ISO time format (i.e 2018-07-01T00:00:00Z) | Optional | 
| end_time | An optional ISO formatted timestamp. Only investigations whose createTime is before this date will be returned by the api. If this parameter is omitted investigations with any create_time may be returned - Use ISO time format (i.e 2018-07-01T00:00:00Z) | Optional | 
| statuses | Only an investigation whose status matches one of the entries in the list will be returned. If this parameter is omitted investigations with any status may be returned. | Optional | 
| index | The optional 0 based index of the page to retrieve. Must be an integer greater than or equal to 0 | Optional | 
| page_size | The optional size of the page to retrieve. Must be an integer greater than 0 or less than or equal to 1000 | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Rapid7InsightIDR.Investigation.title | String | Title of investigation | 
| Rapid7InsightIDR.Investigation.id | String | ID of investigation | 
| Rapid7InsightIDR.Investigation.status | String | Whether it is open or closed | 
| Rapid7InsightIDR.Investigation.created_time | String | Time the investigation was created | 
| Rapid7InsightIDR.Investigation.source | String | Source of the investigation | 
| Rapid7InsightIDR.Investigation.assignee.email | String | Email of investigation assignee | 
| Rapid7InsightIDR.Investigation.assignee.name | String | Name of investigation assignee | 
| Rapid7InsightIDR.Investigation.alert.type | String | Type of alert in the investigation | 
| Rapid7InsightIDR.Investigation.alert.type_description | String | Type description of alert in the investigation | 
| Rapid7InsightIDR.Investigation.alert.first_event_time | String | first event time of alert in the investigation | 


#### Command Example
```!rapid7-insight-idr-list-investigations time_range="7 days" page_size=6```

#### Context Example
```json
{
    "Rapid7InsightIDR": {
        "Investigation": [
            {
                "alerts": [],
                "created_time": "2020-11-16T11:50:53.817Z",
                "id": "b7c3af95-fe53-46d3-98ac-fc99c0eaf113",
                "source": "MANUAL",
                "status": "OPEN",
                "title": "1234"
            },
            {
                "alerts": [],
                "created_time": "2020-11-16T10:00:00.610Z",
                "id": "25f58808-7171-4728-af4d-7feb5b04b97e",
                "source": "HUNT",
                "status": "OPEN",
                "title": "forensics 1 job at 20201116T100000.242Z"
            },
            {
                "alerts": [
                    {
                        "first_event_time": "2020-11-15T10:22:57.124Z",
                        "type": "Custom Alert - Pattern Detection",
                        "type_description": "One or more logs matched the pattern you defined."
                    }
                ],
                "created_time": "2020-11-15T10:30:05.523Z",
                "id": "cce874ae-e8cf-44a1-a4c6-eb044efa9255",
                "source": "ALERT",
                "status": "OPEN",
                "title": "Custom Alert where(new_authentication=true) was triggered for log Endpoint Agents in log set Asset Authentication"
            },
            {
                "alerts": [
                    {
                        "first_event_time": "2020-11-15T10:21:55.548Z",
                        "type": "New Asset Logon",
                        "type_description": "A user is authenticating to a new asset."
                    }
                ],
                "assignee": {
                    "email": "noamh@qmasters.co",
                    "name": "Noam Hazon"
                },
                "created_time": "2020-11-15T10:25:28.601Z",
                "id": "f24fedd4-698b-441e-9ccf-d7d3c2b617a3",
                "source": "ALERT",
                "status": "CLOSED",
                "title": "Account orc logged on to new asset 1orc-restore-ageent.qmasters.co"
            },
            {
                "alerts": [],
                "assignee": {
                    "email": "ykatzir@qmasters.co",
                    "name": "Yoel Katzir"
                },
                "created_time": "2020-11-15T10:00:00.448Z",
                "id": "ed475853-05da-4a8a-9f99-b9139d0fe8c0",
                "source": "HUNT",
                "status": "CLOSED",
                "title": "forensics 1 job at 20201115T100000.120Z"
            },
            {
                "alerts": [],
                "created_time": "2020-11-14T10:00:00.453Z",
                "id": "524b1447-b155-4f9c-b94d-67f7d2f835bd",
                "source": "HUNT",
                "status": "CLOSED",
                "title": "forensics 1 job at 20201114T100000.115Z"
            }
        ]
    }
}
```

#### Human Readable Output

>### Requested Investigations
>|title|id|status|created_time|source|assignee|alerts|
>|---|---|---|---|---|---|---|
>| 1234 | b7c3af95-fe53-46d3-98ac-fc99c0eaf113 | OPEN | 2020-11-16T11:50:53.817Z | MANUAL |  |  |
>| forensics 1 job at 20201116T100000.242Z | 25f58808-7171-4728-af4d-7feb5b04b97e | OPEN | 2020-11-16T10:00:00.610Z | HUNT |  |  |
>| Custom Alert where(new_authentication=true) was triggered for log Endpoint Agents in log set Asset Authentication | cce874ae-e8cf-44a1-a4c6-eb044efa9255 | OPEN | 2020-11-15T10:30:05.523Z | ALERT |  | {'type': 'Custom Alert - Pattern Detection', 'type_description': 'One or more logs matched the pattern you defined.', 'first_event_time': '2020-11-15T10:22:57.124Z'} |
>| Account orc logged on to new asset 1orc-restore-ageent.qmasters.co | f24fedd4-698b-441e-9ccf-d7d3c2b617a3 | CLOSED | 2020-11-15T10:25:28.601Z | ALERT | name: Noam Hazon<br/>email: noamh@qmasters.co | {'type': 'New Asset Logon', 'type_description': 'A user is authenticating to a new asset.', 'first_event_time': '2020-11-15T10:21:55.548Z'} |
>| forensics 1 job at 20201115T100000.120Z | ed475853-05da-4a8a-9f99-b9139d0fe8c0 | CLOSED | 2020-11-15T10:00:00.448Z | HUNT | name: Yoel Katzir<br/>email: ykatzir@qmasters.co |  |
>| forensics 1 job at 20201114T100000.115Z | 524b1447-b155-4f9c-b94d-67f7d2f835bd | CLOSED | 2020-11-14T10:00:00.453Z | HUNT |  |  |


### rapid7-insight-idr-get-investigation
***
Get a single open/closed investigation


#### Base Command

`rapid7-insight-idr-get-investigation`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| investigation_id | ID of the investigation to get | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Rapid7InsightIDR.Investigation.title | String | Title of investigation | 
| Rapid7InsightIDR.Investigation.id | String | ID of investigation | 
| Rapid7InsightIDR.Investigation.status | String | Whether it is open or closed | 
| Rapid7InsightIDR.Investigation.created_time | String | Time the investigation was created | 
| Rapid7InsightIDR.Investigation.source | String | Source of the investigation | 
| Rapid7InsightIDR.Investigation.assignee.email | String | Email of investigation assignee | 
| Rapid7InsightIDR.Investigation.assignee.name | String | Name of investigation assignee | 
| Rapid7InsightIDR.Investigation.alert.type | String | Type of alert in the investigation | 
| Rapid7InsightIDR.Investigation.alert.type_description | String | Type description of alert in the investigation | 
| Rapid7InsightIDR.Investigation.alert.first_event_time | String | first event time of alert in the investigation | 


#### Command Example
```!rapid7-insight-idr-get-investigation investigation_id=f24fedd4-698b-441e-9ccf-d7d3c2b617a3```

#### Context Example
```json
{
    "Rapid7InsightIDR": {
        "Investigation": {
            "alerts": [
                {
                    "first_event_time": "2020-11-15T10:21:55.548Z",
                    "type": "New Asset Logon",
                    "type_description": "A user is authenticating to a new asset."
                }
            ],
            "assignee": {
                "email": "noamh@qmasters.co",
                "name": "Noam Hazon"
            },
            "created_time": "2020-11-15T10:25:28.601Z",
            "id": "f24fedd4-698b-441e-9ccf-d7d3c2b617a3",
            "source": "ALERT",
            "status": "CLOSED",
            "title": "Account orc logged on to new asset 1orc-restore-ageent.qmasters.co"
        }
    }
}
```

#### Human Readable Output

>### Investigation Information (id: f24fedd4-698b-441e-9ccf-d7d3c2b617a3)
>|title|id|status|created_time|source|assignee|alerts|
>|---|---|---|---|---|---|---|
>| Account orc logged on to new asset 1orc-restore-ageent.qmasters.co | f24fedd4-698b-441e-9ccf-d7d3c2b617a3 | CLOSED | 2020-11-15T10:25:28.601Z | ALERT | name: Noam Hazon<br/>email: noamh@qmasters.co | {'type': 'New Asset Logon', 'type_description': 'A user is authenticating to a new asset.', 'first_event_time': '2020-11-15T10:21:55.548Z'} |


### rapid7-insight-idr-close-investigations
***
Close several investigations in bulk by time range


#### Base Command

`rapid7-insight-idr-close-investigations`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start_time | An ISO formatted timestamp. Only investigations whose createTime is after this date will be returned by the API. If this parameter is omitted investigations with any create_time may be returned - Use ISO time format (i.e 2018-07-01T00:00:00Z) | Required | 
| end_time | An ISO formatted timestamp. Only investigations whose createTime is before this date will be returned by the API. If this parameter is omitted investigations with any create_time may be returned - Use ISO time format (i.e 2018-07-01T00:00:00Z) | Required | 
| source | The name of an investigation source. Only investigations from this source will be closed. If the source is ALERT, an alert type must be specified as well. | Required | 
| alert_type | The category of alerts that should be closed. This parameter is required if the source is ALERT and ignored for other sources. This value must exactly match the alert type returned by the List Investigations response. | Optional | 
| max_investigations_to_close | An optional maximum number of alerts to close with this request. If this parameter is not specified then there is no maximum. If this limit is exceeded, then a 400 error response is returned. The minimum value is 0. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Rapid7InsightIDR.Investigation.id | String | ID of investigation | 


#### Command Example
```!rapid7-insight-idr-close-investigations source=HUNT start_time=2020-11-14T10:00:00.453Z end_time=2020-11-15T10:00:00.448Z```

#### Context Example
```json
{
    "Rapid7InsightIDR": {
        "Investigation": [
            {
                "id": "ed475853-05da-4a8a-9f99-b9139d0fe8c0",
                "status": "CLOSED"
            },
            {
                "id": "524b1447-b155-4f9c-b94d-67f7d2f835bd",
                "status": "CLOSED"
            }
        ]
    }
}
```

#### Human Readable Output

>### Closed Investigations IDs
>|id|
>|---|
>| ed475853-05da-4a8a-9f99-b9139d0fe8c0,<br/>524b1447-b155-4f9c-b94d-67f7d2f835bd |


### rapid7-insight-idr-assign-user
***
Assign a user by email to an investigation


#### Base Command

`rapid7-insight-idr-assign-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| investigation_id | ID of the investigation to assign the user to | Required | 
| user_email_address | The email address of the user to assign to this Investigation. Same email used to log into the insight platform | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Rapid7InsightIDR.Investigation.title | String | Title of investigation | 
| Rapid7InsightIDR.Investigation.id | String | ID of investigation | 
| Rapid7InsightIDR.Investigation.status | String | Whether it is open or closed | 
| Rapid7InsightIDR.Investigation.created_time | String | Time the investigation was created | 
| Rapid7InsightIDR.Investigation.source | String | Source of the investigation | 
| Rapid7InsightIDR.Investigation.assignee.email | String | Email of investigation assignee | 
| Rapid7InsightIDR.Investigation.assignee.name | String | Name of investigation assignee | 
| Rapid7InsightIDR.Investigation.alert.type | String | Type of alert in the investigation | 
| Rapid7InsightIDR.Investigation.alert.type_description | String | Type description of alert in the investigation | 
| Rapid7InsightIDR.Investigation.alert.first_event_time | String | first event time of alert in the investigation | 


#### Command Example
```!rapid7-insight-idr-assign-user investigation_id=ed475853-05da-4a8a-9f99-b9139d0fe8c0  user_email_address=ykatzir@qmasters.co```

#### Context Example
```json
{
    "Rapid7InsightIDR": {
        "Investigation": {
            "alerts": [],
            "assignee": {
                "email": "ykatzir@qmasters.co",
                "name": "Yoel Katzir"
            },
            "created_time": "2020-11-15T10:00:00.448Z",
            "id": "ed475853-05da-4a8a-9f99-b9139d0fe8c0",
            "source": "HUNT",
            "status": "CLOSED",
            "title": "forensics 1 job at 20201115T100000.120Z"
        }
    }
}
```

#### Human Readable Output

>### Investigation Information (id: ed475853-05da-4a8a-9f99-b9139d0fe8c0)
>|title|id|status|created_time|source|assignee|
>|---|---|---|---|---|---|
>| forensics 1 job at 20201115T100000.120Z | ed475853-05da-4a8a-9f99-b9139d0fe8c0 | CLOSED | 2020-11-15T10:00:00.448Z | HUNT | name: Yoel Katzir<br/>email: ykatzir@qmasters.co |


### rapid7-insight-idr-set-status
***
Set investigation status to open/closed


#### Base Command

`rapid7-insight-idr-set-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| investigation_id | ID of the investigation to set the status of | Required | 
| status | The new status for the investigation | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Rapid7InsightIDR.Investigation.Title | String | Title of investigation | 
| Rapid7InsightIDR.Investigation.Id | String | ID of investigation | 
| Rapid7InsightIDR.Investigation.Status | String | Whether it is open or closed | 
| Rapid7InsightIDR.Investigation.CreatedTime | String | Time the investigation was created | 
| Rapid7InsightIDR.Investigation.Source | String | Source of the investigation | 
| Rapid7InsightIDR.Investigation.AssigneeEmail | String | Email of investigation assignee | 
| Rapid7InsightIDR.Investigation.AssigneeName | String | Name of investigation assignee | 
| Rapid7InsightIDR.Investigation.AlertType | String | Type of alert in the investigation | 


#### Command Example
```!rapid7-insight-idr-set-status status=open investigation_id=ed475853-05da-4a8a-9f99-b9139d0fe8c0,524b1447-b155-4f9c-b94d-67f7d2f835bd```

#### Context Example
```json
{
    "Rapid7InsightIDR": {
        "Investigation": [
            {
                "alerts": [],
                "assignee": {
                    "email": "ykatzir@qmasters.co",
                    "name": "Yoel Katzir"
                },
                "created_time": "2020-11-15T10:00:00.448Z",
                "id": "ed475853-05da-4a8a-9f99-b9139d0fe8c0",
                "source": "HUNT",
                "status": "OPEN",
                "title": "forensics 1 job at 20201115T100000.120Z"
            },
            {
                "alerts": [],
                "created_time": "2020-11-14T10:00:00.453Z",
                "id": "524b1447-b155-4f9c-b94d-67f7d2f835bd",
                "source": "HUNT",
                "status": "OPEN",
                "title": "forensics 1 job at 20201114T100000.115Z"
            }
        ]
    }
}
```

#### Human Readable Output

>### Investigation Information (id: ed475853-05da-4a8a-9f99-b9139d0fe8c0,524b1447-b155-4f9c-b94d-67f7d2f835bd)
>|title|id|status|created_time|source|assignee|
>|---|---|---|---|---|---|
>| forensics 1 job at 20201115T100000.120Z | ed475853-05da-4a8a-9f99-b9139d0fe8c0 | OPEN | 2020-11-15T10:00:00.448Z | HUNT | name: Yoel Katzir<br/>email: ykatzir@qmasters.co |
>| forensics 1 job at 20201114T100000.115Z | 524b1447-b155-4f9c-b94d-67f7d2f835bd | OPEN | 2020-11-14T10:00:00.453Z | HUNT |  |


### rapid7-insight-idr-add-threat-indicators
***
Add new indicators to a threat


#### Base Command

`rapid7-insight-idr-add-threat-indicators`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| key | Key of the threat (or threats) to add indicators to | Required | 
| ip_addresses | IPs indicators to add | Optional | 
| hashes | hashes indicators to add | Optional | 
| domain_names | Domain indicators to add | Optional | 
| url | URL indicators to add | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Rapid7InsightIDR.Threat.name | String | Name of the Threat. | 
| Rapid7InsightIDR.Threat.note | String | Notes for the Threat. | 
| Rapid7InsightIDR.Threat.indicator_count | Number | How many indicators the threat has. | 
| Rapid7InsightIDR.Threat.published | Boolean | Whether or not the threat is published. | 


#### Command Example
```!rapid7-insight-idr-add-threat-indicators key=75fd98f3-a88c-475e-be39-ad9e44ecc6db ip_addresses=20.20.20.20```

#### Context Example
```json
{
    "Rapid7InsightIDR": {
        "Threat": {
            "indicator_count": 9,
            "name": "Threat2",
            "note": "This is Threat2 desciption",
            "published": false
        }
    }
}
```

#### Human Readable Output

>### Threat Information (key: 75fd98f3-a88c-475e-be39-ad9e44ecc6db)
>|name|note|indicator_count|published|
>|---|---|---|---|
>| Threat2 | This is Threat2 desciption | 9 | false |


### rapid7-insight-idr-replace-threat-indicators
***
Delete existing indicators and insert new ones.


#### Base Command

`rapid7-insight-idr-replace-threat-indicators`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| key | Key of the threat (or threats) to replace indicators for | Required | 
| ip_addresses | IPs indicators to add | Optional | 
| hashes | hashes indicators to add | Optional | 
| domain_names | Domain indicators to add | Optional | 
| url | URL indicators to add | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Rapid7InsightIDR.Threat.name | String | Name of the Threat. | 
| Rapid7InsightIDR.Threat.note | String | Notes for the Threat. | 
| Rapid7InsightIDR.Threat.indicator_count | Number | How many indicators the threat has. | 
| Rapid7InsightIDR.Threat.published | Boolean | Whether or not the threat is published. | 


#### Command Example
```!rapid7-insight-idr-replace-threat-indicators key=75fd98f3-a88c-475e-be39-ad9e44ecc6db ip_addresses=30.30.30.30```

#### Context Example
```json
{
    "Rapid7InsightIDR": {
        "Threat": {
            "indicator_count": 9,
            "name": "Threat2",
            "note": "This is Threat2 desciption",
            "published": false
        }
    }
}
```

#### Human Readable Output

>### Threat Information (key: 75fd98f3-a88c-475e-be39-ad9e44ecc6db)
>|name|note|indicator_count|published|
>|---|---|---|---|
>| Threat2 | This is Threat2 desciption | 9 | false |


### rapid7-insight-idr-list-logs
***
List all existing logs for an account


#### Base Command

`rapid7-insight-idr-list-logs`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Rapid7InsightIDR.Log.name | String | Log name | 
| Rapid7InsightIDR.Log.id | String | Log ID | 


#### Command Example
```!rapid7-insight-idr-list-logs```

#### Context Example
```json
{
    "Rapid7InsightIDR": {
        "Log": [
            {
                "id": "a668beb0-a769-4329-9c95-eeef55fb33d3",
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/management/logs/a668beb0-a769-4329-9c95-eeef55fb33d3/topkeys",
                        "rel": "Related"
                    }
                ],
                "logsets_info": [
                    {
                        "id": "c826ff7f-683a-4f9c-9167-9edec6979bbb",
                        "links": [
                            {
                                "href": "https://us.api.insight.rapid7.com/log_search/management/logsets/c826ff7f-683a-4f9c-9167-9edec6979bbb",
                                "rel": "Self"
                            }
                        ],
                        "name": "Unparsed Data",
                        "rrn": "rrn:logsearch:us:7a6865a8-3594-43c2-9625-93dbcd0e1f78:logset:c826ff7f-683a-4f9c-9167-9edec6979bbb"
                    }
                ],
                "name": "Windows Defender",
                "retention_period": "default",
                "rrn": "rrn:logsearch:us:7a6865a8-3594-43c2-9625-93dbcd0e1f78:log:a668beb0-a769-4329-9c95-eeef55fb33d3",
                "source_type": "token",
                "structures": [
                    "12d8ca9d-3b1b-4a36-b564-45de5f8425e9"
                ],
                "token_seed": null,
                "tokens": [
                    "3fcfc8c1-32f7-4d97-9a1b-bd372236dfe5"
                ],
                "user_data": {
                    "platform_managed": "true"
                }
            },
            {
                "id": "82b2969c-8597-41a3-9e2a-4bce4d0f6ab6",
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/management/logs/82b2969c-8597-41a3-9e2a-4bce4d0f6ab6/topkeys",
                        "rel": "Related"
                    }
                ],
                "logsets_info": [
                    {
                        "id": "f6e6410d-deb4-4b56-9c90-300f4cdaf46d",
                        "links": [
                            {
                                "href": "https://us.api.insight.rapid7.com/log_search/management/logsets/f6e6410d-deb4-4b56-9c90-300f4cdaf46d",
                                "rel": "Self"
                            }
                        ],
                        "name": "Internal Logs",
                        "rrn": "rrn:logsearch:us:7a6865a8-3594-43c2-9625-93dbcd0e1f78:logset:f6e6410d-deb4-4b56-9c90-300f4cdaf46d"
                    }
                ],
                "name": "Web Access Log",
                "retention_period": "default",
                "rrn": "rrn:logsearch:us:7a6865a8-3594-43c2-9625-93dbcd0e1f78:log:82b2969c-8597-41a3-9e2a-4bce4d0f6ab6",
                "source_type": "internal",
                "structures": [],
                "token_seed": null,
                "tokens": [],
                "user_data": {}
            },
            {
                "id": "bd65dfa8-7ddf-42b0-bf8c-27853bca1618",
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/management/logs/bd65dfa8-7ddf-42b0-bf8c-27853bca1618/topkeys",
                        "rel": "Related"
                    }
                ],
                "logsets_info": [
                    {
                        "id": "f6e6410d-deb4-4b56-9c90-300f4cdaf46d",
                        "links": [
                            {
                                "href": "https://us.api.insight.rapid7.com/log_search/management/logsets/f6e6410d-deb4-4b56-9c90-300f4cdaf46d",
                                "rel": "Self"
                            }
                        ],
                        "name": "Internal Logs",
                        "rrn": "rrn:logsearch:us:7a6865a8-3594-43c2-9625-93dbcd0e1f78:logset:f6e6410d-deb4-4b56-9c90-300f4cdaf46d"
                    }
                ],
                "name": "Alert Audit Log",
                "retention_period": "default",
                "rrn": "rrn:logsearch:us:7a6865a8-3594-43c2-9625-93dbcd0e1f78:log:bd65dfa8-7ddf-42b0-bf8c-27853bca1618",
                "source_type": "internal",
                "structures": [
                    "fa6a4440-4579-4a03-be08-c259a84db062"
                ],
                "token_seed": null,
                "tokens": [],
                "user_data": {}
            },
            {
                "id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/management/logs/ab5a7594-5fde-4c5c-9ee6-e67291f0a40c/topkeys",
                        "rel": "Related"
                    }
                ],
                "logsets_info": [
                    {
                        "id": "74c4af9d-2673-4bc2-b8e8-afe3d1354987",
                        "links": [
                            {
                                "href": "https://us.api.insight.rapid7.com/log_search/management/logsets/74c4af9d-2673-4bc2-b8e8-afe3d1354987",
                                "rel": "Self"
                            }
                        ],
                        "name": "Asset Authentication",
                        "rrn": "rrn:logsearch:us:7a6865a8-3594-43c2-9625-93dbcd0e1f78:logset:74c4af9d-2673-4bc2-b8e8-afe3d1354987"
                    }
                ],
                "name": "Endpoint Agents",
                "retention_period": "default",
                "rrn": "rrn:logsearch:us:7a6865a8-3594-43c2-9625-93dbcd0e1f78:log:ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "source_type": "token",
                "structures": [
                    "12d8ca9d-3b1b-4a36-b564-45de5f8425e9"
                ],
                "token_seed": null,
                "tokens": [
                    "b6c9d703-d3b5-4752-b24f-2aaf76bb7932"
                ],
                "user_data": {
                    "platform_managed": "true"
                }
            },
            {
                "id": "7efaf894-cf8a-4ed2-9495-77395bf2e5a6",
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/management/logs/7efaf894-cf8a-4ed2-9495-77395bf2e5a6/topkeys",
                        "rel": "Related"
                    }
                ],
                "logsets_info": [
                    {
                        "id": "5e6303c5-ef5e-4384-b1f7-13668a4a0d39",
                        "links": [
                            {
                                "href": "https://us.api.insight.rapid7.com/log_search/management/logsets/5e6303c5-ef5e-4384-b1f7-13668a4a0d39",
                                "rel": "Self"
                            }
                        ],
                        "name": "Raw Log",
                        "rrn": "rrn:logsearch:us:7a6865a8-3594-43c2-9625-93dbcd0e1f78:logset:5e6303c5-ef5e-4384-b1f7-13668a4a0d39"
                    }
                ],
                "name": "PersonalLogs",
                "retention_period": "default",
                "rrn": "rrn:logsearch:us:7a6865a8-3594-43c2-9625-93dbcd0e1f78:log:7efaf894-cf8a-4ed2-9495-77395bf2e5a6",
                "source_type": "token",
                "structures": [
                    "fa6a4440-4579-4a03-be08-c259a84db062"
                ],
                "token_seed": null,
                "tokens": [
                    "47b697be-f283-4257-876e-c4c716563ef7"
                ],
                "user_data": {
                    "platform_managed": "true"
                }
            },
            {
                "id": "c5f51e68-809f-4272-b714-275f3019ddd5",
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/management/logs/c5f51e68-809f-4272-b714-275f3019ddd5/topkeys",
                        "rel": "Related"
                    }
                ],
                "logsets_info": [
                    {
                        "id": "f6e6410d-deb4-4b56-9c90-300f4cdaf46d",
                        "links": [
                            {
                                "href": "https://us.api.insight.rapid7.com/log_search/management/logsets/f6e6410d-deb4-4b56-9c90-300f4cdaf46d",
                                "rel": "Self"
                            }
                        ],
                        "name": "Internal Logs",
                        "rrn": "rrn:logsearch:us:7a6865a8-3594-43c2-9625-93dbcd0e1f78:logset:f6e6410d-deb4-4b56-9c90-300f4cdaf46d"
                    }
                ],
                "name": "Log Updates",
                "retention_period": "default",
                "rrn": "rrn:logsearch:us:7a6865a8-3594-43c2-9625-93dbcd0e1f78:log:c5f51e68-809f-4272-b714-275f3019ddd5",
                "source_type": "internal",
                "structures": [
                    "fa6a4440-4579-4a03-be08-c259a84db062"
                ],
                "token_seed": null,
                "tokens": [],
                "user_data": {}
            }
        ]
    }
}
```

#### Human Readable Output

>### List Logs
>|name|id|
>|---|---|
>| Windows Defender | a668beb0-a769-4329-9c95-eeef55fb33d3 |
>| Web Access Log | 82b2969c-8597-41a3-9e2a-4bce4d0f6ab6 |
>| Alert Audit Log | bd65dfa8-7ddf-42b0-bf8c-27853bca1618 |
>| Endpoint Agents | ab5a7594-5fde-4c5c-9ee6-e67291f0a40c |
>| PersonalLogs | 7efaf894-cf8a-4ed2-9495-77395bf2e5a6 |
>| Log Updates | c5f51e68-809f-4272-b714-275f3019ddd5 |


### rapid7-insight-idr-list-log-sets
***
List all existing log sets for an account


#### Base Command

`rapid7-insight-idr-list-log-sets`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Rapid7InsightIDR.LogSet.name | String | Log name | 
| Rapid7InsightIDR.LogSet.id | String | Log ID | 


#### Command Example
```!rapid7-insight-idr-list-log-sets```

#### Context Example
```json
{
    "Rapid7InsightIDR": {
        "LogSet": [
            {
                "description": null,
                "id": "f6e6410d-deb4-4b56-9c90-300f4cdaf46d",
                "logs_info": [
                    {
                        "id": "82b2969c-8597-41a3-9e2a-4bce4d0f6ab6",
                        "links": [
                            {
                                "href": "https://us.api.insight.rapid7.com/log_search/management/logs/82b2969c-8597-41a3-9e2a-4bce4d0f6ab6",
                                "rel": "Self"
                            }
                        ],
                        "name": "Web Access Log",
                        "rrn": "rrn:logsearch:us:7a6865a8-3594-43c2-9625-93dbcd0e1f78:log:82b2969c-8597-41a3-9e2a-4bce4d0f6ab6"
                    },
                    {
                        "id": "bd65dfa8-7ddf-42b0-bf8c-27853bca1618",
                        "links": [
                            {
                                "href": "https://us.api.insight.rapid7.com/log_search/management/logs/bd65dfa8-7ddf-42b0-bf8c-27853bca1618",
                                "rel": "Self"
                            }
                        ],
                        "name": "Alert Audit Log",
                        "rrn": "rrn:logsearch:us:7a6865a8-3594-43c2-9625-93dbcd0e1f78:log:bd65dfa8-7ddf-42b0-bf8c-27853bca1618"
                    },
                    {
                        "id": "c5f51e68-809f-4272-b714-275f3019ddd5",
                        "links": [
                            {
                                "href": "https://us.api.insight.rapid7.com/log_search/management/logs/c5f51e68-809f-4272-b714-275f3019ddd5",
                                "rel": "Self"
                            }
                        ],
                        "name": "Log Updates",
                        "rrn": "rrn:logsearch:us:7a6865a8-3594-43c2-9625-93dbcd0e1f78:log:c5f51e68-809f-4272-b714-275f3019ddd5"
                    }
                ],
                "name": "Internal Logs",
                "rrn": "rrn:logsearch:us:7a6865a8-3594-43c2-9625-93dbcd0e1f78:logset:f6e6410d-deb4-4b56-9c90-300f4cdaf46d",
                "user_data": {}
            },
            {
                "description": null,
                "id": "74c4af9d-2673-4bc2-b8e8-afe3d1354987",
                "logs_info": [
                    {
                        "id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                        "links": [
                            {
                                "href": "https://us.api.insight.rapid7.com/log_search/management/logs/ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                                "rel": "Self"
                            }
                        ],
                        "name": "Endpoint Agents",
                        "rrn": "rrn:logsearch:us:7a6865a8-3594-43c2-9625-93dbcd0e1f78:log:ab5a7594-5fde-4c5c-9ee6-e67291f0a40c"
                    }
                ],
                "name": "Asset Authentication",
                "rrn": "rrn:logsearch:us:7a6865a8-3594-43c2-9625-93dbcd0e1f78:logset:74c4af9d-2673-4bc2-b8e8-afe3d1354987",
                "user_data": {
                    "platform_managed": "true"
                }
            },
            {
                "description": null,
                "id": "c826ff7f-683a-4f9c-9167-9edec6979bbb",
                "logs_info": [
                    {
                        "id": "a668beb0-a769-4329-9c95-eeef55fb33d3",
                        "links": [
                            {
                                "href": "https://us.api.insight.rapid7.com/log_search/management/logs/a668beb0-a769-4329-9c95-eeef55fb33d3",
                                "rel": "Self"
                            }
                        ],
                        "name": "Windows Defender",
                        "rrn": "rrn:logsearch:us:7a6865a8-3594-43c2-9625-93dbcd0e1f78:log:a668beb0-a769-4329-9c95-eeef55fb33d3"
                    }
                ],
                "name": "Unparsed Data",
                "rrn": "rrn:logsearch:us:7a6865a8-3594-43c2-9625-93dbcd0e1f78:logset:c826ff7f-683a-4f9c-9167-9edec6979bbb",
                "user_data": {
                    "platform_managed": "true"
                }
            },
            {
                "description": null,
                "id": "5e6303c5-ef5e-4384-b1f7-13668a4a0d39",
                "logs_info": [
                    {
                        "id": "7efaf894-cf8a-4ed2-9495-77395bf2e5a6",
                        "links": [
                            {
                                "href": "https://us.api.insight.rapid7.com/log_search/management/logs/7efaf894-cf8a-4ed2-9495-77395bf2e5a6",
                                "rel": "Self"
                            }
                        ],
                        "name": "PersonalLogs",
                        "rrn": "rrn:logsearch:us:7a6865a8-3594-43c2-9625-93dbcd0e1f78:log:7efaf894-cf8a-4ed2-9495-77395bf2e5a6"
                    }
                ],
                "name": "Raw Log",
                "rrn": "rrn:logsearch:us:7a6865a8-3594-43c2-9625-93dbcd0e1f78:logset:5e6303c5-ef5e-4384-b1f7-13668a4a0d39",
                "user_data": {
                    "platform_managed": "true"
                }
            }
        ]
    }
}
```

#### Human Readable Output

>### List Log Sets
>|name|id|
>|---|---|
>| Internal Logs | f6e6410d-deb4-4b56-9c90-300f4cdaf46d |
>| Asset Authentication | 74c4af9d-2673-4bc2-b8e8-afe3d1354987 |
>| Unparsed Data | c826ff7f-683a-4f9c-9167-9edec6979bbb |
>| Raw Log | 5e6303c5-ef5e-4384-b1f7-13668a4a0d39 |


### rapid7-insight-idr-download-logs
***
Download up to 10 logs for an account.


#### Base Command

`rapid7-insight-idr-download-logs`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| log_ids | IDs of the logs to download - up to 10 logs allowed. | Required | 
| start_time | Lower bound of the time range you want to query against. Format: UNIX timestamp in milliseconds. This is optional if time_range is supplied. | Optional | 
| end_time | Upper bound of the time range you want to query against. Format: UNIX timestamp in milliseconds. | Optional | 
| time_range | The relative time range in a readable format. Optional if from is supplied. Example: Last 4 Days. Note that if start_time, end_time and time_range is not provided - The default will be Last 3 days. | Optional | 
| query | The LEQL query to match desired log events. Do not use a calculation. | Optional | 
| limit | Max number of log events to download; cannot exceed 20 million. The default is 20 million (Note that a number should be written like "10 thousand" or "2 million") | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


#### Command Example
```!rapid7-insight-idr-download-logs log_ids=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c time_range="last 7 days"```

#### Context Example
```json
{
    "File": {
        "EntryID": "1743@e5ab5eb3-dafd-4dbc-8239-201263c94952",
        "Extension": "log",
        "Info": "log",
        "MD5": "b505cc2d5961101ad49a2f79487a4ee9",
        "Name": "EndpointAgents_2020-11-10_074618_2020-11-17_074618.log",
        "SHA1": "d5f53add5bb0ff3344f7d676b0d324b9049aaf1e",
        "SHA256": "4d3fc9801a7a6621cd507842c791d21e9f30c20a77faa16e12ce839a97300ea7",
        "SHA512": "cdd870e01115e6e768a9f7723291025113164ce253a7c290931bf9e205963230dfa31cec628d24df3c8c8adab7147445e367f0c6d4b209a5fe52061e8146f975",
        "SSDeep": "768:i5oJ5LwN0Zt6KYtU/Z9XSXHKW9XyXHTS9XcXHPW9XgXHy79XkXHTg9XnXHyMmkmX:qofLwN0Zt6KYtU/CXUXtX1XjXYXC1Lu6",
        "Size": 45114,
        "Type": "ASCII text, with very long lines"
    }
}
```

#### Human Readable Output



### rapid7-insight-idr-query-log
***
Query inside a log for certain values.


#### Base Command

`rapid7-insight-idr-query-log`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| log_id | Logentries log key | Required | 
| query | A valid LEQL query to run against the log | Required | 
| start_time | Lower bound of the time range you want to query against. Format: UNIX timestamp in milliseconds. Example:1450557004000 | Required | 
| end_time | Upper bound of the time range you want to query against. Format: UNIX timestamp in milliseconds. Example:1460557604000 | Required | 
| logs_per_page | The number of log entries to return per page. Default of 50 | Optional | 
| sequence_number | the earlier sequence number of a log entry to start searching from | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Rapid7InsightIDR.Event.log_id | String | Event message | 
| Rapid7InsightIDR.Event.message | String | ID of the log the event appears in | 
| Rapid7InsightIDR.Event.timestamp | Number | Time when the event fired | 


#### Command Example
```!rapid7-insight-idr-query-log log_id=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c query=where(destination_asset=\"jenkinsnode.qmasters.co\") start_time=0 end_time=3000557004000```

#### Context Example
```json
{
    "Rapid7InsightIDR": {
        "Event": [
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237201778429120512?per_page=50&timestamp=1605102271671&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-11T13:44:21.067Z\",\"destination_asset\":\"jenkinsnode.qmasters.co\",\"source_asset_address\":\"192.168.91.19\",\"destination_asset_address\":\"jenkinsnode.qmasters.co\",\"destination_local_account\":\"root\",\"logon_type\":\"NETWORK\",\"result\":\"SUCCESS\",\"new_authentication\":\"true\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":755448,\"pid\":15620,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"PAM:authentication\",\"grantors\":\"pam_unix\",\"acct\":\"root\",\"hostname\":\"192.168.91.19\",\"addr\":\"192.168.91.19\",\"terminal\":\"ssh\",\"res\":\"success\",\"type\":1100,\"startTime\":1605102231970,\"cmdLine\":\"sshd: root [priv]   \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"5370a21294928c65f4a5cf0990454a75847bfc7eade425c3392dcf7789395058\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"root\",\"gidName\":\"root\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"root\",\"egidName\":\"root\",\"auidName\":null,\"domain\":\"qmasters.co\"}}",
                "sequence_number": 3237201778429120500,
                "sequence_number_str": "3237201778429120512",
                "timestamp": 1605102271671
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237201778429128704?per_page=50&timestamp=1605102271671&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-11T13:43:57.509Z\",\"destination_asset\":\"jenkinsnode.qmasters.co\",\"source_asset_address\":\"192.168.91.19\",\"destination_asset_address\":\"jenkinsnode.qmasters.co\",\"destination_local_account\":\"root\",\"logon_type\":\"NETWORK\",\"result\":\"FAILED_OTHER\",\"new_authentication\":\"true\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":755429,\"pid\":15620,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"PAM:authentication\",\"acct\":\"root\",\"hostname\":\"192.168.91.19\",\"addr\":\"192.168.91.19\",\"terminal\":\"ssh\",\"res\":\"failed\",\"type\":1100,\"startTime\":1605102231970,\"cmdLine\":\"sshd: root [priv]   \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"5370a21294928c65f4a5cf0990454a75847bfc7eade425c3392dcf7789395058\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"root\",\"gidName\":\"root\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"root\",\"egidName\":\"root\",\"auidName\":null,\"domain\":\"qmasters.co\"}}",
                "sequence_number": 3237201778429128700,
                "sequence_number_str": "3237201778429128704",
                "timestamp": 1605102271671
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237201778429132800?per_page=50&timestamp=1605102271671&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-11T13:44:21.554Z\",\"destination_asset\":\"jenkinsnode.qmasters.co\",\"source_asset_address\":\"192.168.91.19\",\"destination_asset_address\":\"jenkinsnode.qmasters.co\",\"destination_local_account\":\"root\",\"logon_type\":\"NETWORK\",\"result\":\"SUCCESS\",\"new_authentication\":\"false\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":755452,\"pid\":15620,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"success\",\"acct\":\"root\",\"addr\":\"192.168.91.19\",\"terminal\":\"ssh\",\"res\":\"success\",\"type\":1100,\"startTime\":1605102231970,\"cmdLine\":\"sshd: root@pts/1    \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"89715ccf32b3f36cc769952cf203bb177ba5ad8d775fc8794d6dd613d371d2f0\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"root\",\"gidName\":\"root\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"root\",\"egidName\":\"root\",\"auidName\":null,\"domain\":\"qmasters.co\",\"hostname\":\"jenkinsnode\"}}",
                "sequence_number": 3237201778429133000,
                "sequence_number_str": "3237201778429132800",
                "timestamp": 1605102271671
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237201778429136896?per_page=50&timestamp=1605102271671&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-11T13:43:59.683Z\",\"destination_asset\":\"jenkinsnode.qmasters.co\",\"source_asset_address\":\"192.168.91.19\",\"destination_asset_address\":\"jenkinsnode.qmasters.co\",\"destination_local_account\":\"root\",\"logon_type\":\"NETWORK\",\"result\":\"FAILED_OTHER\",\"new_authentication\":\"true\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":755430,\"pid\":15620,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"password\",\"acct\":\"root\",\"addr\":\"192.168.91.19\",\"terminal\":\"ssh\",\"res\":\"failed\",\"type\":1100,\"startTime\":1605102231970,\"cmdLine\":\"sshd: root [priv]   \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"5370a21294928c65f4a5cf0990454a75847bfc7eade425c3392dcf7789395058\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"root\",\"gidName\":\"root\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"root\",\"egidName\":\"root\",\"auidName\":null,\"domain\":\"qmasters.co\",\"hostname\":\"jenkinsnode\"}}",
                "sequence_number": 3237201778429137000,
                "sequence_number_str": "3237201778429136896",
                "timestamp": 1605102271671
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237201778429140992?per_page=50&timestamp=1605102271671&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-11T13:44:07.343Z\",\"destination_asset\":\"jenkinsnode.qmasters.co\",\"source_asset_address\":\"192.168.91.19\",\"destination_asset_address\":\"jenkinsnode.qmasters.co\",\"destination_local_account\":\"root\",\"logon_type\":\"NETWORK\",\"result\":\"FAILED_OTHER\",\"new_authentication\":\"true\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":755445,\"pid\":15620,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"PAM:authentication\",\"acct\":\"root\",\"hostname\":\"192.168.91.19\",\"addr\":\"192.168.91.19\",\"terminal\":\"ssh\",\"res\":\"failed\",\"type\":1100,\"startTime\":1605102231970,\"cmdLine\":\"sshd: root [priv]   \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"5370a21294928c65f4a5cf0990454a75847bfc7eade425c3392dcf7789395058\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"root\",\"gidName\":\"root\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"root\",\"egidName\":\"root\",\"auidName\":null,\"domain\":\"qmasters.co\"}}",
                "sequence_number": 3237201778429141000,
                "sequence_number_str": "3237201778429140992",
                "timestamp": 1605102271671
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237201778429145088?per_page=50&timestamp=1605102271671&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-11T13:44:08.986Z\",\"destination_asset\":\"jenkinsnode.qmasters.co\",\"source_asset_address\":\"192.168.91.19\",\"destination_asset_address\":\"jenkinsnode.qmasters.co\",\"destination_local_account\":\"root\",\"logon_type\":\"NETWORK\",\"result\":\"FAILED_OTHER\",\"new_authentication\":\"true\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":755446,\"pid\":15620,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"password\",\"acct\":\"root\",\"addr\":\"192.168.91.19\",\"terminal\":\"ssh\",\"res\":\"failed\",\"type\":1100,\"startTime\":1605102231970,\"cmdLine\":\"sshd: root [priv]   \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"5370a21294928c65f4a5cf0990454a75847bfc7eade425c3392dcf7789395058\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"root\",\"gidName\":\"root\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"root\",\"egidName\":\"root\",\"auidName\":null,\"domain\":\"qmasters.co\",\"hostname\":\"jenkinsnode\"}}",
                "sequence_number": 3237201778429145000,
                "sequence_number_str": "3237201778429145088",
                "timestamp": 1605102271671
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237199644177084416?per_page=50&timestamp=1605535859467&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-16T14:10:36.743Z\",\"destination_asset\":\"jenkinsnode.qmasters.co\",\"source_asset_address\":\"192.168.91.19\",\"destination_asset_address\":\"jenkinsnode.qmasters.co\",\"destination_local_account\":\"root\",\"logon_type\":\"NETWORK\",\"result\":\"SUCCESS\",\"new_authentication\":\"false\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":853390,\"pid\":3243,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"PAM:authentication\",\"grantors\":\"pam_unix\",\"acct\":\"root\",\"hostname\":\"192.168.91.19\",\"addr\":\"192.168.91.19\",\"terminal\":\"ssh\",\"res\":\"success\",\"type\":1100,\"startTime\":1605535824080,\"cmdLine\":\"sshd: root [priv]   \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"d8328060d3e0d52ba552390f7c03ba235d6e18fe63ac996b01b8565ff93f32de\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"root\",\"gidName\":\"root\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"root\",\"egidName\":\"root\",\"auidName\":null,\"domain\":\"qmasters.co\"}}",
                "sequence_number": 3237199644177084400,
                "sequence_number_str": "3237199644177084416",
                "timestamp": 1605535859467
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237199644177088512?per_page=50&timestamp=1605535859467&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-16T14:10:31.194Z\",\"destination_asset\":\"jenkinsnode.qmasters.co\",\"source_asset_address\":\"192.168.91.19\",\"destination_asset_address\":\"jenkinsnode.qmasters.co\",\"destination_local_account\":\"root\",\"logon_type\":\"NETWORK\",\"result\":\"FAILED_OTHER\",\"new_authentication\":\"false\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":853387,\"pid\":3243,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"PAM:authentication\",\"acct\":\"root\",\"hostname\":\"192.168.91.19\",\"addr\":\"192.168.91.19\",\"terminal\":\"ssh\",\"res\":\"failed\",\"type\":1100,\"startTime\":1605535824080,\"cmdLine\":\"sshd: root [priv]   \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"d8328060d3e0d52ba552390f7c03ba235d6e18fe63ac996b01b8565ff93f32de\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"root\",\"gidName\":\"root\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"root\",\"egidName\":\"root\",\"auidName\":null,\"domain\":\"qmasters.co\"}}",
                "sequence_number": 3237199644177088500,
                "sequence_number_str": "3237199644177088512",
                "timestamp": 1605535859467
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237199644177092608?per_page=50&timestamp=1605535859467&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-16T14:10:39.212Z\",\"destination_asset\":\"jenkinsnode.qmasters.co\",\"source_asset_address\":\"192.168.91.19\",\"destination_asset_address\":\"jenkinsnode.qmasters.co\",\"destination_local_account\":\"root\",\"logon_type\":\"NETWORK\",\"result\":\"SUCCESS\",\"new_authentication\":\"false\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":853394,\"pid\":3243,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"success\",\"acct\":\"root\",\"addr\":\"192.168.91.19\",\"terminal\":\"ssh\",\"res\":\"success\",\"type\":1100,\"startTime\":1605535824080,\"cmdLine\":\"sshd: root@pts/1    \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"fe326b6ee65a983946f2847f66f735ba41d20d096a13ea9fa7f8341ad5e7da61\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"root\",\"gidName\":\"root\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"root\",\"egidName\":\"root\",\"auidName\":null,\"domain\":\"qmasters.co\",\"hostname\":\"jenkinsnode\"}}",
                "sequence_number": 3237199644177092600,
                "sequence_number_str": "3237199644177092608",
                "timestamp": 1605535859467
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237199644177096704?per_page=50&timestamp=1605535859467&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-16T14:10:31.872Z\",\"destination_asset\":\"jenkinsnode.qmasters.co\",\"source_asset_address\":\"192.168.91.19\",\"destination_asset_address\":\"jenkinsnode.qmasters.co\",\"destination_local_account\":\"root\",\"logon_type\":\"NETWORK\",\"result\":\"FAILED_OTHER\",\"new_authentication\":\"false\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":853388,\"pid\":3243,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"password\",\"acct\":\"root\",\"addr\":\"192.168.91.19\",\"terminal\":\"ssh\",\"res\":\"failed\",\"type\":1100,\"startTime\":1605535824080,\"cmdLine\":\"sshd: root [priv]   \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"d8328060d3e0d52ba552390f7c03ba235d6e18fe63ac996b01b8565ff93f32de\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"root\",\"gidName\":\"root\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"root\",\"egidName\":\"root\",\"auidName\":null,\"domain\":\"qmasters.co\",\"hostname\":\"jenkinsnode\"}}",
                "sequence_number": 3237199644177096700,
                "sequence_number_str": "3237199644177096704",
                "timestamp": 1605535859467
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237134439879106560?per_page=50&timestamp=1605536181913&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-16T14:15:36.401Z\",\"destination_asset\":\"jenkinsnode.qmasters.co\",\"source_asset_address\":\"192.168.91.19\",\"destination_asset_address\":\"jenkinsnode.qmasters.co\",\"destination_local_account\":\"root\",\"logon_type\":\"NETWORK\",\"result\":\"SUCCESS\",\"new_authentication\":\"false\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":853508,\"pid\":3656,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"PAM:authentication\",\"grantors\":\"pam_unix\",\"acct\":\"root\",\"hostname\":\"192.168.91.19\",\"addr\":\"192.168.91.19\",\"terminal\":\"ssh\",\"res\":\"success\",\"type\":1100,\"startTime\":1605536135850,\"cmdLine\":\"sshd: root [priv]   \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"97c6f7ba4f67c2c7b2b8d566dc9a01d79f3a5b5ff28078cb649c1726241a90ad\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"root\",\"gidName\":\"root\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"root\",\"egidName\":\"root\",\"auidName\":null,\"domain\":\"qmasters.co\"}}",
                "sequence_number": 3237134439879106600,
                "sequence_number_str": "3237134439879106560",
                "timestamp": 1605536181913
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237134439879110656?per_page=50&timestamp=1605536181913&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-16T14:15:36.406Z\",\"destination_asset\":\"jenkinsnode.qmasters.co\",\"source_asset_address\":\"192.168.91.19\",\"destination_asset_address\":\"jenkinsnode.qmasters.co\",\"destination_local_account\":\"root\",\"logon_type\":\"NETWORK\",\"result\":\"SUCCESS\",\"new_authentication\":\"false\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":853512,\"pid\":3656,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"success\",\"acct\":\"root\",\"addr\":\"192.168.91.19\",\"terminal\":\"ssh\",\"res\":\"success\",\"type\":1100,\"startTime\":1605536135850,\"cmdLine\":\"sshd: root [priv]   \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"97c6f7ba4f67c2c7b2b8d566dc9a01d79f3a5b5ff28078cb649c1726241a90ad\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"root\",\"gidName\":\"root\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"root\",\"egidName\":\"root\",\"auidName\":null,\"domain\":\"qmasters.co\",\"hostname\":\"jenkinsnode\"}}",
                "sequence_number": 3237134439879110700,
                "sequence_number_str": "3237134439879110656",
                "timestamp": 1605536181913
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237127759570530304?per_page=50&timestamp=1605540767722&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-16T15:31:59.538Z\",\"destination_asset\":\"jenkinsnode.qmasters.co\",\"source_asset_address\":\"172.16.100.22\",\"destination_asset_address\":\"jenkinsnode.qmasters.co\",\"destination_local_account\":\"root\",\"logon_type\":\"NETWORK\",\"result\":\"FAILED_OTHER\",\"new_authentication\":\"false\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":854639,\"pid\":8343,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"PAM:authentication\",\"acct\":\"root\",\"hostname\":\"172.16.100.22\",\"addr\":\"172.16.100.22\",\"terminal\":\"ssh\",\"res\":\"failed\",\"type\":1100,\"startTime\":1605540715180,\"cmdLine\":\"sshd: root [priv]   \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"a710f00b6754f1553797cab5829410e227c60f12f3c6b46511f7a3fc5e0f5cf6\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"root\",\"gidName\":\"root\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"root\",\"egidName\":\"root\",\"auidName\":null,\"domain\":\"qmasters.co\"}}",
                "sequence_number": 3237127759570530300,
                "sequence_number_str": "3237127759570530304",
                "timestamp": 1605540767722
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237127759570534400?per_page=50&timestamp=1605540767722&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-16T15:32:04.843Z\",\"destination_asset\":\"jenkinsnode.qmasters.co\",\"source_asset_address\":\"172.16.100.22\",\"destination_asset_address\":\"jenkinsnode.qmasters.co\",\"destination_local_account\":\"root\",\"logon_type\":\"NETWORK\",\"result\":\"SUCCESS\",\"new_authentication\":\"false\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":854655,\"pid\":8343,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"PAM:authentication\",\"grantors\":\"pam_unix\",\"acct\":\"root\",\"hostname\":\"172.16.100.22\",\"addr\":\"172.16.100.22\",\"terminal\":\"ssh\",\"res\":\"success\",\"type\":1100,\"startTime\":1605540715180,\"cmdLine\":\"sshd: root [priv]   \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"a710f00b6754f1553797cab5829410e227c60f12f3c6b46511f7a3fc5e0f5cf6\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"root\",\"gidName\":\"root\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"root\",\"egidName\":\"root\",\"auidName\":null,\"domain\":\"qmasters.co\"}}",
                "sequence_number": 3237127759570534400,
                "sequence_number_str": "3237127759570534400",
                "timestamp": 1605540767722
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237127759570538496?per_page=50&timestamp=1605540767722&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-16T15:31:59.841Z\",\"destination_asset\":\"jenkinsnode.qmasters.co\",\"source_asset_address\":\"172.16.100.22\",\"destination_asset_address\":\"jenkinsnode.qmasters.co\",\"destination_local_account\":\"root\",\"logon_type\":\"NETWORK\",\"result\":\"FAILED_OTHER\",\"new_authentication\":\"false\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":854640,\"pid\":8343,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"password\",\"acct\":\"root\",\"addr\":\"172.16.100.22\",\"terminal\":\"ssh\",\"res\":\"failed\",\"type\":1100,\"startTime\":1605540715180,\"cmdLine\":\"sshd: root [priv]   \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"a710f00b6754f1553797cab5829410e227c60f12f3c6b46511f7a3fc5e0f5cf6\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"root\",\"gidName\":\"root\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"root\",\"egidName\":\"root\",\"auidName\":null,\"domain\":\"qmasters.co\",\"hostname\":\"jenkinsnode\"}}",
                "sequence_number": 3237127759570538500,
                "sequence_number_str": "3237127759570538496",
                "timestamp": 1605540767722
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237127759570542592?per_page=50&timestamp=1605540767722&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-16T15:32:07.557Z\",\"destination_asset\":\"jenkinsnode.qmasters.co\",\"source_asset_address\":\"172.16.100.22\",\"destination_asset_address\":\"jenkinsnode.qmasters.co\",\"destination_local_account\":\"root\",\"logon_type\":\"NETWORK\",\"result\":\"SUCCESS\",\"new_authentication\":\"false\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":854659,\"pid\":8343,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"success\",\"acct\":\"root\",\"addr\":\"172.16.100.22\",\"terminal\":\"ssh\",\"res\":\"success\",\"type\":1100,\"startTime\":1605540715180,\"cmdLine\":\"sshd: root@pts/2    \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"ddd669c2a201339a549a5d9bab79c8a61dfd6ff2b4b0ed846fa9798f5bf2cc9c\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"root\",\"gidName\":\"root\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"root\",\"egidName\":\"root\",\"auidName\":null,\"domain\":\"qmasters.co\",\"hostname\":\"jenkinsnode\"}}",
                "sequence_number": 3237127759570542600,
                "sequence_number_str": "3237127759570542592",
                "timestamp": 1605540767722
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237202737554612224?per_page=50&timestamp=1605541577601&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-16T15:46:13.083Z\",\"destination_asset\":\"jenkinsnode.qmasters.co\",\"source_asset_address\":\"172.16.100.22\",\"destination_asset_address\":\"jenkinsnode.qmasters.co\",\"destination_local_account\":\"root\",\"logon_type\":\"NETWORK\",\"result\":\"FAILED_OTHER\",\"new_authentication\":\"false\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":914355,\"pid\":23992,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"PAM:authentication\",\"acct\":\"root\",\"hostname\":\"172.16.100.22\",\"addr\":\"172.16.100.22\",\"terminal\":\"ssh\",\"res\":\"failed\",\"type\":1100,\"startTime\":1605541569420,\"cmdLine\":\"sshd: root [priv]   \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"cc0a6c4f86c0e1695022c8f3c56de41c6eea5becfe91f1891749c585ff493ee1\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"root\",\"gidName\":\"root\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"root\",\"egidName\":\"root\",\"auidName\":null,\"domain\":\"qmasters.co\"}}",
                "sequence_number": 3237202737554612000,
                "sequence_number_str": "3237202737554612224",
                "timestamp": 1605541577601
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237202737554616320?per_page=50&timestamp=1605541580470&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-16T15:46:18.886Z\",\"destination_asset\":\"jenkinsnode.qmasters.co\",\"source_asset_address\":\"172.16.100.22\",\"destination_asset_address\":\"jenkinsnode.qmasters.co\",\"destination_local_account\":\"root\",\"logon_type\":\"NETWORK\",\"result\":\"SUCCESS\",\"new_authentication\":\"false\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":914725,\"pid\":23992,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"PAM:authentication\",\"grantors\":\"pam_unix\",\"acct\":\"root\",\"hostname\":\"172.16.100.22\",\"addr\":\"172.16.100.22\",\"terminal\":\"ssh\",\"res\":\"success\",\"type\":1100,\"startTime\":1605541569420,\"cmdLine\":\"sshd: root [priv]   \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"cc0a6c4f86c0e1695022c8f3c56de41c6eea5becfe91f1891749c585ff493ee1\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"root\",\"gidName\":\"root\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"root\",\"egidName\":\"root\",\"auidName\":null,\"domain\":\"qmasters.co\"}}",
                "sequence_number": 3237202737554616300,
                "sequence_number_str": "3237202737554616320",
                "timestamp": 1605541580470
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237202737554620416?per_page=50&timestamp=1605541580470&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-16T15:46:17.123Z\",\"destination_asset\":\"jenkinsnode.qmasters.co\",\"source_asset_address\":\"172.16.100.22\",\"destination_asset_address\":\"jenkinsnode.qmasters.co\",\"destination_local_account\":\"root\",\"logon_type\":\"NETWORK\",\"result\":\"FAILED_OTHER\",\"new_authentication\":\"false\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":914407,\"pid\":23992,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"password\",\"acct\":\"root\",\"addr\":\"172.16.100.22\",\"terminal\":\"ssh\",\"res\":\"failed\",\"type\":1100,\"startTime\":1605541569420,\"cmdLine\":\"sshd: root [priv]   \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"cc0a6c4f86c0e1695022c8f3c56de41c6eea5becfe91f1891749c585ff493ee1\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"root\",\"gidName\":\"root\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"root\",\"egidName\":\"root\",\"auidName\":null,\"domain\":\"qmasters.co\",\"hostname\":\"jenkinsnode\"}}",
                "sequence_number": 3237202737554620400,
                "sequence_number_str": "3237202737554620416",
                "timestamp": 1605541580470
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237202737554624512?per_page=50&timestamp=1605541580470&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-16T15:46:18.903Z\",\"destination_asset\":\"jenkinsnode.qmasters.co\",\"source_asset_address\":\"172.16.100.22\",\"destination_asset_address\":\"jenkinsnode.qmasters.co\",\"destination_local_account\":\"root\",\"logon_type\":\"NETWORK\",\"result\":\"SUCCESS\",\"new_authentication\":\"false\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":914729,\"pid\":23992,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"success\",\"acct\":\"root\",\"addr\":\"172.16.100.22\",\"terminal\":\"ssh\",\"res\":\"success\",\"type\":1100,\"startTime\":1605541569420,\"cmdLine\":\"sshd: root [priv]   \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"cc0a6c4f86c0e1695022c8f3c56de41c6eea5becfe91f1891749c585ff493ee1\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"root\",\"gidName\":\"root\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"root\",\"egidName\":\"root\",\"auidName\":null,\"domain\":\"qmasters.co\",\"hostname\":\"jenkinsnode\"}}",
                "sequence_number": 3237202737554624500,
                "sequence_number_str": "3237202737554624512",
                "timestamp": 1605541580470
            }
        ]
    }
}
```

#### Human Readable Output

>### Query Results
>|log_id|message|timestamp|
>|---|---|---|
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-11T13:44:21.067Z","destination_asset":"jenkinsnode.qmasters.co","source_asset_address":"192.168.91.19","destination_asset_address":"jenkinsnode.qmasters.co","destination_local_account":"root","logon_type":"NETWORK","result":"SUCCESS","new_authentication":"true","service":"/usr/sbin/sshd","source_json":{"audit_id":755448,"pid":15620,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"PAM:authentication","grantors":"pam_unix","acct":"root","hostname":"192.168.91.19","addr":"192.168.91.19","terminal":"ssh","res":"success","type":1100,"startTime":1605102231970,"cmdLine":"sshd: root [priv]   ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"processUUID":"5370a21294928c65f4a5cf0990454a75847bfc7eade425c3392dcf7789395058","hashes":{"md5":"686cd72b4339da33bfb6fe8fb94a301f","sha1":"0205dc86c73109c380f97b4481cad911b98df5cd","sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"root","gidName":"root"},"euid":0,"egid":0,"uidName":null,"euidName":"root","egidName":"root","auidName":null,"domain":"qmasters.co"}} | 1605102271671 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-11T13:43:57.509Z","destination_asset":"jenkinsnode.qmasters.co","source_asset_address":"192.168.91.19","destination_asset_address":"jenkinsnode.qmasters.co","destination_local_account":"root","logon_type":"NETWORK","result":"FAILED_OTHER","new_authentication":"true","service":"/usr/sbin/sshd","source_json":{"audit_id":755429,"pid":15620,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"PAM:authentication","acct":"root","hostname":"192.168.91.19","addr":"192.168.91.19","terminal":"ssh","res":"failed","type":1100,"startTime":1605102231970,"cmdLine":"sshd: root [priv]   ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"processUUID":"5370a21294928c65f4a5cf0990454a75847bfc7eade425c3392dcf7789395058","hashes":{"md5":"686cd72b4339da33bfb6fe8fb94a301f","sha1":"0205dc86c73109c380f97b4481cad911b98df5cd","sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"root","gidName":"root"},"euid":0,"egid":0,"uidName":null,"euidName":"root","egidName":"root","auidName":null,"domain":"qmasters.co"}} | 1605102271671 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-11T13:44:21.554Z","destination_asset":"jenkinsnode.qmasters.co","source_asset_address":"192.168.91.19","destination_asset_address":"jenkinsnode.qmasters.co","destination_local_account":"root","logon_type":"NETWORK","result":"SUCCESS","new_authentication":"false","service":"/usr/sbin/sshd","source_json":{"audit_id":755452,"pid":15620,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"success","acct":"root","addr":"192.168.91.19","terminal":"ssh","res":"success","type":1100,"startTime":1605102231970,"cmdLine":"sshd: root@pts/1    ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"processUUID":"89715ccf32b3f36cc769952cf203bb177ba5ad8d775fc8794d6dd613d371d2f0","hashes":{"md5":"686cd72b4339da33bfb6fe8fb94a301f","sha1":"0205dc86c73109c380f97b4481cad911b98df5cd","sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"root","gidName":"root"},"euid":0,"egid":0,"uidName":null,"euidName":"root","egidName":"root","auidName":null,"domain":"qmasters.co","hostname":"jenkinsnode"}} | 1605102271671 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-11T13:43:59.683Z","destination_asset":"jenkinsnode.qmasters.co","source_asset_address":"192.168.91.19","destination_asset_address":"jenkinsnode.qmasters.co","destination_local_account":"root","logon_type":"NETWORK","result":"FAILED_OTHER","new_authentication":"true","service":"/usr/sbin/sshd","source_json":{"audit_id":755430,"pid":15620,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"password","acct":"root","addr":"192.168.91.19","terminal":"ssh","res":"failed","type":1100,"startTime":1605102231970,"cmdLine":"sshd: root [priv]   ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"processUUID":"5370a21294928c65f4a5cf0990454a75847bfc7eade425c3392dcf7789395058","hashes":{"md5":"686cd72b4339da33bfb6fe8fb94a301f","sha1":"0205dc86c73109c380f97b4481cad911b98df5cd","sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"root","gidName":"root"},"euid":0,"egid":0,"uidName":null,"euidName":"root","egidName":"root","auidName":null,"domain":"qmasters.co","hostname":"jenkinsnode"}} | 1605102271671 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-11T13:44:07.343Z","destination_asset":"jenkinsnode.qmasters.co","source_asset_address":"192.168.91.19","destination_asset_address":"jenkinsnode.qmasters.co","destination_local_account":"root","logon_type":"NETWORK","result":"FAILED_OTHER","new_authentication":"true","service":"/usr/sbin/sshd","source_json":{"audit_id":755445,"pid":15620,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"PAM:authentication","acct":"root","hostname":"192.168.91.19","addr":"192.168.91.19","terminal":"ssh","res":"failed","type":1100,"startTime":1605102231970,"cmdLine":"sshd: root [priv]   ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"processUUID":"5370a21294928c65f4a5cf0990454a75847bfc7eade425c3392dcf7789395058","hashes":{"md5":"686cd72b4339da33bfb6fe8fb94a301f","sha1":"0205dc86c73109c380f97b4481cad911b98df5cd","sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"root","gidName":"root"},"euid":0,"egid":0,"uidName":null,"euidName":"root","egidName":"root","auidName":null,"domain":"qmasters.co"}} | 1605102271671 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-11T13:44:08.986Z","destination_asset":"jenkinsnode.qmasters.co","source_asset_address":"192.168.91.19","destination_asset_address":"jenkinsnode.qmasters.co","destination_local_account":"root","logon_type":"NETWORK","result":"FAILED_OTHER","new_authentication":"true","service":"/usr/sbin/sshd","source_json":{"audit_id":755446,"pid":15620,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"password","acct":"root","addr":"192.168.91.19","terminal":"ssh","res":"failed","type":1100,"startTime":1605102231970,"cmdLine":"sshd: root [priv]   ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"processUUID":"5370a21294928c65f4a5cf0990454a75847bfc7eade425c3392dcf7789395058","hashes":{"md5":"686cd72b4339da33bfb6fe8fb94a301f","sha1":"0205dc86c73109c380f97b4481cad911b98df5cd","sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"root","gidName":"root"},"euid":0,"egid":0,"uidName":null,"euidName":"root","egidName":"root","auidName":null,"domain":"qmasters.co","hostname":"jenkinsnode"}} | 1605102271671 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-16T14:10:36.743Z","destination_asset":"jenkinsnode.qmasters.co","source_asset_address":"192.168.91.19","destination_asset_address":"jenkinsnode.qmasters.co","destination_local_account":"root","logon_type":"NETWORK","result":"SUCCESS","new_authentication":"false","service":"/usr/sbin/sshd","source_json":{"audit_id":853390,"pid":3243,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"PAM:authentication","grantors":"pam_unix","acct":"root","hostname":"192.168.91.19","addr":"192.168.91.19","terminal":"ssh","res":"success","type":1100,"startTime":1605535824080,"cmdLine":"sshd: root [priv]   ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"processUUID":"d8328060d3e0d52ba552390f7c03ba235d6e18fe63ac996b01b8565ff93f32de","hashes":{"md5":"686cd72b4339da33bfb6fe8fb94a301f","sha1":"0205dc86c73109c380f97b4481cad911b98df5cd","sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"root","gidName":"root"},"euid":0,"egid":0,"uidName":null,"euidName":"root","egidName":"root","auidName":null,"domain":"qmasters.co"}} | 1605535859467 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-16T14:10:31.194Z","destination_asset":"jenkinsnode.qmasters.co","source_asset_address":"192.168.91.19","destination_asset_address":"jenkinsnode.qmasters.co","destination_local_account":"root","logon_type":"NETWORK","result":"FAILED_OTHER","new_authentication":"false","service":"/usr/sbin/sshd","source_json":{"audit_id":853387,"pid":3243,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"PAM:authentication","acct":"root","hostname":"192.168.91.19","addr":"192.168.91.19","terminal":"ssh","res":"failed","type":1100,"startTime":1605535824080,"cmdLine":"sshd: root [priv]   ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"processUUID":"d8328060d3e0d52ba552390f7c03ba235d6e18fe63ac996b01b8565ff93f32de","hashes":{"md5":"686cd72b4339da33bfb6fe8fb94a301f","sha1":"0205dc86c73109c380f97b4481cad911b98df5cd","sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"root","gidName":"root"},"euid":0,"egid":0,"uidName":null,"euidName":"root","egidName":"root","auidName":null,"domain":"qmasters.co"}} | 1605535859467 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-16T14:10:39.212Z","destination_asset":"jenkinsnode.qmasters.co","source_asset_address":"192.168.91.19","destination_asset_address":"jenkinsnode.qmasters.co","destination_local_account":"root","logon_type":"NETWORK","result":"SUCCESS","new_authentication":"false","service":"/usr/sbin/sshd","source_json":{"audit_id":853394,"pid":3243,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"success","acct":"root","addr":"192.168.91.19","terminal":"ssh","res":"success","type":1100,"startTime":1605535824080,"cmdLine":"sshd: root@pts/1    ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"processUUID":"fe326b6ee65a983946f2847f66f735ba41d20d096a13ea9fa7f8341ad5e7da61","hashes":{"md5":"686cd72b4339da33bfb6fe8fb94a301f","sha1":"0205dc86c73109c380f97b4481cad911b98df5cd","sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"root","gidName":"root"},"euid":0,"egid":0,"uidName":null,"euidName":"root","egidName":"root","auidName":null,"domain":"qmasters.co","hostname":"jenkinsnode"}} | 1605535859467 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-16T14:10:31.872Z","destination_asset":"jenkinsnode.qmasters.co","source_asset_address":"192.168.91.19","destination_asset_address":"jenkinsnode.qmasters.co","destination_local_account":"root","logon_type":"NETWORK","result":"FAILED_OTHER","new_authentication":"false","service":"/usr/sbin/sshd","source_json":{"audit_id":853388,"pid":3243,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"password","acct":"root","addr":"192.168.91.19","terminal":"ssh","res":"failed","type":1100,"startTime":1605535824080,"cmdLine":"sshd: root [priv]   ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"processUUID":"d8328060d3e0d52ba552390f7c03ba235d6e18fe63ac996b01b8565ff93f32de","hashes":{"md5":"686cd72b4339da33bfb6fe8fb94a301f","sha1":"0205dc86c73109c380f97b4481cad911b98df5cd","sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"root","gidName":"root"},"euid":0,"egid":0,"uidName":null,"euidName":"root","egidName":"root","auidName":null,"domain":"qmasters.co","hostname":"jenkinsnode"}} | 1605535859467 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-16T14:15:36.401Z","destination_asset":"jenkinsnode.qmasters.co","source_asset_address":"192.168.91.19","destination_asset_address":"jenkinsnode.qmasters.co","destination_local_account":"root","logon_type":"NETWORK","result":"SUCCESS","new_authentication":"false","service":"/usr/sbin/sshd","source_json":{"audit_id":853508,"pid":3656,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"PAM:authentication","grantors":"pam_unix","acct":"root","hostname":"192.168.91.19","addr":"192.168.91.19","terminal":"ssh","res":"success","type":1100,"startTime":1605536135850,"cmdLine":"sshd: root [priv]   ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"processUUID":"97c6f7ba4f67c2c7b2b8d566dc9a01d79f3a5b5ff28078cb649c1726241a90ad","hashes":{"md5":"686cd72b4339da33bfb6fe8fb94a301f","sha1":"0205dc86c73109c380f97b4481cad911b98df5cd","sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"root","gidName":"root"},"euid":0,"egid":0,"uidName":null,"euidName":"root","egidName":"root","auidName":null,"domain":"qmasters.co"}} | 1605536181913 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-16T14:15:36.406Z","destination_asset":"jenkinsnode.qmasters.co","source_asset_address":"192.168.91.19","destination_asset_address":"jenkinsnode.qmasters.co","destination_local_account":"root","logon_type":"NETWORK","result":"SUCCESS","new_authentication":"false","service":"/usr/sbin/sshd","source_json":{"audit_id":853512,"pid":3656,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"success","acct":"root","addr":"192.168.91.19","terminal":"ssh","res":"success","type":1100,"startTime":1605536135850,"cmdLine":"sshd: root [priv]   ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"processUUID":"97c6f7ba4f67c2c7b2b8d566dc9a01d79f3a5b5ff28078cb649c1726241a90ad","hashes":{"md5":"686cd72b4339da33bfb6fe8fb94a301f","sha1":"0205dc86c73109c380f97b4481cad911b98df5cd","sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"root","gidName":"root"},"euid":0,"egid":0,"uidName":null,"euidName":"root","egidName":"root","auidName":null,"domain":"qmasters.co","hostname":"jenkinsnode"}} | 1605536181913 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-16T15:31:59.538Z","destination_asset":"jenkinsnode.qmasters.co","source_asset_address":"172.16.100.22","destination_asset_address":"jenkinsnode.qmasters.co","destination_local_account":"root","logon_type":"NETWORK","result":"FAILED_OTHER","new_authentication":"false","service":"/usr/sbin/sshd","source_json":{"audit_id":854639,"pid":8343,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"PAM:authentication","acct":"root","hostname":"172.16.100.22","addr":"172.16.100.22","terminal":"ssh","res":"failed","type":1100,"startTime":1605540715180,"cmdLine":"sshd: root [priv]   ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"processUUID":"a710f00b6754f1553797cab5829410e227c60f12f3c6b46511f7a3fc5e0f5cf6","hashes":{"md5":"686cd72b4339da33bfb6fe8fb94a301f","sha1":"0205dc86c73109c380f97b4481cad911b98df5cd","sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"root","gidName":"root"},"euid":0,"egid":0,"uidName":null,"euidName":"root","egidName":"root","auidName":null,"domain":"qmasters.co"}} | 1605540767722 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-16T15:32:04.843Z","destination_asset":"jenkinsnode.qmasters.co","source_asset_address":"172.16.100.22","destination_asset_address":"jenkinsnode.qmasters.co","destination_local_account":"root","logon_type":"NETWORK","result":"SUCCESS","new_authentication":"false","service":"/usr/sbin/sshd","source_json":{"audit_id":854655,"pid":8343,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"PAM:authentication","grantors":"pam_unix","acct":"root","hostname":"172.16.100.22","addr":"172.16.100.22","terminal":"ssh","res":"success","type":1100,"startTime":1605540715180,"cmdLine":"sshd: root [priv]   ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"processUUID":"a710f00b6754f1553797cab5829410e227c60f12f3c6b46511f7a3fc5e0f5cf6","hashes":{"md5":"686cd72b4339da33bfb6fe8fb94a301f","sha1":"0205dc86c73109c380f97b4481cad911b98df5cd","sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"root","gidName":"root"},"euid":0,"egid":0,"uidName":null,"euidName":"root","egidName":"root","auidName":null,"domain":"qmasters.co"}} | 1605540767722 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-16T15:31:59.841Z","destination_asset":"jenkinsnode.qmasters.co","source_asset_address":"172.16.100.22","destination_asset_address":"jenkinsnode.qmasters.co","destination_local_account":"root","logon_type":"NETWORK","result":"FAILED_OTHER","new_authentication":"false","service":"/usr/sbin/sshd","source_json":{"audit_id":854640,"pid":8343,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"password","acct":"root","addr":"172.16.100.22","terminal":"ssh","res":"failed","type":1100,"startTime":1605540715180,"cmdLine":"sshd: root [priv]   ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"processUUID":"a710f00b6754f1553797cab5829410e227c60f12f3c6b46511f7a3fc5e0f5cf6","hashes":{"md5":"686cd72b4339da33bfb6fe8fb94a301f","sha1":"0205dc86c73109c380f97b4481cad911b98df5cd","sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"root","gidName":"root"},"euid":0,"egid":0,"uidName":null,"euidName":"root","egidName":"root","auidName":null,"domain":"qmasters.co","hostname":"jenkinsnode"}} | 1605540767722 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-16T15:32:07.557Z","destination_asset":"jenkinsnode.qmasters.co","source_asset_address":"172.16.100.22","destination_asset_address":"jenkinsnode.qmasters.co","destination_local_account":"root","logon_type":"NETWORK","result":"SUCCESS","new_authentication":"false","service":"/usr/sbin/sshd","source_json":{"audit_id":854659,"pid":8343,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"success","acct":"root","addr":"172.16.100.22","terminal":"ssh","res":"success","type":1100,"startTime":1605540715180,"cmdLine":"sshd: root@pts/2    ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"processUUID":"ddd669c2a201339a549a5d9bab79c8a61dfd6ff2b4b0ed846fa9798f5bf2cc9c","hashes":{"md5":"686cd72b4339da33bfb6fe8fb94a301f","sha1":"0205dc86c73109c380f97b4481cad911b98df5cd","sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"root","gidName":"root"},"euid":0,"egid":0,"uidName":null,"euidName":"root","egidName":"root","auidName":null,"domain":"qmasters.co","hostname":"jenkinsnode"}} | 1605540767722 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-16T15:46:13.083Z","destination_asset":"jenkinsnode.qmasters.co","source_asset_address":"172.16.100.22","destination_asset_address":"jenkinsnode.qmasters.co","destination_local_account":"root","logon_type":"NETWORK","result":"FAILED_OTHER","new_authentication":"false","service":"/usr/sbin/sshd","source_json":{"audit_id":914355,"pid":23992,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"PAM:authentication","acct":"root","hostname":"172.16.100.22","addr":"172.16.100.22","terminal":"ssh","res":"failed","type":1100,"startTime":1605541569420,"cmdLine":"sshd: root [priv]   ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"processUUID":"cc0a6c4f86c0e1695022c8f3c56de41c6eea5becfe91f1891749c585ff493ee1","hashes":{"md5":"686cd72b4339da33bfb6fe8fb94a301f","sha1":"0205dc86c73109c380f97b4481cad911b98df5cd","sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"root","gidName":"root"},"euid":0,"egid":0,"uidName":null,"euidName":"root","egidName":"root","auidName":null,"domain":"qmasters.co"}} | 1605541577601 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-16T15:46:18.886Z","destination_asset":"jenkinsnode.qmasters.co","source_asset_address":"172.16.100.22","destination_asset_address":"jenkinsnode.qmasters.co","destination_local_account":"root","logon_type":"NETWORK","result":"SUCCESS","new_authentication":"false","service":"/usr/sbin/sshd","source_json":{"audit_id":914725,"pid":23992,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"PAM:authentication","grantors":"pam_unix","acct":"root","hostname":"172.16.100.22","addr":"172.16.100.22","terminal":"ssh","res":"success","type":1100,"startTime":1605541569420,"cmdLine":"sshd: root [priv]   ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"processUUID":"cc0a6c4f86c0e1695022c8f3c56de41c6eea5becfe91f1891749c585ff493ee1","hashes":{"md5":"686cd72b4339da33bfb6fe8fb94a301f","sha1":"0205dc86c73109c380f97b4481cad911b98df5cd","sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"root","gidName":"root"},"euid":0,"egid":0,"uidName":null,"euidName":"root","egidName":"root","auidName":null,"domain":"qmasters.co"}} | 1605541580470 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-16T15:46:17.123Z","destination_asset":"jenkinsnode.qmasters.co","source_asset_address":"172.16.100.22","destination_asset_address":"jenkinsnode.qmasters.co","destination_local_account":"root","logon_type":"NETWORK","result":"FAILED_OTHER","new_authentication":"false","service":"/usr/sbin/sshd","source_json":{"audit_id":914407,"pid":23992,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"password","acct":"root","addr":"172.16.100.22","terminal":"ssh","res":"failed","type":1100,"startTime":1605541569420,"cmdLine":"sshd: root [priv]   ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"processUUID":"cc0a6c4f86c0e1695022c8f3c56de41c6eea5becfe91f1891749c585ff493ee1","hashes":{"md5":"686cd72b4339da33bfb6fe8fb94a301f","sha1":"0205dc86c73109c380f97b4481cad911b98df5cd","sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"root","gidName":"root"},"euid":0,"egid":0,"uidName":null,"euidName":"root","egidName":"root","auidName":null,"domain":"qmasters.co","hostname":"jenkinsnode"}} | 1605541580470 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-16T15:46:18.903Z","destination_asset":"jenkinsnode.qmasters.co","source_asset_address":"172.16.100.22","destination_asset_address":"jenkinsnode.qmasters.co","destination_local_account":"root","logon_type":"NETWORK","result":"SUCCESS","new_authentication":"false","service":"/usr/sbin/sshd","source_json":{"audit_id":914729,"pid":23992,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"success","acct":"root","addr":"172.16.100.22","terminal":"ssh","res":"success","type":1100,"startTime":1605541569420,"cmdLine":"sshd: root [priv]   ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"processUUID":"cc0a6c4f86c0e1695022c8f3c56de41c6eea5becfe91f1891749c585ff493ee1","hashes":{"md5":"686cd72b4339da33bfb6fe8fb94a301f","sha1":"0205dc86c73109c380f97b4481cad911b98df5cd","sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"root","gidName":"root"},"euid":0,"egid":0,"uidName":null,"euidName":"root","egidName":"root","auidName":null,"domain":"qmasters.co","hostname":"jenkinsnode"}} | 1605541580470 |


### rapid7-insight-idr-query-log-set
***
Query inside a log set for certain values.


#### Base Command

`rapid7-insight-idr-query-log-set`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| log_set_id | log set ID | Required | 
| query | A valid LEQL query to run against the log | Required | 
| start_time | Lower bound of the time range you want to query against. Format: UNIX timestamp in milliseconds. Example:1450557004000 | Required | 
| end_time | Upper bound of the time range you want to query against. Format: UNIX timestamp in milliseconds. Example:1460557604000 | Required | 
| logs_per_page | The number of log entries to return per page. Default of 50 | Optional | 
| sequence_number | the earlier sequence number of a log entry to start searching from | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Rapid7InsightIDR.Event.log_id | String | Event message | 
| Rapid7InsightIDR.Event.message | String | ID of the log the event appears in | 
| Rapid7InsightIDR.Event.timestamp | Number | Time when the event fired | 


#### Command Example
```!rapid7-insight-idr-query-log-set log_set_id=74c4af9d-2673-4bc2-b8e8-afe3d1354987 query=where(destination_asset=\"jenkinsnode.qmasters.co\") start_time=0 end_time=3000557004000```

#### Context Example
```json
{
    "Rapid7InsightIDR": {
        "Event": [
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237201778429120512?per_page=50&timestamp=1605102271671&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-11T13:44:21.067Z\",\"destination_asset\":\"jenkinsnode.qmasters.co\",\"source_asset_address\":\"192.168.91.19\",\"destination_asset_address\":\"jenkinsnode.qmasters.co\",\"destination_local_account\":\"root\",\"logon_type\":\"NETWORK\",\"result\":\"SUCCESS\",\"new_authentication\":\"true\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":755448,\"pid\":15620,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"PAM:authentication\",\"grantors\":\"pam_unix\",\"acct\":\"root\",\"hostname\":\"192.168.91.19\",\"addr\":\"192.168.91.19\",\"terminal\":\"ssh\",\"res\":\"success\",\"type\":1100,\"startTime\":1605102231970,\"cmdLine\":\"sshd: root [priv]   \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"5370a21294928c65f4a5cf0990454a75847bfc7eade425c3392dcf7789395058\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"root\",\"gidName\":\"root\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"root\",\"egidName\":\"root\",\"auidName\":null,\"domain\":\"qmasters.co\"}}",
                "sequence_number": 3237201778429120500,
                "sequence_number_str": "3237201778429120512",
                "timestamp": 1605102271671
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237201778429128704?per_page=50&timestamp=1605102271671&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-11T13:43:57.509Z\",\"destination_asset\":\"jenkinsnode.qmasters.co\",\"source_asset_address\":\"192.168.91.19\",\"destination_asset_address\":\"jenkinsnode.qmasters.co\",\"destination_local_account\":\"root\",\"logon_type\":\"NETWORK\",\"result\":\"FAILED_OTHER\",\"new_authentication\":\"true\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":755429,\"pid\":15620,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"PAM:authentication\",\"acct\":\"root\",\"hostname\":\"192.168.91.19\",\"addr\":\"192.168.91.19\",\"terminal\":\"ssh\",\"res\":\"failed\",\"type\":1100,\"startTime\":1605102231970,\"cmdLine\":\"sshd: root [priv]   \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"5370a21294928c65f4a5cf0990454a75847bfc7eade425c3392dcf7789395058\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"root\",\"gidName\":\"root\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"root\",\"egidName\":\"root\",\"auidName\":null,\"domain\":\"qmasters.co\"}}",
                "sequence_number": 3237201778429128700,
                "sequence_number_str": "3237201778429128704",
                "timestamp": 1605102271671
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237201778429132800?per_page=50&timestamp=1605102271671&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-11T13:44:21.554Z\",\"destination_asset\":\"jenkinsnode.qmasters.co\",\"source_asset_address\":\"192.168.91.19\",\"destination_asset_address\":\"jenkinsnode.qmasters.co\",\"destination_local_account\":\"root\",\"logon_type\":\"NETWORK\",\"result\":\"SUCCESS\",\"new_authentication\":\"false\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":755452,\"pid\":15620,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"success\",\"acct\":\"root\",\"addr\":\"192.168.91.19\",\"terminal\":\"ssh\",\"res\":\"success\",\"type\":1100,\"startTime\":1605102231970,\"cmdLine\":\"sshd: root@pts/1    \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"89715ccf32b3f36cc769952cf203bb177ba5ad8d775fc8794d6dd613d371d2f0\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"root\",\"gidName\":\"root\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"root\",\"egidName\":\"root\",\"auidName\":null,\"domain\":\"qmasters.co\",\"hostname\":\"jenkinsnode\"}}",
                "sequence_number": 3237201778429133000,
                "sequence_number_str": "3237201778429132800",
                "timestamp": 1605102271671
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237201778429136896?per_page=50&timestamp=1605102271671&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-11T13:43:59.683Z\",\"destination_asset\":\"jenkinsnode.qmasters.co\",\"source_asset_address\":\"192.168.91.19\",\"destination_asset_address\":\"jenkinsnode.qmasters.co\",\"destination_local_account\":\"root\",\"logon_type\":\"NETWORK\",\"result\":\"FAILED_OTHER\",\"new_authentication\":\"true\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":755430,\"pid\":15620,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"password\",\"acct\":\"root\",\"addr\":\"192.168.91.19\",\"terminal\":\"ssh\",\"res\":\"failed\",\"type\":1100,\"startTime\":1605102231970,\"cmdLine\":\"sshd: root [priv]   \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"5370a21294928c65f4a5cf0990454a75847bfc7eade425c3392dcf7789395058\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"root\",\"gidName\":\"root\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"root\",\"egidName\":\"root\",\"auidName\":null,\"domain\":\"qmasters.co\",\"hostname\":\"jenkinsnode\"}}",
                "sequence_number": 3237201778429137000,
                "sequence_number_str": "3237201778429136896",
                "timestamp": 1605102271671
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237201778429140992?per_page=50&timestamp=1605102271671&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-11T13:44:07.343Z\",\"destination_asset\":\"jenkinsnode.qmasters.co\",\"source_asset_address\":\"192.168.91.19\",\"destination_asset_address\":\"jenkinsnode.qmasters.co\",\"destination_local_account\":\"root\",\"logon_type\":\"NETWORK\",\"result\":\"FAILED_OTHER\",\"new_authentication\":\"true\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":755445,\"pid\":15620,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"PAM:authentication\",\"acct\":\"root\",\"hostname\":\"192.168.91.19\",\"addr\":\"192.168.91.19\",\"terminal\":\"ssh\",\"res\":\"failed\",\"type\":1100,\"startTime\":1605102231970,\"cmdLine\":\"sshd: root [priv]   \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"5370a21294928c65f4a5cf0990454a75847bfc7eade425c3392dcf7789395058\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"root\",\"gidName\":\"root\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"root\",\"egidName\":\"root\",\"auidName\":null,\"domain\":\"qmasters.co\"}}",
                "sequence_number": 3237201778429141000,
                "sequence_number_str": "3237201778429140992",
                "timestamp": 1605102271671
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237201778429145088?per_page=50&timestamp=1605102271671&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-11T13:44:08.986Z\",\"destination_asset\":\"jenkinsnode.qmasters.co\",\"source_asset_address\":\"192.168.91.19\",\"destination_asset_address\":\"jenkinsnode.qmasters.co\",\"destination_local_account\":\"root\",\"logon_type\":\"NETWORK\",\"result\":\"FAILED_OTHER\",\"new_authentication\":\"true\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":755446,\"pid\":15620,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"password\",\"acct\":\"root\",\"addr\":\"192.168.91.19\",\"terminal\":\"ssh\",\"res\":\"failed\",\"type\":1100,\"startTime\":1605102231970,\"cmdLine\":\"sshd: root [priv]   \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"5370a21294928c65f4a5cf0990454a75847bfc7eade425c3392dcf7789395058\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"root\",\"gidName\":\"root\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"root\",\"egidName\":\"root\",\"auidName\":null,\"domain\":\"qmasters.co\",\"hostname\":\"jenkinsnode\"}}",
                "sequence_number": 3237201778429145000,
                "sequence_number_str": "3237201778429145088",
                "timestamp": 1605102271671
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237199644177084416?per_page=50&timestamp=1605535859467&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-16T14:10:36.743Z\",\"destination_asset\":\"jenkinsnode.qmasters.co\",\"source_asset_address\":\"192.168.91.19\",\"destination_asset_address\":\"jenkinsnode.qmasters.co\",\"destination_local_account\":\"root\",\"logon_type\":\"NETWORK\",\"result\":\"SUCCESS\",\"new_authentication\":\"false\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":853390,\"pid\":3243,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"PAM:authentication\",\"grantors\":\"pam_unix\",\"acct\":\"root\",\"hostname\":\"192.168.91.19\",\"addr\":\"192.168.91.19\",\"terminal\":\"ssh\",\"res\":\"success\",\"type\":1100,\"startTime\":1605535824080,\"cmdLine\":\"sshd: root [priv]   \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"d8328060d3e0d52ba552390f7c03ba235d6e18fe63ac996b01b8565ff93f32de\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"root\",\"gidName\":\"root\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"root\",\"egidName\":\"root\",\"auidName\":null,\"domain\":\"qmasters.co\"}}",
                "sequence_number": 3237199644177084400,
                "sequence_number_str": "3237199644177084416",
                "timestamp": 1605535859467
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237199644177088512?per_page=50&timestamp=1605535859467&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-16T14:10:31.194Z\",\"destination_asset\":\"jenkinsnode.qmasters.co\",\"source_asset_address\":\"192.168.91.19\",\"destination_asset_address\":\"jenkinsnode.qmasters.co\",\"destination_local_account\":\"root\",\"logon_type\":\"NETWORK\",\"result\":\"FAILED_OTHER\",\"new_authentication\":\"false\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":853387,\"pid\":3243,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"PAM:authentication\",\"acct\":\"root\",\"hostname\":\"192.168.91.19\",\"addr\":\"192.168.91.19\",\"terminal\":\"ssh\",\"res\":\"failed\",\"type\":1100,\"startTime\":1605535824080,\"cmdLine\":\"sshd: root [priv]   \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"d8328060d3e0d52ba552390f7c03ba235d6e18fe63ac996b01b8565ff93f32de\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"root\",\"gidName\":\"root\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"root\",\"egidName\":\"root\",\"auidName\":null,\"domain\":\"qmasters.co\"}}",
                "sequence_number": 3237199644177088500,
                "sequence_number_str": "3237199644177088512",
                "timestamp": 1605535859467
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237199644177092608?per_page=50&timestamp=1605535859467&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-16T14:10:39.212Z\",\"destination_asset\":\"jenkinsnode.qmasters.co\",\"source_asset_address\":\"192.168.91.19\",\"destination_asset_address\":\"jenkinsnode.qmasters.co\",\"destination_local_account\":\"root\",\"logon_type\":\"NETWORK\",\"result\":\"SUCCESS\",\"new_authentication\":\"false\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":853394,\"pid\":3243,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"success\",\"acct\":\"root\",\"addr\":\"192.168.91.19\",\"terminal\":\"ssh\",\"res\":\"success\",\"type\":1100,\"startTime\":1605535824080,\"cmdLine\":\"sshd: root@pts/1    \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"fe326b6ee65a983946f2847f66f735ba41d20d096a13ea9fa7f8341ad5e7da61\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"root\",\"gidName\":\"root\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"root\",\"egidName\":\"root\",\"auidName\":null,\"domain\":\"qmasters.co\",\"hostname\":\"jenkinsnode\"}}",
                "sequence_number": 3237199644177092600,
                "sequence_number_str": "3237199644177092608",
                "timestamp": 1605535859467
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237199644177096704?per_page=50&timestamp=1605535859467&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-16T14:10:31.872Z\",\"destination_asset\":\"jenkinsnode.qmasters.co\",\"source_asset_address\":\"192.168.91.19\",\"destination_asset_address\":\"jenkinsnode.qmasters.co\",\"destination_local_account\":\"root\",\"logon_type\":\"NETWORK\",\"result\":\"FAILED_OTHER\",\"new_authentication\":\"false\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":853388,\"pid\":3243,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"password\",\"acct\":\"root\",\"addr\":\"192.168.91.19\",\"terminal\":\"ssh\",\"res\":\"failed\",\"type\":1100,\"startTime\":1605535824080,\"cmdLine\":\"sshd: root [priv]   \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"d8328060d3e0d52ba552390f7c03ba235d6e18fe63ac996b01b8565ff93f32de\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"root\",\"gidName\":\"root\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"root\",\"egidName\":\"root\",\"auidName\":null,\"domain\":\"qmasters.co\",\"hostname\":\"jenkinsnode\"}}",
                "sequence_number": 3237199644177096700,
                "sequence_number_str": "3237199644177096704",
                "timestamp": 1605535859467
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237134439879106560?per_page=50&timestamp=1605536181913&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-16T14:15:36.401Z\",\"destination_asset\":\"jenkinsnode.qmasters.co\",\"source_asset_address\":\"192.168.91.19\",\"destination_asset_address\":\"jenkinsnode.qmasters.co\",\"destination_local_account\":\"root\",\"logon_type\":\"NETWORK\",\"result\":\"SUCCESS\",\"new_authentication\":\"false\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":853508,\"pid\":3656,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"PAM:authentication\",\"grantors\":\"pam_unix\",\"acct\":\"root\",\"hostname\":\"192.168.91.19\",\"addr\":\"192.168.91.19\",\"terminal\":\"ssh\",\"res\":\"success\",\"type\":1100,\"startTime\":1605536135850,\"cmdLine\":\"sshd: root [priv]   \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"97c6f7ba4f67c2c7b2b8d566dc9a01d79f3a5b5ff28078cb649c1726241a90ad\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"root\",\"gidName\":\"root\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"root\",\"egidName\":\"root\",\"auidName\":null,\"domain\":\"qmasters.co\"}}",
                "sequence_number": 3237134439879106600,
                "sequence_number_str": "3237134439879106560",
                "timestamp": 1605536181913
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237134439879110656?per_page=50&timestamp=1605536181913&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-16T14:15:36.406Z\",\"destination_asset\":\"jenkinsnode.qmasters.co\",\"source_asset_address\":\"192.168.91.19\",\"destination_asset_address\":\"jenkinsnode.qmasters.co\",\"destination_local_account\":\"root\",\"logon_type\":\"NETWORK\",\"result\":\"SUCCESS\",\"new_authentication\":\"false\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":853512,\"pid\":3656,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"success\",\"acct\":\"root\",\"addr\":\"192.168.91.19\",\"terminal\":\"ssh\",\"res\":\"success\",\"type\":1100,\"startTime\":1605536135850,\"cmdLine\":\"sshd: root [priv]   \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"97c6f7ba4f67c2c7b2b8d566dc9a01d79f3a5b5ff28078cb649c1726241a90ad\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"root\",\"gidName\":\"root\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"root\",\"egidName\":\"root\",\"auidName\":null,\"domain\":\"qmasters.co\",\"hostname\":\"jenkinsnode\"}}",
                "sequence_number": 3237134439879110700,
                "sequence_number_str": "3237134439879110656",
                "timestamp": 1605536181913
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237127759570530304?per_page=50&timestamp=1605540767722&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-16T15:31:59.538Z\",\"destination_asset\":\"jenkinsnode.qmasters.co\",\"source_asset_address\":\"172.16.100.22\",\"destination_asset_address\":\"jenkinsnode.qmasters.co\",\"destination_local_account\":\"root\",\"logon_type\":\"NETWORK\",\"result\":\"FAILED_OTHER\",\"new_authentication\":\"false\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":854639,\"pid\":8343,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"PAM:authentication\",\"acct\":\"root\",\"hostname\":\"172.16.100.22\",\"addr\":\"172.16.100.22\",\"terminal\":\"ssh\",\"res\":\"failed\",\"type\":1100,\"startTime\":1605540715180,\"cmdLine\":\"sshd: root [priv]   \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"a710f00b6754f1553797cab5829410e227c60f12f3c6b46511f7a3fc5e0f5cf6\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"root\",\"gidName\":\"root\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"root\",\"egidName\":\"root\",\"auidName\":null,\"domain\":\"qmasters.co\"}}",
                "sequence_number": 3237127759570530300,
                "sequence_number_str": "3237127759570530304",
                "timestamp": 1605540767722
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237127759570534400?per_page=50&timestamp=1605540767722&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-16T15:32:04.843Z\",\"destination_asset\":\"jenkinsnode.qmasters.co\",\"source_asset_address\":\"172.16.100.22\",\"destination_asset_address\":\"jenkinsnode.qmasters.co\",\"destination_local_account\":\"root\",\"logon_type\":\"NETWORK\",\"result\":\"SUCCESS\",\"new_authentication\":\"false\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":854655,\"pid\":8343,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"PAM:authentication\",\"grantors\":\"pam_unix\",\"acct\":\"root\",\"hostname\":\"172.16.100.22\",\"addr\":\"172.16.100.22\",\"terminal\":\"ssh\",\"res\":\"success\",\"type\":1100,\"startTime\":1605540715180,\"cmdLine\":\"sshd: root [priv]   \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"a710f00b6754f1553797cab5829410e227c60f12f3c6b46511f7a3fc5e0f5cf6\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"root\",\"gidName\":\"root\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"root\",\"egidName\":\"root\",\"auidName\":null,\"domain\":\"qmasters.co\"}}",
                "sequence_number": 3237127759570534400,
                "sequence_number_str": "3237127759570534400",
                "timestamp": 1605540767722
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237127759570538496?per_page=50&timestamp=1605540767722&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-16T15:31:59.841Z\",\"destination_asset\":\"jenkinsnode.qmasters.co\",\"source_asset_address\":\"172.16.100.22\",\"destination_asset_address\":\"jenkinsnode.qmasters.co\",\"destination_local_account\":\"root\",\"logon_type\":\"NETWORK\",\"result\":\"FAILED_OTHER\",\"new_authentication\":\"false\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":854640,\"pid\":8343,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"password\",\"acct\":\"root\",\"addr\":\"172.16.100.22\",\"terminal\":\"ssh\",\"res\":\"failed\",\"type\":1100,\"startTime\":1605540715180,\"cmdLine\":\"sshd: root [priv]   \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"a710f00b6754f1553797cab5829410e227c60f12f3c6b46511f7a3fc5e0f5cf6\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"root\",\"gidName\":\"root\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"root\",\"egidName\":\"root\",\"auidName\":null,\"domain\":\"qmasters.co\",\"hostname\":\"jenkinsnode\"}}",
                "sequence_number": 3237127759570538500,
                "sequence_number_str": "3237127759570538496",
                "timestamp": 1605540767722
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237127759570542592?per_page=50&timestamp=1605540767722&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-16T15:32:07.557Z\",\"destination_asset\":\"jenkinsnode.qmasters.co\",\"source_asset_address\":\"172.16.100.22\",\"destination_asset_address\":\"jenkinsnode.qmasters.co\",\"destination_local_account\":\"root\",\"logon_type\":\"NETWORK\",\"result\":\"SUCCESS\",\"new_authentication\":\"false\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":854659,\"pid\":8343,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"success\",\"acct\":\"root\",\"addr\":\"172.16.100.22\",\"terminal\":\"ssh\",\"res\":\"success\",\"type\":1100,\"startTime\":1605540715180,\"cmdLine\":\"sshd: root@pts/2    \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"ddd669c2a201339a549a5d9bab79c8a61dfd6ff2b4b0ed846fa9798f5bf2cc9c\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"root\",\"gidName\":\"root\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"root\",\"egidName\":\"root\",\"auidName\":null,\"domain\":\"qmasters.co\",\"hostname\":\"jenkinsnode\"}}",
                "sequence_number": 3237127759570542600,
                "sequence_number_str": "3237127759570542592",
                "timestamp": 1605540767722
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237202737554612224?per_page=50&timestamp=1605541577601&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-16T15:46:13.083Z\",\"destination_asset\":\"jenkinsnode.qmasters.co\",\"source_asset_address\":\"172.16.100.22\",\"destination_asset_address\":\"jenkinsnode.qmasters.co\",\"destination_local_account\":\"root\",\"logon_type\":\"NETWORK\",\"result\":\"FAILED_OTHER\",\"new_authentication\":\"false\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":914355,\"pid\":23992,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"PAM:authentication\",\"acct\":\"root\",\"hostname\":\"172.16.100.22\",\"addr\":\"172.16.100.22\",\"terminal\":\"ssh\",\"res\":\"failed\",\"type\":1100,\"startTime\":1605541569420,\"cmdLine\":\"sshd: root [priv]   \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"cc0a6c4f86c0e1695022c8f3c56de41c6eea5becfe91f1891749c585ff493ee1\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"root\",\"gidName\":\"root\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"root\",\"egidName\":\"root\",\"auidName\":null,\"domain\":\"qmasters.co\"}}",
                "sequence_number": 3237202737554612000,
                "sequence_number_str": "3237202737554612224",
                "timestamp": 1605541577601
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237202737554616320?per_page=50&timestamp=1605541580470&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-16T15:46:18.886Z\",\"destination_asset\":\"jenkinsnode.qmasters.co\",\"source_asset_address\":\"172.16.100.22\",\"destination_asset_address\":\"jenkinsnode.qmasters.co\",\"destination_local_account\":\"root\",\"logon_type\":\"NETWORK\",\"result\":\"SUCCESS\",\"new_authentication\":\"false\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":914725,\"pid\":23992,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"PAM:authentication\",\"grantors\":\"pam_unix\",\"acct\":\"root\",\"hostname\":\"172.16.100.22\",\"addr\":\"172.16.100.22\",\"terminal\":\"ssh\",\"res\":\"success\",\"type\":1100,\"startTime\":1605541569420,\"cmdLine\":\"sshd: root [priv]   \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"cc0a6c4f86c0e1695022c8f3c56de41c6eea5becfe91f1891749c585ff493ee1\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"root\",\"gidName\":\"root\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"root\",\"egidName\":\"root\",\"auidName\":null,\"domain\":\"qmasters.co\"}}",
                "sequence_number": 3237202737554616300,
                "sequence_number_str": "3237202737554616320",
                "timestamp": 1605541580470
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237202737554620416?per_page=50&timestamp=1605541580470&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-16T15:46:17.123Z\",\"destination_asset\":\"jenkinsnode.qmasters.co\",\"source_asset_address\":\"172.16.100.22\",\"destination_asset_address\":\"jenkinsnode.qmasters.co\",\"destination_local_account\":\"root\",\"logon_type\":\"NETWORK\",\"result\":\"FAILED_OTHER\",\"new_authentication\":\"false\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":914407,\"pid\":23992,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"password\",\"acct\":\"root\",\"addr\":\"172.16.100.22\",\"terminal\":\"ssh\",\"res\":\"failed\",\"type\":1100,\"startTime\":1605541569420,\"cmdLine\":\"sshd: root [priv]   \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"cc0a6c4f86c0e1695022c8f3c56de41c6eea5becfe91f1891749c585ff493ee1\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"root\",\"gidName\":\"root\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"root\",\"egidName\":\"root\",\"auidName\":null,\"domain\":\"qmasters.co\",\"hostname\":\"jenkinsnode\"}}",
                "sequence_number": 3237202737554620400,
                "sequence_number_str": "3237202737554620416",
                "timestamp": 1605541580470
            },
            {
                "labels": [],
                "links": [
                    {
                        "href": "https://us.api.insight.rapid7.com/log_search/query/context/3237202737554624512?per_page=50&timestamp=1605541580470&log_keys=ab5a7594-5fde-4c5c-9ee6-e67291f0a40c&context_type=SURROUND",
                        "rel": "Context"
                    }
                ],
                "log_id": "ab5a7594-5fde-4c5c-9ee6-e67291f0a40c",
                "message": "{\"timestamp\":\"2020-11-16T15:46:18.903Z\",\"destination_asset\":\"jenkinsnode.qmasters.co\",\"source_asset_address\":\"172.16.100.22\",\"destination_asset_address\":\"jenkinsnode.qmasters.co\",\"destination_local_account\":\"root\",\"logon_type\":\"NETWORK\",\"result\":\"SUCCESS\",\"new_authentication\":\"false\",\"service\":\"/usr/sbin/sshd\",\"source_json\":{\"audit_id\":914729,\"pid\":23992,\"uid\":null,\"auid\":4294967295,\"ses\":4294967295,\"subj\":\"system_u:system_r:sshd_t:s0-s0:c0.c1023\",\"op\":\"success\",\"acct\":\"root\",\"addr\":\"172.16.100.22\",\"terminal\":\"ssh\",\"res\":\"success\",\"type\":1100,\"startTime\":1605541569420,\"cmdLine\":\"sshd: root [priv]   \",\"processName\":\"sshd\",\"executablePath\":\"/usr/sbin/sshd\",\"ppid\":1131,\"processUUID\":\"cc0a6c4f86c0e1695022c8f3c56de41c6eea5becfe91f1891749c585ff493ee1\",\"hashes\":{\"md5\":\"686cd72b4339da33bfb6fe8fb94a301f\",\"sha1\":\"0205dc86c73109c380f97b4481cad911b98df5cd\",\"sha256\":\"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68\"},\"metadata\":{\"creationDate\":1592052866191,\"lastModifiedDate\":1565314847000,\"lastAccessDate\":1605098588968,\"size\":852856,\"permissions\":\"-rwxr-xr-x\",\"uid\":0,\"gid\":0,\"uidName\":\"root\",\"gidName\":\"root\"},\"euid\":0,\"egid\":0,\"uidName\":null,\"euidName\":\"root\",\"egidName\":\"root\",\"auidName\":null,\"domain\":\"qmasters.co\",\"hostname\":\"jenkinsnode\"}}",
                "sequence_number": 3237202737554624500,
                "sequence_number_str": "3237202737554624512",
                "timestamp": 1605541580470
            }
        ]
    }
}
```

#### Human Readable Output

>### Query Results
>|log_id|message|timestamp|
>|---|---|---|
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-11T13:44:21.067Z","destination_asset":"jenkinsnode.qmasters.co","source_asset_address":"192.168.91.19","destination_asset_address":"jenkinsnode.qmasters.co","destination_local_account":"root","logon_type":"NETWORK","result":"SUCCESS","new_authentication":"true","service":"/usr/sbin/sshd","source_json":{"audit_id":755448,"pid":15620,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"PAM:authentication","grantors":"pam_unix","acct":"root","hostname":"192.168.91.19","addr":"192.168.91.19","terminal":"ssh","res":"success","type":1100,"startTime":1605102231970,"cmdLine":"sshd: root [priv]   ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"processUUID":"5370a21294928c65f4a5cf0990454a75847bfc7eade425c3392dcf7789395058","hashes":{"md5":"686cd72b4339da33bfb6fe8fb94a301f","sha1":"0205dc86c73109c380f97b4481cad911b98df5cd","sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"root","gidName":"root"},"euid":0,"egid":0,"uidName":null,"euidName":"root","egidName":"root","auidName":null,"domain":"qmasters.co"}} | 1605102271671 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-11T13:43:57.509Z","destination_asset":"jenkinsnode.qmasters.co","source_asset_address":"192.168.91.19","destination_asset_address":"jenkinsnode.qmasters.co","destination_local_account":"root","logon_type":"NETWORK","result":"FAILED_OTHER","new_authentication":"true","service":"/usr/sbin/sshd","source_json":{"audit_id":755429,"pid":15620,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"PAM:authentication","acct":"root","hostname":"192.168.91.19","addr":"192.168.91.19","terminal":"ssh","res":"failed","type":1100,"startTime":1605102231970,"cmdLine":"sshd: root [priv]   ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"processUUID":"5370a21294928c65f4a5cf0990454a75847bfc7eade425c3392dcf7789395058","hashes":{"md5":"686cd72b4339da33bfb6fe8fb94a301f","sha1":"0205dc86c73109c380f97b4481cad911b98df5cd","sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"root","gidName":"root"},"euid":0,"egid":0,"uidName":null,"euidName":"root","egidName":"root","auidName":null,"domain":"qmasters.co"}} | 1605102271671 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-11T13:44:21.554Z","destination_asset":"jenkinsnode.qmasters.co","source_asset_address":"192.168.91.19","destination_asset_address":"jenkinsnode.qmasters.co","destination_local_account":"root","logon_type":"NETWORK","result":"SUCCESS","new_authentication":"false","service":"/usr/sbin/sshd","source_json":{"audit_id":755452,"pid":15620,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"success","acct":"root","addr":"192.168.91.19","terminal":"ssh","res":"success","type":1100,"startTime":1605102231970,"cmdLine":"sshd: root@pts/1    ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"processUUID":"89715ccf32b3f36cc769952cf203bb177ba5ad8d775fc8794d6dd613d371d2f0","hashes":{"md5":"686cd72b4339da33bfb6fe8fb94a301f","sha1":"0205dc86c73109c380f97b4481cad911b98df5cd","sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"root","gidName":"root"},"euid":0,"egid":0,"uidName":null,"euidName":"root","egidName":"root","auidName":null,"domain":"qmasters.co","hostname":"jenkinsnode"}} | 1605102271671 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-11T13:43:59.683Z","destination_asset":"jenkinsnode.qmasters.co","source_asset_address":"192.168.91.19","destination_asset_address":"jenkinsnode.qmasters.co","destination_local_account":"root","logon_type":"NETWORK","result":"FAILED_OTHER","new_authentication":"true","service":"/usr/sbin/sshd","source_json":{"audit_id":755430,"pid":15620,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"password","acct":"root","addr":"192.168.91.19","terminal":"ssh","res":"failed","type":1100,"startTime":1605102231970,"cmdLine":"sshd: root [priv]   ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"processUUID":"5370a21294928c65f4a5cf0990454a75847bfc7eade425c3392dcf7789395058","hashes":{"md5":"686cd72b4339da33bfb6fe8fb94a301f","sha1":"0205dc86c73109c380f97b4481cad911b98df5cd","sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"root","gidName":"root"},"euid":0,"egid":0,"uidName":null,"euidName":"root","egidName":"root","auidName":null,"domain":"qmasters.co","hostname":"jenkinsnode"}} | 1605102271671 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-11T13:44:07.343Z","destination_asset":"jenkinsnode.qmasters.co","source_asset_address":"192.168.91.19","destination_asset_address":"jenkinsnode.qmasters.co","destination_local_account":"root","logon_type":"NETWORK","result":"FAILED_OTHER","new_authentication":"true","service":"/usr/sbin/sshd","source_json":{"audit_id":755445,"pid":15620,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"PAM:authentication","acct":"root","hostname":"192.168.91.19","addr":"192.168.91.19","terminal":"ssh","res":"failed","type":1100,"startTime":1605102231970,"cmdLine":"sshd: root [priv]   ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"processUUID":"5370a21294928c65f4a5cf0990454a75847bfc7eade425c3392dcf7789395058","hashes":{"md5":"686cd72b4339da33bfb6fe8fb94a301f","sha1":"0205dc86c73109c380f97b4481cad911b98df5cd","sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"root","gidName":"root"},"euid":0,"egid":0,"uidName":null,"euidName":"root","egidName":"root","auidName":null,"domain":"qmasters.co"}} | 1605102271671 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-11T13:44:08.986Z","destination_asset":"jenkinsnode.qmasters.co","source_asset_address":"192.168.91.19","destination_asset_address":"jenkinsnode.qmasters.co","destination_local_account":"root","logon_type":"NETWORK","result":"FAILED_OTHER","new_authentication":"true","service":"/usr/sbin/sshd","source_json":{"audit_id":755446,"pid":15620,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"password","acct":"root","addr":"192.168.91.19","terminal":"ssh","res":"failed","type":1100,"startTime":1605102231970,"cmdLine":"sshd: root [priv]   ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"processUUID":"5370a21294928c65f4a5cf0990454a75847bfc7eade425c3392dcf7789395058","hashes":{"md5":"686cd72b4339da33bfb6fe8fb94a301f","sha1":"0205dc86c73109c380f97b4481cad911b98df5cd","sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"root","gidName":"root"},"euid":0,"egid":0,"uidName":null,"euidName":"root","egidName":"root","auidName":null,"domain":"qmasters.co","hostname":"jenkinsnode"}} | 1605102271671 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-16T14:10:36.743Z","destination_asset":"jenkinsnode.qmasters.co","source_asset_address":"192.168.91.19","destination_asset_address":"jenkinsnode.qmasters.co","destination_local_account":"root","logon_type":"NETWORK","result":"SUCCESS","new_authentication":"false","service":"/usr/sbin/sshd","source_json":{"audit_id":853390,"pid":3243,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"PAM:authentication","grantors":"pam_unix","acct":"root","hostname":"192.168.91.19","addr":"192.168.91.19","terminal":"ssh","res":"success","type":1100,"startTime":1605535824080,"cmdLine":"sshd: root [priv]   ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"processUUID":"d8328060d3e0d52ba552390f7c03ba235d6e18fe63ac996b01b8565ff93f32de","hashes":{"md5":"686cd72b4339da33bfb6fe8fb94a301f","sha1":"0205dc86c73109c380f97b4481cad911b98df5cd","sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"root","gidName":"root"},"euid":0,"egid":0,"uidName":null,"euidName":"root","egidName":"root","auidName":null,"domain":"qmasters.co"}} | 1605535859467 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-16T14:10:31.194Z","destination_asset":"jenkinsnode.qmasters.co","source_asset_address":"192.168.91.19","destination_asset_address":"jenkinsnode.qmasters.co","destination_local_account":"root","logon_type":"NETWORK","result":"FAILED_OTHER","new_authentication":"false","service":"/usr/sbin/sshd","source_json":{"audit_id":853387,"pid":3243,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"PAM:authentication","acct":"root","hostname":"192.168.91.19","addr":"192.168.91.19","terminal":"ssh","res":"failed","type":1100,"startTime":1605535824080,"cmdLine":"sshd: root [priv]   ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"processUUID":"d8328060d3e0d52ba552390f7c03ba235d6e18fe63ac996b01b8565ff93f32de","hashes":{"md5":"686cd72b4339da33bfb6fe8fb94a301f","sha1":"0205dc86c73109c380f97b4481cad911b98df5cd","sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"root","gidName":"root"},"euid":0,"egid":0,"uidName":null,"euidName":"root","egidName":"root","auidName":null,"domain":"qmasters.co"}} | 1605535859467 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-16T14:10:39.212Z","destination_asset":"jenkinsnode.qmasters.co","source_asset_address":"192.168.91.19","destination_asset_address":"jenkinsnode.qmasters.co","destination_local_account":"root","logon_type":"NETWORK","result":"SUCCESS","new_authentication":"false","service":"/usr/sbin/sshd","source_json":{"audit_id":853394,"pid":3243,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"success","acct":"root","addr":"192.168.91.19","terminal":"ssh","res":"success","type":1100,"startTime":1605535824080,"cmdLine":"sshd: root@pts/1    ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"processUUID":"fe326b6ee65a983946f2847f66f735ba41d20d096a13ea9fa7f8341ad5e7da61","hashes":{"md5":"686cd72b4339da33bfb6fe8fb94a301f","sha1":"0205dc86c73109c380f97b4481cad911b98df5cd","sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"root","gidName":"root"},"euid":0,"egid":0,"uidName":null,"euidName":"root","egidName":"root","auidName":null,"domain":"qmasters.co","hostname":"jenkinsnode"}} | 1605535859467 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-16T14:10:31.872Z","destination_asset":"jenkinsnode.qmasters.co","source_asset_address":"192.168.91.19","destination_asset_address":"jenkinsnode.qmasters.co","destination_local_account":"root","logon_type":"NETWORK","result":"FAILED_OTHER","new_authentication":"false","service":"/usr/sbin/sshd","source_json":{"audit_id":853388,"pid":3243,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"password","acct":"root","addr":"192.168.91.19","terminal":"ssh","res":"failed","type":1100,"startTime":1605535824080,"cmdLine":"sshd: root [priv]   ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"processUUID":"d8328060d3e0d52ba552390f7c03ba235d6e18fe63ac996b01b8565ff93f32de","hashes":{"md5":"686cd72b4339da33bfb6fe8fb94a301f","sha1":"0205dc86c73109c380f97b4481cad911b98df5cd","sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"root","gidName":"root"},"euid":0,"egid":0,"uidName":null,"euidName":"root","egidName":"root","auidName":null,"domain":"qmasters.co","hostname":"jenkinsnode"}} | 1605535859467 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-16T14:15:36.401Z","destination_asset":"jenkinsnode.qmasters.co","source_asset_address":"192.168.91.19","destination_asset_address":"jenkinsnode.qmasters.co","destination_local_account":"root","logon_type":"NETWORK","result":"SUCCESS","new_authentication":"false","service":"/usr/sbin/sshd","source_json":{"audit_id":853508,"pid":3656,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"PAM:authentication","grantors":"pam_unix","acct":"root","hostname":"192.168.91.19","addr":"192.168.91.19","terminal":"ssh","res":"success","type":1100,"startTime":1605536135850,"cmdLine":"sshd: root [priv]   ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"processUUID":"97c6f7ba4f67c2c7b2b8d566dc9a01d79f3a5b5ff28078cb649c1726241a90ad","hashes":{"md5":"686cd72b4339da33bfb6fe8fb94a301f","sha1":"0205dc86c73109c380f97b4481cad911b98df5cd","sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"root","gidName":"root"},"euid":0,"egid":0,"uidName":null,"euidName":"root","egidName":"root","auidName":null,"domain":"qmasters.co"}} | 1605536181913 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-16T14:15:36.406Z","destination_asset":"jenkinsnode.qmasters.co","source_asset_address":"192.168.91.19","destination_asset_address":"jenkinsnode.qmasters.co","destination_local_account":"root","logon_type":"NETWORK","result":"SUCCESS","new_authentication":"false","service":"/usr/sbin/sshd","source_json":{"audit_id":853512,"pid":3656,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"success","acct":"root","addr":"192.168.91.19","terminal":"ssh","res":"success","type":1100,"startTime":1605536135850,"cmdLine":"sshd: root [priv]   ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"processUUID":"97c6f7ba4f67c2c7b2b8d566dc9a01d79f3a5b5ff28078cb649c1726241a90ad","hashes":{"md5":"686cd72b4339da33bfb6fe8fb94a301f","sha1":"0205dc86c73109c380f97b4481cad911b98df5cd","sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"root","gidName":"root"},"euid":0,"egid":0,"uidName":null,"euidName":"root","egidName":"root","auidName":null,"domain":"qmasters.co","hostname":"jenkinsnode"}} | 1605536181913 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-16T15:31:59.538Z","destination_asset":"jenkinsnode.qmasters.co","source_asset_address":"172.16.100.22","destination_asset_address":"jenkinsnode.qmasters.co","destination_local_account":"root","logon_type":"NETWORK","result":"FAILED_OTHER","new_authentication":"false","service":"/usr/sbin/sshd","source_json":{"audit_id":854639,"pid":8343,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"PAM:authentication","acct":"root","hostname":"172.16.100.22","addr":"172.16.100.22","terminal":"ssh","res":"failed","type":1100,"startTime":1605540715180,"cmdLine":"sshd: root [priv]   ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"processUUID":"a710f00b6754f1553797cab5829410e227c60f12f3c6b46511f7a3fc5e0f5cf6","hashes":{"md5":"686cd72b4339da33bfb6fe8fb94a301f","sha1":"0205dc86c73109c380f97b4481cad911b98df5cd","sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"root","gidName":"root"},"euid":0,"egid":0,"uidName":null,"euidName":"root","egidName":"root","auidName":null,"domain":"qmasters.co"}} | 1605540767722 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-16T15:32:04.843Z","destination_asset":"jenkinsnode.qmasters.co","source_asset_address":"172.16.100.22","destination_asset_address":"jenkinsnode.qmasters.co","destination_local_account":"root","logon_type":"NETWORK","result":"SUCCESS","new_authentication":"false","service":"/usr/sbin/sshd","source_json":{"audit_id":854655,"pid":8343,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"PAM:authentication","grantors":"pam_unix","acct":"root","hostname":"172.16.100.22","addr":"172.16.100.22","terminal":"ssh","res":"success","type":1100,"startTime":1605540715180,"cmdLine":"sshd: root [priv]   ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"processUUID":"a710f00b6754f1553797cab5829410e227c60f12f3c6b46511f7a3fc5e0f5cf6","hashes":{"md5":"686cd72b4339da33bfb6fe8fb94a301f","sha1":"0205dc86c73109c380f97b4481cad911b98df5cd","sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"root","gidName":"root"},"euid":0,"egid":0,"uidName":null,"euidName":"root","egidName":"root","auidName":null,"domain":"qmasters.co"}} | 1605540767722 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-16T15:31:59.841Z","destination_asset":"jenkinsnode.qmasters.co","source_asset_address":"172.16.100.22","destination_asset_address":"jenkinsnode.qmasters.co","destination_local_account":"root","logon_type":"NETWORK","result":"FAILED_OTHER","new_authentication":"false","service":"/usr/sbin/sshd","source_json":{"audit_id":854640,"pid":8343,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"password","acct":"root","addr":"172.16.100.22","terminal":"ssh","res":"failed","type":1100,"startTime":1605540715180,"cmdLine":"sshd: root [priv]   ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"processUUID":"a710f00b6754f1553797cab5829410e227c60f12f3c6b46511f7a3fc5e0f5cf6","hashes":{"md5":"686cd72b4339da33bfb6fe8fb94a301f","sha1":"0205dc86c73109c380f97b4481cad911b98df5cd","sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"root","gidName":"root"},"euid":0,"egid":0,"uidName":null,"euidName":"root","egidName":"root","auidName":null,"domain":"qmasters.co","hostname":"jenkinsnode"}} | 1605540767722 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-16T15:32:07.557Z","destination_asset":"jenkinsnode.qmasters.co","source_asset_address":"172.16.100.22","destination_asset_address":"jenkinsnode.qmasters.co","destination_local_account":"root","logon_type":"NETWORK","result":"SUCCESS","new_authentication":"false","service":"/usr/sbin/sshd","source_json":{"audit_id":854659,"pid":8343,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"success","acct":"root","addr":"172.16.100.22","terminal":"ssh","res":"success","type":1100,"startTime":1605540715180,"cmdLine":"sshd: root@pts/2    ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"processUUID":"ddd669c2a201339a549a5d9bab79c8a61dfd6ff2b4b0ed846fa9798f5bf2cc9c","hashes":{"md5":"686cd72b4339da33bfb6fe8fb94a301f","sha1":"0205dc86c73109c380f97b4481cad911b98df5cd","sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"root","gidName":"root"},"euid":0,"egid":0,"uidName":null,"euidName":"root","egidName":"root","auidName":null,"domain":"qmasters.co","hostname":"jenkinsnode"}} | 1605540767722 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-16T15:46:13.083Z","destination_asset":"jenkinsnode.qmasters.co","source_asset_address":"172.16.100.22","destination_asset_address":"jenkinsnode.qmasters.co","destination_local_account":"root","logon_type":"NETWORK","result":"FAILED_OTHER","new_authentication":"false","service":"/usr/sbin/sshd","source_json":{"audit_id":914355,"pid":23992,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"PAM:authentication","acct":"root","hostname":"172.16.100.22","addr":"172.16.100.22","terminal":"ssh","res":"failed","type":1100,"startTime":1605541569420,"cmdLine":"sshd: root [priv]   ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"processUUID":"cc0a6c4f86c0e1695022c8f3c56de41c6eea5becfe91f1891749c585ff493ee1","hashes":{"md5":"686cd72b4339da33bfb6fe8fb94a301f","sha1":"0205dc86c73109c380f97b4481cad911b98df5cd","sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"root","gidName":"root"},"euid":0,"egid":0,"uidName":null,"euidName":"root","egidName":"root","auidName":null,"domain":"qmasters.co"}} | 1605541577601 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-16T15:46:18.886Z","destination_asset":"jenkinsnode.qmasters.co","source_asset_address":"172.16.100.22","destination_asset_address":"jenkinsnode.qmasters.co","destination_local_account":"root","logon_type":"NETWORK","result":"SUCCESS","new_authentication":"false","service":"/usr/sbin/sshd","source_json":{"audit_id":914725,"pid":23992,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"PAM:authentication","grantors":"pam_unix","acct":"root","hostname":"172.16.100.22","addr":"172.16.100.22","terminal":"ssh","res":"success","type":1100,"startTime":1605541569420,"cmdLine":"sshd: root [priv]   ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"processUUID":"cc0a6c4f86c0e1695022c8f3c56de41c6eea5becfe91f1891749c585ff493ee1","hashes":{"md5":"686cd72b4339da33bfb6fe8fb94a301f","sha1":"0205dc86c73109c380f97b4481cad911b98df5cd","sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"root","gidName":"root"},"euid":0,"egid":0,"uidName":null,"euidName":"root","egidName":"root","auidName":null,"domain":"qmasters.co"}} | 1605541580470 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-16T15:46:17.123Z","destination_asset":"jenkinsnode.qmasters.co","source_asset_address":"172.16.100.22","destination_asset_address":"jenkinsnode.qmasters.co","destination_local_account":"root","logon_type":"NETWORK","result":"FAILED_OTHER","new_authentication":"false","service":"/usr/sbin/sshd","source_json":{"audit_id":914407,"pid":23992,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"password","acct":"root","addr":"172.16.100.22","terminal":"ssh","res":"failed","type":1100,"startTime":1605541569420,"cmdLine":"sshd: root [priv]   ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"processUUID":"cc0a6c4f86c0e1695022c8f3c56de41c6eea5becfe91f1891749c585ff493ee1","hashes":{"md5":"686cd72b4339da33bfb6fe8fb94a301f","sha1":"0205dc86c73109c380f97b4481cad911b98df5cd","sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"root","gidName":"root"},"euid":0,"egid":0,"uidName":null,"euidName":"root","egidName":"root","auidName":null,"domain":"qmasters.co","hostname":"jenkinsnode"}} | 1605541580470 |
>| ab5a7594-5fde-4c5c-9ee6-e67291f0a40c | {"timestamp":"2020-11-16T15:46:18.903Z","destination_asset":"jenkinsnode.qmasters.co","source_asset_address":"172.16.100.22","destination_asset_address":"jenkinsnode.qmasters.co","destination_local_account":"root","logon_type":"NETWORK","result":"SUCCESS","new_authentication":"false","service":"/usr/sbin/sshd","source_json":{"audit_id":914729,"pid":23992,"uid":null,"auid":4294967295,"ses":4294967295,"subj":"system_u:system_r:sshd_t:s0-s0:c0.c1023","op":"success","acct":"root","addr":"172.16.100.22","terminal":"ssh","res":"success","type":1100,"startTime":1605541569420,"cmdLine":"sshd: root [priv]   ","processName":"sshd","executablePath":"/usr/sbin/sshd","ppid":1131,"processUUID":"cc0a6c4f86c0e1695022c8f3c56de41c6eea5becfe91f1891749c585ff493ee1","hashes":{"md5":"686cd72b4339da33bfb6fe8fb94a301f","sha1":"0205dc86c73109c380f97b4481cad911b98df5cd","sha256":"2c6bf828ee0b4e78c49a71affd3d33b7916700cf7a288cd1a55fc4e701e50d68"},"metadata":{"creationDate":1592052866191,"lastModifiedDate":1565314847000,"lastAccessDate":1605098588968,"size":852856,"permissions":"-rwxr-xr-x","uid":0,"gid":0,"uidName":"root","gidName":"root"},"euid":0,"egid":0,"uidName":null,"euidName":"root","egidName":"root","auidName":null,"domain":"qmasters.co","hostname":"jenkinsnode"}} | 1605541580470 |

