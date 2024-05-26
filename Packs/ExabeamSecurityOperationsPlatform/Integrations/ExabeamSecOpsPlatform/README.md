Exabeam Security Operations Platform offers a centralized and scalable platform for log management.
This integration was integrated and tested with version v1.0 of ExabeamSecOpsPlatform.

## Configure Exabeam Security Operations Platform on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Exabeam Security Operations Platform.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Server URL | True |
    | Client ID | True |
    | Client Secret | True |
    | Trust any certificate (not secure) | False |
    | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### exabeam-platform-event-search

***
Get events from Exabeam Security Operations Platform.

#### Base Command

`exabeam-platform-event-search`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start_time | The starting date for the search range. | Required | 
| end_time | The ending date for the search range. | Required | 
| query | Query, using Lucene syntax, filters log data for precise analysis. | Optional | 
| fields | Comma-separated list of fields to be returned from the search. | Optional | 
| group_by | Comma-separated list of fields by which to group the results. | Optional | 
| limit | The maximal number of results to return. Maximum value is 3000. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ExabeamPlatform.Event.id | String | The unique identifier associated with the event. | 
| ExabeamPlatform.Event.rawLogIds | String | The raw log identifiers associated with the event. | 
| ExabeamPlatform.Event.tier | String | The tier associated with the event. | 
| ExabeamPlatform.Event.parsed | String | Whether the event has been parsed. | 
| ExabeamPlatform.Event.rawLogs | String | The raw logs associated with the event. | 

#### Command example
```!exabeam-platform-event-search end_time="today" start_time="7 days ago" limit=2```
#### Context Example
```json
{
    "ExabeamPlatform": {
        "Event": [
            {
                "approxLogTime": 1715694190909000,
                "collector_timestamp": 1715694190909000,
                "customFieldsJSON": "{}",
                "id": "fake",
                "ingest_time": 1715694222815000,
                "metadataFieldsJSON": "{\"m_collector_id\":\"aae1627e-8637-4597-9f43-e49a703a6151\",\"m_collector_name\":\"exa-cribl-logs-sm_exa_ws\",\"m_collector_type\":\"cribl-logs\"}",
                "parsed": false,
                "rawLogIds": [
                    "log-fic"
                ],
                "rawLogs": [
                    "ANY rawLog"
                ],
                "raw_log_size": 9,
                "tier": "Tier 4"
            },
            {
                "approxLogTime": 1715694915916000,
                "collector_timestamp": 1715694915916000,
                "customFieldsJSON": "{}",
                "id": "fictive-id",
                "ingest_time": 1715694946775000,
                "metadataFieldsJSON": "{\"m_collector_id\":\"aae1627e-8637-4597-9f43-e49a703a6151\",\"m_collector_name\":\"exa-cribl-logs-sm_exa_ws\",\"m_collector_type\":\"cribl-logs\"}",
                "parsed": false,
                "rawLogIds": [
                    "rawLogId"
                ],
                "rawLogs": [
                    "CONNECT hotmail"
                ],
                "raw_log_size": 59,
                "tier": "Tier 4"
            }
        ]
    }
}
```

#### Human Readable Output

>### Logs
>|Id|Is Parsed|Raw Log Ids|Raw Logs|Tier|
>|---|---|---|---|---|
>| fake | false | log-fic | ANY rawLog | Tier 4 |
>| fictive-id | false | rawLogId | CONNECT hotmail  | Tier 4 |

