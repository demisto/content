Exabeam Security Operations Platform offers robust search functionality, enabling security teams to efficiently query, analyze, and visualize security data. It provides a centralized and scalable platform for log management, threat detection, and incident investigation.
This integration was integrated and tested with version xx of ExabeamSecOpsPlatform.

## Configure Exabeam Security Operations Platform on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Exabeam Security Operations Platform.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Server URL | True |
    | Client Id | True |
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
| group_by | Comma-separated list of fields to GROUP BY. | Optional | 
| limit | The maximal number of results to return. Maximum value is 3000. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ExabeamPlatform.Event.activity | String | Indicates the specific activity performed. | 
| ExabeamPlatform.Event.activity_type | String | Specifies the type of the activity. | 
| ExabeamPlatform.Event.business_criticality | String | Reflects the criticality level assigned to the business context of the event. | 
| ExabeamPlatform.Event.host | String | Identifies the host the activity occurred. | 
| ExabeamPlatform.Event.landscape | String | Describes the landscape in which the event took place. | 
| ExabeamPlatform.Event.outcome | String | Indicates the outcome of the activity. | 
| ExabeamPlatform.Event.platform | String | Specifies the platform involved in the event. | 
| ExabeamPlatform.Event.product | String | Indicates the specific product related to the event. | 
| ExabeamPlatform.Event.product_category | String | Specifies the category of the product involved in the event. | 
| ExabeamPlatform.Event.subject | String | Identifies the subject involved in the activity. | 
| ExabeamPlatform.Event.time | String | Represents the timestamp of occurrence for the event. | 
| ExabeamPlatform.Event.vendor | String | Indicates the vendor associated with the event. | 

#### Command example
```!exabeam-platform-event-search end_time="today" start_time="7 days ago" limit=4```
#### Context Example
```json
{
    "ExabeamPlatform": {
        "Event": [
            {
                "activity": "trigger",
                "activity_type": "alert-trigger",
                "alert_name": "[Risk] Abnormal Amount of Open Ports",
                "alert_severity": "Medium",
                "alert_status": "Unhandled",
                "alert_type": "System Policy Violation",
                "approxLogTime": 1716209600000000,
                "builder_name": "armis_byid_trigger_custom",
                "collector_timestamp": 1716209614248000,
                "customFieldsJSON": "{\"c_device_id_list\":\"15\",\"c_device_severity\":\"Medium\"}",
                "id": "8bbd9ff9-92ea-4bf5-baaa-2e214092de18",
                "ingest_time": 1716209614644000,
                "is_ioc": false,
                "landscape": "network devices",
                "metadataFieldsJSON": "{\"m_collector_name\":\"armis\",\"m_collector_type\":\"Webhook\"}",
                "msg_type": "armis-byid-cef-alert-trigger-success-systempolicyviolation-custom",
                "outcome": "success",
                "parsed": true,
                "parser_version": "v1.0.0",
                "platform": "aruba wireless controller",
                "product": "Armis",
                "rawLogIds": [
                    "dd09f357-fb77-483d-84c2-85e0f3297ad4"
                ],
                "rawLogs": [
                    "{\"time\":\"2024-05-20T12:53:20\",\"title\":\"[Risk] Abnormal Amount of Open Ports\",\"type\":\"System Policy Violation\",\"severity\":\"Medium\",\"status\":\"Unhandled\",\"deviceIds\":[15]} SE_GENERATED armis-alertiotbyid"
                ],
                "raw_log_size": 200,
                "raw_log_time": 1716209600000000,
                "raw_log_time_format": "yyyy-MM-dd'T'HH:mm:ss",
                "raw_log_time_str": "2024-05-20T12:53:20",
                "subject": "alert",
                "tier": "Tier 2",
                "time": "2024-05-20T12:53:20",
                "vendor": "Armis"
            },
            {
                "approxLogTime": 1716209108762000,
                "collector_timestamp": 1716209108762000,
                "customFieldsJSON": "{}",
                "error_detail": "[{\"stage\":\"Parsing\",\"errors\":[{\"reason\":\"TIME_PARSING_ERROR\",\"msg\":\"Parser definition contains time field but time was not parsed\",\"field\":\"time\"}]}]",
                "id": "6d90933e-1d8d-4865-b352-07f4efdecadc",
                "ingest_time": 1716209409454000,
                "is_ioc": false,
                "metadataFieldsJSON": "{\"m_collector_id\":\"3f1a69f0-ce69-4f41-bc02-649e5c5a39a3\",\"m_collector_name\":\"exa-cribl-logs-exabeam-out\",\"m_collector_type\":\"cribl-logs\"}",
                "msg_type": "exa-palo-network-unparsed",
                "parsed": true,
                "parser_version": "v1.0.0",
                "product": "Palo Alto NGFW",
                "rawLogIds": [
                    "723a214f-890f-4604-bd0c-ba9288b9f09a"
                ],
                "rawLogs": [
                    ",2020/05/07 02:40:08,44A1B3FC68F5304,TRAFFIC,end,2049,,205.185.123.210,192.168.10.53,205.185.123.210,192.168.10.53,splunk,,,incomplete,vsys1,untrusted,trusted,ethernet1/3,ethernet1/2,log-forwarding-default,,574239,1,50340,8088,50340,8088,0x400064,tcp,allow,296,296,0,4,2020/05/07 02:40:08,7,any,,730183,0x0,United States,10.0.0.0-10.255.255.255,,4,0,aged-out,,,,,,PA-VM,from-policy,,,0,,0,,N/A,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,"
                ],
                "raw_log_size": 446,
                "tier": "Tier 3",
                "time": "2024-05-20T12:45:08.762000",
                "vendor": "Palo Alto Networks"
            },
            {
                "approxLogTime": 1716209108763000,
                "collector_timestamp": 1716209108763000,
                "customFieldsJSON": "{}",
                "error_detail": "[{\"stage\":\"Parsing\",\"errors\":[{\"reason\":\"TIME_PARSING_ERROR\",\"msg\":\"Parser definition contains time field but time was not parsed\",\"field\":\"time\"}]}]",
                "id": "9ad694b9-38ce-476c-8dcf-0065654bd9fd",
                "ingest_time": 1716209409505000,
                "is_ioc": false,
                "metadataFieldsJSON": "{\"m_collector_id\":\"3f1a69f0-ce69-4f41-bc02-649e5c5a39a3\",\"m_collector_name\":\"exa-cribl-logs-exabeam-out\",\"m_collector_type\":\"cribl-logs\"}",
                "msg_type": "exa-palo-network-unparsed",
                "parsed": true,
                "parser_version": "v1.0.0",
                "product": "Palo Alto NGFW",
                "rawLogIds": [
                    "1e0eceba-c207-4f65-9ac4-6c12a00c6eb7"
                ],
                "rawLogs": [
                    ",2020/05/07 02:40:09,44A1B3FC68F5304,TRAFFIC,end,2049,,108.161.138.152,192.168.1.55,108.161.138.152,192.168.1.55,splunk,,,incomplete,vsys1,untrusted,trusted,ethernet1/3,ethernet1/2,log-forwarding-default,,574267,1,34756,8088,34756,8088,0x400064,tcp,allow,296,296,0,4,2020/05/07 02:40:09,7,any,,730214,0x0,United States,10.0.0.0-10.255.255.255,,4,0,aged-out,,,,,,PA-VM,from-policy,,,0,,0,,N/A,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,"
                ],
                "raw_log_size": 444,
                "tier": "Tier 3",
                "time": "2024-05-20T12:45:08.763000",
                "vendor": "Palo Alto Networks"
            },
            {
                "approxLogTime": 1716209114761000,
                "collector_timestamp": 1716209114761000,
                "customFieldsJSON": "{}",
                "error_detail": "[{\"stage\":\"Parsing\",\"errors\":[{\"reason\":\"TIME_PARSING_ERROR\",\"msg\":\"Parser definition contains time field but time was not parsed\",\"field\":\"time\"}]}]",
                "id": "c8ead65b-b64d-43a5-a1c3-5f211b125183",
                "ingest_time": 1716209409506000,
                "is_ioc": false,
                "metadataFieldsJSON": "{\"m_collector_id\":\"3f1a69f0-ce69-4f41-bc02-649e5c5a39a3\",\"m_collector_name\":\"exa-cribl-logs-exabeam-out\",\"m_collector_type\":\"cribl-logs\"}",
                "msg_type": "exa-palo-network-unparsed",
                "parsed": true,
                "parser_version": "v1.0.0",
                "product": "Palo Alto NGFW",
                "rawLogIds": [
                    "bf8ccbfe-d840-4304-af1e-36fe2ea59b9e"
                ],
                "rawLogs": [
                    ",2020/05/07 02:40:10,44A1B3FC68F5304,TRAFFIC,end,2049,,111.223.73.130,192.168.10.53,111.223.73.130,192.168.10.53,splunk,,,incomplete,vsys1,untrusted,trusted,ethernet1/3,ethernet1/2,log-forwarding-default,,574294,1,41166,8088,41166,8088,0x400064,tcp,allow,296,296,0,4,2020/05/07 02:40:10,7,any,,730238,0x0,United States,10.0.0.0-10.255.255.255,,4,0,aged-out,,,,,,PA-VM,from-policy,,,0,,0,,N/A,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,"
                ],
                "raw_log_size": 444,
                "tier": "Tier 3",
                "time": "2024-05-20T12:45:14.761000",
                "vendor": "Palo Alto Networks"
            }
        ]
    }
}
```

#### Human Readable Output

>### Logs
>|activity|activity_type|landscape|outcome|platform|product|subject|time|vendor|
>|---|---|---|---|---|---|---|---|---|
>| trigger | alert-trigger | network devices | success | aruba wireless controller | Armis | alert | 2024-05-20T12:53:20 | Armis |
>|  |  |  |  |  | Palo Alto NGFW |  | 2024-05-20T12:45:08.762000 | Palo Alto Networks |
>|  |  |  |  |  | Palo Alto NGFW |  | 2024-05-20T12:45:08.763000 | Palo Alto Networks |
>|  |  |  |  |  | Palo Alto NGFW |  | 2024-05-20T12:45:14.761000 | Palo Alto Networks |

