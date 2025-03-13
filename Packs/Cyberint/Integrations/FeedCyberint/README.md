Use the Cyberint Feed integration to get indicators from the feed.

## Configure Cyberint Feed on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Cyberint Feed.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description**                                                                                                                                                                                        | **Required** |
    | --- |--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------| --- |
    | Cyberint API URL | Example: `https://yourcompany.cyberint.io`                                                                                                                                                               | True |
    | API access token |                                                                                                                                                                                                        | True |
    | Fetch indicators | Should be checked (true)                                                                                                                                                                               | False |
    | Indicator Type | Which indicator types to fetch                                                                                                                                                                         | True |
    | Confidence | Confidence about the indicator details. The value of confidence to fetch indicators from. The value between 0-100.                                                                                     | False |
    | Severity | Severity about the indicator details. The value of severity to fetch indicators from. The value between 0-100.                                                                                         | False |
    | Tags | Supports CSV values.                                                                                                                                                                                   | False |
    | Bypass exclusion list | When selected, the exclusion list is ignored for indicators from this feed. This means that if an indicator from this feed is on the exclusion list, the indicator might still be added to the system. | False |
    | Trust any certificate (not secure) |                                                                                                                                                                                                        | False |
    | Use system proxy settings |                                                                                                                                                                                                        | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### cyberint-get-indicators

***
Gets indicators from the feed.

#### Base Command

`cyberint-get-indicators`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of results to return. The default value is 10. Default is 10. | Optional |

#### Context Output

| **Path**                   | **Type** | **Description** |
|----------------------------| --- | --- |
| Cyberint.ioc_value         | String | The indicator value. |
| Cyberint.ioc_type          | String | The indicator type. |
| Cyberint.description       | String | The feed description. |
| Cyberint.detected_activity | String | The feed detected activity. |
| Cyberint.observation_date  | String | The feed observation date. |
| Cyberint.severity_score    | String | The feed severity score. |
| Cyberint.confidence        | String | The feed confidence. |

#### Command example
```!cyberint-get-indicators limit=10 execution-timeout=700```
#### Context Example
```json
{
    "Cyberint": [
        {
            "fields": {
                "Description": "Recognized as Malicious.",
                "FirstSeenBySource": "2024-01-23T22:53:36+00:00",
                "reportedby": "Cyberint",
                "trafficlightprotocol": "GREEN"
            },
            "rawJSON": {
                "confidence": 80,
                "description": "Recognized as Malicious.",
                "detected_activity": "malware_payload",
                "ioc_type": "file/sha256",
                "ioc_value": "ioc1",
                "observation_date": "2024-01-23T22:53:36+00:00",
                "severity_score": 100
            },
            "service": "Cyberint",
            "type": "File",
            "value": "ioc1"
        },
        {
            "fields": {
                "Description": "Recognized as zzz.",
                "FirstSeenBySource": "2024-01-23T22:55:36+00:00",
                "reportedby": "Cyberint",
                "trafficlightprotocol": "GREEN"
            },
            "rawJSON": {
                "confidence": 80,
                "description": "Recognized as zzz.",
                "detected_activity": "malware_payload",
                "ioc_type": "file/sha256",
                "ioc_value": "ioc2",
                "observation_date": "2024-01-23T22:55:36+00:00",
                "severity_score": 100
            },
            "service": "Cyberint",
            "type": "File",
            "value": "ioc2"
        },
        {
            "fields": {
                "Description": "Recognized as xxx.",
                "FirstSeenBySource": "2024-01-23T22:53:35+00:00",
                "reportedby": "Cyberint",
                "trafficlightprotocol": "GREEN"
            },
            "rawJSON": {
                "confidence": 80,
                "description": "Recognized as xxx.",
                "detected_activity": "malware_payload",
                "ioc_type": "file/sha256",
                "ioc_value": "ioc3",
                "observation_date": "2024-01-23T22:53:35+00:00",
                "severity_score": 100
            },
            "service": "Cyberint",
            "type": "File",
            "value": "ioc3"
        },
        {
            "fields": {
                "Description": "Recognized as xxx.",
                "FirstSeenBySource": "2024-01-23T22:55:31+00:00",
                "reportedby": "Cyberint",
                "trafficlightprotocol": "GREEN"
            },
            "rawJSON": {
                "confidence": 80,
                "description": "Recognized as xxx.",
                "detected_activity": "malware_payload",
                "ioc_type": "file/sha256",
                "ioc_value": "ioc4",
                "observation_date": "2024-01-23T22:55:31+00:00",
                "severity_score": 100
            },
            "service": "Cyberint",
            "type": "File",
            "value": "ioc4"
        },
        {
            "fields": {
                "Description": "Recognized as xxx.",
                "FirstSeenBySource": "2024-01-23T22:55:35+00:00",
                "reportedby": "Cyberint",
                "trafficlightprotocol": "GREEN"
            },
            "rawJSON": {
                "confidence": 80,
                "description": "Recognized as xxx.",
                "detected_activity": "malware_payload",
                "ioc_type": "file/sha256",
                "ioc_value": "ioc5",
                "observation_date": "2024-01-23T22:55:35+00:00",
                "severity_score": 100
            },
            "service": "Cyberint",
            "type": "File",
            "value": "ioc5"
        },
        {
            "fields": {
                "Description": "Recognized as Trojan.xxx.",
                "FirstSeenBySource": "2024-01-23T22:55:39+00:00",
                "reportedby": "Cyberint",
                "trafficlightprotocol": "GREEN"
            },
            "rawJSON": {
                "confidence": 80,
                "description": "Recognized as Trojan.xxx.",
                "detected_activity": "malware_payload",
                "ioc_type": "file/sha256",
                "ioc_value": "ioc6",
                "observation_date": "2024-01-23T22:55:39+00:00",
                "severity_score": 100
            },
            "service": "Cyberint",
            "type": "File",
            "value": "ioc6"
        },
        {
            "fields": {
                "Description": "Recognized as xxx.",
                "FirstSeenBySource": "2024-01-12T01:39:06+00:00",
                "reportedby": "Cyberint",
                "trafficlightprotocol": "GREEN"
            },
            "rawJSON": {
                "confidence": 80,
                "description": "Recognized as xxx.",
                "detected_activity": "malware_payload",
                "ioc_type": "file/sha256",
                "ioc_value": "ioc7",
                "observation_date": "2024-01-12T01:39:06+00:00",
                "severity_score": 100
            },
            "service": "Cyberint",
            "type": "File",
            "value": "ioc7"
        },
        {
            "fields": {
                "Description": "Recognized as xxx.",
                "FirstSeenBySource": "2024-01-23T22:55:36+00:00",
                "reportedby": "Cyberint",
                "trafficlightprotocol": "GREEN"
            },
            "rawJSON": {
                "confidence": 80,
                "description": "Recognized as xxx.",
                "detected_activity": "malware_payload",
                "ioc_type": "file/sha256",
                "ioc_value": "ioc8",
                "observation_date": "2024-01-23T22:55:36+00:00",
                "severity_score": 100
            },
            "service": "Cyberint",
            "type": "File",
            "value": "ioc8"
        },
        {
            "fields": {
                "Description": "Recognized as xxx.",
                "FirstSeenBySource": "2023-12-16T21:28:01+00:00",
                "reportedby": "Cyberint",
                "trafficlightprotocol": "GREEN"
            },
            "rawJSON": {
                "confidence": 70,
                "description": "Recognized as xxx.",
                "detected_activity": "malware_payload",
                "ioc_type": "file/sha256",
                "ioc_value": "ioc9",
                "observation_date": "2023-12-16T21:28:01+00:00",
                "severity_score": 100
            },
            "service": "Cyberint",
            "type": "File",
            "value": "ioc9"
        },
        {
            "fields": {
                "Description": "Recognized as xxx.",
                "FirstSeenBySource": "2024-01-23T22:55:35+00:00",
                "reportedby": "Cyberint",
                "trafficlightprotocol": "GREEN"
            },
            "rawJSON": {
                "confidence": 80,
                "description": "Recognized as xxx.",
                "detected_activity": "malware_payload",
                "ioc_type": "file/sha256",
                "ioc_value": "ioc10",
                "observation_date": "2024-01-23T22:55:35+00:00",
                "severity_score": 100
            },
            "service": "Cyberint",
            "type": "File",
            "value": "ioc10"
        }
    ]
}
```

#### Human Readable Output

>### Indicators from Cyberint Feed:
>|Value|Type|
>|---|---|
>| ioc1 | File |
>| ioc2 | File |
>| ioc3 | File |
>| ioc4 | File |
>| ioc5 | File |
>| ioc6 | File |
>| ioc7 | File |
>| ioc8 | File |
>| ioc9 | File |
>| ioc10 | File |
