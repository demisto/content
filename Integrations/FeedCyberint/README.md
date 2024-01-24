Use the Cyberint Feed integration to get indicators from the feed.
This integration was integrated and tested with version 1 of Cyberint Feed.

## Configure Cyberint Feed on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Cyberint Feed.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | The Cyberint IOC feed endpoint URL |  | True |
    | API Key (Leave empty. Fill in the API Key in the password field.) |  | True |
    | API access token |  | True |
    | Fetch indicators |  | False |
    | Indicator Reputation | Indicators from this integration instance will be marked with this reputation | False |
    | Source Reliability | Reliability of the source providing the intelligence data | True |
    | Traffic Light Protocol Color | The Traffic Light Protocol \(TLP\) designation to apply to indicators fetched from the feed | False |
    | Indicator Type | Which indicator types to fetch | True |
    | Feed Name |  | True |
    | Confidence | Confidence about the indicator details. The value of confidence to fetch indicators from. The value between 0-100. | False |
    | Severity | Severity about the indicator details. The value of severity to fetch indicators from. The value between 0-100. | False |
    |  |  | False |
    |  |  | False |
    | Feed Fetch Interval |  | False |
    | Tags | Supports CSV values. | False |
    | Bypass exclusion list | When selected, the exclusion list is ignored for indicators from this feed. This means that if an indicator from this feed is on the exclusion list, the indicator might still be added to the system. | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |

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

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cyberint.value | String | The indicator value. |
| Cyberint.type | String | The indicator type. |
| Cyberint.Tags | String | Tags that are associated with the indicator. |
| Cyberint.description | String | The feed description. |
| Cyberint.detected_activity | String | The feed detected activity. |
| Cyberint.observation_date | String | The feed observation date. |
| Cyberint.severity_score | String | The feed severity score. |
| Cyberint.confidence | String | The feed confidence. |

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
                "ioc_value": "39989b501fd179bf89907e798532b0d9e6c7c7664db138bd2d29d4cc227da2e8",
                "observation_date": "2024-01-23T22:53:36+00:00",
                "severity_score": 100
            },
            "service": "Cyberint",
            "type": "File",
            "value": "39989b501fd179bf89907e798532b0d9e6c7c7664db138bd2d29d4cc227da2e8"
        },
        {
            "fields": {
                "Description": "Recognized as Gen:Variant.Cerbu.173465.",
                "FirstSeenBySource": "2024-01-23T22:55:36+00:00",
                "reportedby": "Cyberint",
                "trafficlightprotocol": "GREEN"
            },
            "rawJSON": {
                "confidence": 80,
                "description": "Recognized as Gen:Variant.Cerbu.173465.",
                "detected_activity": "malware_payload",
                "ioc_type": "file/sha256",
                "ioc_value": "4669b5c52e264b1a3c6de0b402e2c10119fd09f2c0f3413b8a60ee4c30972747",
                "observation_date": "2024-01-23T22:55:36+00:00",
                "severity_score": 100
            },
            "service": "Cyberint",
            "type": "File",
            "value": "4669b5c52e264b1a3c6de0b402e2c10119fd09f2c0f3413b8a60ee4c30972747"
        },
        {
            "fields": {
                "Description": "Recognized as Trojan.GenericKDZ.105087.",
                "FirstSeenBySource": "2024-01-23T22:53:35+00:00",
                "reportedby": "Cyberint",
                "trafficlightprotocol": "GREEN"
            },
            "rawJSON": {
                "confidence": 80,
                "description": "Recognized as Trojan.GenericKDZ.105087.",
                "detected_activity": "malware_payload",
                "ioc_type": "file/sha256",
                "ioc_value": "f92c2bb535bdbcff04cfa25553eec6cb6d502174c1588640e9a74082803e617b",
                "observation_date": "2024-01-23T22:53:35+00:00",
                "severity_score": 100
            },
            "service": "Cyberint",
            "type": "File",
            "value": "f92c2bb535bdbcff04cfa25553eec6cb6d502174c1588640e9a74082803e617b"
        },
        {
            "fields": {
                "Description": "Recognized as Trojan.Agent.GIKJ.",
                "FirstSeenBySource": "2024-01-23T22:55:31+00:00",
                "reportedby": "Cyberint",
                "trafficlightprotocol": "GREEN"
            },
            "rawJSON": {
                "confidence": 80,
                "description": "Recognized as Trojan.Agent.GIKJ.",
                "detected_activity": "malware_payload",
                "ioc_type": "file/sha256",
                "ioc_value": "451a04d491861299b059596ae3d28a11c890a7498b940052352b6158e0adbdf7",
                "observation_date": "2024-01-23T22:55:31+00:00",
                "severity_score": 100
            },
            "service": "Cyberint",
            "type": "File",
            "value": "451a04d491861299b059596ae3d28a11c890a7498b940052352b6158e0adbdf7"
        },
        {
            "fields": {
                "Description": "Recognized as Application.Coinminer.GU.",
                "FirstSeenBySource": "2024-01-23T22:55:35+00:00",
                "reportedby": "Cyberint",
                "trafficlightprotocol": "GREEN"
            },
            "rawJSON": {
                "confidence": 80,
                "description": "Recognized as Application.Coinminer.GU.",
                "detected_activity": "malware_payload",
                "ioc_type": "file/sha256",
                "ioc_value": "93d145854c297fb81a04c5af74eb08391d2ad269b103a90f7f3236992733a159",
                "observation_date": "2024-01-23T22:55:35+00:00",
                "severity_score": 100
            },
            "service": "Cyberint",
            "type": "File",
            "value": "93d145854c297fb81a04c5af74eb08391d2ad269b103a90f7f3236992733a159"
        },
        {
            "fields": {
                "Description": "Recognized as Trojan.GenericKDZ.70387.",
                "FirstSeenBySource": "2024-01-23T22:55:39+00:00",
                "reportedby": "Cyberint",
                "trafficlightprotocol": "GREEN"
            },
            "rawJSON": {
                "confidence": 80,
                "description": "Recognized as Trojan.GenericKDZ.70387.",
                "detected_activity": "malware_payload",
                "ioc_type": "file/sha256",
                "ioc_value": "c8ab4a1b80a984ec32d81dd02beed44368f36db6d567c868965b275a4ceb1ed3",
                "observation_date": "2024-01-23T22:55:39+00:00",
                "severity_score": 100
            },
            "service": "Cyberint",
            "type": "File",
            "value": "c8ab4a1b80a984ec32d81dd02beed44368f36db6d567c868965b275a4ceb1ed3"
        },
        {
            "fields": {
                "Description": "Recognized as AIT:Trojan.Nymeria.4261.",
                "FirstSeenBySource": "2024-01-12T01:39:06+00:00",
                "reportedby": "Cyberint",
                "trafficlightprotocol": "GREEN"
            },
            "rawJSON": {
                "confidence": 80,
                "description": "Recognized as AIT:Trojan.Nymeria.4261.",
                "detected_activity": "malware_payload",
                "ioc_type": "file/sha256",
                "ioc_value": "a092e3e8e7da270af60a7b05aa55e00e90ae6067cd09a5533bf7c994185ed0f2",
                "observation_date": "2024-01-12T01:39:06+00:00",
                "severity_score": 100
            },
            "service": "Cyberint",
            "type": "File",
            "value": "a092e3e8e7da270af60a7b05aa55e00e90ae6067cd09a5533bf7c994185ed0f2"
        },
        {
            "fields": {
                "Description": "Recognized as Trojan.GenericKD.70718472.",
                "FirstSeenBySource": "2024-01-23T22:55:36+00:00",
                "reportedby": "Cyberint",
                "trafficlightprotocol": "GREEN"
            },
            "rawJSON": {
                "confidence": 80,
                "description": "Recognized as Trojan.GenericKD.70718472.",
                "detected_activity": "malware_payload",
                "ioc_type": "file/sha256",
                "ioc_value": "07392601ec30bb83eace25e2b4045a6c98821ef3f3242ba32d9b9e245043918c",
                "observation_date": "2024-01-23T22:55:36+00:00",
                "severity_score": 100
            },
            "service": "Cyberint",
            "type": "File",
            "value": "07392601ec30bb83eace25e2b4045a6c98821ef3f3242ba32d9b9e245043918c"
        },
        {
            "fields": {
                "Description": "Recognized as RiskWare/MSIL.Gamehack.",
                "FirstSeenBySource": "2023-12-16T21:28:01+00:00",
                "reportedby": "Cyberint",
                "trafficlightprotocol": "GREEN"
            },
            "rawJSON": {
                "confidence": 70,
                "description": "Recognized as RiskWare/MSIL.Gamehack.",
                "detected_activity": "malware_payload",
                "ioc_type": "file/sha256",
                "ioc_value": "4a2a580d7a2bfc76efa3e7ddca9f2811051b85dd125264b436fe148e9bf6b521",
                "observation_date": "2023-12-16T21:28:01+00:00",
                "severity_score": 100
            },
            "service": "Cyberint",
            "type": "File",
            "value": "4a2a580d7a2bfc76efa3e7ddca9f2811051b85dd125264b436fe148e9bf6b521"
        },
        {
            "fields": {
                "Description": "Recognized as Trojan.GenericKD.71273579.",
                "FirstSeenBySource": "2024-01-23T22:55:35+00:00",
                "reportedby": "Cyberint",
                "trafficlightprotocol": "GREEN"
            },
            "rawJSON": {
                "confidence": 80,
                "description": "Recognized as Trojan.GenericKD.71273579.",
                "detected_activity": "malware_payload",
                "ioc_type": "file/sha256",
                "ioc_value": "3028203f4b301ed16f2aa70d4f9f1b01c27401b4fb17cf9a36b30543ac003986",
                "observation_date": "2024-01-23T22:55:35+00:00",
                "severity_score": 100
            },
            "service": "Cyberint",
            "type": "File",
            "value": "3028203f4b301ed16f2aa70d4f9f1b01c27401b4fb17cf9a36b30543ac003986"
        }
    ]
}
```

#### Human Readable Output

>### Indicators from Cyberint Feed:
>|Value|Type|
>|---|---|
>| 39989b501fd179bf89907e798532b0d9e6c7c7664db138bd2d29d4cc227da2e8 | File |
>| 4669b5c52e264b1a3c6de0b402e2c10119fd09f2c0f3413b8a60ee4c30972747 | File |
>| f92c2bb535bdbcff04cfa25553eec6cb6d502174c1588640e9a74082803e617b | File |
>| 451a04d491861299b059596ae3d28a11c890a7498b940052352b6158e0adbdf7 | File |
>| 93d145854c297fb81a04c5af74eb08391d2ad269b103a90f7f3236992733a159 | File |
>| c8ab4a1b80a984ec32d81dd02beed44368f36db6d567c868965b275a4ceb1ed3 | File |
>| a092e3e8e7da270af60a7b05aa55e00e90ae6067cd09a5533bf7c994185ed0f2 | File |
>| 07392601ec30bb83eace25e2b4045a6c98821ef3f3242ba32d9b9e245043918c | File |
>| 4a2a580d7a2bfc76efa3e7ddca9f2811051b85dd125264b436fe148e9bf6b521 | File |
>| 3028203f4b301ed16f2aa70d4f9f1b01c27401b4fb17cf9a36b30543ac003986 | File |
