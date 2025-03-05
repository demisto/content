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

### cyberint-get-file-sha256

***
Gets File SHA256 from the feed.

#### Base Command

`cyberint-get-file-sha256`

#### Input

| **Argument Name** | **Description**  | **Required** |
|-------------------|------------------|--------------|
| value             | File SHA256 hash | Required     |

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
```!cyberint-get-file-sha256 value=6a7b02c43837dcb8e40d271edb88d13d2e723c721a74931857aaef4853317789```
#### Context Example
```json
{
    "data": {
        "entity": {
            "type": "file/sha256",
            "value": "6a7b02c43837dcb8e40d271edb88d13d2e723c721a74931857aaef4853317789"
        },
        "risk": {
            "malicious_score": 100,
            "detected_activities": [
                {
                    "type": "malware",
                    "observation_date": "2025-03-05T14:47:43.994848+00:00",
                    "description": "",
                    "confidence": 100,
                    "occurrences_count": 1
                },
                {
                    "type": "malware_payload",
                    "observation_date": "2025-02-12T21:08:13+00:00",
                    "description": "Detected in 1 source(s). Recognized as Trojan.Agent.CYZT.",
                    "confidence": 80,
                    "occurrences_count": 1
                }
            ],
            "occurrences_count": 2
        },
        "enrichment": {
            "related_entities": null,
            "filenames": [
                "rifaien2-TwxvxoHtj44icOI0.exe"
            ],
            "first_seen": "2025-02-12T21:08:13+00:00",
            "download_urls": []
        },
        "benign": false
    }
}
```

#### Human Readable Output

### cyberint-get-domain

***
Gets Domain from the feed.

#### Base Command

`cyberint-get-domain`

#### Input

| **Argument Name** | **Description** | **Required** |
|-------------------|-----------------|--------------|
| value             | Domain          | Required     |

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
```!cyberint-get-domain value=dummy.com```
#### Context Example
```json
{
    "data": {
        "entity": {
            "type": "domain",
            "value": "domain.com"
        },
        "risk": {
            "malicious_score": 80,
            "detected_activities": [
                {
                    "type": "infecting_url",
                    "observation_date": "2025-03-05T14:47:23.534044+00:00",
                    "description": "URL that may infect it’s visitors with malware.",
                    "confidence": 100,
                    "occurrences_count": 1
                },
                {
                    "type": "phishing_website",
                    "observation_date": "2024-09-16T06:26:16+00:00",
                    "description": "Detected phishing website targeting Dummy.",
                    "confidence": 20,
                    "occurrences_count": 1
                }
            ],
            "occurrences_count": 2
        },
        "enrichment": {
            "related_entities": null,
            "ips": [
                "11.197.130.221"
            ],
            "whois": {
                "registrant_name": null,
                "registrant_email": null,
                "registrant_organization": null,
                "registrant_country": "USA",
                "registrant_telephone": null,
                "technical_contact_email": null,
                "technical_contact_name": null,
                "technical_contact_organization": null,
                "registrar_name": "Registrar.com",
                "admin_contact_name": null,
                "admin_contact_organization": null,
                "admin_contact_email": null,
                "created_date": "2024-09-10T09:29:58",
                "updated_date": "2024-10-18T05:44:51",
                "expiration_date": "2025-09-10T23:59:59"
            }
        },
        "benign": false
    }
}
```

#### Human Readable Output

### cyberint-get-ipv4

***
Gets Domain from the feed.

#### Base Command

`cyberint-get-ipv4`

#### Input

| **Argument Name** | **Description** | **Required** |
|-------------------|-----------------|--------------|
| value             | IPv4            | Required     |

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
```!cyberint-get-ipv4 value=1.1.1.1```
#### Context Example
```json
{
    "data": {
        "entity": {
            "type": "ipv4",
            "value": "11.197.130.221"
        },
        "risk": {
            "malicious_score": 100,
            "detected_activities": [
                {
                    "type": "payload_delivery",
                    "observation_date": "2025-02-13T08:38:50+00:00",
                    "description": "Detected hosting malware.",
                    "confidence": 20,
                    "occurrences_count": 836
                },
                {
                    "type": "phishing_website",
                    "observation_date": "2025-03-05T10:17:32+00:00",
                    "description": "Detected phishing website targeting Dummy, ING Direct, genericcloudflare.",
                    "confidence": 20,
                    "occurrences_count": 143
                },
                {
                    "type": "cnc_server",
                    "observation_date": "2025-02-14T22:21:12.084000+00:00",
                    "description": "Detected in 21 source(s). Recognized as Quasar RAT. Detected activity linked to: Bumblebee (Malware), Cotton Sandstorm (Threat-Actor-Group), DadSec (Malware), GHOSTSPIDER (Malware), Quasar RAT (Malware), Salt Typhoon (Threat-Actor-Group), Sneaky 2FA (Malware), Vidar (Malware)",
                    "confidence": 90,
                    "occurrences_count": 21
                }
            ],
            "occurrences_count": 1000
        },
        "enrichment": {
            "related_entities": [
                {
                    "entity_id": "c654837d-444e-4f5c-a444-09fd8250696c",
                    "entity_type": "Malware",
                    "entity_name": "GHOSTSPIDER"
                },
                {
                    "entity_id": "70b54325-05ea-46c6-b4e9-b25bc3617104",
                    "entity_type": "Threat-Actor-Group",
                    "entity_name": "Salt Typhoon"
                },
                {
                    "entity_id": "baffd4c4-4483-4b84-96eb-0d19af94d2e8",
                    "entity_type": "Malware",
                    "entity_name": "DadSec"
                },
                {
                    "entity_id": "862341a5-1951-4e09-b3c1-baac41dc7bcb",
                    "entity_type": "Malware",
                    "entity_name": "Vidar"
                },
                {
                    "entity_id": "7b0a986f-733e-4497-8867-6aed00b802b8",
                    "entity_type": "Threat-Actor-Group",
                    "entity_name": "Cotton Sandstorm"
                },
                {
                    "entity_id": "58cbb47d-176d-4937-9ebc-5121ceb36cf9",
                    "entity_type": "Malware",
                    "entity_name": "Sneaky 2FA"
                },
                {
                    "entity_id": "2728ad3e-d870-4654-afd3-9a839f97dd72",
                    "entity_type": "Malware",
                    "entity_name": "Bumblebee"
                },
                {
                    "entity_id": "fc26b8a7-a7cc-47b8-be1e-92b7a969543b",
                    "entity_type": "Malware",
                    "entity_name": "Quasar RAT"
                }
            ],
            "geo": {
                "country": "United States",
                "city": null
            },
            "asn": {
                "number": 16509,
                "organization": "AMAZON-02"
            },
            "suspicious_urls": [],
            "suspicious_domains": []
        },
        "benign": false
    }
}
```

#### Human Readable Output

### cyberint-get-url

***
Gets Domain from the feed.

#### Base Command

`cyberint-get-url`

#### Input

| **Argument Name** | **Description** | **Required** |
|-------------------|-----------------|--------------|
| value             | URL             | Required     |

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
```!cyberint-get-url value=http://dummy.com```
#### Context Example
```json
{
    "data": {
        "entity": {
            "type": "url",
            "value": "http://dummy.com"
        },
        "risk": {
            "malicious_score": 80,
            "detected_activities": [
                {
                    "type": "infecting_url",
                    "observation_date": "2025-03-05T11:18:01.941280+00:00",
                    "description": "URL that may infect it’s visitors with malware.",
                    "confidence": 100,
                    "occurrences_count": 1
                }
            ],
            "occurrences_count": 1
        },
        "enrichment": {
            "related_entities": null,
            "ips": [],
            "hostname": null,
            "domain": null
        },
        "benign": false
    }
}
```

#### Human Readable Output
