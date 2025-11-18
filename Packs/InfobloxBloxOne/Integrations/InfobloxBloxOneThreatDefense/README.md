Infoblox Threat Defense with DDI integration leverages DNS as the first line of defense to detect and block cyber threats, while also using threat intelligence to manage insight incident response and enrich indicators.
This integration was integrated and tested with version 1.0.0 of Infoblox Threat Defense with DDI.

## Configure Infoblox Threat Defense with DDI in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Service API Key |  | True |
| Source Reliability | Reliability of the source providing the intelligence data. | False |
| Create relationships | Create relationships between indicators as part of Enrichment. | False |
| Fetch incidents |  | False |
| Incident type |  | False |
| Ingestion Type | Select the ingestion type to fetch as XSOAR incident. Default is SOC Insight. | False |
| SOC Insight Status | Retrieve the SOC Insights as specified status. | False |
| SOC Insight Threat Type | Retrieve the SOC Insights as specified threat type. | False |
| SOC Insight Priority Level | Retrieve the SOC Insights as specified priority level. | False |
| DNS Security Event Feed Name | Retrieve the DNS Security Events as specified feed name or custom list name. | False |
| DNS Security Event Network | Retrieve the DNS Security Events as specified network name. | False |
| DNS Security Event Policy Action | Retrieve the DNS Security Events as specified policy action. | False |
| DNS Security Event Policy Name | Retrieve the DNS Security Events as specified policy name. | False |
| DNS Security Event Queried Name | Retrieve the DNS Security Events as specified queried name. | False |
| DNS Security Event Threat Class | Retrieve the DNS Security Events as specified threat class. | False |
| DNS Security Event Threat Family | Retrieve the DNS Security Events as specified threat family. | False |
| DNS Security Event Threat Indicator | Retrieve the DNS Security Events as specified threat indicator. | False |
| DNS Security Event Threat Level | Retrieve the DNS Security Events as specified threat level. | False |
| Max Fetch | The maximum number of SOC Insights or DNS Security Events to fetch each time. If the value is greater than 200, it will be considered as 200. The maximum is 200. | False |
| First fetch timestamp | The date or relative timestamp from which to begin fetching incidents. Note: This parameter is only applicable for DNS Security Events.<br/><br/>Supported formats: 2 minutes, 2 hours, 2 days, 2 weeks, 2 months, 2 years, yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ.<br/><br/>For example: 01 May 2025, 01 May 2025 04:45:33, 2025-05-17T14:05:44Z. | False |
| Incidents Fetch Interval |  | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### bloxone-td-dossier-lookup-get

***
The Dossier Lookup API returns detailed information on the specified indicator from the requested sources.

#### Base Command

`bloxone-td-dossier-lookup-get`

#### Input

| **Argument Name**   | **Description**                                                                                                                                                                                                               | **Required** |
| ------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------ |
| indicator_type      | The type of indcator to search by. Possible values are: host, ip, url, hash, email.                                                                                                                                           | Required     |
| value               | The indicator to search on.                                                                                                                                                                                                   | Required     |
| sources             | The sources to query. Multiple sources can be specified. If no source is specified, the call will search on all available sources. (You can see the list of the available sources by running bloxone-td-dossier-source-list). | Optional     |
| interval_in_seconds | The interval in seconds between each poll. Default is 10.                                                                                                                                                                     | Optional     |
| timeout             | The timeout in seconds until polling ends. Default is 600.                                                                                                                                                                    | Optional     |
| job_id              | used for polling.                                                                                                                                                                                                             | Optional     |

#### Context Output

| **Path**                        | **Type** | **Description**         |
| ------------------------------- | -------- | ----------------------- |
| BloxOneTD.DossierLookup.source  | String   | The Dossier source.     |
| BloxOneTD.DossierLookup.target  | String   | The targeted indicator. |
| BloxOneTD.DossierLookup.task_id | String   | The Dossier task ID.    |
| BloxOneTD.DossierLookup.type    | String   | The indicator type.     |

#### Command example

```!bloxone-td-dossier-lookup-get indicator_type="ip" value="11.22.33.44" sources="activity,threatfox,ccb"```

#### Context Example

```json
{
    "BloxOneTD": {
        "DossierLookup": [
            {
                "params": {
                    "source": "ccb",
                    "target": "11.22.33.44",
                    "type": "ip"
                },
                "status": "success",
                "task_id": "97bdeca2-b66d-47b1-b1ef-9e4833654df2",
                "time": 6401,
                "v": "3.0.0"
            },
            {
                "data": {
                    "impacted_devices": [],
                    "requests_by_day": []
                },
                "params": {
                    "source": "activity",
                    "target": "11.22.33.44",
                    "type": "ip"
                },
                "status": "success",
                "task_id": "4074cb34-2bec-485d-8d6d-9e9cc88d5229",
                "time": 1708,
                "v": "3.0.0"
            },
            {
                "data": {
                    "matches": []
                },
                "params": {
                    "source": "threatfox",
                    "target": "11.22.33.44",
                    "type": "ip"
                },
                "status": "success",
                "task_id": "73892ea3-1e22-433f-bc74-f59133b914d0",
                "time": 8,
                "v": "3.0.0"
            }
        ]
    }
}
```

#### Human Readable Output

>### Lookalike Domain List
>
>|Task Id|Type|Target|Source|
>|---|---|---|---|
>| d418b8d6-831c-4f6f-a31a-6d48995d2267 | ip | 11.22.33.44 | threatfox |
>| 91945be3-0cef-4d03-afd7-e4f25864553d | ip | 11.22.33.44 | ccb |
>| 7145a1ca-40a9-43df-b0a3-c4281e5abd7e | ip | 11.22.33.44 | activity |

### bloxone-td-dossier-source-list

***
Get available Dossier sources.

#### Base Command

`bloxone-td-dossier-source-list`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path**                | **Type** | **Description**            |
| ----------------------- | -------- | -------------------------- |
| BloxOneTD.DossierSource | String   | Available Dossier sources. |

#### Command example

```!bloxone-td-dossier-source-list```

#### Context Example

```json
{
    "BloxOneTD": {
        "DossierSource": [
            "ccb",
            "activity",
            "geo",
            "threatfox"
        ]
    }
}
```

#### Human Readable Output

>### Results
>
>|DossierSource|
>|---|
>| activity |
>| ccb |
>| geo |
>| threatfox |

### bloxone-td-lookalike-domain-list

***
Get lookalike domain lists.

Notice: Submitting indicators using this command might make the indicator data publicly available. See the vendorâ€™s documentation for more details.

#### Base Command

`bloxone-td-lookalike-domain-list`

#### Input

| **Argument Name** | **Description**                                                                                                                                                  | **Required** |
| ----------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------ |
| filter            | The free query filter argument.                                                                                                                                  | Optional     |
| target_domain     | Filter by target domain.                                                                                                                                         | Optional     |
| detected_at       | Filter by values that are greater than or equal to the given value. You can use ISO format (e.g. '2023-02-14T00:11:22Z') or use a relative time (e.g. "3 days"). | Optional     |
| limit             | Maximum number of results to return from the query. Default is 50.                                                                                               | Optional     |
| offset            | Return results starting at this offset. Should be an integer. Default is 0.                                                                                      | Optional     |

#### Context Output

| **Path**                                   | **Type** | **Description**                                       |
| ------------------------------------------ | -------- | ----------------------------------------------------- |
| BloxOneTD.LookalikeDomain.detected_at      | Date     | The date of the lookalike detection.                  |
| BloxOneTD.LookalikeDomain.lookalike_domain | String   | The lookalike domain.                                 |
| BloxOneTD.LookalikeDomain.lookalike_host   | String   | The lookalike host.                                   |
| BloxOneTD.LookalikeDomain.reason           | String   | The reason for the detection.                         |
| BloxOneTD.LookalikeDomain.target_domain    | String   | The domain that was targeted by the lookalike domain. |

#### Command example

```!bloxone-td-lookalike-domain-list detected_at="1y"```

#### Context Example

```json
{
    "BloxOneTD": {
        "LookalikeDomain": [
            {
                "detected_at": "2023-01-27T18:43:01Z",
                "lookalike_domain": "test.a.com",
                "lookalike_host": "test.a.com",
                "reason": "Domain is a lookalike to test.com. The creation date is 2023-01-22.",
                "target_domain": "test.com"
            },
            {
                "detected_at": "2023-01-28T18:36:27Z",
                "lookalike_domain": "test.b.com",
                "lookalike_host": "test.b.com",
                "reason": "Domain is a lookalike to test.com and has suspicious registration, behavior, or associations with known threats. The creation date is 2022-11-30.",
                "suspicious": true,
                "target_domain": "test.com"
            },
            {
                "detected_at": "2023-01-28T18:37:03Z",
                "lookalike_domain": "test.c.com",
                "lookalike_host": "test.c.com",
                "reason": "Domain is a lookalike to test.com. The creation date is 2022-09-18.",
                "target_domain": "test.com"
            }
        ]
    }
}
```

#### Human Readable Output

>### Results
>
>|Detected At|Lookalike Domain|Lookalike Host|Reason|Target Domain|
>|---|---|---|---|---|
>| 2023-01-27T18:43:01Z | test.a.com | test.a.com | Domain is a lookalike to test.com. The creation date is 2023-01-22. | test.com |
>| 2023-01-28T18:36:27Z | test.b.com | test.b.com | Domain is a lookalike to test.com and has suspicious registration, behavior, or associations with known threats. The creation date is 2022-11-30. | test.com |
>| 2023-01-28T18:37:03Z | test.c.com | test.c.com | Domain is a lookalike to test.com. The creation date is 2022-09-18. | test.com |

### infobloxcloud-block-ip

***
The given IP addresses will be added to the provided block list.

#### Base Command

`infobloxcloud-block-ip`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | Specify the IP addresses to block. Supports comma-separated values. | Required |
| custom_list_name | Specify the name of the custom list to add the given IP addresses to. Default is Default Block. | Optional |
| custom_list_type | Specify the type of the custom list to add the given IP addresses to. Possible values are: default_block, custom_list, threat_insight, dga, dnsm, zero_day_dns, threat_insight_nde. Default is default_block. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| InfobloxCloud.CustomList.id | String | The ID of the custom list. |
| InfobloxCloud.CustomList.name | String | The name of the custom list. |
| InfobloxCloud.CustomList.type | String | The type of the custom list. |
| InfobloxCloud.CustomList.items | String | The items in the custom list. |
| InfobloxCloud.CustomList.items_described | Array | The items described in the custom list. |
| InfobloxCloud.CustomList.item_count | Number | The number of items in the custom list. |
| InfobloxCloud.CustomList.confidence_level | String | The confidence level of the custom list. |
| InfobloxCloud.CustomList.created_time | String | The time the custom list was created. |
| InfobloxCloud.CustomList.last_updated_time | String | The time the custom list was last updated. |
| InfobloxCloud.CustomList.description | String | The description of the custom list. |
| InfobloxCloud.CustomList.policies | String | The policies of the custom list. |
| InfobloxCloud.CustomList.tags | String | The tags of the custom list. |
| InfobloxCloud.CustomList.type | String | The type of the custom list. |
| InfobloxCloud.CustomList.threat_level | String | The threat level of the custom list. |

#### Command example

```!infobloxcloud-block-ip ip=0.0.0.0```

#### Context Example

```json
{
    "InfobloxCloud": {
        "CustomList": {
            "confidence_level": "HIGH",
            "created_time": "2024-04-01T18:24:37Z",
            "description": "Auto-generated",
            "id": 456789,
            "item_count": 2,
            "items": [
                "0.0.0.0/32",
                "0.0.0.1/32"
            ],
            "items_described": [
                {
                    "description": "",
                    "item": "0.0.0.0/32",
                    "status": "ACTIVE",
                    "status_details": ""
                },
                {
                    "description": "",
                    "item": "0.0.0.1/32",
                    "status": "ACTIVE",
                    "status_details": ""
                }
            ],
            "name": "Test Block",
            "policies": [
                "Test Policy"
            ],
            "tags": {
                "test_key": "test_value"
            },
            "threat_level": "MEDIUM",
            "type": "test_block",
            "updated_time": "2025-07-29T08:47:54Z"
        }
    }
}
```

#### Human Readable Output

>### '0.0.0.0' indicators added to the 'Test Block' list
>
>|ID|Name|Type|Description|Items|Confidence Level|Threat Level|Tags|Created Time|Updated Time|
>|---|---|---|---|---|---|---|---|---|---|
>| 792594 | Test Block | test_block | Auto-generated | 0.0.0.0/32,<br/>0.0.0.1/32 | HIGH | MEDIUM | test\_key: test\_value | 2024-04-01T18:24:37Z | 2025-07-29T08:47:54Z |

### infobloxcloud-unblock-ip

***
The given IP addresses will be added to the provided allow list.

#### Base Command

`infobloxcloud-unblock-ip`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | Specify the IP addresses to unblock. Supports comma-separated values. | Required |
| custom_list_name | Specify the name of the custom list to add the given IP addresses to. Default is Default Allow. | Optional |
| custom_list_type | Specify the type of the custom list to add the given IP addresses to. Possible values are: default_allow, custom_list, threat_insight, threat_insight_nde. Default is default_allow. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| InfobloxCloud.CustomList.id | String | The ID of the custom list. |
| InfobloxCloud.CustomList.name | String | The name of the custom list. |
| InfobloxCloud.CustomList.type | String | The type of the custom list. |
| InfobloxCloud.CustomList.items | String | The items in the custom list. |
| InfobloxCloud.CustomList.items_described | Array | The items described in the custom list. |
| InfobloxCloud.CustomList.item_count | Number | The number of items in the custom list. |
| InfobloxCloud.CustomList.confidence_level | String | The confidence level of the custom list. |
| InfobloxCloud.CustomList.created_time | String | The time the custom list was created. |
| InfobloxCloud.CustomList.last_updated_time | String | The time the custom list was last updated. |
| InfobloxCloud.CustomList.description | String | The description of the custom list. |
| InfobloxCloud.CustomList.policies | String | The policies of the custom list. |
| InfobloxCloud.CustomList.tags | String | The tags of the custom list. |
| InfobloxCloud.CustomList.type | String | The type of the custom list. |
| InfobloxCloud.CustomList.threat_level | String | The threat level of the custom list. |

#### Command example

```!infobloxcloud-unblock-ip ip=0.0.0.0```

#### Context Example

```json
{
    "InfobloxCloud": {
        "CustomList": {
            "confidence_level": "HIGH",
            "created_time": "2024-04-01T18:24:37Z",
            "description": "Auto-generated",
            "id": 123456,
            "item_count": 2,
            "items": [
                "0.0.0.0/32",
                "0.0.0.1/32"
            ],
            "items_described": [
                {
                    "description": "",
                    "item": "0.0.0.0/32",
                    "status": "ACTIVE",
                    "status_details": ""
                },
                {
                    "description": "",
                    "item": "0.0.0.1/32",
                    "status": "ACTIVE",
                    "status_details": ""
                }
            ],
            "name": "Test Allow",
            "policies": [
                "Test Policy"
            ],
            "tags": {
                "test_key": "test_value"
            },
            "threat_level": "MEDIUM",
            "type": "test_allow",
            "updated_time": "2025-07-29T08:48:02Z"
        }
    }
}
```

#### Human Readable Output

>### '0.0.0.0' indicators added to the 'Test Allow' list
>
>|ID|Name|Type|Description|Items|Confidence Level|Threat Level|Tags|Created Time|Updated Time|
>|---|---|---|---|---|---|---|---|---|---|
>| 123456 | Test Allow | test_allow | Auto-generated | 0.0.0.0/32,<br/>0.0.0.1/32 | HIGH | MEDIUM | test\_key: test\_value | 2024-04-01T18:24:37Z | 2025-07-29T08:48:02Z |

### infobloxcloud-block-domain

***
The given domains will be added to the provided block list.

#### Base Command

`infobloxcloud-block-domain`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | Specify the Domains to block. Supports comma-separated values. | Required |
| custom_list_name | Specify the name of the custom list to add the given domains to. Default is Default Block. | Optional |
| custom_list_type | Specify the type of the custom list to add the given domains to. Possible values are: default_block, custom_list, threat_insight, dga, dnsm, zero_day_dns, threat_insight_nde. Default is default_block. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| InfobloxCloud.CustomList.id | String | The ID of the custom list. |
| InfobloxCloud.CustomList.name | String | The name of the custom list. |
| InfobloxCloud.CustomList.type | String | The type of the custom list. |
| InfobloxCloud.CustomList.items | String | The items in the custom list. |
| InfobloxCloud.CustomList.items_described | Array | The items described in the custom list. |
| InfobloxCloud.CustomList.item_count | Number | The number of items in the custom list. |
| InfobloxCloud.CustomList.confidence_level | String | The confidence level of the custom list. |
| InfobloxCloud.CustomList.created_time | String | The time the custom list was created. |
| InfobloxCloud.CustomList.last_updated_time | String | The time the custom list was last updated. |
| InfobloxCloud.CustomList.description | String | The description of the custom list. |
| InfobloxCloud.CustomList.policies | String | The policies of the custom list. |
| InfobloxCloud.CustomList.tags | String | The tags of the custom list. |
| InfobloxCloud.CustomList.type | String | The type of the custom list. |
| InfobloxCloud.CustomList.threat_level | String | The threat level of the custom list. |

#### Command example

```!infobloxcloud-block-domain domain="test.com"```

#### Context Example

```json
{
    "InfobloxCloud": {
        "CustomList": {
            "confidence_level": "HIGH",
            "created_time": "2024-04-01T18:24:37Z",
            "description": "Auto-generated",
            "id": 456789,
            "item_count": 2,
            "items": [
                "test.com",
                "test.org"
            ],
            "items_described": [
                {
                    "description": "",
                    "item": "test.com",
                    "status": "ACTIVE",
                    "status_details": ""
                },
                {
                    "description": "",
                    "item": "test.org",
                    "status": "ACTIVE",
                    "status_details": ""
                }
            ],
            "name": "Test Block",
            "policies": [
                "Test Policy"
            ],
            "tags": null,
            "threat_level": "MEDIUM",
            "type": "test_block",
            "updated_time": "2025-07-29T10:27:49Z"
        }
    }
}
```

#### Human Readable Output

>### 'test.com' indicator added to the 'Test Block' list
>
>|ID|Name|Type|Description|Items|Confidence Level|Threat Level|Created Time|Updated Time|
>|---|---|---|---|---|---|---|---|---|
>| 456789 | Test Block | test_block | Auto-generated | test.com,<br/>test.org | HIGH | MEDIUM | 2024-04-01T18:24:37Z | 2025-07-29T10:27:49Z |

### infobloxcloud-unblock-domain

***
The given domains will be added to the provided allow list.

#### Base Command

`infobloxcloud-unblock-domain`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | Specify the Domains to unblock. Supports comma-separated values. | Required |
| custom_list_name | Specify the name of the custom list to add the given domains to. Default is Default Allow. | Optional |
| custom_list_type | Specify the type of the custom list to add the given domains to. Possible values are: default_allow, custom_list, threat_insight, threat_insight_nde. Default is default_allow. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| InfobloxCloud.CustomList.id | String | The ID of the custom list. |
| InfobloxCloud.CustomList.name | String | The name of the custom list. |
| InfobloxCloud.CustomList.type | String | The type of the custom list. |
| InfobloxCloud.CustomList.items | String | The items in the custom list. |
| InfobloxCloud.CustomList.items_described | Array | The items described in the custom list. |
| InfobloxCloud.CustomList.item_count | Number | The number of items in the custom list. |
| InfobloxCloud.CustomList.confidence_level | String | The confidence level of the custom list. |
| InfobloxCloud.CustomList.created_time | String | The time the custom list was created. |
| InfobloxCloud.CustomList.last_updated_time | String | The time the custom list was last updated. |
| InfobloxCloud.CustomList.description | String | The description of the custom list. |
| InfobloxCloud.CustomList.policies | String | The policies of the custom list. |
| InfobloxCloud.CustomList.tags | String | The tags of the custom list. |
| InfobloxCloud.CustomList.type | String | The type of the custom list. |
| InfobloxCloud.CustomList.threat_level | String | The threat level of the custom list. |

#### Command example

```!infobloxcloud-unblock-domain domain="test.com"```

#### Context Example

```json
{
    "InfobloxCloud": {
        "CustomList": {
            "confidence_level": "HIGH",
            "created_time": "2024-04-01T18:24:37Z",
            "description": "Auto-generated",
            "id": 123456,
            "item_count": 2,
            "items": [
                "test.com",
                "test.org"
            ],
            "items_described": [
                {
                    "description": "",
                    "item": "test.com",
                    "status": "ACTIVE",
                    "status_details": ""
                },
                {
                    "description": "",
                    "item": "test.org",
                    "status": "ACTIVE",
                    "status_details": ""
                }
            ],
            "name": "Test Allow",
            "policies": [
                "Test Policy"
            ],
            "tags": {
                "test_key": "test_value"
            },
            "threat_level": "MEDIUM",
            "type": "test_allow",
            "updated_time": "2025-07-29T10:27:56Z"
        }
    }
}
```

#### Human Readable Output

>### 'test.com' indicator added to the 'Test Allow' list
>
>|ID|Name|Type|Description|Items|Confidence Level|Threat Level|Tags|Created Time|Updated Time|
>|---|---|---|---|---|---|---|---|---|---|
>| 123456 | Test Allow | test_allow | Auto-generated | test.com,<br/>test.org | HIGH | MEDIUM | test\_key: test\_value | 2024-04-01T18:24:37Z | 2025-07-29T10:27:56Z |

### infobloxcloud-customlist-indicator-remove

***
The given indicators will be removed from the provided custom list.

#### Base Command

`infobloxcloud-customlist-indicator-remove`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicators | Specify the indicators to remove from the custom list. Format accepted is: "0.0.0.0, example.com". | Required |
| custom_list_name | Specify the name of the custom list to remove the given indicators from. | Required |
| custom_list_type | Specify the type of the custom list to remove the given indicators from. Possible values are: default_allow, default_block, custom_list, threat_insight, dga, dnsm, zero_day_dns, threat_insight_nde. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| InfobloxCloud.CustomList.id | String | The ID of the custom list. |
| InfobloxCloud.CustomList.name | String | The name of the custom list. |
| InfobloxCloud.CustomList.type | String | The type of the custom list. |
| InfobloxCloud.CustomList.items | String | The items in the custom list. |
| InfobloxCloud.CustomList.items_described | Array | The items described in the custom list. |
| InfobloxCloud.CustomList.item_count | Number | The number of items in the custom list. |
| InfobloxCloud.CustomList.confidence_level | String | The confidence level of the custom list. |
| InfobloxCloud.CustomList.created_time | String | The time the custom list was created. |
| InfobloxCloud.CustomList.last_updated_time | String | The time the custom list was last updated. |
| InfobloxCloud.CustomList.description | String | The description of the custom list. |
| InfobloxCloud.CustomList.policies | String | The policies of the custom list. |
| InfobloxCloud.CustomList.tags | String | The tags of the custom list. |
| InfobloxCloud.CustomList.type | String | The type of the custom list. |
| InfobloxCloud.CustomList.threat_level | String | The threat level of the custom list. |

#### Command example

```!infobloxcloud-customlist-indicator-remove indicators="0.0.0.0" custom_list_name="Test Allow" custom_list_type="test_allow"```

#### Context Example

```json
{
    "InfobloxCloud": {
        "CustomList": {
            "confidence_level": "HIGH",
            "created_time": "2024-04-01T18:24:37Z",
            "description": "Auto-generated",
            "id": 123456,
            "item_count": 1,
            "items": [
                "example.com"
            ],
            "items_described": [
                {
                    "description": "",
                    "item": "example.com",
                    "status": "ACTIVE",
                    "status_details": ""
                }
            ],
            "name": "Test Allow",
            "policies": [
                "Test Policy",
            ],
            "tags": {
                "test_key": "test_value"
            },
            "threat_level": "MEDIUM",
            "type": "test_allow",
            "updated_time": "2025-07-31T11:07:41Z"
        }
    }
}
```

#### Human Readable Output

>### '0.0.0.0' indicators removed from the 'Test Allow' list
>
>|ID|Name|Type|Description|Items|Confidence Level|Threat Level|Tags|Created Time|Updated Time|
>|---|---|---|---|---|---|---|---|---|---|
>| 123456 | Test Allow | test_allow | Auto-generated | example.com | HIGH | MEDIUM | test\_key: test\_value | 2024-04-01T18:24:37Z | 2025-07-31T11:07:41Z |

### ip

***
Gets the comprehensive IP reputation and threat intelligence from Infoblox Threat Defense, including threat indicators, IPAM address information, and standard IP reputation data.

#### Base Command

`ip`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | IP\(s\) for which to retrieve reputation and threat intelligence. Supports comma-separated values. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| InfobloxCloud.IP.ip | String | The requested IP address. |
| IP.Address | String | IP address. |
| IP.Relationships.EntityA | String | The source of the relationship. |
| IP.Relationships.EntityB | String | The destination of the relationship. |
| IP.Relationships.Relationship | String | The name of the relationship. |
| IP.Relationships.EntityAType | String | The type of the source of the relationship. |
| IP.Relationships.EntityBType | String | The type of the destination of the relationship. |
| IP.ASN | String | The autonomous system name for the IP address, for example: "AS8948". |
| IP.Hostname | String | The hostname that is mapped to this IP address. |
| IP.Geo.Location | String | The geolocation where the IP address is located, in the format: latitude:longitude. |
| IP.Geo.Country | String | The country in which the IP address is located. |
| IP.Geo.Description | String | Additional information about the location. |
| IP.DetectionEngines | Number | The total number of engines that checked the indicator. |
| IP.PositiveDetections | Number | The number of engines that positively detected the indicator as malicious. |
| IP.Malicious.Vendor | String | The vendor reporting the IP address as malicious. |
| IP.Malicious.Description | String | A description explaining why the IP address was reported as malicious. |
| IP.Tags | Unknown | \(List\) Tags of the IP address. |
| IP.FeedRelatedIndicators.value | String | Indicators that are associated with the IP address. |
| IP.FeedRelatedIndicators.type | String | The type of the indicators that are associated with the IP address. |
| IP.FeedRelatedIndicators.description | String | The description of the indicators that are associated with the IP address. |
| IP.MalwareFamily | String | The malware family associated with the IP address. |
| IP.Organization.Name | String | The organization of the IP address. |
| IP.Organization.Type | String | The organization type of the IP address. |
| IP.ASOwner | String | The autonomous system owner of the IP address. |
| IP.Region | String | The region in which the IP address is located. |
| IP.Port | String | Ports that are associated with the IP address. |
| IP.Internal | Boolean | Whether the IP address is internal or external. |
| IP.UpdatedDate | Date | The date that the IP address was last updated. |
| IP.Registrar.Abuse.Name | String | The name of the contact for reporting abuse. |
| IP.Registrar.Abuse.Address | String | The address of the contact for reporting abuse. |
| IP.Registrar.Abuse.Country | String | The country of the contact for reporting abuse. |
| IP.Registrar.Abuse.Network | String | The network of the contact for reporting abuse. |
| IP.Registrar.Abuse.Phone | String | The phone number of the contact for reporting abuse. |
| IP.Registrar.Abuse.Email | String | The email address of the contact for reporting abuse. |
| IP.Campaign | String | The campaign associated with the IP address. |
| IP.TrafficLightProtocol | String | The Traffic Light Protocol \(TLP\) color that is suitable for the IP address. |
| IP.CommunityNotes.note | String | Notes on the IP address that were given by the community. |
| IP.CommunityNotes.timestamp | Date | The time in which the note was published. |
| IP.Publications.source | String | The source in which the article was published. |
| IP.Publications.title | String | The name of the article. |
| IP.Publications.link | String | A link to the original article. |
| IP.Publications.timestamp | Date | The time in which the article was published. |
| IP.ThreatTypes.threatcategory | String | The threat category associated to this indicator by the source vendor. For example, Phishing, Control, TOR, etc. |
| IP.ThreatTypes.threatcategoryconfidence | String | The confidence level provided by the vendor for the threat type category For example, a confidence of 90 for the threat type category 'malware' means that the vendor rates that this is 90% confidence of being a malware. |
| DBotScore.Indicator | String | The indicator that was tested. |
| DBotScore.Type | String | The indicator type. |
| DBotScore.Vendor | String | The vendor used to calculate the score. |
| DBotScore.Score | Number | The actual score. |
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. |
| InfobloxCloud.IP.Threat.id | String | The unique identifier for the threat indicator. |
| InfobloxCloud.IP.Threat.type | String | The type of threat indicator. |
| InfobloxCloud.IP.Threat.ip | String | The IP address identified as a threat indicator. |
| InfobloxCloud.IP.Threat.profile | String | The threat profile or classification source. |
| InfobloxCloud.IP.Threat.property | String | The specific property or category of the threat. |
| InfobloxCloud.IP.Threat.class | String | The classification of the threat. |
| InfobloxCloud.IP.Threat.threat_level | Number | The numeric threat level score. |
| InfobloxCloud.IP.Threat.threat_label | String | The textual threat level label. |
| InfobloxCloud.IP.Threat.expiration | Date | The timestamp when the threat indicator will expire. |
| InfobloxCloud.IP.Threat.detected | Date | The timestamp when the threat activity was first detected. |
| InfobloxCloud.IP.Threat.received | Date | The timestamp when the threat indicator was received by the system. |
| InfobloxCloud.IP.Threat.imported | Date | The timestamp when the threat indicator was imported into the system. |
| InfobloxCloud.IP.Threat.up | String | The boolean status flag indicating whether the threat indicator is currently active. |
| InfobloxCloud.IP.Threat.batch_id | String | The batch ID of the threat indicator. |
| InfobloxCloud.IP.Threat.confidence | Number | The numeric confidence score representing the reliability of the threat indicator. |
| InfobloxCloud.IP.Threat.extended.notes | String | The additional notes or information about the threat indicator. |
| InfobloxCloud.IP.Threat.threat_score | Number | The numeric score representing the calculated threat severity. |
| InfobloxCloud.IP.Threat.threat_score_rating | String | The textual rating of the threat score. |
| InfobloxCloud.IP.Threat.threat_score_vector | String | The vector string representing threat scoring details. |
| InfobloxCloud.IP.Threat.risk_score | Number | The numeric risk score assigned to the threat indicator. |
| InfobloxCloud.IP.Threat.risk_score_rating | String | The textual rating of the risk score. |
| InfobloxCloud.IP.Threat.risk_score_vector | String | The vector string representing risk scoring details. |
| InfobloxCloud.IP.Threat.confidence_score | Number | The numeric confidence score for the threat assessment. |
| InfobloxCloud.IP.Threat.confidence_score_rating | String | The textual rating of the confidence score. |
| InfobloxCloud.IP.Threat.confidence_score_vector | String | The vector string representing confidence scoring details. |
| InfobloxCloud.IP.Threat.extended.cyberint_guid | String | The unique identifier for the threat indicator. |
| InfobloxCloud.IP.Threat.extended.attack_chain | String | The attack chain associated with the threat indicator. |
| InfobloxCloud.IP.Threat.extended.extended | String | The additional information or metadata associated with the threat indicator. |
| InfobloxCloud.IP.Threat.extended.protocol | String | The protocol associated with the threat indicator. |
| InfobloxCloud.IP.Threat.extended.references | String | The references associated with the threat indicator. |
| InfobloxCloud.IP.Threat.extended.threat_actor | String | The threat actor associated with the threat indicator. |
| InfobloxCloud.IP.Threat.extended.threat_actor_vector | String | The vector string representing threat actor details. |
| InfobloxCloud.IP.Threat.extended.risk_score | String | The numeric risk score assigned to the threat indicator. |
| InfobloxCloud.IP.Threat.extended.threat_score | String | The numeric threat score assigned to the threat indicator. |
| InfobloxCloud.IP.Threat.extended.sample_sha256 | String | The SHA-256 hash of the sample associated with the threat. |
| InfobloxCloud.IP.Threat.extended.original_profile | String | The original profile or classification source of the threat. |
| InfobloxCloud.IP.Address.address | String | The IP address assigned to the resource. |
| InfobloxCloud.IP.Address.comment | String | A user-provided comment or annotation for the address record. |
| InfobloxCloud.IP.Address.compartment_id | String | The compartment ID of the IP address. |
| InfobloxCloud.IP.Address.created_at | Date | The timestamp when the IP address was created. |
| InfobloxCloud.IP.Address.dhcp_info | Unknown | The DHCP information associated with the IP address. |
| InfobloxCloud.IP.Address.disable_dhcp | Boolean | A boolean flag indicating whether DHCP is disabled for the IP address. |
| InfobloxCloud.IP.Address.discovery_attrs | Unknown | The discovery attributes associated with the IP address. |
| InfobloxCloud.IP.Address.discovery_metadata | Unknown | The discovery metadata associated with the IP address. |
| InfobloxCloud.IP.Address.external_keys | Unknown | External keys associated with the IP address. |
| InfobloxCloud.IP.Address.host | Unknown | The host name of the IP address. |
| InfobloxCloud.IP.Address.hwaddr | String | The hardware address of the IP address. |
| InfobloxCloud.IP.Address.id | String | The unique identifier of the IP address. |
| InfobloxCloud.IP.Address.interface | String | The interface of the IP address. |
| InfobloxCloud.IP.Address.names | Unknown | The names associated with the IP address. |
| InfobloxCloud.IP.Address.parent | String | The parent of the IP address. |
| InfobloxCloud.IP.Address.protocol | String | The protocol of the IP address. |
| InfobloxCloud.IP.Address.range | String | The range of the IP address. |
| InfobloxCloud.IP.Address.space | String | The space of the IP address. |
| InfobloxCloud.IP.Address.state | String | The state of the IP address. |
| InfobloxCloud.IP.Address.tags | Unknown | The tags associated with the IP address. |
| InfobloxCloud.IP.Address.updated_at | Date | The timestamp when the IP address was last updated. |
| InfobloxCloud.IP.Address.usage | String | The usage of the IP address. |
| InfobloxCloud.IP.Address.names.name | String | The name of the IP address. |
| InfobloxCloud.IP.Address.names.type | Unknown | The type of the IP address. |

#### Command example

```!ip ip="0.0.0.1"```

#### Context Example

```json
{
    "DBotScore": {
        "Indicator": "0.0.0.1",
        "Reliability": "A - Completely reliable",
        "Score": 3,
        "Type": "ip",
        "Vendor": "InfobloxThreatDefensewithDDI"
    },
    "IP": {
        "Address": "0.0.0.1",
        "Description": "Malware Download associated with the APT group",
        "ThreatTypes": [
            {
                "threatcategory": "IP",
                "threatcategoryconfidence": "100"
            }
        ],
        "Hostname": "name",
        "DetectionEngines": 1,
        "Tags": [
            "cyberint_guid: simple_cyberint_guid",
            "notes: Malware Download associated with the APT group",
            "Protocol: ip4",
            "State: used",
            "temp: true"
        ],
        "MalwareFamily": "APT",
        "Malicious": {
            "Vendor": "InfobloxThreatDefensewithDDI",
            "Description": "Malware Download associated with the APT group"
        }
    },
    "InfobloxCloud": {
        "IP": {
            "ip": "0.0.0.1",
            "Threat": {
                "id": "00000000-0000-0000-0000-000000000000",
                "type": "IP",
                "ip": "0.0.0.1",
                "profile": "IID",
                "property": "APT_Malware",
                "class": "APT",
                "threat_level": 100,
                "expiration": "2042-11-01T09:29:18.721Z",
                "detected": "2025-07-29T09:29:18.721Z",
                "received": "2025-07-29T09:31:39.329Z",
                "imported": "2025-07-29T09:31:39.329Z",
                "up": "true",
                "confidence": 100,
                "batch_id": "00000000-0000-0000-0000-000000000000",
                "threat_score": 10,
                "threat_score_rating": "Critical",
                "threat_score_vector": "simple_threat_vector",
                "risk_score": 9.9,
                "risk_score_rating": "Critical",
                "risk_score_vector": "simple_risk_vector",
                "confidence_score": 0.1,
                "confidence_score_rating": "Unconfirmed",
                "confidence_score_vector": "simple_confidence_vector",
                "extended": {
                    "cyberint_guid": "simple_cyberint_guid",
                    "notes": "Malware Download associated with the APT group"
                }
            },
            "Address": {
                "address": "0.0.0.1",
                "comment": "comment",
                "compartment_id": "00000000-0000-0000-0000-000000000000",
                "created_at": "2025-06-27T13:07:21.476126Z",
                "disable_dhcp": false,
                "external_keys": {
                    "e3": "3e3"
                },
                "host": "ipam/host/00000000-0000-0000-0000-000000000000",
                "hwaddr": "00:00:00:00:00:00",
                "id": "ipam/address/00000000-0000-0000-0000-000000000000",
                "interface": "interface",
                "names": [
                    {
                        "name": "name",
                        "type": "user"
                    }
                ],
                "parent": "ipam/subnet/00000000-0000-0000-0000-000000000000",
                "protocol": "ip4",
                "range": "ipam/range/00000000-0000-0000-0000-000000000000",
                "space": "ipam/ip_space/00000000-0000-0000-0000-000000000000",
                "state": "used",
                "tags": {
                    "temp": "true"
                },
                "updated_at": "2025-06-27T13:07:21.429056Z",
                "usage": [
                    "IPAM RESERVED"
                ]
            }
        }
    }
}
```

#### Human Readable Output

>## Information for the given Bad IP: 0.0.0.1
>
>### Threat Intelligence Summary
>
>|Batch Id|Class|Confidence|Confidence Score|Confidence Score Rating|Confidence Score Vector|Detected|Expiration|Extended|Id|Imported|IP|Profile|Property|Received|Risk Score|Risk Score Rating|Risk Score Vector|Threat Level|Threat Score|Threat Score Rating|Threat Score Vector|Type|Up|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 00000000-0000-0000-0000-000000000000 | APT | 100 | 0.1 | Unconfirmed | simple_confidence_vector | 2025-07-29T09:29:18.721Z | 2042-11-01T09:29:18.721Z | ***cyberint_guid***: simple_cyberint_guid<br/>***notes***: Malware Download associated with the APT group | 00000000-0000-0000-0000-000000000000 | 2025-07-29T09:31:39.329Z | 0.0.0.1 | IID | APT_Malware | 2025-07-29T09:31:39.329Z | 9.9 | Critical | simple_risk_vector | 100 | 10 | Critical | simple_threat_vector | IP | true |
>
>### Address Information
>
>|Address|Comment|Compartment Id|Created At|Disable Dhcp|External Keys|Host|Hwaddr|Id|Interface|Names|Parent|Protocol|Range|Space|State|Tags|Updated At|Usage|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 0.0.0.1 | comment | 00000000-0000-0000-0000-000000000000 | 2025-06-27T13:07:21.476126Z | False | ***e3***: 3e3 | ipam/host/00000000-0000-0000-0000-000000000000 | 00:00:00:00:00:00 | ipam/address/00000000-0000-0000-0000-000000000000 | interface | **-** ***name***: name<br/> ***type***: user | ipam/subnet/00000000-0000-0000-0000-000000000000 | ip4 | ipam/range/00000000-0000-0000-0000-000000000000 | ipam/ip_space/00000000-0000-0000-0000-000000000000 | used | ***temp***: true | 2025-06-27T13:07:21.429056Z | ***values***: IPAM RESERVED |

### domain

***
Gets the comprehensive domain/host reputation and threat intelligence from Infoblox Threat Defense, including threat indicators, IPAM address information and standard domain reputation data.

#### Base Command

`domain`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | Domain\(s\) or Hosts\(s\) for which to retrieve reputation and threat intelligence. Supports comma-separated values. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| InfobloxCloud.Domain.domain | String | The requested domain. |
| Domain.Name | String | The domain name, for example: "google.com". |
| Domain.Relationships.EntityA | string | The source of the relationship. |
| Domain.Relationships.EntityB | string | The destination of the relationship. |
| Domain.Relationships.Relationship | string | The name of the relationship. |
| Domain.Relationships.EntityAType | string | The type of the source of the relationship. |
| Domain.Relationships.EntityBType | string | The type of the destination of the relationship. |
| Domain.DNS | String | A list of IP objects resolved by DNS. |
| Domain.DetectionEngines | Number | The total number of engines that checked the indicator. |
| Domain.PositiveDetections | Number | The number of engines that positively detected the indicator as malicious. |
| Domain.CreationDate | Date | The date that the domain was created. |
| Domain.UpdatedDate | String | The date that the domain was last updated. |
| Domain.ExpirationDate | Date | The expiration date of the domain. |
| Domain.DomainStatus | Datte | The status of the domain. |
| Domain.NameServers | Unknown | \(List&lt;String&gt;\) Name servers of the domain. |
| Domain.Organization | String | The organization of the domain. |
| Domain.Subdomains | Unknown | \(List&lt;String&gt;\) Subdomains of the domain. |
| Domain.Admin.Country | String | The country of the domain administrator. |
| Domain.Admin.Email | String | The email address of the domain administrator. |
| Domain.Admin.Name | String | The name of the domain administrator. |
| Domain.Admin.Phone | String | The phone number of the domain administrator. |
| Domain.Registrant.Country | String | The country of the registrant. |
| Domain.Registrant.Email | String | The email address of the registrant. |
| Domain.Registrant.Name | String | The name of the registrant. |
| Domain.Registrant.Phone | String | The phone number for receiving abuse reports. |
| Domain.Tags | Unknown | \(List\) Tags of the domain. |
| Domain.FeedRelatedIndicators.value | String | Indicators that are associated with the domain. |
| Domain.FeedRelatedIndicators.type | String | The type of the indicators that are associated with the domain. |
| Domain.FeedRelatedIndicators.description | String | The description of the indicators that are associated with the domain. |
| Domain.MalwareFamily | String | The malware family associated with the domain. |
| Domain.WHOIS.DomainStatus | String | The status of the domain. |
| Domain.WHOIS.NameServers | String | \(List&lt;String&gt;\) Name servers of the domain. |
| Domain.WHOIS.CreationDate | Date | The date that the domain was created. |
| Domain.WHOIS.UpdatedDate | Date | The date that the domain was last updated. |
| Domain.WHOIS.ExpirationDate | Date | The expiration date of the domain. |
| Domain.WHOIS.Registrant.Name | String | The name of the registrant. |
| Domain.WHOIS.Registrant.Email | String | The email address of the registrant. |
| Domain.WHOIS.Registrant.Phone | String | The phone number of the registrant. |
| Domain.WHOIS.Registrar.Name | String | The name of the registrar. |
| Domain.WHOIS.Registrar.AbuseEmail | String | The email address of the contact for reporting abuse. |
| Domain.WHOIS.Registrar.AbusePhone | String | The phone number of contact for reporting abuse. |
| Domain.WHOIS.Admin.Name | String | The name of the domain administrator. |
| Domain.WHOIS.Admin.Email | String | The email address of the domain administrator. |
| Domain.WHOIS.Admin.Phone | String | The phone number of the domain administrator. |
| Domain.WHOIS/History | String | List of Whois objects. |
| Domain.Malicious.Vendor | String | The vendor reporting the domain as malicious. |
| Domain.Malicious.Description | String | A description explaining why the domain was reported as malicious. |
| Domain.DomainIDNName | String | The internationalized domain name \(IDN\) of the domain. |
| Domain.Port | String | Ports that are associated with the domain. |
| Domain.Internal | Bool | Whether or not the domain is internal or external. |
| Domain.Category | String | The category associated with the indicator. |
| Domain.Campaign | String | The campaign associated with the domain. |
| Domain.TrafficLightProtocol | String | The Traffic Light Protocol \(TLP\) color that is suitable for the domain. |
| Domain.ThreatTypes.threatcategory | String | The threat category associated to this indicator by the source vendor. For example, Phishing, Control, TOR, etc. |
| Domain.ThreatTypes.threatcategoryconfidence | String | Threat Category Confidence is the confidence level provided by the vendor for the threat type category For example a confidence of 90 for threat type category 'malware' means that the vendor rates that this is 90% confidence of being a malware. |
| Domain.Geo.Location | String | The geolocation where the domain address is located, in the format: latitude:longitude. |
| Domain.Geo.Country | String | The country in which the domain address is located. |
| Domain.Geo.Description | String | Additional information about the location. |
| Domain.Tech.Country | String | The country of the domain technical contact. |
| Domain.Tech.Name | String | The name of the domain technical contact. |
| Domain.Tech.Organization | String | The organization of the domain technical contact. |
| Domain.Tech.Email | String | The email address of the domain technical contact. |
| Domain.CommunityNotes.note | String | Notes on the domain that were given by the community. |
| Domain.CommunityNotes.timestamp | Date | The time in which the note was published. |
| Domain.Publications.source | String | The source in which the article was published. |
| Domain.Publications.title | String | The name of the article. |
| Domain.Publications.link | String | A link to the original article. |
| Domain.Publications.timestamp | Date | The time in which the article was published. |
| Domain.Billing | String | The billing address of the domain. |
| DBotScore.Indicator | String | The indicator that was tested. |
| DBotScore.Type | String | The indicator type. |
| DBotScore.Vendor | String | The vendor used to calculate the score. |
| DBotScore.Score | Number | The actual score. |
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. |
| InfobloxCloud.Domain.Threat.id | String | The unique identifier for the threat indicator. |
| InfobloxCloud.Domain.Threat.type | String | The type of threat indicator. |
| InfobloxCloud.Domain.Threat.domain | String | The domain identified as a threat indicator. |
| InfobloxCloud.Domain.Threat.profile | String | The threat profile or classification source. |
| InfobloxCloud.Domain.Threat.property | String | The specific property or category of the threat. |
| InfobloxCloud.Domain.Threat.class | String | The classification of the threat. |
| InfobloxCloud.Domain.Threat.threat_level | Number | The numeric threat level score. |
| InfobloxCloud.Domain.Threat.threat_label | String | The textual threat level label. |
| InfobloxCloud.Domain.Threat.expiration | Date | The timestamp when the threat indicator will expire. |
| InfobloxCloud.Domain.Threat.detected | Date | The timestamp when the threat activity was first detected. |
| InfobloxCloud.Domain.Threat.received | Date | The timestamp when the threat indicator was received by the system. |
| InfobloxCloud.Domain.Threat.imported | Date | The timestamp when the threat indicator was imported into the system. |
| InfobloxCloud.Domain.Threat.up | String | The boolean status flag indicating whether the threat indicator is currently active. |
| InfobloxCloud.Domain.Threat.batch_id | String | The batch ID of the threat indicator. |
| InfobloxCloud.Domain.Threat.confidence | Number | The numeric confidence score representing the reliability of the threat indicator. |
| InfobloxCloud.Domain.Threat.extended.notes | String | The additional notes or information about the threat indicator. |
| InfobloxCloud.Domain.Threat.threat_score | Number | The numeric score representing the calculated threat severity. |
| InfobloxCloud.Domain.Threat.threat_score_rating | String | The textual rating of the threat score. |
| InfobloxCloud.Domain.Threat.threat_score_vector | String | The vector string representing threat scoring details. |
| InfobloxCloud.Domain.Threat.risk_score | Number | The numeric risk score assigned to the threat indicator. |
| InfobloxCloud.Domain.Threat.risk_score_rating | String | The textual rating of the risk score. |
| InfobloxCloud.Domain.Threat.risk_score_vector | String | The vector string representing risk scoring details. |
| InfobloxCloud.Domain.Threat.confidence_score | Number | The numeric confidence score for the threat assessment. |
| InfobloxCloud.Domain.Threat.confidence_score_rating | String | The textual rating of the confidence score. |
| InfobloxCloud.Domain.Threat.confidence_score_vector | String | The vector string representing confidence scoring details. |
| InfobloxCloud.Domain.Threat.extended.cyberint_guid | String | The unique identifier for the threat indicator. |
| InfobloxCloud.Domain.Threat.extended.attack_chain | String | The attack chain associated with the threat indicator. |
| InfobloxCloud.Domain.Threat.extended.extended | String | The additional information or metadata associated with the threat indicator. |
| InfobloxCloud.Domain.Threat.extended.protocol | String | The protocol associated with the threat indicator. |
| InfobloxCloud.Domain.Threat.extended.references | String | The references associated with the threat indicator. |
| InfobloxCloud.Domain.Threat.extended.threat_actor | String | The threat actor associated with the threat indicator. |
| InfobloxCloud.Domain.Threat.extended.threat_actor_vector | String | The vector string representing threat actor details. |
| InfobloxCloud.Domain.Threat.extended.risk_score | String | The numeric risk score assigned to the threat indicator. |
| InfobloxCloud.Domain.Threat.extended.threat_score | String | The numeric threat score assigned to the threat indicator. |
| InfobloxCloud.Domain.Threat.extended.sample_sha256 | String | The SHA-256 hash of the sample associated with the threat. |
| InfobloxCloud.Domain.Threat.extended.original_profile | String | The original profile or classification source of the threat. |
| InfobloxCloud.Domain.Threat.dga | String | The domain name generated by a DGA \(Domain Generation Algorithm\). |
| InfobloxCloud.Domain.Threat.host | String | The host name of the domain. |
| InfobloxCloud.Domain.Threat.tld | String | The top-level domain \(TLD\) of the threat. |
| InfobloxCloud.Domain.Address.addresses.address | String | The address of the IP address. |
| InfobloxCloud.Domain.Address.addresses.ref | String | The reference of the IP address. |
| InfobloxCloud.Domain.Address.addresses.space | String | The space of the IP address. |
| InfobloxCloud.Domain.Address.auto_generate_records | Boolean | A boolean flag indicating whether auto generate records is enabled for the IP address. |
| InfobloxCloud.Domain.Address.comment | String | The description for the IPAM host. |
| InfobloxCloud.Domain.Address.created_at | Date | Time when the object has been created. |
| InfobloxCloud.Domain.Address.host_names | Unknown | The name records to be generated for the host. |
| InfobloxCloud.Domain.Address.id | String | The resource identifier. |
| InfobloxCloud.Domain.Address.name | String | The name of the IPAM host. |
| InfobloxCloud.Domain.Address.host_names.alias | Boolean | A boolean flag indicating whether the name record is an alias. |
| InfobloxCloud.Domain.Address.host_names.name | String | The name of the host. |
| InfobloxCloud.Domain.Address.host_names.primary_name | Boolean | A boolean flag indicating whether the name record is the primary name. |
| InfobloxCloud.Domain.Address.host_names.zone | String | The zone of the host. |
| InfobloxCloud.Domain.Address.tags | Unknown | The tags associated with the IP address. |
| InfobloxCloud.Domain.Address.addresses | Unknown | The IP address assigned to the resource. |

#### Command example

```!domain domain=test.com```

#### Context Example

```json
{
    "DBotScore": {
        "Indicator": "test.com",
        "Reliability": "A - Completely reliable",
        "Score": 3,
        "Type": "domain",
        "Vendor": "InfobloxBloxOneThreatDefense"
    },
    "Domain": {
        "Description": "cyber actors, possibly associated with the APT group Agent Serpens, created a fake website mimicking a modeling agency to collect detailed visitor.",
        "DetectionEngines": 1,
        "Malicious": {
            "Description": "cyber actors, possibly associated with the APT group Agent Serpens, created a fake website mimicking a modeling agency to collect detailed visitor.",
            "Vendor": "InfobloxThreatDefensewithDDI"
        },
        "MalwareFamily": "Phishing",
        "Name": "test.com",
        "Relationships": [
            {
                "EntityA": "test.com",
                "EntityAType": "Domain",
                "EntityB": "0.0.0.1",
                "EntityBType": "IP",
                "Relationship": "resolves-to"
            }
        ],
        "Tags": [
            "cyberint_guid: simple_cyberint_guid",
            "notes: cyber actors, possibly associated with the APT group Agent Serpens, created a fake website mimicking a modeling agency to collect detailed visitor."
        ],
        "ThreatTypes": [
            {
                "threatcategory": "HOST",
                "threatcategoryconfidence": "100"
            }
        ]
    },
    "InfobloxCloud": {
        "Domain": {
            "Address": {
                "addresses": [
                    {
                        "address": "0.0.0.1",
                        "ref": "ipam/address/00000000-0000-0000-0000-000000000000",
                        "space": "ipam/ip_space/00000000-0000-0000-0000-000000000000"
                    }
                ],
                "auto_generate_records": true,
                "comment": "comment",
                "created_at": "2025-07-22T05:26:46.834693Z",
                "host_names": [
                    {
                        "alias": false,
                        "name": "test.com",
                        "primary_name": true,
                        "zone": "dns/auth_zone/8ce66502-8d4b-439e-8690-0c59d3122b9f"
                    }
                ],
                "id": "ipam/host/00000000-0000-0000-0000-000000000000",
                "name": "test.com",
                "updated_at": "2025-07-22T05:26:57.219235Z"
            },
            "domain": "test.com",
            "Threat": {
                "batch_id": "00000000-0000-0000-0000-000000000001",
                "class": "Phishing",
                "confidence": 100,
                "detected": "2025-05-08T16:39:38.959Z",
                "dga": "false",
                "domain": "test.com",
                "expiration": "2025-09-05T16:39:38.959Z",
                "extended": {
                    "cyberint_guid": "simple_cyberint_guid",
                    "notes": "cyber actors, possibly associated with the APT group Agent Serpens, created a fake website mimicking a modeling agency to collect detailed visitor."
                },
                "host": "test.com",
                "id": "00000000-0000-0000-0000-000000000001",
                "imported": "2025-05-08T16:41:37.894Z",
                "profile": "IID",
                "property": "Phishing_Lookalike",
                "received": "2025-05-08T16:41:37.894Z",
                "threat_level": 100,
                "tld": "com",
                "type": "HOST",
                "up": "true"
            }
        }
    }
}
```

#### Human Readable Output

>## Information for the given Bad Domain: test.com
>
>### Threat Intelligence Summary
>
>|Batch Id|Class|Confidence|Detected|Dga|Domain|Expiration|Extended|Host|Id|Imported|Profile|Property|Received|Threat Level|Tld|Type|Up|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 00000000-0000-0000-0000-000000000001 | Phishing | 100 | 2025-05-08T16:39:38.959Z | false | test.com | 2025-09-05T16:39:38.959Z | ***cyberint_guid***: simple_cyberint_guid<br/>***notes***: cyber actors, possibly associated with the APT group Agent Serpens, created a fake website mimicking a modeling agency to collect detailed visitor. | test.com | 00000000-0000-0000-0000-000000000001 | 2025-05-08T16:41:37.894Z | IID | Phishing_Lookalike | 2025-05-08T16:41:37.894Z | 100 | com | HOST | true |
>
>### Address Information
>
>|Addresses|Auto Generate Records|Comment|Created At|Host Names|Id|Name|Updated At|
>|---|---|---|---|---|---|---|---|
>| **-** ***address***: 0.0.0.1<br/> ***ref***: ipam/address/00000000-0000-0000-0000-000000000000<br/> ***space***: ipam/ip_space/00000000-0000-0000-0000-000000000000 | True | comment | 2025-07-22T05:26:46.834693Z | **-** ***alias***: False<br/> ***name***: test.com<br/> ***primary_name***: True<br/> ***zone***: dns/auth_zone/8ce66502-8d4b-439e-8690-0c59d3122b9f | ipam/host/00000000-0000-0000-0000-000000000000 | test.com | 2025-07-22T05:26:57.219235Z |

### url

***
Gets the comprehensive URL reputation and threat intelligence from Infoblox Threat Defense, including threat indicators, and standard URL reputation data.

#### Base Command

`url`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | URL\(s\) for which to retrieve reputation and threat intelligence. Supports comma-separated values. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| InfobloxCloud.URL.url | String | The requested URL. |
| URL.Data | String | The URL. |
| URL.Relationships.EntityA | string | The source of the relationship. |
| URL.Relationships.EntityB | string | The destination of the relationship. |
| URL.Relationships.Relationship | string | The name of the relationship. |
| URL.Relationships.EntityAType | string | The type of the source of the relationship. |
| URL.Relationships.EntityBType | string | The type of the destination of the relationship. |
| URL.DetectionEngines | String | The total number of engines that checked the indicator. |
| URL.PositiveDetections | String | The number of engines that positively detected the indicator as malicious. |
| URL.Category | String | The category associated with the indicator. |
| URL.Malicious.Vendor | String | The vendor reporting the URL as malicious. |
| URL.Malicious.Description | String | A description of the malicious URL. |
| URL.Tags | Unknown | \(List\) Tags of the URL. |
| URL.FeedRelatedIndicators.value | String | Indicators that are associated with the URL. |
| URL.FeedRelatedIndicators.type | String | The type of the indicators that are associated with the URL. |
| URL.FeedRelatedIndicators.description | String | The description of the indicators that are associated with the URL. |
| URL.MalwareFamily | String | The malware family associated with the URL. |
| URL.Port | String | Ports that are associated with the URL. |
| URL.Internal | Bool | Whether or not the URL is internal or external. |
| URL.Campaign | String | The campaign associated with the URL. |
| URL.TrafficLightProtocol | String | The Traffic Light Protocol \(TLP\) color that is suitable for the URL. |
| URL.ThreatTypes.threatcategory | String | The threat category associated to this indicator by the source vendor. For example, Phishing, Control, TOR, etc. |
| URL.ThreatTypes.threatcategoryconfidence | String | Threat Category Confidence is the confidence level provided by the vendor for the threat type category For example a confidence of 90 for threat type category 'malware' means that the vendor rates that this is 90% confidence of being a malware. |
| URL.ASN | String | The autonomous system name for the URL, for example: 'AS8948'. |
| URL.ASOwner | String | The autonomous system owner of the URL. |
| URL.GeoCountry | String | The country in which the URL is located. |
| URL.Organization | String | The organization of the URL. |
| URL.CommunityNotes.note | String | Notes on the URL that were given by the community. |
| URL.CommunityNotes.timestamp | Date | The time in which the note was published. |
| URL.Publications.source | String | The source in which the article was published. |
| URL.Publications.title | String | The name of the article. |
| URL.Publications.link | String | A link to the original article. |
| URL.Publications.timestamp | Date | The time in which the article was published. |
| DBotScore.Indicator | String | The indicator that was tested. |
| DBotScore.Type | String | The indicator type. |
| DBotScore.Vendor | String | The vendor used to calculate the score. |
| DBotScore.Score | Number | The actual score. |
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. |
| InfobloxCloud.URL.Threat.id | String | The unique identifier for the threat indicator. |
| InfobloxCloud.URL.Threat.type | String | The type of threat indicator. |
| InfobloxCloud.URL.Threat.url | String | The URL identified as a threat indicator. |
| InfobloxCloud.URL.Threat.profile | String | The threat profile or classification source. |
| InfobloxCloud.URL.Threat.property | String | The specific property or category of the threat. |
| InfobloxCloud.URL.Threat.class | String | The classification of the threat. |
| InfobloxCloud.URL.Threat.threat_level | Number | The numeric threat level score. |
| InfobloxCloud.URL.Threat.threat_label | String | The textual threat level label. |
| InfobloxCloud.URL.Threat.expiration | Date | The timestamp when the threat indicator will expire. |
| InfobloxCloud.URL.Threat.detected | Date | The timestamp when the threat activity was first detected. |
| InfobloxCloud.URL.Threat.received | Date | The timestamp when the threat indicator was received by the system. |
| InfobloxCloud.URL.Threat.imported | Date | The timestamp when the threat indicator was imported into the system. |
| InfobloxCloud.URL.Threat.up | String | The boolean status flag indicating whether the threat indicator is currently active. |
| InfobloxCloud.URL.Threat.batch_id | String | The batch ID of the threat indicator. |
| InfobloxCloud.URL.Threat.confidence | Number | The numeric confidence score representing the reliability of the threat indicator. |
| InfobloxCloud.URL.Threat.extended.notes | String | The additional notes or information about the threat indicator. |
| InfobloxCloud.URL.Threat.threat_score | Number | The numeric score representing the calculated threat severity. |
| InfobloxCloud.URL.Threat.threat_score_rating | String | The textual rating of the threat score. |
| InfobloxCloud.URL.Threat.threat_score_vector | String | The vector string representing threat scoring details. |
| InfobloxCloud.URL.Threat.risk_score | Number | The numeric risk score assigned to the threat indicator. |
| InfobloxCloud.URL.Threat.risk_score_rating | String | The textual rating of the risk score. |
| InfobloxCloud.URL.Threat.risk_score_vector | String | The vector string representing risk scoring details. |
| InfobloxCloud.URL.Threat.confidence_score | Number | The numeric confidence score for the threat assessment. |
| InfobloxCloud.URL.Threat.confidence_score_rating | String | The textual rating of the confidence score. |
| InfobloxCloud.URL.Threat.confidence_score_vector | String | The vector string representing confidence scoring details. |
| InfobloxCloud.URL.Threat.extended.cyberint_guid | String | The unique identifier for the threat indicator. |
| InfobloxCloud.URL.Threat.extended.attack_chain | String | The attack chain associated with the threat indicator. |
| InfobloxCloud.URL.Threat.extended.extended | String | The additional information or metadata associated with the threat indicator. |
| InfobloxCloud.URL.Threat.extended.protocol | String | The protocol associated with the threat indicator. |
| InfobloxCloud.URL.Threat.extended.references | String | The references associated with the threat indicator. |
| InfobloxCloud.URL.Threat.extended.threat_actor | String | The threat actor associated with the threat indicator. |
| InfobloxCloud.URL.Threat.extended.threat_actor_vector | String | The vector string representing threat actor details. |
| InfobloxCloud.URL.Threat.extended.risk_score | String | The numeric risk score assigned to the threat indicator. |
| InfobloxCloud.URL.Threat.extended.threat_score | String | The numeric threat score assigned to the threat indicator. |
| InfobloxCloud.URL.Threat.extended.sample_sha256 | String | The SHA-256 hash of the sample associated with the threat. |
| InfobloxCloud.URL.Threat.extended.original_profile | String | The original profile or classification source of the threat. |

#### Command example

```!url url=https://test.com```

#### Context Example

```json
{
    "DBotScore": {
        "Indicator": "https://test.com",
        "Reliability": "A - Completely reliable",
        "Score": 3,
        "Type": "url",
        "Vendor": "InfobloxBloxOneThreatDefense"
    },
    "InfobloxCloud": {
        "URL": {
            "Threat": {
                "id": "00000000-0000-0000-0000-000000000001",
                "type": "URL",
                "host": "test.com",
                "url": "https://test.com",
                "domain": "test.com",
                "tld": "com",
                "profile": "IID",
                "property": "Scam_Generic",
                "class": "Scam",
                "threat_level": 100,
                "expiration": "2025-10-05T12:12:00.22Z",
                "detected": "2025-06-07T12:12:00.22Z",
                "received": "2025-06-07T12:16:32.337Z",
                "imported": "2025-06-07T12:16:32.337Z",
                "up": "true",
                "confidence": 100,
                "batch_id": "00000000-0000-0000-0000-000000000000",
                "extended": {
                    "cyberint_guid": "simple_cyberint_guid",
                    "notes": "Scam advertised. Lures victims to put their money into fake investments.",
                    "protocol": "https",
                    "references": "https://test.com"
                }
            },
            "url": "https://test.com"
        }
    },
    "URL": {
        "Data": "https://test.com",
        "Description": "Scam advertised. Lures victims to put their money into fake investments.",
        "DetectionEngines": 1,
        "Malicious": {
            "Description": "Scam advertised. Lures victims to put their money into fake investments.",
            "Vendor": "InfobloxThreatDefensewithDDI"
        },
        "MalwareFamily": "Scam",
        "Tags": [
            "cyberint_guid: simple_cyberint_guid",
            "notes: Scam advertised. Lures victims to put their money into fake investments.",
            "protocol: https",
            "references: https://test.com"
        ],
        "ThreatTypes": [
            {
                "threatcategory": "URL",
                "threatcategoryconfidence": "100"
            }
        ]
    }
}
```

#### Human Readable Output

>## Information for the given Bad URL: https://test.com
>
>### Threat Intelligence Summary
>
>|Batch Id|Class|Confidence|Detected|Domain|Expiration|Extended|Host|Id|Imported|Profile|Property|Received|Threat Level|Tld|Type|Up|URL|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 00000000-0000-0000-0000-000000000000 | Scam | 100 | 2025-06-07T12:12:00.22Z | test.com | 2025-10-05T12:12:00.22Z | ***cyberint_guid***: simple_cyberint_guid<br/>***notes***: Scam advertised. Lures victims to put their money into fake investments.<br/>***protocol***: https<br/>***references***: https://test.com | test.com | 00000000-0000-0000-0000-000000000001 | 2025-06-07T12:16:32.337Z | IID | Scam_Generic | 2025-06-07T12:16:32.337Z | 100 | com | URL | true | https://test.com |
>

### infobloxcloud-mac-enrich

***
Enrich a MAC address with DHCP lease information.

#### Base Command

`infobloxcloud-mac-enrich`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| mac | Specify the MAC Address to enrich. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| InfobloxCloud.DHCPLease.address | String | The IP address assigned in the DHCP lease. |
| InfobloxCloud.DHCPLease.client_id | String | The identifier of the DHCP client. |
| InfobloxCloud.DHCPLease.ends | String | The timestamp indicating when the DHCP lease ends. |
| InfobloxCloud.DHCPLease.fingerprint | String | The DHCP client fingerprint, indicating device type or OS. |
| InfobloxCloud.DHCPLease.fingerprint_processed | String | The processed fingerprint result, if available. |
| InfobloxCloud.DHCPLease.ha_group | Unknown | The high-availability group associated with the lease, if any. |
| InfobloxCloud.DHCPLease.hardware | String | The hardware \(MAC\) address of the DHCP client. |
| InfobloxCloud.DHCPLease.host | String | The reference or identifier for the host associated with this lease. |
| InfobloxCloud.DHCPLease.hostname | String | The hostname provided by the DHCP client. |
| InfobloxCloud.DHCPLease.iaid | Number | The Identity Association Identifier \(IAID\) for the DHCP lease. |
| InfobloxCloud.DHCPLease.last_updated | String | The timestamp when the lease was last updated. |
| InfobloxCloud.DHCPLease.options | String | The encoded DHCP options provided with the lease. |
| InfobloxCloud.DHCPLease.preferred_lifetime | String | The preferred lifetime of the lease. |
| InfobloxCloud.DHCPLease.protocol | String | The protocol used for the lease. |
| InfobloxCloud.DHCPLease.space | String | The identifier for the IP space to which this lease belongs. |
| InfobloxCloud.DHCPLease.starts | String | The timestamp indicating when the DHCP lease started. |
| InfobloxCloud.DHCPLease.state | String | The current state of the lease. |
| InfobloxCloud.DHCPLease.type | String | The type of DHCP lease. |

#### Command example

```!infobloxcloud-mac-enrich mac="00:00:00:00:00:01"```

#### Context Example

```json
{
    "InfobloxCloud": {
        "DHCPLease": {
            "address": "0.0.0.1",
            "client_id": "01:00:00:00:00:00:01",
            "ends": "2025-07-01T19:25:24Z",
            "fingerprint": "VMware:Virtual Machine:Windows:",
            "fingerprint_processed": "processed",
            "hardware": "00:00:00:00:00:01",
            "host": "dhcp/host/123456",
            "hostname": "test-host01",
            "iaid": 0,
            "last_updated": "2025-07-01T18:25:24.792Z",
            "options": "{\"Options\":[{\"Code\":\"57\",\"Value\":\"test\"},{\"Code\":\"61\",\"Value\":\"sample\"},{\"Code\":\"53\",\"Value\":\"world\"},{\"Code\":\"55\",\"Value\":\"bar\"}]}",
            "preferred_lifetime": "2025-07-01T18:25:24Z",
            "protocol": "",
            "space": "ipam/ip_space/12345678-1234-1234-1234-123456789012",
            "starts": "2025-07-01T18:25:24Z",
            "state": "used",
            "type": "DHCPv4"
        }
    }
}
```

#### Human Readable Output

>### DHCP Lease Information for MAC: 00:00:00:00:00:01
>
>|Address|Client Id|Ends|Fingerprint|Fingerprint Processed|Hardware|Host|Hostname|Iaid|Last Updated|Options|Preferred Lifetime|Space|Starts|State|Type|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 0.0.0.1 | 01:00:00:00:00:00:01 | 2025-07-01T19:25:24Z | VMware:Virtual Machine:Windows: | processed | 00:00:00:00:00:01 | dhcp/host/123456 | test-host01 | 0 | 2025-07-01T18:25:24.792Z | **-** ***Code***: 57<br/> ***Value***: test<br/>**-** ***Code***: 61<br/> ***Value***: sample<br/>**-** ***Code***: 53<br/> ***Value***: world<br/>**-** ***Code***: 55<br/> ***Value***: bar | 2025-07-01T18:25:24Z | ipam/ip_space/12345678-1234-1234-1234-123456789012 | 2025-07-01T18:25:24Z | used | DHCPv4 |

### infobloxcloud-soc-insight-list

***
List SOC Insights from Infoblox Cloud.

#### Base Command

`infobloxcloud-soc-insight-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| status | Specify the status of SOC Insights to fetch. Possible values are: Active, Closed. | Optional |
| threat_type | Specify the threat type of SOC Insights to fetch. Possible values are: DGA, Undefined, Malicious, Open Resolver, Phishing, DNS Tunneling, MalwareDownload, Sinkhole, Zero Day DNS, Notional Data Exfiltration, MalwareC2DGA, MalwareC2, Restricted Country Communications, Suspicious, CompromisedHost, CompromisedDomain, Lookalike Threat, Sanctioned Feed Disabled, DNSTunnel. | Optional |
| priority | Specify the priority level of SOC Insights to fetch. Possible values are: INFO, MEDIUM, HIGH, CRITICAL. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| InfobloxCloud.SOCInsight.insightId | String | The ID of the SOC Insight. |
| InfobloxCloud.SOCInsight.priorityText | String | The priority level of the SOC Insight. |
| InfobloxCloud.SOCInsight.tClass | String | The threat class of the SOC Insight. |
| InfobloxCloud.SOCInsight.tFamily | String | The threat family of the SOC Insight. |
| InfobloxCloud.SOCInsight.startedAt | String | The start time of the SOC Insight. |
| InfobloxCloud.SOCInsight.status | String | The status of the SOC Insight. |
| InfobloxCloud.SOCInsight.persistentDate | String | Timestamp when the threat was first observed as persistent. |
| InfobloxCloud.SOCInsight.spreadingDate | String | Timestamp when the threat was first observed as spreading. |
| InfobloxCloud.SOCInsight.dateChanged | String | Timestamp when the SOC Insight was last updated. |
| InfobloxCloud.SOCInsight.changer | String | The user or process that last changed the SOC Insight status or data. |
| InfobloxCloud.SOCInsight.feedSource | String | The source feed or provider of the SOC Insight. |
| InfobloxCloud.SOCInsight.threatType | String | The threat type of the SOC Insight. |
| InfobloxCloud.SOCInsight.numEvents | String | The number of events associated with the SOC Insight. |
| InfobloxCloud.SOCInsight.eventsNotBlockedCount | String | The number of events not blocked by the SOC Insight. |
| InfobloxCloud.SOCInsight.mostRecentAt | String | The most recent time the SOC Insight was updated. |

#### Command example

```!infobloxcloud-soc-insight-list```

#### Context Example

```json
{
    "InfobloxCloud": {
        "SOCInsight": [
            {
                "changer": "abc@xyz.com",
                "dateChanged": "2025-05-21T00:54:49.407214Z",
                "eventsBlockedCount": "3",
                "feedSource": "Insight Detection Framework",
                "insightId": "00000000-0000-0000-0000-000000000000",
                "mostRecentAt": "2025-07-19T19:25:11.723397Z",
                "numEvents": "3",
                "persistentDate": "2025-04-14T07:00:00Z",
                "priorityText": "HIGH",
                "spreadingDate": "2025-05-10T19:00:00Z",
                "startedAt": "2025-04-14T07:00:00Z",
                "status": "Active",
                "tClass": "Suspicious",
                "tFamily": "EmergentDomain",
                "threatType": "Suspicious"
            },
            {
                "tClass": "TI-RESTRICTED",
                "tFamily": "OFAC",
                "insightId": "00000000-0000-0000-0000-000000000001",
                "feedSource": "Insight Detection Framework",
                "startedAt": "2025-04-12T18:00:00Z",
                "threatType": "Sanctioned Feed Disabled",
                "status": "Active",
                "persistentDate": "2025-04-12T15:00:00Z",
                "numEvents": "246",
                "mostRecentAt": "2025-08-07T23:59:19Z",
                "eventsNotBlockedCount": "246",
                "changer": "abc@xyz.com",
                "dateChanged": "2025-08-06T13:58:01.050800Z",
                "priorityText": "INFO"
            }
        ]
    }
}
```

#### Human Readable Output

>### SOC Insights
>
>|ID|Priority|Class|Threat Type|Status|Threat Family|Feed Source|Most Recent At|
>|---|---|---|---|---|---|---|---|
>| 00000000-0000-0000-0000-000000000000 | HIGH | Suspicious | Suspicious | Active | EmergentDomain | Insight Detection Framework | 2025-07-19T19:25:11.723397Z |
>| 00000000-0000-0000-0000-000000000001 | INFO | TI-RESTRICTED | Sanctioned Feed Disabled | Active | OFAC | Insight Detection Framework | 2025-08-07T23:59:19Z |

### infobloxcloud-soc-insight-event-list

***
List events for a specific SOC Insight.

#### Base Command

`infobloxcloud-soc-insight-event-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| soc_insight_id | Specify the SOC Insight ID to fetch events for. | Required |
| limit | Specify the maximum number of events to fetch. Default is 50. | Optional |
| start_time | Specify the start time for the events.<br/><br/>Format: YYYY-MM-DDTHH:MM:SSZ, YYYY-MM-DD, N days, N hours.<br/><br/>Example: 2025-04-25T00:00:00Z, 2025-04-25, 2 days, 5 hours, 01 Mar 2025, 01 Feb 2025 04:45:33, 15 Jun. | Optional |
| end_time | Specify the end time for the events.<br/><br/>Format: YYYY-MM-DDTHH:MM:SSZ, YYYY-MM-DD, N days, N hours.<br/><br/>Example: 2025-04-25T00:00:00Z, 2025-04-25, 2 days, 5 hours, 01 Mar 2025, 01 Feb 2025 04:45:33, 15 Jun. | Optional |
| threat_level | Specify the threat level of the events. Possible values are: High, Medium, Low, Info. | Optional |
| confidence_level | Specify the confidence level of the events. Possible values are: High, Medium, Low, Info. | Optional |
| query | Specify the query to search for events. | Optional |
| query_type | Specify the query type to search for events. Possible values are: A, AAAA, ANY, TXT, RRSIG, CNAME, MX, NS, PTR, SOA, SRV. | Optional |
| source | Specify the source of the events. | Optional |
| device_ip | Specify the device IP of the events. | Optional |
| indicator | Specify the indicator of the events. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| InfobloxCloud.Event.confidenceLevel | String | The confidence level of the threat detection. |
| InfobloxCloud.Event.deviceCountry | String | The country where the device is located. |
| InfobloxCloud.Event.deviceName | String | The name or identifier of the device. |
| InfobloxCloud.Event.deviceRegion | String | The region where the device is located. |
| InfobloxCloud.Event.dnsView | String | The DNS view used for the query. |
| InfobloxCloud.Event.feed | String | The feed that identified the threat. |
| InfobloxCloud.Event.source | String | The source of the threat detection. |
| InfobloxCloud.Event.action | String | The action taken on the detected threat. |
| InfobloxCloud.Event.policy | String | The policy applied to the detection. |
| InfobloxCloud.Event.deviceIp | String | The IP address of the device. |
| InfobloxCloud.Event.query | String | The DNS query that triggered the detection. |
| InfobloxCloud.Event.queryType | String | The type of DNS query. |
| InfobloxCloud.Event.response | String | The DNS response for the query. |
| InfobloxCloud.Event.class | String | The classification of the threat. |
| InfobloxCloud.Event.threatFamily | String | The family of the threat. |
| InfobloxCloud.Event.threatIndicator | String | The indicator of the threat. |
| InfobloxCloud.Event.detected | String | The timestamp when the event was detected. |
| InfobloxCloud.Event.property | String | The property of the event. |
| InfobloxCloud.Event.user | String | The user associated with the detection. |
| InfobloxCloud.Event.threatLevel | String | The severity level of the event. |

#### Command example

```!infobloxcloud-soc-insight-event-list soc_insight_id="00000000-0000-0000-0000-000000000000"```

#### Context Example

```json
{
    "InfobloxCloud": {
        "Event": [
            {
                "action": "Allow - No Log",
                "class": "TI-CONFIGURATIONISSUE",
                "confidenceLevel": "High",
                "detected": "2025-08-11 23:42:04 +0000 UTC",
                "deviceIp": "0.0.0.0",
                "deviceName": "0.0.0.0",
                "policy": "DoH",
                "property": "example.com",
                "query": "example.com",
                "queryType": "A",
                "source": "unknown",
                "threatFamily": "OPENRESOLVER",
                "threatLevel": "Low",
                "user": "unknown"
            },
            {
                "action": "Block",
                "class": "Suspicious",
                "confidenceLevel": "High",
                "detected": "2025-07-16 07:37:29 +0000 UTC",
                "deviceIp": "0.0.0.1",
                "deviceName": "0.0.0.1",
                "policy": "Default Policy",
                "property": "EmergentDomain",
                "query": "example.org",
                "queryType": "RRSIG",
                "source": "Endpoint",
                "threatFamily": "EmergentDomain",
                "threatLevel": "High",
                "user": "unknown"
            }
        ]
    }
}
```

#### Human Readable Output

>### Events for the given SOC Insight: 00000000-0000-0000-0000-000000000000
>
>|Confidence Level|Threat Level|Threat Family|Action|Class|Detected|
>|---|---|---|---|---|---|
>| High | Low | OPENRESOLVER | Allow - No Log | TI-CONFIGURATIONISSUE | 2025-08-11 23:42:04 +0000 UTC |
>| High | High | EmergentDomain | Block | Suspicious | 2025-07-16 07:37:29 +0000 UTC |

### infobloxcloud-soc-insight-indicator-list

***
List indicators for a specific SOC Insight.

#### Base Command

`infobloxcloud-soc-insight-indicator-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| soc_insight_id | Specify the SOC Insight ID to fetch indicators for. | Required |
| limit | Specify the maximum number of indicators to fetch. Default is 50. | Optional |
| start_time | Specify the start time for the indicators.<br/><br/>Format: YYYY-MM-DDTHH:MM:SSZ, YYYY-MM-DD, N days, N hours.<br/><br/>Example: 2025-04-25T00:00:00Z, 2025-04-25, 2 days, 5 hours, 01 Mar 2025, 01 Feb 2025 04:45:33, 15 Jun. | Optional |
| end_time | Specify the end time for the indicators.<br/><br/>Format: YYYY-MM-DDTHH:MM:SSZ, YYYY-MM-DD, N days, N hours.<br/><br/>Example: 2025-04-25T00:00:00Z, 2025-04-25, 2 days, 5 hours, 01 Mar 2025, 01 Feb 2025 04:45:33, 15 Jun. | Optional |
| confidence | Specify the confidence of the indicators. Possible values are: 1, 2, 3. | Optional |
| indicator | Specify the indicator of the indicators. | Optional |
| action | Specify the action of the indicators. Possible values are: Blocked, Not Blocked. | Optional |
| actor | Specify the actor of the indicators. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| InfobloxCloud.Indicator.action | String | The action taken for the indicator. |
| InfobloxCloud.Indicator.confidence | String | The confidence level of the indicator. |
| InfobloxCloud.Indicator.count | Number | The number of occurrences of the indicator. |
| InfobloxCloud.Indicator.feedName | String | The feed name that identified the indicator. |
| InfobloxCloud.Indicator.threatLevelMax | String | The maximum threat level associated with the indicator. |
| InfobloxCloud.Indicator.indicator | String | The value of the indicator. |
| InfobloxCloud.Indicator.timeMax | Date | The latest time the indicator was observed. |
| InfobloxCloud.Indicator.timeMin | Date | The earliest time the indicator was observed. |

#### Command example

```!infobloxcloud-soc-insight-indicator-list soc_insight_id="00000000-0000-0000-0000-000000000000"```

#### Context Example

```json
{
    "InfobloxCloud": {
        "Indicator": [
            {
                "action": "Not Blocked",
                "confidence": "3",
                "count": 189,
                "indicator": "example.org",
                "threatLevelMax": "1",
                "timeMax": "2025-08-11T23:00:00.000",
                "timeMin": "2025-07-13T15:00:00.000"
            },
            {
                "action": "Blocked",
                "confidence": "1",
                "count": 5,
                "indicator": "example.com",
                "threatLevelMax": "3",
                "timeMax": "2025-08-11T12:00:00.000",
                "timeMin": "2025-07-14T10:00:00.000"
            }
        ]
    }
}
```

#### Human Readable Output

>### Indicators for the given SOC Insight: 00000000-0000-0000-0000-000000000000
>
>|Action|Confidence|Max Threat Level|Indicator|Count|Max Time|Min Time|
>|---|---|---|---|---|---|---|
>| Not Blocked | 3 | 1 | example.org | 189 | 2025-08-11T23:00:00.000 | 2025-07-13T15:00:00.000 |
>| Blocked | 1 | 3 | example.com | 5 | 2025-08-11T12:00:00.000 | 2025-07-14T10:00:00.000 |

### infobloxcloud-soc-insight-asset-list

***
List assets for a specific SOC Insight.

#### Base Command

`infobloxcloud-soc-insight-asset-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| soc_insight_id | Specify the SOC Insight ID to fetch assets for. | Required |
| limit | Specify the maximum number of assets to fetch. Default is 50. | Optional |
| start_time | Specify the start time for the assets.<br/><br/>Format: YYYY-MM-DDTHH:MM:SSZ, YYYY-MM-DD, N days, N hours.<br/><br/>Example: 2025-04-25T00:00:00Z, 2025-04-25, 2 days, 5 hours, 01 Mar 2025, 01 Feb 2025 04:45:33, 15 Jun. | Optional |
| end_time | Specify the end time for the assets.<br/><br/>Format: YYYY-MM-DDTHH:MM:SSZ, YYYY-MM-DD, N days, N hours.<br/><br/>Example: 2025-04-25T00:00:00Z, 2025-04-25, 2 days, 5 hours, 01 Mar 2025, 01 Feb 2025 04:45:33, 15 Jun. | Optional |
| qip | Specify the IP address of the assets. | Optional |
| cmac | Specify the MAC address of the assets. | Optional |
| os_version | Specify the OS version of the assets. | Optional |
| user | Specify the user of the assets. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| InfobloxCloud.Asset.count | Number | The number of occurrences associated with the asset. |
| InfobloxCloud.Asset.qip | String | The IP address of the asset. |
| InfobloxCloud.Asset.location | String | The geographical location of the asset. |
| InfobloxCloud.Asset.threatLevelMax | String | The maximum threat level associated with the asset. |
| InfobloxCloud.Asset.threatIndicatorDistinctCount | String | The number of distinct threat indicators associated with the asset. |
| InfobloxCloud.Asset.timeMax | Date | The latest time the asset was observed. |
| InfobloxCloud.Asset.timeMin | Date | The earliest time the asset was observed. |
| InfobloxCloud.Asset.mostRecentAction | String | The most recent action taken for the asset. |

#### Command example

```!infobloxcloud-soc-insight-asset-list soc_insight_id="00000000-0000-0000-0000-000000000000"```

#### Context Example

```json
{
    "InfobloxCloud": {
        "Asset": [
            {
                "count": 5,
                "location": "Leidschendam,Netherlands",
                "mostRecentAction": "Not Blocked",
                "qip": "0.0.0.0",
                "threatIndicatorDistinctCount": "1",
                "threatLevelMax": "1",
                "timeMax": "2025-08-11T12:00:00.000",
                "timeMin": "2025-07-14T10:00:00.000"
            },
            {
                "count": 1,
                "location": "Minneapolis,United States",
                "mostRecentAction": "Not Blocked",
                "qip": "0.0.0.1",
                "threatIndicatorDistinctCount": "1",
                "threatLevelMax": "1",
                "timeMax": "2025-08-07T12:00:00.000",
                "timeMin": "2025-08-07T12:00:00.000"
            }
        ]
    }
}
```

#### Human Readable Output

>### Assets for the given SOC Insight: 00000000-0000-0000-0000-000000000000
>
>|Count|QIP|Max Threat Level|Location|Threat Indicator Distinct Count|Time Max|Time Min|Most Recent Action|
>|---|---|---|---|---|---|---|---|
>| 5 | 0.0.0.0 | 1 | Leidschendam,Netherlands | 1 | 2025-08-11T12:00:00.000 | 2025-07-14T10:00:00.000 | Not Blocked |
>| 1 | 0.0.0.1 | 1 | Minneapolis,United States | 1 | 2025-08-07T12:00:00.000 | 2025-08-07T12:00:00.000 | Not Blocked |

### infobloxcloud-soc-insight-comment-list

***
List comments for a specific SOC Insight.

#### Base Command

`infobloxcloud-soc-insight-comment-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| soc_insight_id | Specify the SOC Insight ID to fetch comments for. | Required |
| start_time | Specify the start time for the comments.<br/><br/>Format: YYYY-MM-DDTHH:MM:SSZ, YYYY-MM-DD, N days, N hours.<br/><br/>Example: 2025-04-25T00:00:00Z, 2025-04-25, 2 days, 5 hours, 01 Mar 2025, 01 Feb 2025 04:45:33, 15 Jun. | Optional |
| end_time | Specify the end time for the comments.<br/><br/>Format: YYYY-MM-DDTHH:MM:SSZ, YYYY-MM-DD, N days, N hours.<br/><br/>Example: 2025-04-25T00:00:00Z, 2025-04-25, 2 days, 5 hours, 01 Mar 2025, 01 Feb 2025 04:45:33, 15 Jun. | Optional |
| limit | Specify the maximum number of comments to fetch. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| InfobloxCloud.Comment.commentsChanger | String | The user who created or changed the comment. |
| InfobloxCloud.Comment.dateChanged | Date | The timestamp when the comment was created or modified. |
| InfobloxCloud.Comment.status | String | The status associated with the comment. |
| InfobloxCloud.Comment.newComment | String | The comment text. |

#### Command example

```!infobloxcloud-soc-insight-comment-list soc_insight_id="00000000-0000-0000-0000-000000000000"```

#### Context Example

```json
{
    "InfobloxCloud": {
        "Comment": [
            {
                "commentsChanger": "abc.zyx.com",
                "dateChanged": "2025-08-02T08:39:43.675",
                "newComment": "\nAsset IP: 0.0.0.0\nScan ID: None\nReference ID: None\nQualys Scan Report URL: https://example.com/fo/report/report_view.php?&id=None\n",
                "status": "Active"
            },
            {
                "commentsChanger": "abc.zyx.com",
                "dateChanged": "2025-07-15T05:24:29.803",
                "newComment": "\nAsset IP: 0.0.0.0\nScan ID: None\nReference ID: None\nQualys Scan Report URL: https://example.com/fo/report/report_view.php?&id=None\n",
                "status": "Active"
            }
        ]
    }
}
```

#### Human Readable Output

>### Comments for the given SOC Insight: 00000000-0000-0000-0000-000000000000
>
>|Comment Changer|Date Changed|Status|Comment|
>|---|---|---|---|
>| abc.zyx.com | 2025-08-02T08:39:43.675 | Active | <br/>Asset IP: 0.0.0.0<br/>Scan ID: None<br/>Reference ID: None<br/>Qualys Scan Report URL: https:<span>//</span>example.com/fo/report/report\_view.php?&id=None<br/> |
>| abc.zyx.com | 2025-07-15T05:24:29.803 | Active | <br/>Asset IP: 0.0.0.0<br/>Scan ID: None<br/>Reference ID: None<br/>Qualys Scan Report URL: https:<span>//</span>example.com/fo/report/report\_view.php?&id=None<br/> |
