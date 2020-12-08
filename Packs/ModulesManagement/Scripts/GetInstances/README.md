Returns all the Instance that existing in xsoar

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags |  |
| Demisto Version | 5.0.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| brand | Filter by the brand name |
| is_enabled | Filter by the instance status |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Modules.name | The instance name | string |
| Modules.category | The instance category | string |
| Modules.defaultIgnored | Is the instance avilable by default | string |
| Modules.state | Is the instance enabled | string |
| Modules.brand | The instance brand | string |


## Script Example
```!GetInstances```

## Context Example
```json
{
    "Modules": [
        {
            "brand": "EWS v2",
            "category": "Messaging",
            "defaultIgnored": "false",
            "name": "EWS v2_instance_1",
            "state": "active"
        },
        {
            "brand": "Elasticsearch v2",
            "category": "Database",
            "defaultIgnored": "false",
            "name": "Elasticsearch v2_instance_1",
            "state": "active"
        },
        {
            "brand": "Elasticsearch v2",
            "category": "Database",
            "defaultIgnored": "false",
            "name": "Elasticsearch v2_instance_2",
            "state": "disabled"
        },
        {
            "brand": "Rapid7 Nexpose",
            "category": "Vulnerability Management",
            "defaultIgnored": "false",
            "name": "Rapid7 Nexpose_instance_1",
            "state": "active"
        },
        {
            "brand": "activedir-login",
            "category": "Messaging",
            "defaultIgnored": "false",
            "name": "ad-login",
            "state": "active"
        },
        {
            "brand": "activedir",
            "category": "Data Enrichment & Threat Intelligence",
            "defaultIgnored": "false",
            "name": "ad-query",
            "state": "active"
        },
        {
            "brand": "d2",
            "category": "Endpoint",
            "defaultIgnored": "false",
            "name": "d2",
            "state": "active"
        },
        {
            "brand": "splunk",
            "category": "Analytics & SIEM",
            "defaultIgnored": "false",
            "name": "splunk",
            "state": "active"
        }
    ]
}
```

## Human Readable Output

>### Results
>|brand|category|defaultIgnored|name|state|
>|---|---|---|---|---|
>| EWS v2 | Messaging | false | EWS v2_instance_1 | active |
>| Elasticsearch v2 | Database | false | Elasticsearch v2_instance_1 | active |
>| Elasticsearch v2 | Database | false | Elasticsearch v2_instance_2 | disabled |
>| Rapid7 Nexpose | Vulnerability Management | false | Rapid7 Nexpose_instance_1 | active |
>| activedir-login | Messaging | false | ad-login | active |
>| activedir | Data Enrichment & Threat Intelligence | false | ad-query | active |
>| d2 | Endpoint | false | d2 | active |
>| splunk | Analytics & SIEM | false | splunk | active |

