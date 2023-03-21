Finds similar incidents by Cyren Case ID

## Permissions
---

This automation runs using the default Limited User role, unless you explicitly change the permissions.
For more information, see the section about permissions here: [https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/6.10/Cortex-XSOAR-Administrator-Guide/Automations](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/6.10/Cortex-XSOAR-Administrator-Guide/Automations)

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | dedup, duplicate, incidents, dynamic-section |
| Cortex XSOAR Version | 6.0.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| case_id | the case id of incidents to return |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| cyrenSimilarIncident.raw_id | Similar incident ID. | string |
| cyrenIsSimilarIncidentFound | Whether a similar incident was found \("true" or "false"\). | boolean |
| cyrenSimilarIncident | Similar incident. | unknown |
| cyrenSimilarIncident.name | Similar incident name. | string |
| cyrenSimilarIncidentList | an array if similar incidents | Unknown |
| cyrenSimilarIncidentCsv | comma separated raw ids | Unknown |


## Script Example
```!Cyren-Find-Similar-Incidents```

## Context Example
```json
{
    "isSimilarIncidentFound": false
}
```

## Human Readable Output

>No similar incidents have been found.
