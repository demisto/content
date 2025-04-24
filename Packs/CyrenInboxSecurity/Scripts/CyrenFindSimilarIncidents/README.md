Finds similar incidents by Cyren Case ID

## Permissions
---

This automation runs using the default Limited User role, unless you explicitly change the permissions.
For more information, see the section about permissions here: For Cortex XSOAR 6, see the https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/6.x/Cortex-XSOAR-Playbook-Design-Guide/Automations for Cortex XSOAR 8 Cloud, see the https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8/Cortex-XSOAR-Cloud-Documentation/Create-a-script for Cortex XSOAR 8 On-prem, see the https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8.7/Cortex-XSOAR-On-prem-Documentation/Create-a-script.

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
