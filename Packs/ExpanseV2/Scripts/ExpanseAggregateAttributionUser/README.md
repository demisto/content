Aggregate entries from multiple sources into AttributionUser

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | |
| Demisto Version | 6.0.0 |

## Used In
---
This script is used in the following playbooks and scripts.
* Expanse Attribution Subplaybook

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| input | Input list. |
| current | Current aggregation state. |
| username_fields | Comma separated list of fields to treat as serial number. |
| sightings_fields | Comma separated list of field names to be considered sighting counts. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Expanse.AttributionUser.username | Username of the user | string |
| Expanse.AttributionUser.domain | Domain of the user | string |
| Expanse.AttributionUser.groups | List of groups the user is member of | Unknown |
| Expanse.AttributionUser.display-name | Display Name | string |
| Expanse.AttributionUser.description | Description of the user | string |
| Expanse.AttributionUser.sightings | Number of sessions seen on this device | number |
