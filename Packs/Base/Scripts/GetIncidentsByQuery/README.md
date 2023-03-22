Gets a list of incident objects and the associated incident outputs that
match the specified query and filters. The results are returned in a structured data file.

This automation runs using the default Limited User role, unless you explicitly change the permissions.
For more information, see the section about permissions here: [https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/6.10/Cortex-XSOAR-Administrator-Guide/Automations](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/6.10/Cortex-XSOAR-Administrator-Guide/Automations)

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | ml |
| Cortex XSOAR Version | 5.0.0 |

## Used In
---
This script is used in the following playbooks and scripts.
* DBot Create Phishing Classifier V2

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| query | Additional text by which to query incidents. |
| incidentTypes | A comma-separated list of incident types by which to filter. |
| fromDate | The start date by which to filter incidents. Date format will be the same as in the incidents query page, for example: "3 days ago", ""2019-01-01T00:00:00 \+0200"\). |
| toDate | The end date by which to filter incidents. Date format will be the same as in the incidents query page, for example: "3 days ago", ""2019-01-01T00:00:00 \+0200"\). |
| limit | The maximum number of incidents to fetch. |
| includeContext | Whether to query and fetch incident context. Can be "true" or "false". The default is "false". |
| timeField | The incident field to specify for the date range. Can be "created" or "modified". The default is "created". Due to performance considerations, you should only use "modified" if you have a large number of incidents. |
| NonEmptyFields | A comma-separated list of non-empty value incident field names by which to filter incidents. |
| outputFormat | The output file format. |
| populateFields | A comma-separated list of fields in the object to poplulate. |
| pageSize | Incidents query batch size |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| GetIncidentsByQuery.Filename | The output file name. | String |
| GetIncidentsByQuery.FileFormat | The output file format. | String |
