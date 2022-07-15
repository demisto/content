Hash fields from the incident list.
Search for incidents by arguments with an option to hash some of its fields.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | incidents, ml |
| Cortex XSOAR Version | 5.0.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| query | Additional text by which to query incidents. |
| incidentTypes | A comma-separated list of incident types by which to filter. |
| fromDate | The start date by which to filter incidents. Date format will be the same as in the incidents query page, for example: "3 days ago", ""2019-01-01T00:00:00 \+0200"\). |
| toDate | The end date by which to filter incidents. Date format will be the same as in the incidents query page, for example: "3 days ago", ""2019-01-01T00:00:00 \+0200"\). |
| limit | The maximum number of incidents to fetch. The default value is 3000. |
| timeField | The incident field to specify for the date range. Can be "created" or "modified". The default is "created". |
| NonEmptyFields | A comma-separated list of non-empty value incident field names by which to filter incidents. |
| outputFormat | The output file format. |
| populateFields | A comma-separated list of fields in the object to poplulate. |
| fieldsToHash | A comma-separated list of fields to hash. Support wildcards. |
| contextKeys | A comma-separated list of context keys to keep. |
| removeLabels | Remove incident labels |
| unPopulateFields | A comma-separated list of fields in the object to un-poplulate. |
| addRandomSalt | Random salt to the hash function |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| HashIncidentsFields.Filename | The output file name. | String |
| HashIncidentsFields.FileFormat | The output file format. | String |
