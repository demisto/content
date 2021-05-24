Prepares an email's data for machine learning text classification automation.
## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python |
| Tags | ml, phishing |
| Cortex XSOAR Version | 4.1.0+ |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| incidentsQuery | The query of the phishing incidents. |
| maxNumberOfIncidents | The maximum number of incidents. |
| emailTextKey | The incident key used to extract the email's text. |
| emailSubjectKey | The incident key used to extract the email's subject. |
| tagKey | The incident key used to extract the email's tag. |
| phishingLabels | The comma-separated values of email tags values and mapping (or "*" value for all labels). The script will consider only the tags specified in this field. Label's can be mapped to another value by using this format: `LABEL:MAPPED_LABEL`. For example: let's say we have 5 values in email tag: "malicious", "credentials harvesting", "inner communitcation", "external legit email", "unclassified". While training, we want to ignore "unclassified" tag, and refer to "credentials harvesting" as "malicious" too. Also, we want to merge "inner communitcation" and "external legit email" to one tag called "non-malicious". The input will be: `malicious, credentials harvesting:malicious, inner communitcation:non-malicious, external legit email:non-malicious`. |
| isContextNeeded | Whether one of the fields is in the context data. |
| hashData | The hash the words of the email. |
| storeFileInList | The list name. The file should be stored in this list as base64 (compressed). |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| DBotPreparePhishingDataFilename | The path of the training file.  | string |
