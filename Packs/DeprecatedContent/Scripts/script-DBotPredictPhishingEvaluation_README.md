Evaluates the phishing model created by text classification ML automation.

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
| emailTextKey | THe incident key used to extract the email's text. |
| emailSubjectKey | The incident key used to extract the email's subject. |
| tagKey | The incident key used to extract the tag. |
| phishingLabels | The comma-separated values of the email tag values and mapping. The script will consider only the tags specified in this field. Labels can be mapped to another value by using this format, `LABEL:MAPPED_LABEL`. For example, given 5 values in an email tag, "malicious", "credentials harvesting", "inner communitcation", "external legit email", "unclassified". While training, we want to ignore the "unclassified" tag, and refer to "credentials harvesting" as "malicious" as well. Also, we want to merge "inner communitcation" and "external legit email" to one tag called "non-malicious". The input would be, "malicious, credentials harvesting:malicious, inner communitcation:non-malicious, external legit email:non-malicious". |
| isContextNeeded | Whether one of the fields is in the context data. |
| hashData |Whether the phishing model is based on hashed data. |
| modelListName | The XSOAR list name that stores the machine learning model. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| DBotPredictPhishingEvaluation.Precision | The precision score. Can be, 0-1. | number |
| DBotPredictPhishingEvaluation.Recall | The recall score. Can be, 0-1. | number |
| DBotPredictPhishingEvaluation.F1 | The F1 score. Can be, 0-1. | number |
| DBotPredictPhishingEvaluation.Size | The test data size. | number |
