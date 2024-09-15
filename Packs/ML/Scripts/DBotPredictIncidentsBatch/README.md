Apply a trained ML model on multiple incidents at once, to compare incidents how the incidents were labeled by analysts, to the predictions of the model. This script is aimed to help evaluate a trained model using past incidents.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | phishing, ml |
| Cortex XSOAR Version | 5.0.0 |

## Dependencies

---
This script uses the following commands and scripts.

* GetIncidentsByQuery
* DBotPredictPhishingWords

## Used In

---
This script is used in the following playbooks and scripts.

* VerifyOOBV2Predictions-Test

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| query | Additional text by which to query incidents. |
| incidentTypes | A comma-separated list of incident types by which to filter. |
| fromDate | The start date by which to filter incidents. Date format will be the same as in the incidents query page \(valid strings exaple: "3 days ago", ""2019-01-01T00:00:00 \+0200"\) |
| toDate | The end date by which to filter incidents. Date format will be the same as in the incidents query page \(valid strings exaple: "3 days ago", ""2019-01-01T00:00:00 \+0200"\) |
| limit | The maximum number of incidents to fetch. |
| tagField | The field name with the label. Supports a comma-separated list, the first non-empty value will be taken. |
| hashSeed | If non-empty, hash every word with this seed. |
| phishingLabels | A comma-separated list of email tags values and mapping. The script considers only the tags specified in this field. You can map a label to another value by using this format: LABEL:MAPPED_LABEL. For example, for 4 values in email tag: malicious, credentials harvesting, inner communitcation, external legit email, unclassified. While training, we want to ignore "unclassified" tag, and refer to "credentials harvesting" as "malicious" too. Also, we want to merge "inner communitcation" and "external legit email" to one tag called "non-malicious". The input will be: malicious, credentials harvesting:malicious, inner communitcation:non-malicious, external legit email:non-malicious |
| modelName | The model name to store in the system. |
| emailsubject | Incident field name with the email subject. |
| emailbody | Incident field name with the email body \(text\). |
| emailbodyhtml | Incident field name with the email body \(html\). |
| populateFields | A comma-separated list of fields in the object to poplulate. |

## Outputs

---
There are no outputs for this script.
