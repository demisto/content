A helper script for the DBot Create Phishing Classifier V2 playbook. This script extends the query based on the phishingLabels argument.

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
| tagField | The field name with the label. Supports a comma-separated list, the first non-empty value will be taken. |
| phishingLabels | A comma-separated list of email tag values and mapping. The script considers only the tags specified in this field. You can map a label to another value by using this format: LABEL:MAPPED_LABEL. For example, for 4 values in an email tag: malicious, credentials harvesting, inner communication, external legit email, unclassified. While training, we want to ignore the "unclassified" tag, and refer to "credentials harvesting" as "malicious" too. Also, we want to merge "inner communication" and "external legit email" to one tag called "non-malicious". The input will be: malicious, credentials harvesting:malicious, inner communication:non-malicious, external legit email:non-malicious. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| ExtendQueryBasedOnPhishingLabels.extendedQuery | The original query extended by a part which takes into account the phishingLabels argument. | Unknown |
