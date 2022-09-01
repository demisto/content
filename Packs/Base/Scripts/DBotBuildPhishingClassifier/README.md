Create a phishing classifier using machine learning technique, based on email content.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | ml |
| Cortex XSOAR Version | 5.0.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| query | Additional text by which to query incidents. |
| incidentTypes | A comma-separated list of incident types by which to filter. |
| fromDate | The start date by which to filter incidents. Date format will be the same as in the incidents query page \(valid strings example: "3 days ago", ""2019-01-01T00:00:00 \+0200"\) |
| toDate | The end date by which to filter incidents. Date format will be the same as in the incidents query page \(valid strings example: "3 days ago", ""2019-01-01T00:00:00 \+0200"\) |
| limit | The maximum number of incidents to fetch. |
| includeContext | Whether to query and fetch incident context. |
| timeField | The incident field \(created or modified\) to specify for the date range. |
| tagField | The field name with the label. Supports a comma-separated list, the first non-empty value will be taken. |
| removeShortTextThreshold | Sample text of which the total number of words are less than or equal to this number will be ignored. |
| dedupThreshold | Remove emails with similarity greater than this threshold, range 0-1, where 1 is completly identical. |
| hashSeed | If non-empty, hash every word with this seed. |
| modelName | The model name to store in the system. |
| phishingLabels | A comma-separated list of email tags values and mapping. The script considers only the tags specified in this field. You can map a label to another value by using this format: LABEL:MAPPED_LABEL. For example, for 4 values in email tag: malicious, credentials harvesting, inner communitcation, external legit email, unclassified. While training, we want to ignore "unclassified" tag, and refer to "credentials harvesting" as "malicious" too. Also, we want to merge "inner communitcation" and "external legit email" to one tag called "non-malicious". The input will be: malicious, credentials harvesting:malicious, inner communitcation:non-malicious, external legit email:non-malicious |
| emailsubject | Incident field name with the email subject. |
| emailbody | Incident field name with the email body \(text\). |
| emailbodyhtml | Incident field name with the email body \(html\). |
| language | The language of the input text. Default is "Any". Can be "Any", "English", "German", "French", "Spanish", "Portuguese", "Italian", "Dutch", or "Other". If "Any"  or "Other" is selected, the script preprocess the entire input, no matter what its acutual language is. If a specific language is selected, the script filters out any other language from the output text. |
| trainingAlgorithm | The training algorithm to use for training the model. Default is "auto". If "auto" is selected, the training algorithm will be chosen automatically based on the number of incidents per each label. Use "from_scratch" to train a new model from scratch, based on your incidents only. In general, "from_scratch" will perform better where the number of incidents is high \(500 incidents or more per each verdict\). "fine-tune" trains a model based on the out-of-the-box model. "fine-tune" will perform better when the number of incidents is relatively low. It's possible to train multiple models using different algorithms options, and compare their results. |

## Outputs
---
There are no outputs for this script.
