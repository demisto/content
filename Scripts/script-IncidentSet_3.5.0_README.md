Modifies the incident information such as name, owner, type, etc.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python |
| Tags | management |
| Demisto Version | 0.0.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| owner | The incident owner. This must be an existing user on the platform. |
| playbook | The new playbook's assigned name. |
| stage | The incident stage. This must be from a predefined list of stages. |
| details | The incident details. |
| severity | The severity to set. Can be, "low","medium","high" or "critical". |
| type | The incident type. |
| name | The incident name. |
| updatePlaybookForType | Whether to update the playbook according to the new given type. Can be "yes" or "no". The default is yes. |
| labels | Sets and override the labels for the incident. The labels expected format is [{"labelName": "labelValue"}, {"labelName1": "labelValue1"}] (JSON). |
| addLabels | Add to the list of labels for the incident. The labels expected format is [{"labelName": "labelValue"}, {"labelName1": "labelValue1"}] (JSON). |
| customFieldName | The name for a custom field you want to change. |
| customFieldValue | The value you want to set for the field specified in `customFieldName`. |

## Outputs
---
There are no outputs for this script.
