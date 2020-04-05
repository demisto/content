Uses generic polling to gets saved question result.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* GenericPolling

### Integrations
This playbook does not use any integrations.

### Scripts
This playbook does not use any scripts.

### Commands
* tn-get-saved-question-result

## Playbook Inputs
---

| **Name** | **Description** | **Required** |
| --- | --- | --- | 
| saved-question-id | The unique IDs of the saved questons. | Required |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Tanium.SavedQuestionResult.Results | The saved question results. | unknown |
| Tanium.SavedQuestionResult.SavedQuestionID | The unique ID of the saved question object. | unknown |

## Playbook Image
---
![Tanium_Get_Saved_Question_Result](https://raw.githubusercontent.com/demisto/content/1bdd5229392bd86f0cc58265a24df23ee3f7e662/docs/images/playbooks/Tanium_Get_Saved_Question_Result.png)
