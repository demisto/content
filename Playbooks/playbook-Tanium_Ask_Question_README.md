Uses generic polling to gets question result.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* GenericPolling

### Integrations
This playbook does not use any integrations.

### Scripts
This playbook does not use any scripts.

### Commands
* tn-ask-question
* tn-get-question-result 

## Playbook Inputs
---

| **Name** | **Description** | **Required** |
| --- | --- | --- |
| question-text |  |  Optional |
| parameters |  | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Tanium.QuestionResult.Results | The question results. | unknown |
| Tanium.Question.ID | The unique ID of the question object | unknown |

![Tanium_Ask_Question](https://github.com/demisto/content/blob/77dfca704d8ac34940713c1737f89b07a5fc2b9d/images/playbooks/Tanium_Ask_Question.png)
