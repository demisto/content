Takes incident data and sends it to Arcanna.Ai for ML inference and automated decision

## Dependencies
There are no dependencies on other playbooks

### Sub-playbooks


### Integrations
This playbook uses ArcannaAi integration

### Scripts
* PrepareArcannaRawJson

### Commands
* arcanna-send-event
* arcanna-get-event-status
* arcanna-send-event-feedback
* arcanna-get-feedback-field

## Playbook Inputs
---

| **Name** | **Description** | **Required** |
| --- | --- | --- |
| incident RawJson | Incident rawJson or another Json  formatted string. | Yes |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Arcanna-Generic-Investigation-V2](https://user-images.githubusercontent.com/6702878/131002353-3176a6e0-c08a-43db-910a-5b33de7b60cc.png)
