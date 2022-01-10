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
![Arcanna-Generic-Investigation](https://user-images.githubusercontent.com/6702878/124025997-cdeede80-d9f9-11eb-8faa-e297c7cd3ca7.png)
