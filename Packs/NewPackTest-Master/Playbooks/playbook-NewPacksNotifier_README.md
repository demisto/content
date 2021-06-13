Send updates on new released packs to slack channel

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
This playbook does not use any integrations.

### Scripts
* GetTime
* IsListExist
* CreateArray
* http

### Commands
* setList
* closeInvestigation
* send-notification
* getList
* createList

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| channel_name | Comma seperated channel names on slack to send the notification to. |  | Required |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![NewPacksNotifier](Insert the link to your image here)