Handles a Logz.io Alert by retrieving the events that generated it.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* Logzio

### Scripts
This playbook does not use any scripts.

### Commands
* logzio-get-logs-by-event-id

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| AlertEventID | Logz.Io Alert Event ID | incident.logzioalerteventid | Required |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Logz.Io Handle Alert](https://raw.githubusercontent.com/demisto/content/3cf14921e3e322c96eaf85fa5b161a07616a32fe/Packs/Logzio/doc_imgs/Logz.Io_Handle_Alert.png)
