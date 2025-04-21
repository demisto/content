Get the triggering events of a Gem Alert and send a validation Slack message to the dev team.
The response will be added to the Gem Timeline.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

* Gem

### Scripts

* Set
* ZipStrings

### Commands

* gem-get-alert-details
* gem-add-timeline-event

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| User | Extra Slack user to send validation to |  | Optional |

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![Gem Validate triggering event](../doc_files/Gem_Validate_triggering_event.png)
