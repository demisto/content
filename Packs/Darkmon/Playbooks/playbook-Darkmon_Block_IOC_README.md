Analyst-facing wrapper around Darkmon - Generic Block Indicator. Lets analysts paste an IOC into a War Room form and trigger a provider-routed block action.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

* Dispatch block via provider switchboard
* Notify SOC of manual block

### Integrations

This playbook does not use any integrations.

### Scripts

This playbook does not use any scripts.

### Commands

This playbook does not use any commands.

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Indicator | The indicator value to block. |  | Required |
| Type | ip \| domain \| url. | ip | Optional |
| Reason | Reason annotated on the block rule. | Manual analyst-triggered block | Optional |

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![Darkmon - Block IOC](../doc_files/Darkmon_-_Block_IOC.png)
