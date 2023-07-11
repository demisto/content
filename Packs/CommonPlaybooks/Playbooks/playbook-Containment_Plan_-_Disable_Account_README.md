This playbook is one of the sub-playbooks in the containment plan. 
This playbook handles disabling the account as a crucial step in the containment action.


## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

* Block Account - Generic v2

### Integrations

This playbook does not use any integrations.

### Scripts

* CompareLists
* IsIntegrationAvailable
* SetAndHandleEmpty

### Commands

* setParentIncidentContext

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| UserContainment | Set to 'True' to disable the user account. | True | Optional |
| Username | The username to disable. |  | Optional |

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![Containment Plan - Disable Account](../doc_files/Containment_Plan_-_Disable_Account.png)
