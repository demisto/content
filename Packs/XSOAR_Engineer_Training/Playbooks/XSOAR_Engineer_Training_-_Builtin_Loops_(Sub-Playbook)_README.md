This sub-playbook runs a SIEM search, and also increments a counter to track how many loops were performed while waiting for a search result.  Used with the parent playbook to demonstrate the Builtin looping method.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

* XSOAR Engineer Training

### Scripts

* Set
* DeleteContext

### Commands

* siem-search

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| query | The query to run on the SIEM |  | Required |

## Playbook Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| SIEM.Result | The results of the SIEM search. The results are a JSON array, in which each item is a SIEM event. | unknown |
| LoopCounter | The number of loops that the sub-playbook went through.  | unknown |

## Playbook Image

---

![XSOAR Engineer Training - Builtin Loops (Sub-Playbook)](../doc_files/XSOAR_Engineer_Training_-_Builtin_Loops_(Sub-Playbook).png)
