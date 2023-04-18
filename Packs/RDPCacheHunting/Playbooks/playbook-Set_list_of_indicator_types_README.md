This playbook takes IOCs as input and adds the type into a list to be able to calculate stats about the types of the extracted indicators

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

This playbook does not use any integrations.

### Scripts

This playbook does not use any scripts.

### Commands

* addToList
* setList

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Domain | Indicators of type domain |  | Optional |
| URL | Indicators of type URL |  | Optional |
| WindowsDateTime | Indicators of type WindowsDateTime |  | Optional |
| IP | Indicators of type IP address |  | Optional |
| Executables | Indicators of type Executables |  | Optional |
| WindowsPaths | Indicators of type Windows Paths |  | Optional |
| EmailAddresses | Indicators of type Email address |  | Optional |

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![Set list of indicator types](../doc_files/Set_list_of_indicator_types.png)
