Loops through New Hire watchlist entries from Code42 Incydr and removes employees based on specified criteria.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

* Code42

### Scripts

* Set
* DeleteContext

### Commands

* code42-user-get-risk-profile
* code42-user-update-risk-profile
* code42-watchlists-remove-user

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| incydr_username | The username \(in email format\) provided by Code42 Incydr. |  | Required |
| look_back | Number of days to compare the start date against \(e.g. "30", "7", etc.\). Default is 30. | 30 | Required |

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![Remove Employees from New Hire Watchlist](../doc_files/Remove_Employees_from_New_Hire_Watchlist.png)
