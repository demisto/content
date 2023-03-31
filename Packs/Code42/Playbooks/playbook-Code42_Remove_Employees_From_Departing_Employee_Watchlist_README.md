Loops through Departing Employee watchlist entries from Code42 Incydr and removes employees based on specified criteria.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

* Code42

### Scripts

* Set

### Commands

* code42-departingemployee-remove
* code42-user-update-risk-profile
* code42-securitydata-search

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| incydr_departure_date | The departure date \(in YYYY-MM-DD format\) provided by Code42 Incydr. |  | Required |
| incydr_username | The username \(in email format\) provided by Code42 Incydr. |  | Required |
| incydr_uid | The unique identifier of a user provided by Code42 Incydr \(optional\). |  | Optional |

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![Remove Employees from Departing Employee Watchlist](../doc_files/Remove_Employees_from_Departing_Employee_Watchlist.png)
