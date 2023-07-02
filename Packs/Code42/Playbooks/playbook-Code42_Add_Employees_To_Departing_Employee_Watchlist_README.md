Loops through stand-down tickets provided by the Departing Employee Auto-Add playbook and adds employees to the Departing Employee watchlist in Code42 Incydr.

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
* code42-watchlists-add-user

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| ticket_username | The username \(in email format\) provided in a stand-down ticket from Jira, Zendesk, etc. |  | Required |
| ticket_departure_date | The departure date \(in YYYY-MM-DD format\) provided in a stand-down ticket from Jira, Zendesk, etc. |  | Required |
| ticket_key | The unique identifier of a stand-down ticket from Jira, Zendesk, etc. \(optional\). |  | Optional |

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![Add Employees to Departing Employee Watchlist](../doc_files/Add_Employees_to_Departing_Employee_Watchlist.png)
