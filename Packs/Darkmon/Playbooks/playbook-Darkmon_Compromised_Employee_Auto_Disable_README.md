Hourly poll of compromised employees. For each new entry, looks up the user
in the configured directory and acts per the integration's
employee_disable_mode parameter:
  - notify-only       : creates incident and notifies; no AD action.   [DEFAULT]
  - approval-required : creates incident, blocks on a manual approval task,
                        then disables on approve.
  - auto-disable      : disables the account immediately, then notifies.
Accounts in the 'Darkmon - Auto-Disable Allowlist' list are NEVER auto-disabled.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

* Darkmon - Generic Notify
* Darkmon - Generic User Action

### Integrations

* Darkmon

### Scripts

* DarkmonCreateIncidents
* DarkmonFilterUnseen

### Commands

* dmontip-get-compromised

## Playbook Inputs

---
There are no inputs for this playbook.

## Playbook Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| NewAccounts | Compromised employee accounts that triggered action this run. | unknown |

## Playbook Image

---

![Darkmon_Compromised_Employee_Auto_Disable](../doc_files/Darkmon_Compromised_Employee_Auto_Disable.png)
