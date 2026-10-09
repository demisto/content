Hourly poll of compromised employees. For each new entry, looks up the user
in the configured directory and acts per the DisableMode playbook input:
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

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| DisableMode | Controls how the playbook reacts when a new compromised employee account is observed. Allowed values: notify-only (default, safe) - creates an incident and notifies, no directory action; approval-required - creates an incident with a manual approval task; on approve, runs the disable; auto-disable - disables the account immediately, then notifies. Accounts in the 'Darkmon - Auto-Disable Allowlist' list are NEVER auto-disabled regardless of this input. | notify-only | Optional |

## Playbook Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| NewAccounts | Compromised employee accounts that triggered action this run. | unknown |
