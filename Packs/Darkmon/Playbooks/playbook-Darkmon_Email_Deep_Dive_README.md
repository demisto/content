Analyst-driven full Darkmon profile for a single email address. Runs board-protection check, all three boardemails categories, and global search. Outputs a unified summary into the incident War Room.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

* Darkmon

### Scripts

* PrintErrorEntry

### Commands

* dmontip-get-boardemails
* dmontip-get-boardprotection
* dmontip-global-search

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Email | Email address to investigate. |  | Required |

## Playbook Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Darkmon.BoardProtection | Board-protection records that match the email. | unknown |
| Darkmon.BoardLeak.Account | Account-class board-leak records for this email. | unknown |
| Darkmon.BoardLeak.ComboList | Combo-list records for this email. | unknown |
| Darkmon.BoardLeak.PublicBreach | Public-breach records for this email. | unknown |
| Darkmon.SearchResult | Global-search hits for the email. | unknown |
