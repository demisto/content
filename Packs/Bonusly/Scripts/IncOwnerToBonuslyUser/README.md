This script gets the email address of the incident owner and then returns the incident owner username in Bonusly.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | Bonusly, Utilities |
| Cortex XSOAR Version | 5.0.0 |

## Used In

---
This script is used in the following playbooks and scripts.

* Bonusly - AutoGratitude

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| json | Enter JSON STRING like \{'email@company':'@bonuslyuser'\} |
| owner | The username of the Cortex XSOAR incident owner. This will look up the incident owner's email address. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| IncOwnerEmail | Email address of the incident owner. | Unknown |
| BonuslyUser | Usernname in Bonusly of the incident owner. | Unknown |
