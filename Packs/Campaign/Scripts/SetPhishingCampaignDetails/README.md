Copying EmailCampaign context from current incident to other existing incident.
This script runs with elevated permissions.
Cortex XSOAR recommends using the built-in RBAC functionality to limit access to only those users requiring access to this script.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Cortex XSOAR Version | 6.0.0 |

## Used In

---
This script is used in the following playbooks and scripts.

* Detect & Manage Phishing Campaigns

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| id | Incident to set context values in. |
| append | If false then the context key will be overwritten. If set to true then the script will append to existing context key. |

## Outputs

---
There are no outputs for this script.
