Compare two lists and put the differences in context.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Cortex XSOAR Version | 5.0.0 |

## Used In

---
This script is used in the following playbooks and scripts.

* Allow IP - Okta Zone
* Checkpoint - Block IP - Append Group
* Checkpoint - Block IP - Custom Block Rule
* IP Whitelist - AWS Security Group
* IP Whitelist - GCP Firewall

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| left | Left list |
| right | Right list |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| ListCompare.LeftOnly | Items only found within the list in the left argument | Unknown |
| ListCompare.RightOnly | Items only found within the list in the right argument | Unknown |
| ListCompare.Both | Common items that were found in both lists | Unknown |
