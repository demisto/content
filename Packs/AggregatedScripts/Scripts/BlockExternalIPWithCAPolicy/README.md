Blocks an external IP via Azure Conditional Access using named IP location and policy JSON.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | Azure, Conditional Access, IP Blocking |
| Cortex XSOAR Version | 6.10.0 |

## Used In

---
This script is used in the following playbooks and scripts.

* silent-Abnormal first access to a resource via SSO in the organization

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| ip | The external IP address to block \(must be public\). |
| named_location_name | The name of the Azure named IP location to use or create. |
| policy_name | Name of the Conditional Access policy to create. |

## Outputs

---
There are no outputs for this script.
