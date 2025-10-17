Checks if an IP is already covered by CIDR/range in Okta BlockedIpZone. If not, it adds it.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | Okta, IP Block, Zone Management |
| Cortex XSOAR Version | 6.10.0 |

## Dependencies

---
This script uses the following commands and scripts.

* Okta v2
* okta-list-zones
* okta-update-zone

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| ip | The external IP address to check/add to BlockedIpZone \(not private\). |

## Outputs

---
There are no outputs for this script.
