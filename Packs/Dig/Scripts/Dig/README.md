DNS lookup utility to provide 'A' and 'PTR' record 

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | Utility |
| Cortex XSOAR Version | 6.0.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| server | The IP address or hostname of the name server to query. The default value will be taken from /etc/resolv.conf e.g. 8.8.8.8 |
| name | Name of the resource record to look up e.g. paloaltonetworks.com. For reverser lookup, provide IP address |
| reverseLookup | Perform reverse lookup |

## Outputs
---
There are no outputs for this script.
