A filter that receives a single IPv4 address string as an input and determines whether it is in the private RFC-1918 address space (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16). For more information, see https://en.wikipedia.org/wiki/Private_network

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | filter |
| Cortex XSOAR Version | 5.0.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| value | The IPv4 address to check. |
| left | The IPv4 address to check \(can be used instead of the value argument\). |

## Outputs
---
There are no outputs for this script.
