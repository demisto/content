Transformer that returns a filtered list of IPv4 addresses, based on whether they do not match a comma-separated list of IPv4 ranges.  Useful for filtering out internal IP address space.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | transformer, entirelist |
| Cortex XSOAR Version | 5.0.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| value | Array or comma-separated list of IPv4 addresses to filter. |
| cidr_ranges | Array or comma-separated list of IPv4 ranges, in CIDR notation, against which to match the IPv4 addresses. |

## Outputs
---
There are no outputs for this script.
