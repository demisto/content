Determines whether an IPv4 or IPv6 address is in part of at least one of the comma-delimited CIDR ranges given. Multiple IPv4/IPv6
addresses can be passed as comma-delimited list to be checked. A mix of IPv4 and IPv6 addresses will always return false.

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
| left | The IPv4 or IPv6 address to search for. |
| right | A comma-separated list of IPv4 or IPv6 ranges in CIDR notation against which to match. |
