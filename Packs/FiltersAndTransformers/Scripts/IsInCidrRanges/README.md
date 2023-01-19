Determines whether an IPv4 address is in part of at least one of the comma-delimited CIDR ranges given. Multiple IPv4
addresses can be passed as comma-delimited list to be checked.

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
| left | The IPv4 address to search for. |
| right | A comma-separated list of IPv4 ranges in CIDR notation against which to match. |
