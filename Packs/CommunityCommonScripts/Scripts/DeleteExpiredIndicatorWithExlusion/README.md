Use this script to delete indicators that have expired.
The executeCommand function is called with two arguments. The first argument is the name of the command, which is "deleteIndicators". The second argument is a dictionary containing additional parameters for the command. In this case, the query parameter is set to "expirationStatus:expired", which specifies that only indicators with an expiration status of "expired" should be deleted. The doNotWhitelist parameter is set to "true", indicating that any indicators deleted should not be updated on exclusion list. 
## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Cortex XSOAR Version | 6.8.0 |

## Inputs
---
There are no inputs for this script.

## Outputs
---
There are no outputs for this script.
