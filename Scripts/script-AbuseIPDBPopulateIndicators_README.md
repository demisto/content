Extracts blacklisted IP addresses from AbuseIPDB, and populates indicators accordingly.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python |
| Tags |  |
| Demisto Version | 0.0.0 |

## Dependencies
---
This script uses the following commands and scripts.
* createNewIndicator
* abuseipdb-get-blacklist

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| days | The time range to return reports for (in days). The default is 30. |
| limit | The maximum number of IP addressess to retrieve. The default is 50  |

## Outputs
---
There are no outputs for this script.
