Uses the Demisto REST API integration to query the server audit trail logs, and return back a CSV or JSON file.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | Utility |

## Dependencies
---
This script uses the following commands and scripts.
* demisto-api-post

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| days_back | How many days back to fetch for, supports 1,2,3 or 7 days back. |
| output | Type of File to return, either JSON, or CSV |

## Outputs
---
There are no outputs for this script.
