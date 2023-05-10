Close historical XSOAR incidents that are already closed on Securonix.

NOTE: This script will close all the XSOAR incidents which are created from Securonix integration and does not have incident type as "Securonix Incident" in the provided time frame.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Cortex XSOAR Version | 6.5.0 |

## Dependencies
---
This script uses the following commands and scripts.
* securonix-incident-activity-history-get

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| from | Filter the incidents which are created after the specified UTC date/time in XSOAR. \(Supported formats: 2 minutes, 2 hours, 2 days, 2 weeks, 2 months, 2 years, yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ, yyyy-MM-ddTHH:mm:ss.SSSZ. For example: 01 Jan 2023, 01 Feb 2023 04:45:33, 2023-01-26T14:05:44Z, 2023-01-26T14:05:44.000Z\) |
| to | Filter the incidents which are created before the specified UTC date/time in XSOAR. \(Supported formats: 2 minutes, 2 hours, 2 days, 2 weeks, 2 months, 2 years, yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ, yyyy-MM-ddTHH:mm:ss.SSSZ. For example: 01 Jan 2023, 01 Feb 2023 04:45:33, 2023-01-26T14:05:44Z, 2023-01-26T14:05:44.000Z\) |
| close_states | If the Securonix incident is in any one of the state mentioned here, then the incident will be Closed on XSOAR. Supports comma-separated values. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Securonix.CloseHistoricalXSOARIncidents.IncidentIDs | List of XSOAR incident IDs that were closed. | Unknown |


## Troubleshooting
---

The default timeout of this script is 1 hour. If you expect more number of incidents to be closed, then increase the
timeout of the script by using the `execution-timeout` argument. This argument expects the value to be passed in `seconds`.