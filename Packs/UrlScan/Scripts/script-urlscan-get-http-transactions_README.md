Gets the HTTP transactions made for a given URL using the `URLScan` integration. 

To use this script properly, go to the **Advanced** section in the task that executes this script, and check the **Run without a worker** checkbox. The system will use less resources for the polling action.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | javascript |
| Tags | polling, UrlScan |


## Dependencies
---
This script uses the following commands and scripts.
* urlscan-get-http-transaction-list
* urlscan-poll-uri
* urlscan-submit-url-command

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| url | The URL to search the transaction list for. |
| wait_time_for_polling | The wait time between two polling actions (in Seconds) of the `URLScan` results page. A rate-limit error may occure if the time value is set too low. |
| timeout | The amount of seconds to wait for the scan ID result. |
| limit | The limit of the results in the War Room. The maximum limit allowed is 100. |

## Outputs
---
There are no outputs for this script.
