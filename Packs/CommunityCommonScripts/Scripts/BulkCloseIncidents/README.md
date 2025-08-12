Prerequisite:
- Core REST API integration must be configured. 

Purpose: Close incidents in bulk without causing any performance impact on the XSOAR server. 

Description: Takes provided query and closes incidents in batches, waiting for a period of time before closing the next batch. Default batch size is 15 and default sleep between batches is 30 seconds. These are safe values to avoid causing any performance impact on the server. Adjust with caution. Timeout is set for 4 hours or 14400 seconds.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | Utilities, Utility |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| query | Lucene query for searching incidents |
| batch_size | Batch size for number of incidents to close at once. Default value is 15. |
| sleep | Amount of time to sleep in between batches, in seconds. Default value is 30. |

## Outputs

---
There are no outputs for this script.
