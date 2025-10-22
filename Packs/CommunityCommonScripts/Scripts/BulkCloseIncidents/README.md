Prerequisite:
- Core REST API integration must be configured. 

Purpose: Close incidents in bulk.

Description: Takes provided query and closes incidents in batches. Default batch size is 50.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | Utilities, Utility |
| Cortex XSOAR Version | 6.10.0 |

## Dependencies

---
This script uses the following commands and scripts.

* Core REST API
* core-api-post

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| query | Query for searching incidents. |
| batch_size | Batch size for number of incidents to close at once. |

## Outputs

---
There are no outputs for this script.
