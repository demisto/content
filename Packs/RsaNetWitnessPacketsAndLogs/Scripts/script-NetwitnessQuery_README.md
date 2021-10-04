Performs a query against the meta database.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python |
| Tags | RSA NetWitness Packets & Logs |


## Dependencies
---
This script uses the following commands and scripts.
* nw-sdk-query

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| id1 | The starting meta ID. To run the query from the most recent to the oldest meta, make ID1 larger than ID2. (uint64, optional) |
| id2 | The ending meta ID. (uint64, optional) |
| size | The maximum number of entries to return, or just stream back all results if zero. (uint32, optional) |
| query | The query string to use. (string, optional)  |
| flags | The flags to use for the query.  Can be, "number" (bitwise mask), or "comma-separated-values" like query-log. (string, optional) |
| threshold | Queries the optimization to stop processing results after the threshold is reached. This is useful with select aggregate functions. Zero means there is no threshold. The default is zero. (uint64, optional) |

## Outputs
---
There are no outputs for this script.
