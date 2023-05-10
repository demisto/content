Enables a clients application to enroll an endpoint or revoke its enrollment. This is usually relevant for endpoints with pending status but can be applicable to endpoints with any current status. The endpoint needs to be specified by its ID, which have been received from an endpoint list request, from a new endpoint notification, or from any other implemented manual or automated input.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python |
| Tags | Imperva Skyfence |


## Dependencies
---
This script uses the following commands and scripts.
* imp-sf-set-endpoint-status

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| endpointId | The ID of the endpoint.  |
| action | Whether to "enroll" or "revoke". |

## Outputs
---
There are no outputs for this script.
