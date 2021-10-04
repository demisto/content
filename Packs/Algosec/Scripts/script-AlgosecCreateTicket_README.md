Creates a new FireFlow change request. 

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python |
| Tags | Algosec |


## Dependencies
---
This script uses the following commands and scripts.
* algosec-create-ticket

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| description | The free text description of the issue. |
| devices | The list of device names, on which the change should be made. |
| action | The device action to perform for the traffic. Can be, "1" which will allow the traffic, or "0" which will block the traffic. |
| destAddress | The destination address to perform the action on. |
| sourceAddress | The source address to perform the action on. |
| requestor | The email address of the requestor. |
| subject | The change request's title. |
| service | The device service or port for the connection, for example, "http" or "tcp/123". |
| user | The user for the connection. |
| application | The application for the connection. |

## Outputs
---
There are no outputs for this script.
