Assigns a "Mailbox Import Export" management role to a user. This script runs through the agent on a Windows machine, pulls and executes a `PowerShell` script, which talks to the Exchange server.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | javascript |
| Tags | exchange, email |


## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| username | The username to assign the role to. |
| role | Whether a different role should be assigned to the user. The default is "Mailbox Import Export". |
| server | The hostname of the Exchange server. |

## Outputs
---
There are no outputs for this script.
