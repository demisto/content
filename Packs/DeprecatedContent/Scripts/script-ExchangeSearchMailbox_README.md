Searches all mailboxes on an Exchange server and copies the results to a specified target mailbox. This script runs through the agent on a Windows machine, and pulls and executes a `PowerShell` script - which talks to the Exchange server.

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
| query | The Exchange query to match the emails against. |
| toMailbox | The destination mailbox. |
| toFolder | The folder within the destination mailbox in which to place the matched emails. |
| server | The hostname of the Exchange server. |

## Outputs
---
There are no outputs for this script.
