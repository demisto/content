Deprecated. Use OSQueryBasicQuery with `query='select distinct pid, family, protocol, local_address, local_port, remote_address, remote_port, path from process_open_sockets where path \<\> '' or remote_address \<\> '';'` instead.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python2 |
| Tags | OSQuery |
| Cortex XSOAR Version | 5.0.0 |

## Dependencies
---
This script uses the following commands and scripts.
* OSQueryBasicQuery

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| system | The System to remote execute on, can be a list of systems |

## Outputs
---
There are no outputs for this script.
