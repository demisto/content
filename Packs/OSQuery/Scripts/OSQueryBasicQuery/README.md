Returns the results from a basic `OSQuery` query on a remote Linux machine.
For more information read this [documentation](https://osquery.readthedocs.io/).

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python |
| Tags | OSQuery |


## Dependencies
---
This script uses the following commands and scripts.
* RemoteExec

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| system | The system to remote execute on. This can be a list of systems. |
| query | The `osquery` query to execute on the remote system. |

## Outputs
---
There are no outputs for this script.

## Examples:
```
!OSQueryBasicQuery system=test_system query="select liu.*, p.name, p.cmdline, p.cwd, p.root from logged_in_users liu, processes p where liu.pid = p.pid;"
```
Returns logged in users details from a remote system using OSQuery.

```
!OSQueryBasicQuery system=test_system query="select distinct pid, family, protocol, local_address, local_port, remote_address, remote_port, path from process_open_sockets where path <> '' or remote_address <> '';"
```
Returns open sockets details from a remote system using OSQuery.

```
!OSQueryBasicQuery system=test_system query="select * from processes;"
```
Returns processes details from a remote system using OSQuery.

```
!OSQueryBasicQuery system=test_system query="select * from users;"
```
Returns Users Table from a remote system using OSQuery.