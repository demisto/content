Prints the current UID (User ID), GID (Group ID), and PWD (current working directory) of the running Docker container environment.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | Utility |
| Cortex XSOAR Version | 6.0.0 and later |

## Inputs

---
There are no inputs for this script.

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| EnvDetails.UID | The User ID of the running process. | Number |
| EnvDetails.GID | The Group ID of the running process. | Number |
| EnvDetails.PWD | The current working directory. | String |
