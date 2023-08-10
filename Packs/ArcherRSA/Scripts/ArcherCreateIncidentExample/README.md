This script is an example script of how to create Incident in Archer. The script generates the created incident data in JSON format and execute the command archer-create-record.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Cortex XSOAR Version | 5.0.0 |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| summary | Incident summary |
| priority | Incident priority |
| category | Incident category |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Archer.Record.Id | Unique ID of the record. | Number |
