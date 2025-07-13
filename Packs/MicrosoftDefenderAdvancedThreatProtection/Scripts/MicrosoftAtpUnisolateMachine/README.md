A polling wrapper script; isolates a machine from accessing external networks.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | Utilities |
| Cortex XSOAR Version | 6.1.0 |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| machine_id | A comma-separated list of machine IDs to be used to stop the isolation. For example: 0a3250e0693a109f1affc9217be9459028aa8426,0a3250e0693a109f1affc9217be9459028aa8424. |
| comment | Comment to associate with the action. |
| ran_once_flag | Flag for the rate limit retry. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| MicrosoftATP.Machine.Isolation.Requestor | Machine un-isolation requestor. | string |
| MicrosoftATP.Machine.Isolation.RequestorComment | Machine un-isolation requestor comment. | string |
| MicrosoftATP.Machine.ID | Machine ID. | Unknown |
