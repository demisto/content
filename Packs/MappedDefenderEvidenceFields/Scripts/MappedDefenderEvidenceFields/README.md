Maps MicrosoftATP.Alert evidence objects into a normalized structure.
 Handles multiple entity types (User, Url, Process) and extracts key fields:
 user, host, file, process, URL, IP, hashes, registry, timestamps, etc.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | transformer, atp, abrar |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| value | Evidence section from MicrosoftATP.Alert |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| DefenderEvidence  | Normalized evidence objects. | Unknown |
