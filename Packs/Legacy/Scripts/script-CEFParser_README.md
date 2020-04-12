Parses CEF data into the context. Outputs will display only the 7 mandatory fields even if the CEF event includes many other custom or extended fields.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | javascript |
| Tags | Utility |


## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| data | The data that contains the CEF rows. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| CEFEvent.cefVersion | The CEF version. | Unknown |
| CEFEvent.vendor | The product vendor. | Unknown |
| CEFEvent.product | The product name. | Unknown |
| CEFEvent.version | The product version. | Unknown |
| CEFEvent.signatureID | The signature ID for the alert, if relevant. | Unknown |
| CEFEvent.name | The alert name. | Unknown |
| CEFEvent.severity | The alert severity. | Unknown |
