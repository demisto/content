This script pre-process an image file from context.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Cortex XSOAR Version | 6.8.0 |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| action | The action to perform on the image. |
| image_resize | Dimensions for resize to. |
| file_entry_id | The entryID of the file to process. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| PreProcessImage.file_entry_id_new | The entryID of the created file. | String |
| PreProcessImage.action | The action that were performed,. | String |
