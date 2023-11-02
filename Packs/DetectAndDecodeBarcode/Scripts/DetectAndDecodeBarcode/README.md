Detect and decode 2D barcodes (including QR codes) in a file.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | basescript |
| Cortex XSOAR Version | 5.5.0 |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| entry_id | The ID for locating a file in War Room. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| File.EntryID | The Entry ID of the file. | String |
| File.Name | The name of the file including extension. | String |
| File.Barcode.Type | The type of barcode. | String |
| File.Barcode.Data | The data in the barcode. | Unknown |
| File.Image | Whether file is an image. | Boolean |
