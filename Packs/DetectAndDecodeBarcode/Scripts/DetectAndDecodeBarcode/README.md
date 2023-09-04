Detect and decode barcodes (including QR codes) in a file.

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
| entry_id | The ID for locating a file in War Room |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| DetectAndDecodeBarcode.File.EntryID | The Entry ID of the file | String |
| DetectAndDecodeBarcode.File.Name | The name of the file including extension | String |
| DetectAndDecodeBarcode.File.Barcode.Type | The type of barcode | String |
| DetectAndDecodeBarcode.File.Barcode.Data | The data in the barcode | Unknown |
| DetectAndDecodeBarcode.File.Image | Whether file is an image | Boolean |
