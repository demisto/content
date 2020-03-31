Reads an image file's metadata and provides `Exif` tags.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python |
| Tags | Utility |
| Demisto Version | 0.0.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| EntryID | The entry ID of the image file. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Exif.tag | The `Exif` tag name. | string |
| Exif.value | The `Exif` tag value. | string |
