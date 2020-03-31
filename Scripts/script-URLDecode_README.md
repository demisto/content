Converts "https:%2F%2Fexample.com" into "https:/<span>/example.com".

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python |
| Tags | transformer |
| Demisto Version | 0.0.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| value | The URL to input.  |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| DecodedURL | The parsed URL as a key/value. | string |
