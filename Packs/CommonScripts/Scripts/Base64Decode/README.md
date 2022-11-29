Decodes an input in Base64 format.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | Utility, transformer, string |
| Cortex XSOAR Version | 5.0.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| value | The value to decode in Base64 format. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Base64.decoded | The decoded output in Base64 format. | string |
| Base64.originalValue | The passed value that was decoded. | string |

## Script Examples
### Example command
```!Base64Decode value=VGhpcyBpcyBhIHRlc3Q```
### Context Example
```json
{
    "Base64": {
        "decoded": "This is a test",
        "originalValue": "VGhpcyBpcyBhIHRlc3Q"
    }
}
```
