
Extract text from QR codes.
The output of this script includes the output of the script "extractIndicators" run on the text extracted from the QR code.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Cortex XSOAR Version | 6.10.0 |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| entry_id | The entry ID of the QR code image. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| QRCodeReader.Text | The raw text extracted from the QR code image. | String |
| QRCodeReader.Domain | The domains extracted from the QR code image if they are present. | String |
| QRCodeReader.URL | The URLs extracted from the QR code image if they are present. | String |
| QRCodeReader.IP | The IPs extracted from the QR code image if they are present. | String |

## Script Examples

### Example command

```!ReadQRCode entry_id=1234@1234abcd-12ab-12ab-12ab-1234abcd```

### Context Example

```json
{
    "QRCodeReader": {
        "Domain": [
            "xsoar.pan.dev"
        ],
        "Text": "https://xsoar.pan.dev/",
        "URL": [
            "https://xsoar.pan.dev/"
        ]
    }
}
```

### Human Readable Output

>### QR Code Read
>|Text|
>|---|
>| https://xsoar.pan.dev/ |

