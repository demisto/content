Extract hyperlinks from office files. Supported file types are: xlsx, docx, pptx.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Cortex XSOAR Version | 5.5.0 |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| entry_id | The entry id of the file to extract hyperlinks from. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| ExtractedHyperLink.URL | The extracted hyperlinks URL. | String |
| ExtractedHyperLink.FileName | The office file that the hyperlinks extracted from. | String |

## Script Examples

### Example command

```!ExtractHyperlinksFromOfficeFiles entry_id=1249@93725c86-540d-4ee4-8728-f0ab82b1cb46```

### Context Example

```json
{
    "ExtractedHyperLink": {
        "FileName": "Link.docx",
        "URL": "https://www.paloaltonetworks.com/"
    }
}
```

### Human Readable Output

># Extracted hyperlinks are:
>
>https://www.paloaltonetworks.com/
