Formats URL to indicator: extracts redirect URL from Proof Point or ATP URLs. Strips and unquotes and unescapes URLs

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | indicator-format |
| Cortex XSOAR Version | 5.5.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| input | URL inputs. Comma separated list. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| URL | URL formatted. | String |


## Script Example
```!FormatURL input=https://urldefense.proofpoint.com/v2/url?u=https-3A__example.com_something.html```

## Context Example
```json
{
    "URL": [
        "https://example.com/something.html"
    ]
}
```

## Human Readable Output

>https://example.com/something.html
