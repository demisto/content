Strips, unquotes and unescapes URLs. If the URL is a Proofpoint or ATP URL, extracts its redirect URL.

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
| input | A comma-separated list of URL inputs. |

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
