Converts string to array.
For example: `http://example.com/?score:1,4,time:55` will be transformed to `["http://example.com/?score:1,4,time:55"]`.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | transformer |
| Cortex XSOAR Version | 6.0.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| value | The URL to transform. |

## Script Example
```!StringToArray value="http://example.com/?score:1,4,time:55"```

## Human Readable Output
```["http://example.com/?score:1,4,time:55"]```
