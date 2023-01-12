Extract regular text from the given HTML

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | Utility |
| Cortex XSOAR Version | 5.0.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| html | The HTML to strip tags from |

## Outputs
---
There are no outputs for this script.


## Script Examples
### Example command
```!TextFromHTML html="<!DOCTYPE html><html><body><h1>This is heading 1</h1></body></html>" ```
### Context Example
```json
{}
```

### Human Readable Output

>This is heading 1
