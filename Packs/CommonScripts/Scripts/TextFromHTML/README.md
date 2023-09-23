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

| **Argument Name** | **Description**| 
| --- | --- |
| html | The HTML to strip tags from |
| html_tag | Specify HTML tag to extract the text from within. | 
| allow_body_fallback | Allow using the input HTML as a fallback for the Body, if no body-tag is found (default: false) |
| context_path | The Context path to store the Converted Text. (optional)  





## Outputs
---
There are no outputs for this script unless specified in `context_path`


## Script Examples
### Example command
```!TextFromHTML html="<!DOCTYPE html><html><body><h1>This is heading 1</h1></body></html>" ```

### Context Example
```json
{}
```

### Human Readable Output

>This is heading 1
