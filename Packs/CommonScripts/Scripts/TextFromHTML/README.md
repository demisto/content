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
| html_tag | Specify HTML tag to extract the text from within. |
| allow_body_fallback | Allow using the input HTML as a fallback for the Body, if no body-tag is found \(default: false\). This only applies, if html_tag is set to body. |
| replace_line_breaks | Replace \`br\` in \`html\` with linebreaks in the output  \(default: false\). |
| trim_result | Trim the extracted result \(default: false\). When set to true, leading and trailing whitespaces are removed and blocks of more than 3 consecutive whitespaces are collapsed to two. |
| output_to_context | Store the converted Text in the Context. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| TextFromHTML | The Text extracted from the given HTML. | string |


## Script Examples
### Example command
```!TextFromHTML html="<!DOCTYPE html><html><body><h1>This is heading 1</h1></body></html>" ```

### Context Example
```json
{}
```

### Human Readable Output

>This is heading 1