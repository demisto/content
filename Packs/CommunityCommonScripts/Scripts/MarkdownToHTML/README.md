Converts Markdown to HTML.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | markdown, HTML |
| Cortex XSOAR Version | 6.2.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| text | Markdown Text to transform. |
| convertOnlyMarkdown | If True - The markdown text will be converted to HTML without a Full HTML structure. |
| prettifyHTML | If True - The resulted HTML will be nicely formatted as a Unicode string, with a separate line for each tag and each string. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| MarkdownToHTML | The MarkdownToHTML script's results | Dict |
