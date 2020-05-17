Extracts URLs redirected by security tools like Proofpoint, and changes "https://urldefense.proofpoint.com/v2/url?u=https-3A__example.com_something.html -> https://example.com/something.html"
Also, this will un-escape URLs that are escaped for safety with formats such as "hxxps://www[.]demisto[.]com".
## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | javascript |
| Tags | indicator-format |


## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| input | The URL(s) to process. |

## Outputs
---
There are no outputs for this script.
