Full text search of a LLM document for a text pattern (regex) for more results as a companion to similarity search that returns a few top results.  Currently supports only war room file entries, search results, and text that has been preprocessed in XSOAR prior to uploading to the LLM.  (See AnyLlmUploadText, AnyLlmUploadFileEntry and AnyLlmUploadDocument). Results are placed in the search results buffer for where they can be added to the LLM's conversation context

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| title | title of the LLM document to search with the XSOAR file entry ID. Example:  "37@25496_anythingllm.txt" |
| pattern | regex to search text for \[ see re.findall\(\) \] |

## Outputs

---
There are no outputs for this script.
