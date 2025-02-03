Sends a message to the LLM.  If any search results have been added to the conversation, they are added to the LLM workspace thread's context just before the latest message is added. The pending search results buffer is then cleared

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| question | The question or message to send to the LLM |
| mode | "chat" mode uses the LLMs full training data and "query" mode requires some results found in the embedded documents in addition to the LLM's conversation  context |

## Outputs

---
There are no outputs for this script.
