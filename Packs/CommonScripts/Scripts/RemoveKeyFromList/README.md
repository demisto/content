Removes a key in key/value store backed by an XSOAR list.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags |  |
| Demisto Version | 5.0.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| listName | List name. |
| keyName | Key. |

## Outputs
---
There are no outputs for this script.


## Script Example
```!RemoveKeyFromList listName="NewList" keyName="SomeKey"```

## Context Example
```json
{}
```

## Human Readable Output

>Successfully removed key SomeKey from list NewList.
