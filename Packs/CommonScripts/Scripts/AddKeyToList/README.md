Adds/Replaces a key in key/value store backed by an XSOAR list.

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
| value | Key Value. |
| append | Append to key. |
| allowDups | Allow duplicates in array keys. |

## Outputs
---
There are no outputs for this script.


## Script Example
```!AddKeyToList listName="NewList" keyName="SomeKey" value="TestValue"```

## Context Example
```json
{}
```

## Human Readable Output

>Successfully updated list NewList.
