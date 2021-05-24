Prints a raw representation of a string or object, visualising things likes tabs and newlines.  For instance, '\n' will be displayed instead of a newline character, or a Windows CR will be displayed as '\r\n'.  This is useful for debugging issues where things aren't behaving as expected, such as when parsing a string with a regular expression.
## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags |  |
| Cortex XSOAR Version | 5.5.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| value | The value to be represented. |

## Outputs
---
There are no outputs for this script.


## Script Example
```
!PrintRaw value=`Lorem ipsum dolor
 sit amet, consectetur adipiscing elit,
sed do eiusmod tempor incididunt  `
```

## Context Example
```
{}
```

## Human Readable Output
'Lorem ipsum dolor\n sit amet, consectetur adipiscing elit,\nsed do eiusmod tempor incididunt  '
