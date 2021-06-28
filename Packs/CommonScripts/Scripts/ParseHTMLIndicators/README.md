This script will extract indicators from HTML and will handle bad TLD to avoid file extensions false positives.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags |  |
| Demisto Version | 5.5.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| url | The full url of the blog |
| excludeIndicators | The indicators to exclude from the results |
| unescapeDomain | Remove \[.\] from the Domain regex. Can result in higher false positives. |
| excludeTLD | Top Level Domain to exclude from domain indicators. |

## Outputs
---
There are no outputs for this script.
