This script will extract indicators from HTML and will handle bad top-level domains to avoid false positives caused by file extensions.

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
| url | The full URL of the blog. |
| excludeIndicators | The indicators to be excluded from the results. |
| unescapeDomain | Whether to remove brackets [ ] from the domain regex extraction. This can result in higher false positives for file extensions. |
| excludeTLD | Top-level domain to be excluded from the domain indicators. |

## Outputs
---
There are no outputs for this script.
