This script will extract indicators from given HTML and will handle bad top-level domains to avoid false positives caused by file extensions.

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
| url | The full URL of the blog |
| exclude_indicators | The indicators to be excluded from the results. |
| exclude_TLD | Top-Level-Domain to be excluded from domain indicators. |
| unescape_domain | Whether to remove brackets \[\] from the domain regex extraction. Can result in higher false positives for file extensions. |

## Outputs
---
There are no outputs for this script.
