# RSSWidget Script

### Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Cortex XSOAR Version | 5.5.0 |

### Inputs
---
| **Argument Name** | **Description** |
| --- | --- |
| url | The URL of the RSS feed. |
| insecure | Trust any certificate (not secure). Possible values: "true" and "false". Default: "false". |
| proxy | Use system proxy settings. Possible values: "true" and "false". Default: "false". |

### Outputs

There are no outputs for this script.


### Script Example
---
```!RSSWidget url=https://threatpost.com/feed/```

### Human Readable Output
---
## [Article Title #1](https://test-article.com/)
_June 25, 2021 3:35 PM_
#### Article #1 Summary
---
## [Article Title #2](https://test-article.com/)
_June 18, 2021 3:35 PM_
#### Article #2 Summary
---
