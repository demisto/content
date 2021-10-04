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
| limit | Maximum number of entries to return. |
| insecure | Trust any certificate (not secure). Possible values: "true" and "false". Default: "false". |
| proxy | Use system proxy settings. Possible values: "true" and "false". Default: "false". |

### Outputs

There are no outputs for this script.


### Script Example
---
```!RSSWidget url=https://threatpost.com/feed/```

### Human Readable Output
---
**[Article Title #1](https://xsoar.pan.dev/)**<br />
*Posted June 25, 2021 3:35 PM by Timor*<br />
Article #1 Summary

**[Article Title #2](https://docs.paloaltonetworks.com/)**<br />
*Posted June 18, 2021 3:35 PM by Shai*<br />
Article #2 Summary
