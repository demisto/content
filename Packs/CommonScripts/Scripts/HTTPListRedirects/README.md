List the redirects for a given URL

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python2 |
| Tags | Utility |
| Cortex XSOAR Version | 5.0.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| url | The URL to follow |
| useHead | Should we use HEAD instead of GET. Safer but might not be the same response. |
| use_system_proxy | Use system proxy settings |
| trust_any_certificate | Trust any certificate \(not secure\) |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| URL.Data | The URL redirects from the given URL | Unknown |
