Resolve the original URL from the given shortened URL and place it in both as output and in the context of a playbook. (https://unshorten.me/api)

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | Utility |
| Cortex XSOAR Version | 5.0.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| url | URL to resolve |
| use_unshorten_me | Whether to use the Unshorten.me API or use the request python package. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| URL.Data | Shortened URL | Unknown |
