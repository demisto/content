Checks if the supplied hostnames match either the organization's internal naming convention or the domain suffix.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | Utility |
| Cortex XSOAR Version | 4.5.0+ |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| hostName | A comma-separated list of hostnames to check. |
| internalRegex | The regex pattern for the organization's hostname for example wwwd$\|www$. for hosts that look like pcx1 or pcx. |
| domainName | The domain name for the organization. For a single domain use this format: "bla.com". For multiple domains use this format: (bla.com\|blabla.com), where the pipe and the brackets are the OR condition for regex. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Endpoint.Hostname | The hostname. | string |
| Endpoint.IsInternal | Whether the supplied hostnames match the organization's naming convention. Can be "true" or "false". | string |
