The script takes one or more domain names and checks whether they're in the Cortex XSOAR list defined in the *InternalDomainsListName* argument. By default, the *InternalDomainsListName* argument will use the Cortex XSOAR list called "InternalDomains".
The list can be customized by the user. It should contain the organization's internal domain names, separated by new lines. Subdomains are also supported in the list.
The results of the script are tagged with the "Internal_Domain_Check_Results" tag, so they can be displayed in the War Room entry sections in incident layouts.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | incident-action-button |
| Cortex XSOAR Version | 6.5.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| InternalDomainsListName | The name of the Cortex XSOAR list that holds the internal domains in the organization. If no list is specified, the script will use the InternalDomains list by default. |
| Domains | A domain name or a list of domain names to check for being internal or external, against the specified list of internal domains. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Domain.Name | The domain name that was checked for being internal/external. | string |
| Domain.Internal | Whether the domain name is internal or external, according to the domain names defined in the Cortex XSOAR list, which is provided in the *InternalDomains* argument. | boolean |
