This script accepts multiple values for both arguments and will iterate through each of the domains to check if the specified subdomains are located in at least one of the specified main domains. 
If the tested subdomain is in one of the main domains, the result will be true. 

For example, if the domain_to_check values are apps.paloaltonetworks.com and apps.paloaltonetworks.bla and the domains_to_compare values are paloaltonetworks.com and demisto.com, the result for apps.paloaltonetworks.com will be true since it is a part of the paloaltonetworks.com domain. The result for apps.paloaltonetworks.bla will be false since it is not a part of the paloaltonetworks.com or demisto.com domain.

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
| main_domains | A comma-separated list of main domains. The subdomains will be compared to this list of main domains. For example, google.com. |
| possible_sub_domains_to_test | A comma-separated list of subdomains. These subdomains will be compared to the list of main domains. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| IsInternalDomain.DomainToTest | The subdomain that was checked to see if it is part of the specified domains. | String |
| IsInternalDomain.IsInternal | True, if the subdomain is part of one of the specified domains. Otherwise, false. | Boolean |
| IsInternalDomain.DomainToCompare | The names of the main domains that were used to compare the subdomains to. | String |
