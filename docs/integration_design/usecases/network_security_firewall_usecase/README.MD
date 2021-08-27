# Network Security (Firewall)
Top Use-Cases:
- [Create block/accept policies (Source, Destination, Port), for IP addresses and domains.](#create)
- [Add addresses and ports (services) to predefined groups, create groups, etc.](#create-address)
- Support custom url categories. 
- Fetch network logs for a specific address for a configurable time frame.
- URL filtering categorization change request
- Built in blocked rule command for fast-blocking.
- If there is a Management FW, allow the option to manage policy rules through it.

**Network Security Firewall Integration Example** – Check Point Firewall


## Command Examples

### panorama-create-rule <a name="create">
---
Creates a policy rule.
##### Base Command
`panorama-create-rule`
##### Input
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rulename | Name of the rule to create. | Optional | 
| description | Description of the rule to create. | Optional | 
| action | Action for the rule. Can be "allow", "deny", or "drop". | Required | 
| source | Source address. Can be "address", or "address group". | Optional | 
| destination | Destination address. Can be "address", or "address group". | Optional | 
| negate_source | Whether to negate the source (address, address group). Can be "Yes" or "No". | Optional | 
| negate_destination | Whether to negate the destination (address, address group). Can be "Yes" or "No". | Optional | 
| service | Service for the rule (service object) to create. | Optional | 
| disable | Whether to disable the rule. Can be "Yes" or "No" (default is "No"). | Optional | 
| application | Application for the rule to create. | Optional | 
| source_user | Source user for the rule to create. | Optional | 
| pre_post | Pre rule or Post rule (Panorama instances). | Optional | 
| target | Specifies a target firewall for the rule (Panorama instances). | Optional | 
| log_forwarding | Log forwarding profile. | Optional | 
| device-group | The device group for which to return addresses for the rule (Panorama instances). | Optional | 
| tags | Rule tags to create. | Optional | 
##### Context Output
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.SecurityRule.Name | string | Rule name. | 
| Panorama.SecurityRule.Description | string | Rule description. | 
| Panorama.SecurityRule.Action | string | Action for the rule. | 
| Panorama.SecurityRule.Source | string | Source address. | 
| Panorama.SecurityRule.Destination | string | Destination address. | 
| Panorama.SecurityRule.NegateSource | boolean | Whether the source is negated (address, address group). | 
| Panorama.SecurityRule.NegateDestination | boolean | Whether the destination negated (address, address group). | 
| Panorama.SecurityRule.Service | string | Service for the rule. | 
| Panorama.SecurityRule.Disabled | string | Whether the rule is disabled. | 
| Panorama.SecurityRule.Application | string | Application for the rule. | 
| Panorama.SecurityRule.Target | string | Target firewall (Panorama instances). | 
| Panorama.SecurityRule.LogForwarding | string | Log forwarding profile (Panorama instances). | 
| Panorama.SecurityRule.DeviceGroup | string | Device group for the rule (Panorama instances). | 
| Panorama.SecurityRules.Tags | String | Rule tags. | 
##### Command Example
``` !panorama-create-rule action=drop pre_post="pre-rulebase" destination=1.1.1.1 rulename=test-rule  ```
##### Context Example
``` {
  "DeviceGroup": "Lab-Devices",
  "From": "any",
  "Name": "test-rule",
  "Destination": "1.1.1.1",
  "Action": "drop",
  "Source": "any",
  "To": "any",
  "CustomUrlCategory": "any"
} ```
### panorama-create-address-group <a name="create-address">
---
Creates a static or dynamic address book.
##### Base Command
`panorama-create-address-group`
##### Input
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Address group name. | Required | 
| type | Address group type. | Required | 
| match | Dynamic Address group match. e.g: "1.1.1.1 or 2.2.2.2" | Optional | 
| addresses | Static address group list of addresses. | Optional | 
| description | Address group description. | Optional | 
| device-group | The device group for which to return addresses (Panorama instances). | Optional | 
| tags | The tags for the Address group. | Optional | 
##### Context Output
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.AddressGroups.Name | string | Address group name. | 
| Panorama.AddressGroups.Type | string | Address group type. | 
| Panorama.AddressGroups.Match | string | Dynamic Address group match. | 
| Panorama.AddressGroups.Addresses | string | Static Address group list of addresses. | 
| Panorama.AddressGroups.Description | string | Address group description. | 
| Panorama.AddressGroups.DeviceGroup | String | Device group for the address group (Panorama instances). | 
| Panorama.AddressGroups.Tag | String | Address group tags. | 
##### Command Example
``` !panorama-create-address-group name=test-group type=dynamic match=test-ag ```
##### Context Example
``` {
  "DeviceGroup": "Lab-Devices",
  "Match": "test-ag",
  "Name": "test-group",
  "Type": "dynamic"
} ```
