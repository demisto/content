Forcepoint SMC provides unified, centralized management of all models of Forcepoint engines whether physical, virtual or cloud—across large, geographically distributed enterprise environments.
This integration was integrated and tested with version 6.10 of Forcepoint Security Management Center

## Configure Forcepoint Security Management Center in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL |  | True |
| API Key | The API Key to use for connection | True |
| Port |  | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### forcepoint-smc-ip-list-create

***
Creates an IP list.

#### Base Command

`forcepoint-smc-ip-list-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the IP list to create. | Required | 
| addresses | A comma-separated list of IP addresses. | Optional | 
| comment | The comment to add to the IP List. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ForcepointSMC.IPList.Name | String | The name of the IP list. | 
| ForcepointSMC.IPList.Addresses | Unknown | The list of addresses in the IP list. | 
| ForcepointSMC.IPList.Comment | String | The comment for the IP list. | 

#### Command example
```!forcepoint-smc-ip-list-create name="name" addresses="1.1.1.1" comment="test"```
#### Context Example
```json
{
    "ForcepointSMC": {
        "IPList": {
            "Addresses": [
                "1.1.1.1"
            ],
            "Comment": "test",
            "Name": "name"
        }
    }
}
```

#### Human Readable Output

>IP List name was created successfully.

### forcepoint-smc-ip-list-update

***
Updates an IP list.

#### Base Command

`forcepoint-smc-ip-list-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the IP list. | Required | 
| addresses | A comma-separated list of addresses to update. | Optional | 
| is_override | If false, the list of addresses will be appended to the existing one. Else, the list will be overwritten. Default is False. Possible values are: False, True. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ForcepointSMC.IPList.Name | String | The name of the IP list. | 
| ForcepointSMC.IPList.Addresses | Unknown | The list of addresses in the IPList | 
| ForcepointSMC.IPList.Comment | String | The comment for the IP list. | 

#### Command example
```!forcepoint-smc-ip-list-update name="name" addresses="1.2.3.4" comment="test" is_override=True```
#### Context Example
```json
{
    "ForcepointSMC": {
        "IPList": {
            "Addresses": [
                "1.2.3.4"
            ],
            "Comment": "test",
            "Name": "name"
        }
    }
}
```

#### Human Readable Output

>IP List name was updated successfully.

### forcepoint-smc-ip-list-list

***
Lists the IP Lists in the system.

#### Base Command

`forcepoint-smc-ip-list-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of a specific IP list to fetch. Overrides the other arguments if used. | Optional | 
| limit | The maximum number of IP lists to return. Default value is 50. | Optional | 
| all_results | Whether to return all of the results or not. Default value is False. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ForcepointSMC.IPList.Name | String | The name of the IP list. | 
| ForcepointSMC.IPList.Addresses | Unknown | The list of addresses in the IP list. | 
| ForcepointSMC.IPList.Comment | String | The comment of the IPList | 

#### Command example
```!forcepoint-smc-ip-list-list name="name"```
#### Context Example
```json
{
    "ForcepointSMC": {
        "IPList": {
            "Addresses": [
                "1.2.3.4"
            ],
            "Comment": "test",
            "Name": "name"
        }
    }
}
```

#### Human Readable Output

>### IP Lists:
>|Name|Addresses|Comment|
>|---|---|---|
>| name | 1.2.3.4 | test |


### forcepoint-smc-ip-list-delete

***
Deletes an IP list.

#### Base Command

`forcepoint-smc-ip-list-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the IP list to delete. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ForcepointSMC.IPList.Name | String | The name of the IP list. | 
| ForcepointSMC.IPList.Deleted | Boolean | Whether the IP list was deleted. | 

#### Command example
```!forcepoint-smc-ip-list-delete name="name"```
#### Context Example
```json
{
    "ForcepointSMC": {
        "IPList": {
            "Deleted": true,
            "Name": "name"
        }
    }
}
```

#### Human Readable Output

>IP List name was deleted successfully.

### forcepoint-smc-host-list

***
Lists the hosts in the system.

#### Base Command

`forcepoint-smc-host-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of a specific host to fetch. | Optional | 
| limit | The maximum number of hosts to return. Default value is 50. | Optional | 
| all_results | Whether to return all of the results. Overrides the other arguments if used. Default value is False. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ForcepointSMC.Host.Name | String | The name of the host. | 
| ForcepointSMC.Host.Address | String | The address of the host. | 
| ForcepointSMC.Host.IPv6_address | String | The IPv6 address of the host. | 
| ForcepointSMC.Host.Secondary_address | String | The secondary address of the host. | 
| ForcepointSMC.Host.Comment | String | The comment for the host. | 

#### Command example
```!forcepoint-smc-host-list name="name"```
#### Context Example
```json
{
    "ForcepointSMC": {
        "Host": {
            "Address": "1.1.1.1",
            "Comment": null,
            "IPv6_address": "",
            "Name": "name",
            "Secondary_address": []
        }
    }
}
```

#### Human Readable Output

>### Hosts:
>|Name|Address|
>|---|---|
>| name | 1.1.1.1 |


### forcepoint-smc-host-create

***
Creates a new host.

#### Base Command

`forcepoint-smc-host-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of a specific host to fetch. | Required | 
| address | The address of the host. Cannot be combined with the ipv6_address argument. | Optional | 
| ipv6_address | The IPv6 address of the host. Cannot be combined with the address argument. | Optional | 
| secondary_address | A comma-separated list of secondary addresses of the host. | Optional | 
| comment | The comment to add to the host. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ForcepointSMC.Host.Name | String | The name of the host. | 
| ForcepointSMC.Host.Address | String | The address of the host. | 
| ForcepointSMC.Host.IPv6_address | String | The IPv6 address of the host. | 
| ForcepointSMC.Host.Secondary_address | Unknown | The secondary address of the host. | 
| ForcepointSMC.Host.Comment | String | The comment for the host. | 

#### Command example
```!forcepoint-smc-host-create name="name" address="1.1.1.1"```
#### Context Example
```json
{
    "ForcepointSMC": {
        "Host": {
            "Address": "1.1.1.1",
            "Comment": "",
            "IPv6_address": "",
            "Name": "name",
            "Secondary_address": []
        }
    }
}
```

#### Human Readable Output

>Host name was created successfully.

### forcepoint-smc-host-update

***
Updates a host.

#### Base Command

`forcepoint-smc-host-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the host to update. | Required | 
| address | The address of the host. Cannot be combined with the ipv6_address argument. | Optional | 
| ipv6_address | The IPv6 address of the host. Cannot be combined with the address argument. | Optional | 
| secondary_address | comma-separated list of secondary addresses of the host. | Optional | 
| comment | The comment to add to the host. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ForcepointSMC.Host.Name | String | The name of the host. | 
| ForcepointSMC.Host.Address | String | The address of the host. | 
| ForcepointSMC.Host.IPv6_address | String | The IPv6 address of the host. | 
| ForcepointSMC.Host.Secondary_address | String | The secondary address of the host. | 
| ForcepointSMC.Host.Comment | String | The comment for the host. | 

#### Command example
```!forcepoint-smc-host-update name="name" address="1.2.3.4"```
#### Context Example
```json
{
    "ForcepointSMC": {
        "Host": {
            "Address": "1.2.3.4",
            "Comment": null,
            "IPv6_address": "",
            "Name": "name",
            "Secondary_address": []
        }
    }
}
```

#### Human Readable Output

>Host name was updated successfully.

### forcepoint-smc-host-delete

***
Deletes a host.

#### Base Command

`forcepoint-smc-host-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the host to delete. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ForcepointSMC.Host.Name | String | The name of the host. | 
| ForcepointSMC.Host.Deleted | Boolean | Whether the host was deleted. | 

#### Command example
```!forcepoint-smc-host-delete name="name"```
#### Context Example
```json
{
    "ForcepointSMC": {
        "Host": {
            "Deleted": true,
            "Name": "name"
        }
    }
}
```

#### Human Readable Output

>Host name was deleted successfully.

### forcepoint-smc-domain-create

***
Creates a new domain.

#### Base Command

`forcepoint-smc-domain-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the domain to create. | Required | 
| comment | The comment to add to the domain. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ForcepointSMC.Domain.Name | String | The name of the host. | 
| ForcepointSMC.Domain.Comment | String | The comment of the host. | 

#### Command example
```!forcepoint-smc-domain-create name="name"```
#### Context Example
```json
{
    "ForcepointSMC": {
        "Domain": {
            "Comment": "",
            "Name": "name"
        }
    }
}
```

#### Human Readable Output

>Domain name was created successfully.

### forcepoint-smc-domain-list

***
Lists the domains in the system.

#### Base Command

`forcepoint-smc-domain-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of a specific domain to fetch. | Optional | 
| limit | The maximum number of hosts to return. Default value is 50. | Optional | 
| all_results | Whether to return all of the results. Overrides the other arguments if used. Default value is False. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ForcepointSMC.Domain.Name | String | The name of the domain. | 
| ForcepointSMC.Domain.Comment | String | The comment for the domain. | 

#### Command example
```!forcepoint-smc-domain-list name="name"```
#### Context Example
```json
{
    "ForcepointSMC": {
        "Domain": {
            "Comment": null,
            "Name": "name"
        }
    }
}
```

#### Human Readable Output

>### Domains:
>|Name|
>|---|
>| name |


### forcepoint-smc-domain-delete

***
Deletes a domain.

#### Base Command

`forcepoint-smc-domain-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the domain to delete. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ForcepointSMC.Domain.Name | String | The name of the domain. | 
| ForcepointSMC.Domain.Deleted | Boolean | Whether the domain was deleted. | 

#### Command example
```!forcepoint-smc-domain-delete name="name"```
#### Context Example
```json
{
    "ForcepointSMC": {
        "Domain": {
            "Deleted": true,
            "Name": "name"
        }
    }
}
```

#### Human Readable Output

>Domain name was deleted successfully.

### forcepoint-smc-policy-template-list

***
Lists the policy templates in the system.

#### Base Command

`forcepoint-smc-policy-template-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of policy templates to return. Default value is 50. | Optional | 
| all_results | Whether to return all of the results. Overrides the other arguments if used. Default value is False. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ForcepointSMC.PolicyTemplate.Name | String | The name of the firewall policy template. | 
| ForcepointSMC.PolicyTemplate.Comment | String | The comment for the firewall policy. | 

#### Command example
```!forcepoint-smc-policy-template-list limit=1```
#### Context Example
```json
{
    "ForcepointSMC": {
        "PolicyTemplate": {
            "Comment": "Firewall Template Policy that uses Inspection rules from the No Inspection Policy.",
            "Name": "Firewall Template"
        }
    }
}
```

#### Human Readable Output

>### Policy template:
>|Name|Comment|
>|---|---|
>| Firewall Template | Firewall Template Policy that uses Inspection rules from the No Inspection Policy. |


### forcepoint-smc-firewall-policy-list

***
Lists the firewall policies in the system.

#### Base Command

`forcepoint-smc-firewall-policy-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of firewall policies to return. Default value is 50. | Optional | 
| all_results | Whether to return all of the results. Overrides the other arguments if used. Default value is False. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ForcepointSMC.Policy.Name | String | The name of the firewall policy. | 
| ForcepointSMC.Policy.Comment | String | The comment for the firewall policy. | 

#### Command example
```!forcepoint-smc-firewall-policy-list limit=1```
#### Context Example
```json
{
    "ForcepointSMC": {
        "FirewallPolicy": {
            "Comment": null,
            "Name": "Policy For May To Test PC"
        }
    }
}
```

#### Human Readable Output

>### Firewall policies:
>|Name|
>|---|
>| Policy For May To Test PC |


### forcepoint-smc-firewall-policy-create

***
Creates a firewall policy.

#### Base Command

`forcepoint-smc-firewall-policy-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the firewall policy. | Required | 
| template | The template name to use to create the firewall policy. Run the forcepoint-smc-policy-template-list command to get the list of policy templates. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ForcepointSMC.Policy.Name | String | The name of the firewall policy. | 
| ForcepointSMC.Policy.Comment | String | The comment for the firewall policy. | 

#### Command example
```!forcepoint-smc-firewall-policy-create name="name" template="Firewall Template"```
#### Context Example
```json
{
    "ForcepointSMC": {
        "Policy": {
            "Comment": null,
            "Name": "name"
        }
    }
}
```

#### Human Readable Output

>Firewall policy name was created successfully.

### forcepoint-smc-firewall-policy-delete

***
Deletes a firewall policy.

#### Base Command

`forcepoint-smc-firewall-policy-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the policy to delete. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ForcepointSMC.Policy.Name | String | The name of the firewall policy. | 
| ForcepointSMC.Policy.Deleted | Boolean | Whether the policy was deleted. | 

#### Command example
```!forcepoint-smc-firewall-policy-delete name="name"```
#### Context Example
```json
{
    "ForcepointSMC": {
        "Policy": {
            "Deleted": true,
            "Name": "name"
        }
    }
}
```

#### Human Readable Output

>Firewall policy name was deleted successfully.

### forcepoint-smc-rule-create

***
Creates a rule.

#### Base Command

`forcepoint-smc-rule-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_name | The name of the firewall policy. | Required | 
| rule_name | The name of the rule to create. | Required | 
| ip_version | The ip_version of the rule. Possible values are: V4, V6. | Required | 
| source_ip_list | A comma-separated list of source ip-list names to use to create the rule. Run the forcepoint-ip-list-list command to get the list of ip lists. | Optional | 
| source_host | A comma-separated list of source host names to use to create the rule. Run the forcepoint-host-list command to get the list of hosts. | Optional | 
| source_domain | A comma-separated list of source domain names to use to create the rule. Run the forcepoint-domain-list command to get the list of domains. | Optional | 
| destination_ip_list | A comma-separated list of destination ip-list names to use to create the rule. Run the forcepoint-ip-list-list command to get the list of ip lists. | Optional | 
| destination_host | A comma-separated list of destination host names to use to create the rule. Run the forcepoint-host-list command to get the list of hosts. | Optional | 
| destination_domain | A comma-separated list of destination domain names to use to create the rule. Run the forcepoint-domain-list command to get the list of domains. | Optional | 
| action | The action of the rule. Possible values are: allow, continue, discard, refuse, enforce_vpn, apply_vpn, forward_vpn, blacklist, forced_next_hop. | Required | 
| comment | The comment to add to the rule. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ForcepointSMC.Rule.Name | String | The name of the rule. | 
| ForcepointSMC.Rule.ID | String | The ID of the rule. | 
| ForcepointSMC.Rule.IP_version | String | The IP version of the rule. | 
| ForcepointSMC.Rule.Action | String | The action of the rule. | 
| ForcepointSMC.Rule.Comment | String | The comment for the rule. | 

#### Command example
```!forcepoint-smc-rule-create policy_name="name" action=allow rule_name="test" destination_ip_list="test" ip_version="V4"```
#### Context Example
```json
{
    "ForcepointSMC": {
        "Rule": {
            "Action": [
                "allow"
            ],
            "Comment": "",
            "Destinations": [
                "test"
            ],
            "ID": "2097186.0",
            "IP_version": "V4",
            "Name": "test",
            "Services": [],
            "Sources": []
        }
    }
}
```

#### Human Readable Output

>The rule test to the policy name was created successfully.

### forcepoint-smc-rule-update

***
Updates a rule.

#### Base Command

`forcepoint-smc-rule-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_name | The name of the firewall policy. | Required | 
| rule_name | The name of the rule to update. | Required | 
| is_override | Whether to override the existing values. Default value is False. Possible values are: False, True. | Optional | 
| ip_version | The ip_version of the rule. Possible values are: V4, V6. | Required | 
| source_ip_list | A comma-separated list of source ip-list names to use to update the rule. Run the forcepoint-ip-list-list command to get the list of ip lists. | Optional | 
| source_host | A comma-separated list of source host names to use to update the rule. Run the forcepoint-host-list command to get the list of hosts. | Optional | 
| source_domain | A comma-separated list of source domain names to use to update the rule. Run the forcepoint-domain-list command to get the list of domains. | Optional | 
| destination_ip_list | A comma-separated list of destination ip-list names to use to update the rule. Run the forcepoint-ip-list-list command to get the list of ip lists. | Optional | 
| destination_host | A comma-separated list of destination host names to use to update the rule. Run the forcepoint-host-list command to get the list of hosts. | Optional | 
| destination_domain | A comma-separated list of destination domain names to use to update the rule. Run the forcepoint-domain-list command to get the list of domains. | Optional | 
| action | The action of the rule. Possible values are: allow, continue, discard, refuse, enforce_vpn, apply_vpn, forward_vpn, blacklist, forced_next_hop. | Optional | 
| comment | The comment to add to the rule. | Optional | 

#### Context Output

There is no context output for this command.
#### Command example
```!forcepoint-smc-rule-update policy_name="name" action=continue rule_name="test" source_ip_list="test" ip_version="V4"```
#### Human Readable Output

>The rule test to the policy name was updated successfully.

### forcepoint-smc-rule-list

***
Lists the rules in a specific policy.

#### Base Command

`forcepoint-smc-rule-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_name | The name of the firewall policy. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ForcepointSMC.Rule.Name | String | The name of the rule. | 
| ForcepointSMC.Rule.ID | String | The ID of the rule. | 
| ForcepointSMC.Rule.IP_version | String | The IP version of the rule. | 
| ForcepointSMC.Rule.Sources | Unknown | The sources of the rule. | 
| ForcepointSMC.Rule.Destinations | Unknown | The destinations of the rule. | 
| ForcepointSMC.Rule.Services | Unknown | The services of the rule. | 
| ForcepointSMC.Rule.Actions | Unknown | The actions of the rule. | 
| ForcepointSMC.Rule.Comment | String | The comment of the rule. | 

#### Command example
```!forcepoint-smc-rule-list policy_name="name"```
#### Context Example
```json
{
    "ForcepointSMC": {
        "Rule": {
            "Actions": [
                "continue"
            ],
            "Comment": "",
            "Destinations": [
                "test"
            ],
            "ID": "2097186.1",
            "IP_version": "V4",
            "Name": "test",
            "Services": [],
            "Sources": [
                "test"
            ]
        }
    }
}
```

#### Human Readable Output

>### Rules:
>|Name|ID|IP_version|Sources|Destinations|Actions|
>|---|---|---|---|---|---|
>| test | 2097186.1 | V4 | test | test | continue |


### forcepoint-smc-rule-delete

***
Deletes a rule.

#### Base Command

`forcepoint-smc-rule-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_name | The name of the firewall policy. | Required | 
| rule_name | The name of the rule to delete. | Required | 
| ip_version | The ip_version of the rule. Possible values are: V4, V6. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ForcepointSMC.Rule.ID | String | The ID of the rule. | 
| ForcepointSMC.Rule.Deleted | Boolean | Whether the rule was deleted. | 

#### Command example
```!forcepoint-smc-rule-delete policy_name="name" rule_name="test" ip_version=V4```
#### Context Example
```json
{
    "ForcepointSMC": {
        "Rule": {
            "Deleted": true,
            "Name": "test"
        }
    }
}
```

#### Human Readable Output

>Rule test was deleted successfully.

### forcepoint-smc-engine-list

***
Lists the engines in the system.

#### Base Command

`forcepoint-smc-engine-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of engines to return. Default value is 50. | Optional | 
| all_results | Whether to return all of the results or not, overrides the other arguments if used. Default value is False. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ForcepointSMC.Engine.Name | String | The name of the engine. | 
| ForcepointSMC.Engine.Comment | String | The comment for the engine. | 

#### Command example
```!forcepoint-smc-engine-list limit=1```
#### Context Example
```json
{
    "ForcepointSMC": {
        "Engine": {
            "Comment": "Forcepoint Engine element pre-populated by installer",
            "Name": "Forcepoint Engine"
        }
    }
}
```

#### Human Readable Output

>### Engines:
>|Name|Comment|
>|---|---|
>| Forcepoint Engine | Forcepoint Engine element pre-populated by installer |