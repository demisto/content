McAfee Network Security Manager gives you real-time visibility and control over all McAfee intrusion prevention systems deployed across your network.
This integration was integrated and tested with version 9.1 of McAfeeNSMv2

Some changes have been made that might affect your existing content. 
If you are upgrading from a previous of this integration, see [Breaking Changes](#breaking-changes-from-the-previous-version-of-this-integration-mcafee-nsm-v2).

## Configure McAfee NSM v2 in Cortex


| **Parameter** | **Required** |
| --- | --- |
| URL (for example: https://192.168.0.1:5000) | True |
| User Name | True |
| Password | True |
| Product Version | True |
| Trust any certificate (not secure) | False |
| Use system proxy settings | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### nsm-list-domain-firewall-policy
***
Gets the list of firewall policies defined in a particular domain.


#### Base Command

`nsm-list-domain-firewall-policy`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain_id | The ID of the domain. To get the domain_id, use the !nsm-get-domains command. | Required | 
| limit | The maximum number of records to return. Default is 50. | Optional | 
| page | The specific result page to display. | Optional | 
| page_size | The number of records in a page. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| NSM.Policy.policyId | Number | The ID of the policy. | 
| NSM.Policy.policyName | String | Name of the firewall policy. | 
| NSM.Policy.domainId | Number | The ID of the domain. | 
| NSM.Policy.visibleToChild | Boolean | Whether the policy is visible to child domains. | 
| NSM.Policy.description | String | Policy description. | 
| NSM.Policy.isEditable | Boolean | Whether the policy is editable. | 
| NSM.Policy.policyType | String | Policy type. Can be "ADVANCED" or "CLASSIC". | 
| NSM.Policy.policyVersion | Number | Policy version. | 
| NSM.Policy.lastModUser | String | Last user who modified the policy. | 

#### Command example
```!nsm-list-domain-firewall-policy domain_id=0 limit=2```
#### Context Example
```json
{
    "NSM": {
        "Policy": [
            {
                "description": "hello updatingg",
                "domainId": 0,
                "isEditable": true,
                "lastModUser": "user",
                "policyId": 292,
                "policyName": "another policy",
                "policyType": "ADVANCED",
                "policyVersion": 1,
                "visibleToChild": true
            },
            {
                "description": "hello updatingg",
                "domainId": 0,
                "isEditable": true,
                "lastModUser": "user",
                "policyId": 161,
                "policyName": "policy",
                "policyType": "ADVANCED",
                "policyVersion": 1,
                "visibleToChild": true
            }
        ]
    }
}
```

#### Human Readable Output

>### Firewall Policies List
>|policyId|policyName|domainId|visibleToChild|description|isEditable|policyType|policyVersion| lastModUser |
>|---|---|---|---|---|---|---|-------------|---|
>| 292 | another policy | 0 | true | hello updatingg | true | ADVANCED | 1 | user        |
>| 161 | policy | 0 | true | hello updatingg | true | ADVANCED | 1 | user        |


### nsm-get-firewall-policy
***
Gets the firewall policy details.


#### Base Command

`nsm-get-firewall-policy`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_id | The ID of the policy. To get the policy_id, use the !nsm-list-domain-firewall-policy command. | Required | 
| include_rule_objects | Whether to insert the rule objects that are linked to the policy in the context. True- the rule object will be inserted. False- not inserted. Possible values are: true, false. Default is false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| NSM.Policy.FirewallPolicyId | Number | Unique firewall policy ID. | 
| NSM.Policy.Name | String | Policy name. | 
| NSM.Policy.DomainId | Number | ID of the domain to which this firewall policy belongs. | 
| NSM.Policy.VisibleToChild | Boolean | Whether the policy is visible to a child domain. | 
| NSM.Policy.Description | String | Firewall policy description. | 
| NSM.Policy.LastModifiedTime | Date | Last modified time of the firewall Policy. | 
| NSM.Policy.IsEditable | Boolean | Whether the policy is editable. | 
| NSM.Policy.PolicyType | String | Policy type. Can be "Advanced" / "Classic". | 
| NSM.Policy.PolicyVersion | Number | Policy version. | 
| NSM.Policy.LastModifiedUser | String | Last user user modified the policy. | 
| NSM.Policy.MemberDetails.MemberRuleList.Description | String | Rule description. | 
| NSM.Policy.MemberDetails.MemberRuleList.Enabled | Boolean | Whether the rule is enabled. | 
| NSM.Policy.MemberDetails.MemberRuleList.Response | String | Action to be performed if the traffic matches this rule. Can be "Scan" / "Drop" / "Deny" / "Ignore" / "Stateless Ignore" / "Stateless Drop" / "Require Authentication". | 
| NSM.Policy.MemberDetails.MemberRuleList.IsLogging | Boolean | Whether logging is enabled for this rule. | 
| NSM.Policy.MemberDetails.MemberRuleList.Direction | String | Rule direction. Can be "Inbound" / "Outbound" / "Either". | 
| NSM.Policy.MemberDetails.MemberRuleList.SourceAddressObjectList.RuleObjectId | String | Unique rule object ID. | 
| NSM.Policy.MemberDetails.MemberRuleList.SourceAddressObjectList.Name | String | Rule object name. | 
| NSM.Policy.MemberDetails.MemberRuleList.SourceAddressObjectList.RuleObjectType | Unknown | Source or destination mode. Can be "Endpoint IP V.4" / "Range IP V.4" / "Network IP V.4" / "Endpoint IP V.6" / "Range IP V.6" / "Network IP V.6". | 
| NSM.Policy.MemberDetails.MemberRuleList.DestinationAddressObjectList.RuleObjectId | String | Unique rule object ID. | 
| NSM.Policy.MemberDetails.MemberRuleList.DestinationAddressObjectList.Name | String | Rule object name. | 
| NSM.Policy.MemberDetails.MemberRuleList.DestinationAddressObjectList.RuleObjectType | Unknown | Source or destination mode. Can be "Endpoint IP V.4" / "Range IP V.4" / "Endpoint IP V.6" / "Range IP V.6" / "Network IP V.6". | 
| NSM.Policy.MemberDetails.MemberRuleList.SourceUserObjectList.RuleObjectId | String | Unique rule object ID. | 
| NSM.Policy.MemberDetails.MemberRuleList.SourceUserObjectList.Name | String | Rule object name. | 
| NSM.Policy.MemberDetails.MemberRuleList.SourceUserObjectList.RuleObjectType | String | Source user. Can be "USER" / "USER_GROUP". | 
| NSM.Policy.MemberDetails.MemberRuleList.ServiceObjectList.RuleObjectId | String | Unique service rule object ID. | 
| NSM.Policy.MemberDetails.MemberRuleList.ServiceObjectList.Name | String | Rule object name. | 
| NSM.Policy.MemberDetails.MemberRuleList.ServiceObjectList.RuleObjectType | Unknown | Service/ application mode. Can be "APPLICATION" / "APPLICATION_GROUP" / "APPLICATION_ON_CUSTOM_PORT" / "SERVICE" / "SERVICE_GROUP". | 
| NSM.Policy.MemberDetails.MemberRuleList.ServiceObjectList.ApplicationType | Unknown | Application type. Can be "DEFAULT" / "CUSTOM". | 
| NSM.Policy.MemberDetails.MemberRuleList.ApplicationObjectList.RuleObjectId | String | Unique service rule object ID. | 
| NSM.Policy.MemberDetails.MemberRuleList.ApplicationObjectList.Name | String | Rule object name. | 
| NSM.Policy.MemberDetails.MemberRuleList.ApplicationObjectList.RuleObjectType | Unknown | Service/ application mode. Can be "APPLICATION" / "APPLICATION_GROUP" / "APPLICATION_ON_CUSTOM_PORT" / "SERVICE" / "SERVICE_GROUP". | 
| NSM.Policy.MemberDetails.MemberRuleList.ApplicationObjectList.ApplicationType | Unknown | Application type. Can be "DEFAULT" / "CUSTOM". | 
| NSM.Policy.MemberDetails.MemberRuleList.TimeObjectList.RuleObjectId | String | Unique service rule object ID. | 
| NSM.Policy.MemberDetails.MemberRuleList.TimeObjectList.Name | String | Rule object name. | 
| NSM.Policy.MemberDetails.MemberRuleList.TimeObjectList.RuleObjectType | Unknown | Time mode. Can be "FINITE_TIME_PERIOD" / "RECURRING_TIME_PERIOD" / "RECURRING_TIME_PERIOD_GROUP". | 

#### Command example
```!nsm-get-firewall-policy policy_id=147 include_rule_objects=true```
#### Context Example
```json
{
    "NSM": {
        "Policy": {
            "Description": "update policy",
            "DomainId": 0,
            "FirewallPolicyId": 147,
            "IsEditable": true,
            "LastModifiedTime": "2022-12-28 05:37:23",
            "LastModifiedUser": "user",
            "MemberDetails": {
                "MemberRuleList": [
                    {
                        "ApplicationObjectList": [],
                        "Description": "r",
                        "DestinationAddressObjectList": [
                            {
                                "Name": "Any",
                                "RuleObjectId": "-1",
                                "RuleObjectType": null
                            }
                        ],
                        "Direction": "EITHER",
                        "Enabled": true,
                        "IsLogging": false,
                        "Response": "SCAN",
                        "ServiceObjectList": [
                            {
                                "ApplicationType": null,
                                "Name": "Any",
                                "RuleObjectId": "-1",
                                "RuleObjectType": null
                            }
                        ],
                        "SourceAddressObjectList": [
                            {
                                "Name": "Range V6 Test",
                                "RuleObjectId": "117",
                                "RuleObjectType": "IPV_6_ADDRESS_RANGE"
                            }
                        ],
                        "SourceUserObjectList": [
                            {
                                "Name": "Any",
                                "RuleObjectId": "-1",
                                "RuleObjectType": "USER"
                            }
                        ],
                        "TimeObjectList": [
                            {
                                "Name": "Always",
                                "RuleObjectId": "-1",
                                "RuleObjectType": null
                            }
                        ]
                    }
                ]
            },
            "Name": "name147",
            "PolicyType": "ADVANCED",
            "PolicyVersion": 1,
            "VisibleToChild": true
        }
    }
}
```

#### Human Readable Output

>### Firewall Policy 147
>|Name|Description|VisibleToChild|IsEditable|PolicyType|PolicyVersion| LastModifiedUser |LastModifiedTime|
>|---|---|---|---|---|------------------|---|---|
>| name147 | update policy | true | true | ADVANCED | 1 | user             | 2022-12-28 05:37:23 |


### nsm-create-firewall-policy
***
Adds a new firewall policy and access rules. You have to provide at lease one of the source/destination rule objects. If you provide the id or type of the source/destination rule object, you must provide the matching type or id the source/destination rule object as well.


#### Base Command

`nsm-create-firewall-policy`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | The ID of the domain. To get the domain ID, use the !nsm-get-domains command. | Required | 
| name | The policy name. | Required | 
| visible_to_child | Whether the policy is visible to the child domain. Possible values are: yes, no. Default is yes. | Optional | 
| description | The description of the policy. | Required | 
| is_editable | Whether the policy is editable. Possible values are: yes, no. Default is yes. | Optional | 
| policy_type | The type of the policy. Possible values are: Advanced, Classic. | Required | 
| rule_description | The rule description. | Required | 
| response | Action to be performed if the traffic matches this rule. Possible values are: Scan, Drop, Deny, Ignore, Stateless Ignore, Stateless Drop, Require Authentication. | Required | 
| rule_enabled | Whether the rule is enabled. Possible values are: yes, no. Default is yes. | Optional | 
| direction | The direction of the rule. Possible values are: Inbound, Outbound, Either. | Required | 
| source_rule_object_id | The ID of the rule connected to the policy. To get the rule_object_id use the command '!nsm-list-domain-rule-object'. | Optional | 
| source_rule_object_type | The type of the rule connected to the policy. To get the rule_object_type use the command '!nsm-list-domain-rule-object'. Possible values are: Endpoint IP V.4, Range IP V.4, Network IP V.4, Endpoint IP V.6, Range IP V.6, Network IP V.6. | Optional | 
| destination_rule_object_id | The ID of the rule connected to the policy. To get the rule_object_id use the command '!nsm-list-domain-rule-object'. | Optional | 
| destination_rule_object_type | The type of the rule connected to the policy. To get the rule_object_type use the command '!nsm-list-domain-rule-object'. Possible values are: Endpoint IP V.4, Range IP V.4, Network IP V.4, Endpoint IP V.6, Range IP V.6, Network IP V.6. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| NSM.Policy.FirewallPolicyId | Number | The ID of the newly created firewall policy. | 

#### Command example
```!nsm-create-firewall-policy domain=0 name=policy visible_to_child=yes description="a new policy" is_editable=yes policy_type=Advanced response=Scan rule_description="Test Member Rule" direction=Inbound destination_rule_object_id=111 destination_rule_object_type="Range IP V.4"```

#### Context Example
```json
{
    "NSM": {
        "Policy": {
            "FirewallPolicyId":112
        }
    }
}
```

#### Human Readable Output
```The firewall policy no.112 was created successfully```

### nsm-update-firewall-policy
***
Updates the firewall policy details. If the argument is_overwrite=true, the new values of the provided addresses will replace the existing values, otherwise the addresses will be added to them. 
* If you want to delete a rule, enter is_overwrite=true and the relevant rule_object_id=-1. 
* If is_overwrite=false and there is no value in one of the rules (source or destination), their value will be as before. 
* If is_overwrite=true, at least one of the rules (source or destination) must be provided. 
* If you provide the id or type of the source/destination rule object, you must provide the matching type or id the source/destination rule object as well.


#### Base Command

`nsm-update-firewall-policy`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_id | The ID of the policy. To get the policy ID, use the !nsm-list-domain-firewall-policy. | Required | 
| domain | The ID of the domain. To get the domain ID, use the !nsm-get-domains command. | Optional | 
| name | The policy name. | Optional | 
| visible_to_child | Whether the policy is visible to the child domain. Possible values are: yes, no. Default is yes. | Optional | 
| description | The description of the policy. | Optional | 
| is_editable | Whether the policy is editable. Possible values are: yes, no. | Optional | 
| policy_type | The type of the policy. Possible values are: Advanced, Classic. | Optional | 
| rule_description | The rule description. | Optional | 
| response | Action to be performed if the traffic matches this rule. Possible values are: Scan, Drop, Deny, Ignore, Stateless Ignore, Stateless Drop, Require Authentication. | Optional | 
| rule_enabled | Whether the rule is enabled. Possible values are: yes, no. Default is yes. | Optional | 
| direction | The direction of the rule. Possible values are: Inbound, Outbound, Either. | Optional | 
| source_rule_object_id | The ID of the rule connected to the policy. To get the rule_object_id use the command '!nsm-list-domain-rule-object'. | Optional | 
| source_rule_object_type | The type of the rule connected to the policy. To get the rule_object_type use the command '!nsm-list-domain-rule-object'. Possible values are: Endpoint IP V.4, Range IP V.4, Network IP V.4, Endpoint IP V.6, Range IP V.6, Network IP V.6. | Optional | 
| destination_rule_object_id | The ID of the rule connected to the policy. To get the rule_object_id use the command '!nsm-list-domain-rule-object'. | Optional | 
| destination_rule_object_type | The type of the rule connected to the policy. To get the rule_object_type use the command '!nsm-list-domain-rule-object'. Possible values are: Endpoint IP V.4, Range IP V.4, Network IP V.4, Endpoint IP V.6, Range IP V.6, Network IP V.6. | Optional | 
| is_overwrite | Whether the new addresses that were provided in the update processes will override the current ones or will be added to them. Possible values are: true, false. | Optional | 


#### Context Output

There is no context output for this command.
#### Command example
```!nsm-update-firewall-policy policy_id=147 description="update policy"```
#### Human Readable Output

>The firewall policy no.147 was updated successfully

### nsm-delete-firewall-policy
***
Deletes the specified firewall policy.


#### Base Command

`nsm-delete-firewall-policy`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_id | The ID of the policy to delete. To get the policy ID, use the !nsm-list-domain-firewall-policy. | Required | 


#### Context Output

There is no context output for this command.

#### Command example
```!nsm-delete-firewall-policy policy_id=101```
#### Human Readable Output

>The firewall policy no.101 was deleted successfully


### nsm-list-domain-rule-object
***
Gets the list of rule objects defined in a particular domain.


#### Base Command

`nsm-list-domain-rule-object`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain_id | The ID of the domain. To get the domain ID, use the !nsm-get-domains command. | Required | 
| type | The type of the rule. Possible values are: Endpoint IP V.4, Range IP V.4, Network IP V.4, Endpoint IP V.6, Range IP V.6, Network IP V.6, All. Default is All. | Optional | 
| limit | The maximum number of records to return. Default is 50. | Optional | 
| page | The specific result page to display. | Optional | 
| page_size | The number of records in a page. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| NSM.Rule.ruleobjId | String | The ID of the rule object. | 
| NSM.Rule.ruleobjType | String | The type of the rule object. | 
| NSM.Rule.name | String | The name of the rule object. | 
| NSM.Rule.description | String | The description of the rule object. | 
| NSM.Rule.domain | Number | The name of the rule object. | 
| NSM.Rule.visibleToChild | Boolean | Whether the rule is visible to child domains. | 
| NSM.Rule.hostCriticality | String | The critical level of the host. | 
| NSM.Rule.ApplicationGroup | Unknown | Application Group object. Should be defined if ruleobjType is "APPLICATION_GROUP". | 
| NSM.Rule.ApplicationOnCustomPort | Unknown | Application defined on Custom Port object. Should be defined if ruleobjType is "APPLICATION_ON_CUSTOM_PORT". | 
| NSM.Rule.FiniteTimePeriod | Unknown | Finite Time Period object. Should be defined if ruleobjType is "FINITE_TIME_PERIOD". | 
| NSM.Rule.HostIPv4 | Unknown | Host IPv4 Address object. Should be defined if ruleobjType is "HOST_IPV_4". | 
| NSM.Rule.HostIPv6 | Unknown | Host IPv6 Address object. Should be defined if ruleobjType is "HOST_IPV_6". | 
| NSM.Rule.HostDNSName | Unknown | Host DNS Name object. Should be defined if ruleobjType is "HOST_DNS_NAME". | 
| NSM.Rule.IPv4AddressRange | Unknown | IPv4 Address Range object. Should be defined if ruleobjType is "IPV_4_ADDRESS_RANGE". | 
| NSM.Rule.IPv6AddressRange | Unknown | IPv6 Address Range object. Should be defined if ruleobjType is "IPV_6_ADDRESS_RANGE". | 
| NSM.Rule.Network_IPV_4 | Unknown | IPv4 Network object. Should be defined if ruleobjType is "NETWORK_IPV_4. | 
| NSM.Rule.Network_IPV_6 | String | IPv6 Network object. Should be defined if ruleobjType is "NETWORK_IPV_6". | 
| NSM.Rule.NetworkGroup | Unknown | Network Group object. Should be defined if ruleobjType is "NETWORK_GROUP". | 
| NSM.Rule.RecurringTimePeriod | Unknown | Recurring Time Period object. Should be defined if ruleobjType is "RECURRING_TIME_PERIOD". | 
| NSM.Rule.RecurringTimePeriodGroup | Unknown | Recurring Time Period Group object. Should be defined if ruleobjType is "RECURRING_TIME_PERIOD_GROUP". | 
| NSM.Rule.Service | Unknown | Service object. Should be defined if ruleobjType is "CUSTOM_SERVICE". | 
| NSM.Rule.ServiceGroup | Unknown | Service Group object. Should be defined if ruleobjType is "SERVICE_GROUP". | 
| NSM.Rule.ServiceRange | Unknown | Service Range object. Should be defined if ruleobjType is "SERVICE_RANGE". | 
| NSM.Rule.IPv6AddressRange.IPV6RangeList | String | List of IPv6 Address Range. | 
| NSM.Rule.HostIPv6.hostIPv6AddressList | String | Host IPv6 address list. | 
| NSM.Rule.Network_IPV_4.networkIPV4List | String | Network IPV4 list. | 
| NSM.Rule.IPv4AddressRange.IPV4RangeList | String | List of IPv4 address range. | 
| NSM.Rule.HostIPv4.hostIPv4AddressList | String | Host IPv4 address list. | 
| NSM.Rule.Network_IPV_6.networkIPV6List | String | Network IPV6 list. | 

#### Command example
```!nsm-list-domain-rule-object domain_id=0 limit=2```
#### Context Example
```json
{
    "NSM": {
        "Rule": [
            {
                "ApplicationGroup": null,
                "ApplicationOnCustomPort": null,
                "FiniteTimePeriod": null,
                "HostDNSName": null,
                "HostIPv4": {
                    "hostIPv4AddressList": [
                        "1.1.1.1"
                    ]
                },
                "HostIPv6": null,
                "IPv4AddressRange": null,
                "IPv6AddressRange": null,
                "NetworkGroup": null,
                "Network_IPV_4": null,
                "Network_IPV_6": null,
                "RecurringTimePeriod": null,
                "RecurringTimePeriodGroup": null,
                "Service": null,
                "ServiceGroup": null,
                "ServiceRange": null,
                "description": null,
                "domain": 0,
                "hostCriticality": "HIGH",
                "name": "testing",
                "ruleobjId": "134",
                "ruleobjType": "Endpoint IP V.4",
                "visibleToChild": true
            },
            {
                "ApplicationGroup": null,
                "ApplicationOnCustomPort": null,
                "FiniteTimePeriod": null,
                "HostDNSName": null,
                "HostIPv4": null,
                "HostIPv6": null,
                "IPv4AddressRange": {
                    "IPV4RangeList": [
                        {
                            "FromAddress": "1.1.1.1",
                            "ToAddress": "2.2.2.2"
                        }
                    ]
                },
                "IPv6AddressRange": null,
                "NetworkGroup": null,
                "Network_IPV_4": null,
                "Network_IPV_6": null,
                "RecurringTimePeriod": null,
                "RecurringTimePeriodGroup": null,
                "Service": null,
                "ServiceGroup": null,
                "ServiceRange": null,
                "description": null,
                "domain": 0,
                "hostCriticality": null,
                "name": "ruleo",
                "ruleobjId": "133",
                "ruleobjType": "Range IP V.4",
                "visibleToChild": true
            }
        ]
    }
}
```

#### Human Readable Output

>### List of Rule Objects
>|RuleId| Name |VisibleToChild|RuleType|
>|---------|---|---|---|
>| 134 | testing | true | Endpoint IP V.4 |
>| 133 | ruleo | true | Range IP V.4 |


### nsm-get-rule-object
***
Gets the details of a rule object.


#### Base Command

`nsm-get-rule-object`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_id | The ID of the rule object. To get the rule object ID, use the !nsm-list-domain-rule-object. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| NSM.Rule.ruleobjId | String | The ID of the rule object. | 
| NSM.Rule.ruleobjType | String | The type of the rule object. | 
| NSM.Rule.name | String | The name of the rule object. | 
| NSM.Rule.description | String | The description of the rule object. | 
| NSM.Rule.domain | Number | The name of the rule object. | 
| NSM.Rule.visibleToChild | Boolean | Whether the rule is visible to child domains. | 
| NSM.Rule.ApplicationGroup | Unknown | Application Group object. Should be defined if ruleobjType is "APPLICATION_GROUP". | 
| NSM.Rule.ApplicationOnCustomPort | Unknown | Application defined on Custom Port object. Should be defined if ruleobjType is "APPLICATION_ON_CUSTOM_PORT". | 
| NSM.Rule.FiniteTimePeriod | Unknown | Finite Time Period object. Should be defined if ruleobjType is "FINITE_TIME_PERIOD". | 
| NSM.Rule.HostIPv4 | Unknown | Host IPv4 Address object. Should be defined if ruleobjType is "HOST_IPV_4". | 
| NSM.Rule.HostIPv6 | Unknown | Host IPv6 Address object. Should be defined if ruleobjType is "HOST_IPV_6". | 
| NSM.Rule.HostDNSName | Unknown | Host DNS Name object. Should be defined if ruleobjType is "HOST_DNS_NAME". | 
| NSM.Rule.IPv4AddressRange | Unknown | IPv4 Address Range object. Should be defined if ruleobjType is "IPV_4_ADDRESS_RANGE". | 
| NSM.Rule.IPv6AddressRange | Unknown | IPv6 Address Range object. Should be defined if ruleobjType is "IPV_6_ADDRESS_RANGE". | 
| NSM.Rule.Network_IPV_4 | Unknown | IPv4 Network object. Should be defined if ruleobjType is "NETWORK_IPV_4. | 
| NSM.Rule.Network_IPV_6 | String | IPv6 Network object. Should be defined if ruleobjType is "NETWORK_IPV_6". | 
| NSM.Rule.NetworkGroup | Unknown | Network Group object. Should be defined if ruleobjType is "NETWORK_GROUP". | 
| NSM.Rule.RecurringTimePeriod | Unknown | Recurring Time Period object. Should be defined if ruleobjType is "RECURRING_TIME_PERIOD". | 
| NSM.Rule.RecurringTimePeriodGroup | Unknown | Recurring Time Period Group object. Should be defined if ruleobjType is "RECURRING_TIME_PERIOD_GROUP". | 
| NSM.Rule.Service | Unknown | Service object. Should be defined if ruleobjType is "CUSTOM_SERVICE". | 
| NSM.Rule.ServiceGroup | Unknown | Service Group object. Should be defined if ruleobjType is "SERVICE_GROUP". | 
| NSM.Rule.ServiceRange | Unknown | Service Range object. Should be defined if ruleobjType is "SERVICE_RANGE". | 
| NSM.Rule.IPv6AddressRange.IPV6RangeList | String | List of IPv6 Address Range. | 
| NSM.Rule.HostIPv6.hostIPv6AddressList | String | Host IPv6 address list. | 
| NSM.Rule.Network_IPV_4.networkIPV4List | String | Network IPV4 list. | 
| NSM.Rule.Network_IPV_6.networkIPV6List | String | Network IPV6 list. | 
| NSM.Rule.IPv4AddressRange.IPV4RangeList | String | List of IPv4 Address Range. | 
| NSM.Rule.HostIPv4.hostIPv4AddressList | String | Host IPv4 address list. | 

### nsm-create-rule-object
***
Adds a new rule object. 
* If the type is “Endpoint IP V.X” or “Network IP V.X”, only the argument “address_ip_v.X” must contain a value. 
* If the type is “Range IP V.X”, only the arguments “from_address_ip_v.X”, “to_address_ip_v.X” must contain a value. Where X is 4 or 6 respectively.


#### Base Command

`nsm-create-rule-object`
#### Input

| **Argument Name** | **Description**                                                                                                                                                                                                                                                                                                                                                                                                                 | **Required** |
| --- |---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------| --- |
| domain | The ID of the domain. To get the domain ID, use the !nsm-get-domains command.                                                                                                                                                                                                                                                                                                                                                   | Required | 
| rule_object_type | The type of the rule. <br/>* If the type is “Endpoint IP V.X” or “Network IP V.X”, only the argument “address_ip_v.X” must contain a value. <br/>* If the type is “Range IP V.X”, only the arguments “from_address_ip_v.X”, “to_address_ip_v.X” must contain a value, where X is 4 or 6 respectively. <br/>* Possible values are: Endpoint IP V.4, Range IP V.4, Network IP V.4, Endpoint IP V.6, Range IP V.6, Network IP V.6. | Required | 
| name | The rule object name.                                                                                                                                                                                                                                                                                                                                                                                                           | Required | 
| visible_to_child | Whether the rule object is visible to the child domain. Possible values are: yes, no. Default is yes.                                                                                                                                                                                                                                                                                                                           | Optional | 
| description | The description of the rule object.                                                                                                                                                                                                                                                                                                                                                                                             | Optional | 
| address_ip_v.4 | List of IPv4 Host Address, separated by a comma.                                                                                                                                                                                                                                                                                                                                                                                | Optional | 
| from_address_ip_v.4 | Start of the IPv4 range.                                                                                                                                                                                                                                                                                                                                                                                                        | Optional | 
| to_address_ip_v.4 | End of the IPv4 range.                                                                                                                                                                                                                                                                                                                                                                                                          | Optional | 
| address_ip_v.6 | List of IPv6 host addresses, separated by a comma.                                                                                                                                                                                                                                                                                                                                                                              | Optional | 
| from_address_ip_v.6 | Start of the IPv6 range.                                                                                                                                                                                                                                                                                                                                                                                                        | Optional | 
| to_address_ip_v.6 | End of the IPv6 range.                                                                                                                                                                                                                                                                                                                                                                                                          | Optional | 
|state|Whether to enable or disable the rule object. Note: This argument is only relevant to version 10x. Default value is 'Enabled'|Optional|


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| NSM.Rule.ruleobjId | Number | The ID of the newly created rule object. | 

#### Command example
```!nsm-create-rule-object domain=0 rule_object_type="Range IP V.4" name="ruleo" visible_to_child=yes from_address_ip_v.4=1.1.1.1 to_address_ip_v.4=2.2.2.2```
#### Context Example
```json
{
    "NSM": {
        "Rule": {
            "ruleobjId": 154
        }
    }
}
```

#### Human Readable Output

>The rule object no.154 was created successfully

### nsm-update-rule-object
***
Updates a Rule object. In case of address rule update: 
* if the rule type is “Endpoint IP V.X” or “Network IP V.X”, only the argument “address_ip_v.X” should contain a value. 
* If the type is “Range IP V.X”, only the arguments “from_address_ip_v.X”, “to_address_ip_v.X” should contain a value, Where X is 4 or 6 respectively.


#### Base Command

`nsm-update-rule-object`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | The ID of the domain. To get the domain ID, use the !nsm-get-domains command. | Required | 
| rule_id | The ID of the rule. To get the rule object ID, use the !nsm-list-domain-rule-object. | Required | 
| name | The rule object name. | Optional | 
| visible_to_child | Whether the rule object is visible to the child domain. Possible values are: yes, no. Default is yes. | Optional | 
| description | The description of the rule object. | Optional | 
| address_ip_v.4 | List of IPv4 host addresses, separated by a comma. | Optional | 
| from_address_ip_v.4 | Start of the IPv4 range. | Optional | 
| to_address_ip_v.4 | End of the IPv4 range. | Optional | 
| address_ip_v.6 | List of IPv6 host addresses, separated by a comma. | Optional | 
| from_address_ip_v.6 | Start of the IPv6 range. | Optional | 
| to_address_ip_v.6 | End of the IPv6 range. | Optional | 
| is_overwrite | Whether the new addresses that were provided in the update processes will override the current ones or will be added to them. The default is false, and the addresses will be added. Possible values are: true, false. | Optional | 
|state|Whether to enable or disable the rule object. Note: This argument is only relevant to version 10x. Default value is 'Enabled'|Optional|


#### Context Output

There is no context output for this command.

#### Command example
```!nsm-update-rule-object domain=0 rule_id=125 description="new desc"```

#### Human Readable Output

>The rule object no.125 was updated successfully.

### nsm-delete-rule-object
***
Deletes a rule object.


#### Base Command

`nsm-delete-rule-object`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_id | The ID of the rule object. To get the rule object ID, use the !nsm-list-domain-rule-object. | Required | 


#### Context Output

There is no context output for this command.

#### Command example
```!nsm-delete-rule-object rule_id=125```

#### Human Readable Output

>The rule object no.125 was deleted successfully.

### nsm-get-alerts
***
Retrieves the alerts.


#### Base Command

`nsm-get-alerts`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of records to return. Default is 50. | Optional | 
| page | The specific result page to display. | Optional | 
| page_size | The number of records in a page. | Optional | 
| time_period | Time period. Possible values are: LAST_5_MINUTES, LAST_1_HOUR, LAST_6_HOURS, LAST_12_HOURS, LAST_24_HOURS, LAST_7_DAYS, LAST_14_DAYS, CUSTOM. Default is LAST_7_DAYS. | Optional | 
| start_time | Start time in "mm/dd/yyyy HH:MM" format. Used for custom time only. | Optional | 
| end_time | End time in "mm/dd/yyyy HH:MM" format. Used for custom time only. | Optional | 
| state | Alert state. Possible values are: ANY, Acknowledged, Unacknowledged. Default is ANY. | Optional | 
| search | Search string in alert details. | Optional | 
| filter | Filter alert by fields. For example: "name:hello;direction:Inbound,Outbound;attackcount:&gt;3,&lt;4". To use the "name" field in the filter, enter only one name in each command run. Filter on the following columns is allowed- name, assignTo, application, layer7Data, result, attackCount, relevance, alertId, direction, device, domain, interface, attackSeverity, nspId, btp, attackCategory, malwarefileName, malwarefileHash, malwareName, malwareConfidence, malwareEngine ,executableName, executableHash, executableConfidenceName, attackerIPAddress, attackerPort, attackerRisk, attackerProxyIP, attackerHostname, targetIPAddress, targetPort, targetRisk, targetProxyIP, targetHostname, botnetFamily. | Optional | 
| domain_id | The ID of the domain. To get the domain_id, use the !nsm-get-domains command. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| NSM.Alerts.ID | number | Alert ID. | 
| NSM.Alerts.Name | String | Alert name. | 
| NSM.Alerts.uniqueAlertId | String | Unique alert ID. | 
| NSM.Alerts.State | String | Alert state \(Acknowledged,Unacknowledged\). | 
| NSM.Alerts.Assignee | String | Alert assignee. | 
| NSM.Alerts.CreatedTime | String | Alert creation time. | 
| NSM.Alerts.AttackSeverity | String | Alert severity. | 
| NSM.Alerts.Event.time | Date | The creation time of the event that triggered the alert. | 
| NSM.Alerts.Event.direction | String | The direction of the event \(Outbound, Inbound\). | 
| NSM.Alerts.Event.result | String | The result of the event. | 
| NSM.Alerts.Event.attackCount | Number | Attack count. | 
| NSM.Alerts.Event.relevance | String | The event relevance. | 
| NSM.Alerts.Event.alertId | String | Alert ID. | 
| NSM.Alerts.Event.domain | String | The event's domain. | 
| NSM.Alerts.Event.interface | String | The event's interface. | 
| NSM.Alerts.Event.device | String | The relevant device. | 
| NSM.Alerts.Attack.nspId | String | Network Security Platform \(NSP\) ID. | 
| NSM.Alerts.Attack.btp | String | Benign Trigger Probability \(BTP\). | 
| NSM.Alerts.Attack.attackCategory | String | The attack category. | 
| NSM.Alerts.Attacker.ipAddrs | String | The attacker IP address. | 
| NSM.Alerts.Attacker.port | Number | The attacker port. | 
| NSM.Alerts.Attacker.hostName | String | The attacker host name. | 
| NSM.Alerts.Attacker.country | String | The attacker country. | 
| NSM.Alerts.Attacker.os | Unknown | The attacker operating system. | 
| NSM.Alerts.Attacker.vmName | Unknown | The attacker VM name. | 
| NSM.Alerts.Attacker.proxyIP | String | The attacker proxy IP. | 
| NSM.Alerts.Attacker.user | Unknown | The user. | 
| NSM.Alerts.Attacker.risk | String | Attacker risk. | 
| NSM.Alerts.Attacker.networkObject | Unknown | The attacker network object. | 
| NSM.Alerts.Target.ipAddrs | String | The target IP address. | 
| NSM.Alerts.Target.port | Number | The target port. | 
| NSM.Alerts.Target.hostName | String | The target host name. | 
| NSM.Alerts.Target.country | String | The target country. | 
| NSM.Alerts.Target.os | Unknown | The target operating system. | 
| NSM.Alerts.Target.vmName | Unknown | The target VM name. | 
| NSM.Alerts.Target.proxyIP | String | The target proxy IP. | 
| NSM.Alerts.Target.user | Unknown | The target user. | 
| NSM.Alerts.Target.risk | String | The target risk. | 
| NSM.Alerts.Target.networkObject | Unknown | The target network object. | 
| NSM.Alerts.MalwareFile.fileName | String | The name of the malware file. | 
| NSM.Alerts.MalwareFile.fileHash | String | The file hash of the malware file. | 
| NSM.Alerts.MalwareFile.fileSHA1Hash | String | The malware file SHA1 hash. | 
| NSM.Alerts.MalwareFile.fileSHA256Hash | Unknown | The file SHA256 hash of the malware file. | 
| NSM.Alerts.MalwareFile.malwareName | String | The name of the malware. | 
| NSM.Alerts.MalwareFile.malwareConfidence | String | Malware confidence | 
| NSM.Alerts.MalwareFile.engine | String | Malware file engine. | 
| NSM.Alerts.MalwareFile.engineId | Number | Malware file engine ID. | 
| NSM.Alerts.MalwareFile.size | Unknown | The malware file size. | 
| NSM.Alerts.MalwareFile.description | Unknown | Malware file description. | 
| NSM.Alerts.MalwareFile.additionalReference | Unknown | Malware file additional reference. | 
| NSM.Alerts.MalwareFile.cveId | Unknown | Malware file CVE ID. | 
| NSM.Alerts.endpointExcutable.name | String | Endpoint executable name. | 
| NSM.Alerts.endpointExcutable.hash | String | Endpoint executable hash. | 
| NSM.Alerts.endpointExcutable.malwareConfidence | String | Endpoint executable malware confidence. | 
| NSM.Alerts.detection.managerId | Number | manager ID. | 
| NSM.Alerts.detection.manager | Unknown | The detection manager. | 
| NSM.Alerts.detection.domain | String | Detection domain. | 
| NSM.Alerts.detection.device | String | Detection device. | 
| NSM.Alerts.detection.deviceId | String | Detection device ID. | 
| NSM.Alerts.detection.interface | String | Detection interface. | 
| NSM.Alerts.Application | String | The application associated to the alert. | 
| NSM.Alerts.layer7Data | String | Layer 7 information. | 
| NSM.Alerts.EventResult | String | Event result. | 
| NSM.Alerts.SensorID | String | Sensor ID. | 

#### Command example
```!nsm-get-alerts domain_id=0 time_period=CUSTOM start_time="12/17/2000 14:14:22" end_time="12/18/2022 00:26:45" limit=2```
#### Context Example
```json
{
    "NSM": {
        "Alerts": [
            {
                "Application": "HTTP",
                "Assignee": "",
                "Attack": {
                    "attackCategory": "Exploit",
                    "btp": "Medium",
                    "nspId": "0x00000000"
                },
                "Attacker": {
                    "country": null,
                    "hostName": "",
                    "ipAddrs": "1.1.1.1",
                    "networkObject": null,
                    "os": null,
                    "port": 22222,
                    "proxyIP": "",
                    "risk": "Disabled",
                    "user": null,
                    "vmName": null
                },
                "CreatedTime": "Dec 17, 2018 21:06:21",
                "Event": {
                    "alertId": "3333333333333333333",
                    "attackCount": 1,
                    "device": "VVVV1",
                    "direction": "Outbound",
                    "domain": "/My Domain",
                    "interface": "1-2",
                    "relevance": "Unknown",
                    "result": "Inconclusive",
                    "time": "Dec 17, 2018 21:06:21"
                },
                "EventResult": "Inconclusive",
                "ID": "3333333333333333333",
                "MalwareFile": {
                    "additionalReference": null,
                    "cveId": null,
                    "description": null,
                    "engine": "",
                    "engineId": 0,
                    "fileHash": "",
                    "fileName": "",
                    "malwareConfidence": "",
                    "malwareName": "",
                    "size": null
                },
                "Name": "HTTP: vulnerability",
                "SensorID": "4444",
                "Target": {
                    "country": null,
                    "hostName": "",
                    "ipAddrs": "2.2.2.2",
                    "networkObject": null,
                    "os": null,
                    "port": 80,
                    "proxyIP": "",
                    "risk": "Disabled",
                    "user": null,
                    "vmName": null
                },
                "State": "Acknowledged",
                "attackSeverity": "High",
                "detection": {
                    "device": "VVVV1",
                    "deviceId": "4444",
                    "domain": "/My Domain",
                    "interface": "1-2",
                    "manager": null,
                    "managerId": 0
                },
                "endpointExcutable": {
                    "hash": "",
                    "malwareConfidence": "",
                    "name": ""
                },
                "layer7Data": "HTTP Request Method: GET ",
                "uniqueAlertId": "1212121212121212121"
            },
            {
                "Application": "Web",
                "Assignee": "",
                "Attack": {
                    "attackCategory": "Exploit",
                    "btp": "Low",
                    "nspId": "0x00000000"
                },
                "Attacker": {
                    "country": null,
                    "hostName": "",
                    "ipAddrs": "1.1.1.1",
                    "networkObject": null,
                    "os": null,
                    "port": 12345,
                    "proxyIP": "",
                    "risk": "---",
                    "user": null,
                    "vmName": null
                },
                "CreatedTime": "Dec 17, 2018 21:04:21",
                "Event": {
                    "alertId": "5555555555555555555",
                    "attackCount": 1,
                    "device": "VVVV1",
                    "direction": "Inbound",
                    "domain": "/My Dmain",
                    "interface": "1-2",
                    "relevance": "Unknown",
                    "result": "Inconclusive",
                    "time": "Dec 17, 2018 21:04:21"
                },
                "EventResult": "Inconclusive",
                "ID": "5555555555555555555",
                "MalwareFile": {
                    "additionalReference": null,
                    "cveId": null,
                    "description": null,
                    "engine": "",
                    "engineId": 0,
                    "fileHash": "",
                    "fileName": "",
                    "malwareConfidence": "",
                    "malwareName": "",
                    "size": null
                },
                "Name": "HTTP: IIS 6.0 (CVE-2017-7269)",
                "SensorID": "4444",
                "Target": {
                    "country": null,
                    "hostName": "",
                    "ipAddrs": "2.2.2.2",
                    "networkObject": null,
                    "os": null,
                    "port": 80,
                    "proxyIP": "",
                    "risk": "---",
                    "user": null,
                    "vmName": null
                },
                "alertState": "Acknowledged",
                "attackSeverity": "High",
                "detection": {
                    "device": "VVVV1",
                    "deviceId": "4444",
                    "domain": "/My Domain",
                    "interface": "1-2",
                    "manager": null,
                    "managerId": 0
                },
                "endpointExcutable": {
                    "hash": "",
                    "malwareConfidence": "",
                    "name": ""
                },
                "layer7Data": "HTTP Request Method: PROPFIND",
                "uniqueAlertId": "2323232323232323232"
            }
        ]
    }
}
```

#### Human Readable Output

>### Alerts list. Showing 2 of 20
>|ID|Name|Severity|State|
>|---|---|---|---|
>| 3333333333333333333 | HTTP: vulnerability | High | Acknowledged |
>| 5555555555555555555 | HTTP: IIS 6.0 (CVE-2017-7269) | High | Acknowledged |

### nsm-get-alert-details
***
Retrieves the relevant alert details.


#### Base Command

`nsm-get-alert-details`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | Alert ID. In order to get the alert ID, use the command '!nsm-get-alerts' and use the output field “ID”. | Required | 
| sensor_id | Sensor ID. In order to get the sensor ID, use the command '!nsm-get-alerts' and use the output field “SensorID”. | Required | 


#### Context Output

| **Path**                                               | **Type** | **Description**                                      |
|--------------------------------------------------------|----------|------------------------------------------------------|
| NSM.Alerts.ID                                          | number   | Alert ID.                                            | 
| NSM.Alerts.Name                                        | String   | Alert name.                                          | 
| NSM.Alerts.CreatedTime                                 | String   | Alert creation time.                                 | 
| NSM.Alerts.uniqueAlertId                               | String   | Unique alert ID.                                     | 
| NSM.Alerts.State                                       | String   | The state of the alert.                              | 
| NSM.Alerts.Assignee                                    | String   | Alert assignee.                                      | 
| NSM.Alerts.Event.application                           | String   | The event application.                               | 
| NSM.Alerts.Event.protocol                              | Unknown  | The event protocol.                                  | 
| NSM.Alerts.Event.domain                                | String   | The domain of the event.                             | 
| NSM.Alerts.Event.manager                               | Unknown  | The event manager.                                   | 
| NSM.Alerts.Event.device                                | String   | The event device.                                    | 
| NSM.Alerts.Event.deviceId                              | String   | The ID of the device related to the event.           | 
| NSM.Alerts.Event.matchedPolicy                         | String   | The policy that matched the event.                   | 
| NSM.Alerts.Event.zone                                  | Unknown  | The event zone.                                      | 
| NSM.Alerts.Event.vlan                                  | String   | The event VLAN.                                      | 
| NSM.Alerts.Event.detection                             | String   | The event detection.                                 | 
| NSM.Alerts.CreatedTime                                 | Date     | The creation time of the event.                      | 
| NSM.Alerts.EventResult                                 | String   | The event result.                                    | 
| NSM.Alerts.Event.attackCount                           | Number   | Event attack count.                                  | 
| NSM.Alerts.Event.relevance                             | String   | The relevance of the event.                          | 
| NSM.Alerts.Event.alertId                               | String   | Alert ID.                                            | 
| NSM.Alerts.Attacker.ipAddrs                            | Unknown  | Attacker IP addresses.                               | 
| NSM.Alerts.Attacker.port                               | Number   | Attacker port.                                       | 
| NSM.Alerts.Attacker.hostName                           | Unknown  | Attacker host name.                                  | 
| NSM.Alerts.Attacker.country                            | Unknown  | Attacker country.                                    | 
| NSM.Alerts.Attacker.os                                 | String   | Attacker operating system.                           | 
| NSM.Alerts.Attacker.vmName                             | Unknown  | Attacker VM name.                                    | 
| NSM.Alerts.Attacker.proxyIP                            | Unknown  | Attacker proxy IP.                                   | 
| NSM.Alerts.Attacker.user                               | String   | Attacker user.                                       | 
| NSM.Alerts.Attacker.risk                               | String   | Attacker risk.                                       | 
| NSM.Alerts.Attacker.networkObject                      | String   | Attacker network object.                             | 
| NSM.Alerts.Target.ipAddrs                              | Unknown  | Target IP address.                                   | 
| NSM.Alerts.Target.port                                 | Number   | Target port.                                         | 
| NSM.Alerts.Target.hostName                             | Unknown  | Target host name.                                    | 
| NSM.Alerts.Target.country                              | Unknown  | Target country.                                      | 
| NSM.Alerts.Target.os                                   | String   | Target operating system.                             | 
| NSM.Alerts.Target.vmName                               | Unknown  | Target VM name.                                      | 
| NSM.Alerts.Target.proxyIP                              | Unknown  | Target proxy IP.                                     | 
| NSM.Alerts.Target.user                                 | String   | Target user.                                         | 
| NSM.Alerts.Target.risk                                 | String   | Target risk.                                         | 
| NSM.Alerts.Target.networkObject                        | String   | Target network object.                               | 
| NSM.Alerts.summary.source                              | Unknown  | The source of the alert.                             | 
| NSM.Alerts.summary.destination                         | Unknown  | The destination of the alert.                        | 
| NSM.Alerts.summary.zoombie                             | Unknown  | Alert zoombie.                                       | 
| NSM.Alerts.summary.cAndcServer                         | Unknown  | The command and control server.                      | 
| NSM.Alerts.summary.fastFluxAgent                       | Unknown  | Fast flux agent.                                     | 
| NSM.Alerts.summary.attackedHIPEndpoint                 | Unknown  | Attacked host intrusion prevention \(HIP\) endpoint. | 
| NSM.Alerts.summary.compromisedEndpoint                 | Unknown  | Compromised endpoint.                                | 
| NSM.Alerts.Details.matchedSignature                    | Unknown  | Matched signature.                                   | 
| NSM.Alerts.MalwareFile                                 | Unknown  | Malware file.                                        | 
| NSM.Alerts.Details.hostSweep                           | Unknown  | Host sweep.                                          | 
| NSM.Alerts.Details.portScan                            | Unknown  | Port scan.                                           | 
| NSM.Alerts.Details.fastFlux                            | Unknown  | Fast flux.                                           | 
| NSM.Alerts.Details.triggeredComponentAttacks           | Unknown  | Triggered component attack.                          | 
| NSM.Alerts.Details.sqlInjection                        | Unknown  | SQL injection.                                       | 
| NSM.Alerts.Details.callbackDetectors                   | Unknown  | Callback detectors.                                  | 
| NSM.Alerts.Details.exceededThreshold                   | Unknown  | Exceeded threshold.                                  | 
| NSM.Alerts.Details.communicationRuleMatch              | Unknown  | Communication rule match.                            | 
| NSM.Alerts.Description                                 | String   | Description.                                         | 
| NSM.Alerts.Description.btp                             | String   | Benign Trigger Probability \(BTP\).                  | 
| NSM.Alerts.Description.rfSB                            | String   | Recommended For Smart Blocking \(RFSB\).             | 
| NSM.Alerts.Description.protectionCategory              | String   | Protection category.                                 | 
| NSM.Alerts.Description.target                          | String   | The target.                                          | 
| NSM.Alerts.Description.httpResponseAttack              | String   | HTTP response attack.                                | 
| NSM.Alerts.Description.priority                        | String   | Priority.                                            | 
| NSM.Alerts.Protocols                                   | String   | Protocols.                                           | 
| NSM.Alerts.Attack.attackCategory                       | String   | Attack category.                                     | 
| NSM.Alerts.Attack.attackSubCategory                    | String   | Attack sub-category.                                 | 
| NSM.Alerts.Description.snortEngine                     | String   | Snort engine.                                        | 
| NSM.Alerts.Description.versionAdded                    | String   | The date the version was added.                      | 
| NSM.Alerts.Description.versionUpdated                  | Unknown  | The date the version was updated.                    | 
| NSM.Alerts.Attack.nspId                                | String   | Network Security Platform \(NSP\) ID.                | 
| NSM.Alerts.Description.reference.cveId                 | String   | Common Vulnerabilities and Exposures \(CVE\) ID.     | 
| NSM.Alerts.Description.reference.microsoftId           | String   | Microsoft ID.                                        | 
| NSM.Alerts.Description.reference.bugtraqId             | String   | Bugtraq ID.                                          | 
| NSM.Alerts.Description.reference.certId                | Unknown  | Cert ID.                                             | 
| NSM.Alerts.Description.reference.arachNidsId           | String   | Arachnics ID.                                        | 
| NSM.Alerts.Description.reference.additionInfo          | String   | Additional information.                              | 
| NSM.Alerts.Description.comments.comments               | String   | Comments.                                            | 
| NSM.Alerts.Description.comments.availabeToChildDomains | Boolean  | Whether the alert is available to child domains.     | 
| NSM.Alerts.Description.comments.parentDomainComments   | Unknown  | Parent domain comments.                              | 
| NSM.Alerts.Event.direction                             | String   | The event direction.                                 | 
| NSM.Alerts.Event.interface                             | String   | The event interface.                                 | 

#### Command example
```!nsm-get-alert-details alert_id=6666666666666666666 sensor_id=1001```
#### Context Example
```json
{
    "NSM": {
        "Alerts": {
            "ID": "6666666666666666666",
            "Name": "Buffer Overflow",
            "uniqueAlertId": "3333333333333333333",
            "State": "UnAcknowledged",
            "CreatedTime": "Apr 23, 2020 22:26:13",
            "Assignee": "---",
            "Description": "some description",
            "EventResult": "Inconclusive",
            "Attack": {
                "attackCategory": "Exploit",
                "attackSubCategory": "Buffer Overflow",
                "nspId": "0x00000000"
            },
            "Protocols": "dns",
            "SensorID": "1001",
            "Event": {
                    "application": "Not Available",
                    "protocol": "telnet",
                    "domain": "/My Domain",
                    "manager": null,
                    "device": "vm600-nsmapi-cc",
                    "interface": "1-2",
                    "matchedPolicy": "Default Prevention",
                    "zone": null,
                    "vlan": "-10",
                    "detection": "Application anomaly",
                    "direction": "Inbound",
                    "attackCount": 1,
                    "relevance": "Unknown",
                    "alertId": "6666666666666666666"
                },
            "Attacker": {
                    "ipAddrs": "9.9.9.9",
                    "port": 11111,
                    "hostName": null,
                    "country": null,
                    "os": "Microsoft Windows Server 2008",
                    "vmName": null,
                    "proxyIP": null,
                    "user": "Unknown",
                    "risk": "N/A",
                    "networkObject": "---"
                },
            "Target": {
                    "ipAddrs": "1.1.1.1",
                    "port": 88888,
                    "hostName": null,
                    "country": null,
                    "os": "Microsoft Windows Server 2003 Service Pack 1",
                    "vmName": null,
                    "proxyIP": null,
                    "user": "Unknown",
                    "risk": "N/A",
                    "networkObject": "---"
                },
            "MalwareFile": null,
            "summary": {
                "source": null,
                "destination": null,
                "zoombie": null,
                "cAndcServer": null,
                "fastFluxAgent": null,
                "attackedHIPEndpoint": null,
                "compromisedEndpoint": null
            },
            "Details": {
                "matchedSignature": {
                    "signatureName": "overflow-iquery.c",
                    "signature": {
                        "name": "Signature#1",
                        "conditions": [
                            "condition 1",
                            "condition 2",
                            "condition 3",
                            "condition 4"
                        ]
                    }
                },
                "layer7": null,
                "hostSweep": null,
                "portScan": null,
                "fastFlux": null,
                "triggeredComponentAttacks": null,
                "sqlInjection": null,
                "callbackDetectors": null,
                "exceededThreshold": null,
                "communicationRuleMatch": null
            },
            "description": {
                "btp": "Low",
                "rfSB": "Yes",
                "protectionCategory": "[Server Protection/Name Servers]",
                "target": "Server",
                "httpResponseAttack": "No",
                "priority": "High",
                "reference": {
                    "cveId": "CVE-1999-0009",
                    "microsoftId": "",
                    "bugtraqId": "123",
                    "certId": null,
                    "arachNidsId": "",
                    "additionInfo": "http://www.website.com/"
                },
                "signatures": [
                    {
                        "name": "Signature#1",
                        "conditions": [
                            "condition 1",
                            "condition 2",
                            "condition 3",
                            "condition 4"
                        ]
                    },
                    {
                        "name": "Signature#2",
                        "conditions": [
                            "condition 1",
                            "condition 2",
                            "condition 3",
                            "condition 4"
                        ]
                    },
                    {
                        "name": "Signature#3",
                        "conditions": [
                            "condition 1",
                            "condition 2",
                            "condition 3",
                            "condition 4",
                            "condition 5"
                        ]
                    }
                ],
                "componentAttacks": [],
                "comments": {
                    "comments": "",
                    "availabeToChildDomains": true,
                    "parentDomainComments": null
                }
            }
        }
    }
}
```

#### Human Readable Output

>### Alerts list. Showing 2 of 20
>|ID|Name|Event Time|State| Direction |Result|Attack Count| Attacker IP | Target IP |
>|---|---|---|---------|---|---|-------------|-----------|---|
>| 6666666666666666666 | Buffer Overflow | Apr 23, 2020 22:26:13 | UnAcknowledged | Inbound | Inconclusive | 1 | 9.9.9.9 | 1.1.1.1 | 


### nsm-get-attacks
***
If an attack is given, the command returns the details for the specific attack. Otherwise, gets all available attack definitions in the Manager UI. This command can take a few minutes. If you get a timeout error, increase the timeout by using the parameter "execution-timeout".


#### Base Command

`nsm-get-attacks`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| attack_id | The ID of the attack. To get the attack_id, use the !nsm-get-attacks command, without an attack ID. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| InfoFile.Name | string | File name. | 
| InfoFile.EntryID | string | The entry ID of the report. | 
| InfoFile.Size | number | File size. | 
| InfoFile.Type | string | File type, e.g., "PE". | 
| InfoFile.Info | string | Basic information about the file. | 
| NSM.Attacks.Direction | Unknown | Attack direction. | 
| NSM.Attacks.Severity | Number | Attack severity. | 
| NSM.Attacks.ID | String | Attack ID. | 
| NSM.Attacks.Name | String | Attack name. | 
| NSM.Attacks.Category | String | Attack category. | 
| NSM.Attacks.description.definition | String | Attack Definition | 
| NSM.Attacks.description.btp | String | Benign Trigger Probability \(BTP\). | 
| NSM.Attacks.description.rfSB | String | Recommended For Smart Blocking \(RFSB\). | 
| NSM.Attacks.description.protectionCategory | String | Protection category. | 
| NSM.Attacks.description.target | String | Attack target. | 
| NSM.Attacks.description.httpResponseAttack | String | HTTP Response Attack. | 
| NSM.Attacks.description.priority | String | Attack priority. | 
| NSM.Attacks.description.protocols | String | Attack protocols. | 
| NSM.Attacks.description.attackCategory | String | Attack category. | 
| NSM.Attacks.description.attackSubCategory | String | Attack sub-category. | 
| NSM.Attacks.description.snortEngine | String | Attack snort engine. | 
| NSM.Attacks.description.versionAdded | String | The date the attack version was added. | 
| NSM.Attacks.description.versionUpdated | String | The date the attack version was updated. | 
| NSM.Attacks.description.reference.nspId | String | Attack Network Security Platform \(NSP\) ID. | 
| NSM.Attacks.description.reference.cveId | String | Attack Common Vulnerabilities and Exposures \(CVE\) ID. | 
| NSM.Attacks.description.reference.microsoftId | String | Attack Microsoft ID. | 
| NSM.Attacks.description.reference.bugtraqId | String | Attack bugtraq ID. | 
| NSM.Attacks.description.reference.certId | String | Attack cert ID. | 
| NSM.Attacks.description.reference.arachNidsId | String | Arachnids ID. | 
| NSM.Attacks.description.reference.additionInfo | Unknown | Additional information. | 
| NSM.Attacks.description.comments.comments | String | Comments. | 
| NSM.Attacks.description.comments.availabeToChildDomains | Boolean | Whether the attack is available to child domains. | 
| NSM.Attacks.description.comments.parentDomainComments | Unknown | Parent domain comments. | 

#### Command example
```!nsm-get-attacks attack_id=0x00000100```
#### Context Example
```json
{
    "NSM": {
        "Attacks": {
            "Category": null,
            "Direction": null,
            "ID": "0x00000100",
            "Name": "IP: too Large",
            "Severity": 5,
            "UiCategory": "EXPLOIT"
        }
    }
}
```

#### Human Readable Output

>### Attack no.0x00000100
>|ID|Name|Severity|
>|---|---|---|
>| 0x00000100 | IP: too Large | 5 |


### nsm-get-domains
***
If a domain ID is given, the command returns the details of the specific domain. Otherwise, gets all available domains.


#### Base Command

`nsm-get-domains`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain_id | Specific domain ID. Leave blank for all domains. To get the domain_id use !nsm-get-domains command and leave the parameter blank. | Optional | 
| limit | The maximum number of records to return. Default is 50.0. | Optional | 
| page | The specific result page to display. | Optional | 
| page_size | The number of records in a page. | Optional | 


#### Context Output

| **Path**                 | **Type** | **Description** |
|--------------------------| --- | --- |
| NSM.Domains.ID           | Number | Domain ID. | 
| NSM.Domains.Name         | String | Domain name. | 
| NSM.Domains.childdomains | Unknown | The children of the domain. | 

#### Command example
```!nsm-get-domains```
#### Context Example
```json
{
    "NSM": {
        "Domains": {
            "ID": 0,
            "Name": "My Company",
            "childdomains": []
        }
    }
}
```

#### Human Readable Output

>### List of Domains
>|ID|Name|
>|---|---|
>| 0 | My Company |


### nsm-get-sensors
***
Gets the list of sensors available in the specified domain. If the domain is not specified, details of all the sensors in all ADs will be provided.


#### Base Command

`nsm-get-sensors`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain_id | Specific domain ID. Leave blank for all domains. To get the domain_id use !nsm-get-domains command and leave the parameter blank. | Optional | 
| limit | The maximum number of records to return. Default is 50. | Optional | 
| page | The specific result page to display. | Optional | 
| page_size | The number of records in a page. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| NSM.Sensors.ID | Number | Sensor ID. | 
| NSM.Sensors.Name | String | Name of the sensor. | 
| NSM.Sensors.model | String | Sensor model. | 
| NSM.Sensors.Description | String | Sensor description. | 
| NSM.Sensors.DomainID | Number | ID of the domain to which this sensor belongs. | 
| NSM.Sensors.isFailOver | Boolean | Whether the sensor is failover. | 
| NSM.Sensors.isNTBA | Boolean | Whether there is Network Threat Behavior Analysis \(NTBA\). | 
| NSM.Sensors.isLoadBalancer | Boolean | Whether the sensor is a load balancer. | 
| NSM.Sensors.SerialNumber | Unknown | The sensor serial number. | 
| NSM.Sensors.SigsetVersion | String | Signature set version number applied to the sensor. | 
| NSM.Sensors.DATVersion | String | DAT version of the sensor. | 
| NSM.Sensors.SoftwareVersion | String | Sensor software version. | 
| NSM.Sensors.LastSignatureUpdateTs | Date | Last configuration download timestamp. | 
| NSM.Sensors.IPSPolicyID | Number | Intrusion prevent system \(IPS\) policy ID applied to the sensor. | 
| NSM.Sensors.ReconPolicyID | Number | Recon policy ID applied to the sensor. | 
| NSM.Sensors.LastModTs | Unknown | Last modified timestamp. | 
| NSM.Sensors.IP Address | String | Sensor IP address. | 
| NSM.Sensors.nsmVersion | String | Network Security Manager \(NSM\) version. | 
| NSM.Sensors.MemberSensors | Unknown | Sensors members. | 

#### Command example
```!nsm-get-sensors```
#### Context Example
```json
{
    "NSM": {
        "Sensors": {
            "DATVersion": null,
            "Description": "MCAFEE-NETWORK-SECURITY-PLATFORM",
            "DomainID": 0,
            "ID": 1111,
            "IP Address": "1.1.1.1",
            "IPSPolicyID": 0,
            "LastModTs": null,
            "LastSignatureUpdateTs": "2022-12-04 02:07:45",
            "MemberSensors": [],
            "Name": "VVVV1",
            "ReconPolicyID": 0,
            "SigsetVersion": null,
            "SoftwareVersion": "9.9.9.9",
            "isFailOver": false,
            "isLoadBalancer": false,
            "model": "IPS-VM100",
            "nsmVersion": "9.1"
        }
    }
}
```

#### Human Readable Output

>### Sensors List
>|ID|Name|Description|DomainID|IPSPolicyID|IP Address|
>|---|---|---|---|---|---|---|
>| 1111 | VVVV1 | MCAFEE-NETWORK-SECURITY-PLATFORM | 0 | 0 | 1.1.1.1 |

### nsm-get-ips-policies
***
Gets all the IPS policies defined in the specific domain.


#### Base Command

`nsm-get-ips-policies`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain_id | Specific domain ID. To get the domain_id use !nsm-get-domains command and leave the parameter blank. | Required | 
| limit | The maximum number of records to return. Default is 50. | Optional | 
| page | The specific result page to display. | Optional | 
| page_size | The number of records in a page. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| NSM.IPSPolicies.IsEditable | Boolean | Whether the IPS policy is editable. | 
| NSM.IPSPolicies.DomainID | Number | ID of the domain to which this policy belongs. | 
| NSM.IPSPolicies.VisibleToChildren | Boolean | Policy visible to child domain. | 
| NSM.IPSPolicies.ID | Number | IPS policy ID. | 
| NSM.IPSPolicies.Name | String | IPS policy name. | 

#### Command example
```!nsm-get-ips-policies domain_id=0 limit=2```
#### Context Example
```json
{
    "NSM": {
        "IPSPolicies": [
            {
                "DomainID": 0,
                "ID": -1,
                "IsEditable": true,
                "Name": "Master",
                "VisibleToChildren": true
            },
            {
                "DomainID": 0,
                "ID": 0,
                "IsEditable": true,
                "Name": "Default",
                "VisibleToChildren": true
            }
        ]
    }
}
```

#### Human Readable Output

>### IPS Policies List of Domain no.0
>|ID|Name|DomainID|IsEditable|VisibleToChildren|
>|---|---|---|---|---|
>| -1 | Master | 0 | true | true |
>| 0 | Default | 0 | true | true |


### nsm-get-ips-policy-details
***
Gets all the IPS policies defined in the specific domain.


#### Base Command

`nsm-get-ips-policy-details`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_id | Specific IPS policy ID. To get the policy_id use !nsm-get-ips-policies command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| NSM.IPSPolicies.ID | number | IPS policy ID. | 
| NSM.IPSPolicies.Name | string | IPS policy name. | 
| NSM.IPSPolicies.Description | string | IPS policy information. | 
| NSM.IPSPolicies.CreatedTime | string | Policy creation time. | 
| NSM.IPSPolicies.IsEditable | boolean | Whether the IPS policy is editable. | 
| NSM.IPSPolicies.VisibleToChildren | boolean | Whether the IPS Policy is visible to the domain's children. | 
| NSM.IPSPolicies.Version | number | IPS policy version. | 
| NSM.IPSPolicies.InboundRuleSet | string | Inbound rule set. | 
| NSM.IPSPolicies.OutboundRuleSet | string | Outbound rule set. | 
| NSM.IPSPolicies.ExploitAttacks | Unknown | A list of exploit attacks related to the IPS policy. | 

#### Command example
```!nsm-get-ips-policy-details policy_id=17```
#### Context Example
```json
{
    "NSM": {
        "IPSPolicies": {
           "ID": 17,
           "Name": "IpsPolicy",
           "Description": "To test the IPS policy",
           "VisibleToChildren": true,
           "InboundRuleSet": "TestIPS",
           "OutboundRuleSet": "Null",
           "ExpolitAttack":
               [
                   {
                       "attackName": "FTP: VMware",
                       "nspId": "0x00000000",
                       "severity": 7,
                       "isSeverityCustomized": false,
                       "isEnabled": true,
                       "isAlertCustomized": false,
                       "isRecommendedForSmartBlocking": false,
                       "AttackResponse":
                       {
                           "TCPReset": "DISABLED",
                           "isTcpResetCustomized": false,
                           "isICMPSend": false,
                           "isICMPSendCustomized": false,
                           "mcAfeeNACNotification": "DISABLED",
                           "isMcAfeeNACNotificationEnabled": false,
                           "isQuarantineCustomized": false,
                           "isRemediateEnabled": false,
                           "blockingOption": "DISABLE",
                           "isBlockingOptionCustomized": false,
                           "isCapturedPrior": true,
                           "isCapturedPriorCustomized": false,
                           "action": "SEND_ALERT_ONLY",
                           "isLogCustomized": false,
                           "isFlowCustomized": false,
                           "isNbytesCustomized": false,
                           "numberOfBytesInEachPacket":
                           {
                               "LogEntirePacket":
                               {
                               }
                           }
                       },
                       "notification":
                       {
                           "isEmail": false,
                           "isPager": false,
                           "isScript": false,
                           "isAutoAck": false,
                           "isSnmp": false,
                           "isSyslog": false,
                           "isEmailCustomized": false,
                           "isPagerCustomized": false,
                           "isScriptCustomized": false,
                           "isAutoAckCustomized": false,
                           "isSnmpCustomized": false,
                           "isSyslogCustomized": false
                       },
                       "protocolList":
                       [
                           "ftp"
                       ],
                       "benignTriggerProbability": "1 (Low)",
                       "blockingType": "attack-packet",
                       "subCategory": "code-execution",
                       "direction": "INBOUND",
                       "isAttackCustomized": false
                   }
               ],
           "AttackCategory":
           {
               
           },
           "OutboundAttackCategory":
           {
           },
           "DosPolicy":
           {
               "LearningAttack":
               [
                   {
                       "attackName": "TCP Control Segment Anomaly",
                       "nspId": "0x00000000",
                       "isSeverityCustomized": false,
                       "severity": 7,
                       "isBlockingSettingCustomized": false,
                       "isDropPacket": false,
                       "IsAlertCustomized": false,
                       "isSendAlertToManager": true,
                       "direction": "BOTH",
                       "notification":
                       {
                           "isEmail": false,
                           "isPager": false,
                           "isScript": false,
                           "isAutoAck": false,
                           "isSnmp": false,
                           "isSyslog": false,
                           "isEmailCustomized": false,
                           "isPagerCustomized": false,
                           "isScriptCustomized": false,
                           "isAutoAckCustomized": false,
                           "isSnmpCustomized": false,
                           "isSyslogCustomized": false
                       },
                       "isAttackCustomized": false
                   }
               ],
               "ThresholdAttack":
               [
                   {
                       "attackName": "Too Many Inbound TCP SYNs",
                       "nspId": "0x00000000",
                       "isSeverityCustomized": false,
                       "severity": 6,
                       "isThresholdValueCustomized": false,
                       "isThresholdDurationCustomized": false,
                       "ThresholdValue": 2000,
                       "ThresholdDuration": 5,
                       "isAlertCustomized": false,
                       "isSendAlertToManager": false,
                       "Notification":
                       {
                           "isEmail": false,
                           "isPager": false,
                           "isScript": false,
                           "isAutoAck": false,
                           "isSnmp": false,
                           "isSyslog": false,
                           "isEmailCustomized": false,
                           "isPagerCustomized": false,
                           "isScriptCustomized": false,
                           "isAutoAckCustomized": false,
                           "isSnmpCustomized": false,
                           "isSyslogCustomized": false
                       },
                       "direction": "INBOUND",
                       "isAttackCustomized": false
                   }
               ],
               "TimeStamp": "2012-06-20 18:44:55.000"
           },
           "DosResponseSensitivityLevel": 0,
           "IsEditable": false,
           "CreatedTime": "2012-06-20 18:44:55.000",
           "Version": 1,
           "IsLightWeightPolicy": false
       }
    }
}
```

#### Human Readable Output

>### IPS Policy no.17 Details
>|ID|Name|Description|CreatedTime|IsEditable|VisibleToChildren|Version|InboundRuleSet|OutboundRuleSet|
>|---|---|---|---|---|---|---|---|---|---|
>| 17 | IpsPolicy | To test the IPS policy | To test the IPS policy | false | true | 1 | To test the IPS policy | Null |

### nsm-update-alerts
***
Update state or assignee of alerts. It is required to provide at least one of them. If none of the alerts match the time_period they won't be updated.


#### Base Command

`nsm-update-alerts`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| state | Alert state. Possible values are: ANY, Acknowledged, Unacknowledged. Default is ANY. | Optional | 
| time_period | Time period. Possible values are: LAST_5_MINUTES, LAST_1_HOUR, LAST_6_HOURS, LAST_12_HOURS, LAST_24_HOURS, LAST_7_DAYS, LAST_14_DAYS, CUSTOM. Default is LAST_7_DAYS. | Optional | 
| start_time | Start time in "mm/dd/yyyy HH:MM" format. Used for custom time only. | Optional | 
| end_time | End time in "mm/dd/yyyy HH:MM" format. Used for custom time only. | Optional | 
| new_state | The new alert state. Possible values are: Acknowledged, Unacknowledged. | Optional | 
| new_assignee | The new assignee. | Optional | 
| search | Search string in alert details. | Optional | 
| filter | Filter alert by fields. example: "name:hello;direction:Inbound,Outbound;attackcount:&gt;3,&lt;4". To use the "name" field in the filter, enter only one name in each command run. Filter on the following columns is allowed - name, assignTo, application, layer7Data, result, attackCount, relevance, alertId, direction, device, domain, interface, attackSeverity, nspId, btp, attackCategory, malwarefileName, malwarefileHash, malwareName, malwareConfidence, malwareEngine ,executableName, executableHash, executableConfidenceName, attackerIPAddress, attackerPort, attackerRisk, attackerProxyIP, attackerHostname, targetIPAddress, targetPort, targetRisk, targetProxyIP, targetHostname, botnetFamily. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| NSM.Alerts.ID | number | Alert ID. | 
| NSM.Alerts.Name | String | Alert name. | 
| NSM.Alerts.uniqueAlertId | String | Unique alert ID. | 
| NSM.Alerts.State | String | Alert state \(Acknowledged,Unacknowledged\). | 
| NSM.Alerts.Assignee | String | Alert assignee. | 
| NSM.Alerts.CreatedTime | String | Alert creation time. | 
| NSM.Alerts.AttackSeverity | String | Alert severity. | 
| NSM.Alerts.Event.time | Date | The creation time of the event that triggered the alert. | 
| NSM.Alerts.Event.direction | String | The direction of the event \(Outbound, Inbound\). | 
| NSM.Alerts.Event.result | String | The result of the event. | 
| NSM.Alerts.Event.attackCount | Number | Attack count. | 
| NSM.Alerts.Event.relevance | String | The event relevance. | 
| NSM.Alerts.Event.alertId | String | Alert ID. | 
| NSM.Alerts.Event.domain | String | The domain. | 
| NSM.Alerts.Event.interface | String | The event's interface. | 
| NSM.Alerts.Event.device | String | The relevant device. | 
| NSM.Alerts.Attack.nspId | String | Network Security Platform \(NSP\) ID. | 
| NSM.Alerts.Attack.btp | String | Benign Trigger Probability \(BTP\). | 
| NSM.Alerts.Attack.attackCategory | String | The attack category. | 
| NSM.Alerts.Attacker.ipAddrs | String | The attacker IP address. | 
| NSM.Alerts.Attacker.port | Number | The port. | 
| NSM.Alerts.Attacker.hostName | String | The attacker host name. | 
| NSM.Alerts.Attacker.country | String | The attacker country. | 
| NSM.Alerts.Attacker.os | Unknown | The attacker operating system. | 
| NSM.Alerts.Attacker.vmName | Unknown | The attacker VM name. | 
| NSM.Alerts.Attacker.proxyIP | String | The attacker proxy IP. | 
| NSM.Alerts.Attacker.user | Unknown | The user. | 
| NSM.Alerts.Attacker.risk | String | Attacker risk. | 
| NSM.Alerts.Attacker.networkObject | Unknown | The attacker network object. | 
| NSM.Alerts.Target.ipAddrs | String | The target IP address. | 
| NSM.Alerts.Target.port | Number | The target port. | 
| NSM.Alerts.Target.hostName | String | The target host name. | 
| NSM.Alerts.Target.country | String | The target country. | 
| NSM.Alerts.Target.os | Unknown | The target operating system. | 
| NSM.Alerts.Target.vmName | Unknown | The target VM name. | 
| NSM.Alerts.Target.proxyIP | String | The target proxy IP. | 
| NSM.Alerts.Target.user | Unknown | The target user. | 
| NSM.Alerts.Target.risk | String | The target risk. | 
| NSM.Alerts.Target.networkObject | Unknown | The target network object. | 
| NSM.Alerts.MalwareFile.fileName | String | The name of the malware file. | 
| NSM.Alerts.MalwareFile.fileHash | String | The file hash of the malware file. | 
| NSM.Alerts.MalwareFile.fileSHA1Hash | String | The malware file SHA1 hash. | 
| NSM.Alerts.MalwareFile.fileSHA256Hash | Unknown | The file SHA256 hash of the malware file. | 
| NSM.Alerts.MalwareFile.malwareName | String | The name of the malware. | 
| NSM.Alerts.MalwareFile.malwareConfidence | String | Malware confidence. | 
| NSM.Alerts.MalwareFile.engine | String | Malware file engine. | 
| NSM.Alerts.MalwareFile.engineId | Number | Malware file engine ID. | 
| NSM.Alerts.MalwareFile.size | Unknown | The Malware file size. | 
| NSM.Alerts.MalwareFile.description | Unknown | Malware file description. | 
| NSM.Alerts.MalwareFile.additionalReference | Unknown | Malware file additional reference. | 
| NSM.Alerts.MalwareFile.cveId | Unknown | Malware File CVE ID. | 
| NSM.Alerts.endpointExcutable.name | String | Endpoint executable name. | 
| NSM.Alerts.endpointExcutable.hash | String | Endpoint executable hash. | 
| NSM.Alerts.endpointExcutable.malwareConfidence | String | Endpoint executable malware confidence. | 
| NSM.Alerts.detection.managerId | Number | Manager ID. | 
| NSM.Alerts.detection.manager | Unknown | The detection manager. | 
| NSM.Alerts.detection.domain | String | Detection domain. | 
| NSM.Alerts.detection.device | String | Detection device. | 
| NSM.Alerts.detection.deviceId | String | Detection device ID. | 
| NSM.Alerts.detection.interface | String | Detection interface. | 
| NSM.Alerts.Application | String | The application associated with the alert. | 
| NSM.Alerts.layer7Data | String | Layer 7 information. | 
| NSM.Alerts.EventResult | String | Event result. | 
| NSM.Alerts.SensorID | String | Sensor ID. | 

#### Command example
```!nsm-update-alerts state=Unacknowledged new_state=Acknowledged 'time_period': 'CUSTOM', 'start_time': '12/17/2000 14:14:22', 'end_time': '12/28/2022 00:26:45'```
#### Context Example
```json
{
    "NSM": {
        "Alerts": [
            {
                "Application": "HTTP",
                "Assignee": "",
                "Attack": {
                    "attackCategory": "Exploit",
                    "btp": "Medium",
                    "nspId": "0x00000000"
                },
                "Attacker": {
                    "country": null,
                    "hostName": "",
                    "ipAddrs": "1.1.1.1",
                    "networkObject": null,
                    "os": null,
                    "port": 22222,
                    "proxyIP": "",
                    "risk": "Disabled",
                    "user": null,
                    "vmName": null
                },
                "CreatedTime": "Dec 17, 2018 21:06:21",
                "Event": {
                    "alertId": "3333333333333333333",
                    "attackCount": 1,
                    "device": "VVVV1",
                    "direction": "Outbound",
                    "domain": "/My Domain",
                    "interface": "1-2",
                    "relevance": "Unknown",
                    "result": "Inconclusive",
                    "time": "Dec 17, 2018 21:06:21"
                },
                "EventResult": "Inconclusive",
                "ID": "3333333333333333333",
                "MalwareFile": {
                    "additionalReference": null,
                    "cveId": null,
                    "description": null,
                    "engine": "",
                    "engineId": 0,
                    "fileHash": "",
                    "fileName": "",
                    "malwareConfidence": "",
                    "malwareName": "",
                    "size": null
                },
                "Name": "HTTP: vulnerability",
                "SensorID": "4444",
                "Target": {
                    "country": null,
                    "hostName": "",
                    "ipAddrs": "2.2.2.2",
                    "networkObject": null,
                    "os": null,
                    "port": 80,
                    "proxyIP": "",
                    "risk": "Disabled",
                    "user": null,
                    "vmName": null
                },
                "State": "Acknowledged",
                "attackSeverity": "High",
                "detection": {
                    "device": "VVVV1",
                    "deviceId": "4444",
                    "domain": "/My Domain",
                    "interface": "1-2",
                    "manager": null,
                    "managerId": 0
                },
                "endpointExcutable": {
                    "hash": "",
                    "malwareConfidence": "",
                    "name": ""
                },
                "layer7Data": "HTTP Request Method: GET",
                "uniqueAlertId": "1212121212121212121"
            },
            {
                "Application": "WebDAV",
                "Assignee": "",
                "Attack": {
                    "attackCategory": "Exploit",
                    "btp": "Low",
                    "nspId": "0x00000000"
                },
                "Attacker": {
                    "country": null,
                    "hostName": "",
                    "ipAddrs": "1.1.1.1",
                    "networkObject": null,
                    "os": null,
                    "port": 11111,
                    "proxyIP": "",
                    "risk": "---",
                    "user": null,
                    "vmName": null
                },
                "CreatedTime": "Dec 17, 2018 21:04:21",
                "Event": {
                    "alertId": "5555555555555555555",
                    "attackCount": 1,
                    "device": "VVVV1",
                    "direction": "Inbound",
                    "domain": "/My Dmain",
                    "interface": "1-2",
                    "relevance": "Unknown",
                    "result": "Inconclusive",
                    "time": "Dec 17, 2018 21:04:21"
                },
                "EventResult": "Inconclusive",
                "ID": "5555555555555555555",
                "MalwareFile": {
                    "additionalReference": null,
                    "cveId": null,
                    "description": null,
                    "engine": "",
                    "engineId": 0,
                    "fileHash": "",
                    "fileName": "",
                    "malwareConfidence": "",
                    "malwareName": "",
                    "size": null
                },
                "Name": "HTTP: IIS 6.0 (CVE-2017-7269)",
                "SensorID": "4444",
                "Target": {
                    "country": null,
                    "hostName": "",
                    "ipAddrs": "2.2.2.2",
                    "networkObject": null,
                    "os": null,
                    "port": 80,
                    "proxyIP": "",
                    "risk": "---",
                    "user": null,
                    "vmName": null
                },
                "alertState": "Acknowledged",
                "attackSeverity": "High",
                "detection": {
                    "device": "VVVV1",
                    "deviceId": "4444",
                    "domain": "/My Domain",
                    "interface": "1-2",
                    "manager": null,
                    "managerId": 0
                },
                "endpointExcutable": {
                    "hash": "",
                    "malwareConfidence": "",
                    "name": ""
                },
                "layer7Data": "HTTP Request Method: PROPFIND",
                "uniqueAlertId": "2323232323232323232"
            }
        ]
    }
}
```

#### Human Readable Output

>### Updated Alerts list. Showing 2 of 20

>|ID|Name|Severity|State|
>|---|---|---|---|
>| 3333333333333333333 | HTTP: vulnerability | High | Acknowledged |
>| 5555555555555555555 | HTTP: IIS 6.0 (CVE-2017-7269) | High | Acknowledged |


### nsm-list-pcap-file
***
Retrieves the list of captured PCAP files.


#### Base Command

`nsm-list-pcap-file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sensor_id | The ID of the sensor. To get the sensor_id, use the !nsm-get-sensors command. | Required | 
| limit | The maximum number of records to return. Default is 50. | Optional | 
| page | The specific result page to display. The default is 1. | Optional | 
| page_size | The number of records in a page. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| NSM.PcapFile | string | PCAP file name. | 

#### Command example
```!nsm-update-alerts state=Unacknowledged new_state=Acknowledged 'time_period': 'CUSTOM', 'start_time': '12/17/2000 14:14:22', 'end_time': '12/28/2022 00:26:45'```
#### Context Example
```json
{
    "NSM": {
        "PcapFile": [
                      {
              "files":["capture_Mon_Aug_18_16_12_49_IST_2014.pcap", "capture_Mon_Aug_18_16_12_55_IST_2014.pcap"]
            }
        ]
    }
}
```

#### Human Readable Output

>### PCAP files List

>|FileName|
>|---|
>| capture_Mon_Aug_18_16_12_49_IST_2014.pcap |
>| capture_Mon_Aug_18_16_12_55_IST_2014.pcap |

### nsm-export-pcap-file
***
Exports the captured PCAP file.


#### Base Command

`nsm-export-pcap-file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sensor_id | The ID of the sensor. To get the sensor_id, use the command !nsm-get-sensors. | Required | 
| file_name | The name of the wanted file. To get the file_name, use the command !nsm-list-pcap-file. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| InfoFile.Name | string | File name. | 
| InfoFile.EntryID | string | The entry ID of the report. | 
| InfoFile.Size | number | File size. | 
| InfoFile.Type | string | File type, e.g., "PE". | 
| InfoFile.Info | string | Basic information about the file. | 

#### Command example
```!nsm-export-pcap-file sensor_id=1003 file_name=Dummy Device Name-PacketCapture-2022-12-21_16-25-52.pcap```

#### Human Readable Output
There isn't a human readable.


## Breaking changes from the previous version of this integration - McAfee NSM v2
The following sections list the changes in this version.


### Arguments
#### The following arguments were removed in this version:

In the *nsm-get-sensors* command:
* *domainID* - this argument was replaced by domain_id.

In the *nsm-get-domains* command:
* *domain* - this argument was replaced by domain_id.

#### The behavior of the following arguments was changed:

In the *nsm-get-alerts* command:
* *time_period* - The default value changed to 'LAST_7_DAYS'.
* *domain_id* - The default value changed to 0.

In the *nsm-get-alert-details* command:
* *sensor_id* - Is now required.
### nsm-list-domain-device

***
List the devices related to a given domain.

#### Base Command

`nsm-list-domain-device`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain_id | The ID of the domain. To get the domain_id, use the !nsm-get-domains command. | Required | 
| limit | The maximum number of devices to return. | Optional | 
| all_results | Return all devices related to the given domain. Possible values are: yes, no. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| NSM.Device.ContactInformation | string | The contact information of the device. | 
| NSM.Device.DeviceId | number | The id of the device. | 
| NSM.Device.DeviceName | string | The name of the device. | 
| NSM.Device.DeviceType | string | The type of the device. | 
| NSM.Device.Location | string | The location of the device. | 
| NSM.Device.UpdatingMode | string | The updating mode of the device. | 

#### Command example
```!nsm-list-domain-device domain_id=0```
#### Context Example
```json
{
    "NSM": {
        "Device": [
            {
                "ContactInformation": null,
                "DeviceId": 1003,
                "DeviceName": "Dummy Device Name",
                "DeviceType": "IPS_NAC_SENSOR",
                "Location": null,
                "UpdatingMode": "ONLINE"
            }
        ]
    }
}
```

#### Human Readable Output

>### Domain devices List
>|DeviceId|DeviceName|DeviceType|UpdatingMode|
>|---|---|---|---|
>| 1003 | Dummy Device Name | IPS_NAC_SENSOR | ONLINE |


### nsm-list-device-interface

***
List the interfaces related to a given device.

#### Base Command

`nsm-list-device-interface`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain_id | The ID of the domain. To get the domain_id, use the !nsm-get-domains command. | Required | 
| device_id | The ID of the device. To get the device ID, use the !nsm-list-domain-device command. | Required | 
| limit | The maximum number of interfaces to return. | Optional | 
| all_results | Return all interfaces related to the given device. Possible values are: yes, no. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| NSM.Interface.InterfaceId | number | The id of the interface. | 
| NSM.Interface.InterfaceName | Unknown | The name of the interface. | 
| NSM.Interface.InterfaceType | string | The type of the interface. | 

#### Command example
```!nsm-list-device-interface device_id=1003 domain_id=0```
#### Context Example
```json
{
    "NSM": {
        "Interface": [
            {
                "InterfaceId": 102,
                "InterfaceName": "5-6",
                "InterfaceType": "Dedicated"
            },
            {
                "InterfaceId": 103,
                "InterfaceName": "3-4",
                "InterfaceType": "Dedicated"
            },
            {
                "InterfaceId": 104,
                "InterfaceName": "1-2",
                "InterfaceType": "Dedicated"
            }
        ]
    }
}
```

#### Human Readable Output

>### Device interfaces List
>|InterfaceId|InterfaceName|InterfaceType|
>|---|---|---|
>| 102 | 5-6 | Dedicated |
>| 103 | 3-4 | Dedicated |
>| 104 | 1-2 | Dedicated |


### nsm-list-device-policy

***
List all the policies assigned to a domain or a specific device.

#### Base Command

`nsm-list-device-policy`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain_id | The ID of the domain. To get the domain_id, use the !nsm-get-domains command. | Required | 
| device_id | The ID of the device. To get the device ID, use the !nsm-list-domain-device command. | Optional | 
| limit | The maximum number of policies to return. | Optional | 
| all_results | Return all policies assigned to a domain or a specific device. Possible values are: yes, no. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| NSM.DevicePolicy.DeviceName | string | The name of the device. | 
| NSM.DevicePolicy.AtdUserForInboundATDAnalysis | Unknown |  | 
| NSM.DevicePolicy.InterfaceName | string | The name of the interface. | 
| NSM.DevicePolicy.FirewallPolicyLast | Unknown |  | 
| NSM.DevicePolicy.ReconnaissancePolicy | Unknown |  | 
| NSM.DevicePolicy.PolicyGroup | Unknown |  | 
| NSM.DevicePolicy.AtdUserForOutboundATDAnalysis | Unknown |  | 
| NSM.DevicePolicy.DeviceId | number | The id of the device. | 
| NSM.DevicePolicy.AdvancedMalwareOutboundPolicy | Unknown |  | 
| NSM.DevicePolicy.QosInboundPolicy | Unknown |  | 
| NSM.DevicePolicy.ConnectionLimitingPolicy | Unknown |  | 
| NSM.DevicePolicy.QosOutboundPolicy | Unknown |  | 
| NSM.DevicePolicy.ProtectionOptionsPolicy | Unknown |  | 
| NSM.DevicePolicy.AdvancedMalwareInboundPolicy | Unknown |  | 
| NSM.DevicePolicy.QosOutboundRateLimitingProfile | Unknown |  | 
| NSM.DevicePolicy.IpsPolicy | Unknown |  | 
| NSM.DevicePolicy.QosInboundRateLimitingProfile | Unknown |  | 
| NSM.DevicePolicy.FirewallPolicyFirst | Unknown |  | 

#### Command example
```!nsm-list-device-policy domain_id=0```
#### Context Example
```json
{
    "NSM": {
        "DevicePolicy": [
            {
                "AdvancedMalwareInboundPolicy": null,
                "AdvancedMalwareOutboundPolicy": null,
                "AtdUserForInboundATDAnalysis": null,
                "AtdUserForOutboundATDAnalysis": null,
                "ConnectionLimitingPolicy": null,
                "DeviceId": 1003,
                "DeviceName": "Dummy Device Name",
                "FirewallPolicy": null,
                "FirewallPolicyFirst": "Test",
                "FirewallPolicyLast": null,
                "FirewallPortPolicy": null,
                "InterfaceId": 0,
                "InterfaceName": null,
                "IpsPolicy": null,
                "PolicyGroup": null,
                "ProtectionOptionsPolicy": null,
                "QosInboundPolicy": null,
                "QosInboundRateLimitingProfile": null,
                "QosOutboundPolicy": null,
                "QosOutboundRateLimitingProfile": null,
                "ReconnaissancePolicy": null
            }
        ]
    }
}
```

#### Human Readable Output

>### Device policy List
>|DeviceId|DeviceName|FirewallPolicyFirst|InterfaceId|
>|---|---|---|---|
>| 1003 | Dummy Device Name | Test | 0 |


### nsm-list-interface-policy

***
List all the policies assigned to all interfaces or a specific interface.

#### Base Command

`nsm-list-interface-policy`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain_id | The ID of the domain. To get the domain_id, use the !nsm-get-domains command. | Required | 
| interface_id | The ID of the interface. To get the interface ID, use the !nsm-list-device-interface command. | Optional | 
| limit | The maximum number of policies to return. | Optional | 
| all_results | Return all policies assigned to all interfaces or a specific interface. Possible values are: yes, no. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| NSM.InterfacePolicy.DeviceName | string | The name of the device. | 
| NSM.InterfacePolicy.AtdUserForInboundATDAnalysis | Unknown |  | 
| NSM.InterfacePolicy.InterfaceName | string | The name of the interface. | 
| NSM.InterfacePolicy.FirewallPolicyLast | Unknown |  | 
| NSM.InterfacePolicy.ReconnaissancePolicy | Unknown |  | 
| NSM.InterfacePolicy.PolicyGroup | Unknown |  | 
| NSM.InterfacePolicy.AtdUserForOutboundATDAnalysis | Unknown |  | 
| NSM.InterfacePolicy.DeviceId | number | The id of the device. | 
| NSM.InterfacePolicy.AdvancedMalwareOutboundPolicy | Unknown |  | 
| NSM.InterfacePolicy.QosInboundPolicy | Unknown |  | 
| NSM.InterfacePolicy.ConnectionLimitingPolicy | Unknown |  | 
| NSM.InterfacePolicy.QosOutboundPolicy | Unknown |  | 
| NSM.InterfacePolicy.ProtectionOptionsPolicy | Unknown |  | 
| NSM.InterfacePolicy.AdvancedMalwareInboundPolicy | Unknown |  | 
| NSM.InterfacePolicy.QosOutboundRateLimitingProfile | Unknown |  | 
| NSM.InterfacePolicy.IpsPolicy | Unknown |  | 
| NSM.InterfacePolicy.QosInboundRateLimitingProfile | Unknown |  | 
| NSM.InterfacePolicy.FirewallPolicyFirst | Unknown |  | 

#### Command example
```!nsm-list-interface-policy domain_id=0```
#### Context Example
```json
{
    "NSM": {
        "InterfacePolicy": [
            {
                "AdvancedMalwareInboundPolicy": null,
                "AdvancedMalwareOutboundPolicy": null,
                "AtdUserForInboundATDAnalysis": null,
                "AtdUserForOutboundATDAnalysis": null,
                "ConnectionLimitingPolicy": null,
                "DeviceId": 1003,
                "DeviceName": "Dummy Device Name",
                "FirewallPolicy": "a policy",
                "FirewallPolicyFirst": null,
                "FirewallPolicyLast": null,
                "FirewallPortPolicy": null,
                "InterfaceId": 104,
                "InterfaceName": "1-2",
                "IpsPolicy": "Default Prevention",
                "PolicyGroup": null,
                "ProtectionOptionsPolicy": null,
                "QosInboundPolicy": null,
                "QosInboundRateLimitingProfile": null,
                "QosOutboundPolicy": null,
                "QosOutboundRateLimitingProfile": null,
                "ReconnaissancePolicy": null
            },
            {
                "AdvancedMalwareInboundPolicy": null,
                "AdvancedMalwareOutboundPolicy": null,
                "AtdUserForInboundATDAnalysis": null,
                "AtdUserForOutboundATDAnalysis": null,
                "ConnectionLimitingPolicy": null,
                "DeviceId": 1003,
                "DeviceName": "Dummy Device Name",
                "FirewallPolicy": null,
                "FirewallPolicyFirst": null,
                "FirewallPolicyLast": null,
                "FirewallPortPolicy": null,
                "InterfaceId": 103,
                "InterfaceName": "3-4",
                "IpsPolicy": "testing",
                "PolicyGroup": null,
                "ProtectionOptionsPolicy": null,
                "QosInboundPolicy": null,
                "QosInboundRateLimitingProfile": null,
                "QosOutboundPolicy": null,
                "QosOutboundRateLimitingProfile": null,
                "ReconnaissancePolicy": null
            },
            {
                "AdvancedMalwareInboundPolicy": null,
                "AdvancedMalwareOutboundPolicy": null,
                "AtdUserForInboundATDAnalysis": null,
                "AtdUserForOutboundATDAnalysis": null,
                "ConnectionLimitingPolicy": null,
                "DeviceId": 1003,
                "DeviceName": "Dummy Device Name",
                "FirewallPolicy": null,
                "FirewallPolicyFirst": null,
                "FirewallPolicyLast": null,
                "FirewallPortPolicy": null,
                "InterfaceId": 102,
                "InterfaceName": "5-6",
                "IpsPolicy": "testing",
                "PolicyGroup": null,
                "ProtectionOptionsPolicy": null,
                "QosInboundPolicy": null,
                "QosInboundRateLimitingProfile": null,
                "QosOutboundPolicy": null,
                "QosOutboundRateLimitingProfile": null,
                "ReconnaissancePolicy": null
            }
        ]
    }
}
```

#### Human Readable Output

>### Interface policy List
>|DeviceId|DeviceName|FirewallPolicy|InterfaceId|InterfaceName|IpsPolicy|
>|---|---|---|---|---|---|
>| 1003 | Dummy Device Name | a policy | 104 | 1-2 | Default Prevention |
>| 1003 | Dummy Device Name |  | 103 | 3-4 | testing |
>| 1003 | Dummy Device Name |  | 102 | 5-6 | testing |


### nsm-assign-device-policy

***
Assign a policy to a specific device.

#### Base Command

`nsm-assign-device-policy`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain_id | The ID of the domain. To get the domain_id, use the !nsm-get-domains command. | Required | 
| device_id | The ID of the device. To get the device ID, use the !nsm-list-domain-device command. | Required | 
| pre_firewall_policy_name | The name of the policy to add to the top of the rule order and evaluated first. To get the policies, use the !nsm-list-domain-firewall-policy command. | Optional | 
| post_firewall_policy_name | The name of the policy to add to the end of the rule order and evaluated last. To get the policies, use the !nsm-list-domain-firewall-policy command. | Optional | 

#### Context Output

There is no context output for this command.
#### Command example
```!nsm-assign-device-policy device_id=1003 domain_id=0 pre_firewall_policy_name=Test```
#### Human Readable Output

>Policy assigned successfully.
### nsm-assign-interface-policy

***
Assign a policy to a specific interface.

#### Base Command

`nsm-assign-interface-policy`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain_id | The ID of the domain. To get the domain_id, use the !nsm-get-domains command. | Required | 
| interface_id | The ID of the interface. To get the interface ID, use the !nsm-list-device-interface command. | Required | 
| firewall_policy_name | The name of the firewall policy that will be connected to the interface. To get the policy name, use the !nsm-list-domain-firewall-policy command. | Optional | 
| firewall_port_policy_name | The name of the firewall policy that will be connected to the interface/port. To get the policy name, use the !nsm-list-domain-firewall-policy command. | Optional | 
| ips_policy_name | The name of the IPS policy that will be connected to the interface. To get the policy name, use the !nsm-get-ips-policies command. | Optional | 
| custom_policy_json | A Json with firewall policy types as keys and firewall policy names as values. (e.g `{"advancedMalwareInboundPolicy":"test"}`). To see all the firewall policy options visit this page https://docs.trellix.com/bundle/network-security-platform-9.1.x-manager-api-reference-guide/page/GUID-5E5F9514-935F-4F16-B2F0-C48E465A4E7C.html. | Optional | 

#### Context Output

There is no context output for this command.
#### Command example
```!nsm-assign-interface-policy domain_id=0 interface_id=102 ips_policy_name=testing```
#### Human Readable Output

>Policy assigned successfully.
### nsm-get-device-configuration

***
Provides configuration information of a given device.

#### Base Command

`nsm-get-device-configuration`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | The ID of the device. To get the device ID, use the !nsm-get-sensors command. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| NSM.DeviceConfiguration.IsSSLConfigurationChanged | boolean | Was the ssl configuration changed. | 
| NSM.DeviceConfiguration.DeviceName | string | The name of the device. | 
| NSM.DeviceConfiguration.IsConfigurationChanged | boolean | Was the configuration changed. | 
| NSM.DeviceConfiguration.IsMalwareConfigurationChanged | boolean |  | 
| NSM.DeviceConfiguration.LastUpdateTime | Unknown |  | 
| NSM.DeviceConfiguration.IsGAMUpdateRequired | boolean |  | 
| NSM.DeviceConfiguration.IsSignatureSetConfigurationChanged | Unknown |  | 
| NSM.DeviceConfiguration.IsSigsetConfigPushRequired | boolean |  | 
| NSM.DeviceConfiguration.IsBotnetPushRequired | boolean |  | 
| NSM.DeviceConfiguration.IsPolicyConfigurationChanged | boolean |  | 
| NSM.DeviceConfiguration.IsSSLPushRequired | boolean |  | 
| NSM.DeviceConfiguration.IsGloablPolicyConfigurationChanged | boolean |  | 
| NSM.DeviceConfiguration.IsBotnetConfigurationChanged | boolean |  | 

#### Command example
```!nsm-get-device-configuration device_id=1003```
#### Context Example
```json
{
    "NSM": {
        "DeviceConfiguration": {
            "DeviceName": "Dummy Device Name",
            "IsBotnetConfigurationChanged": false,
            "IsBotnetPushRequired": false,
            "IsConfigurationChanged": true,
            "IsGAMUpdateRequired": false,
            "IsGloablPolicyConfigurationChanged": false,
            "IsMalwareConfigurationChanged": false,
            "IsPolicyConfigurationChanged": false,
            "IsSSLConfigurationChanged": false,
            "IsSSLPushRequired": false,
            "IsSignatureSetConfigurationChanged": false,
            "IsSigsetConfigPushRequired": true,
            "LastUpdateTime": "2023-03-25 20:52:59.600 UTC"
        }
    }
}
```

#### Human Readable Output

>### Device Configuration
>|DeviceName|IsBotnetConfigurationChanged|IsBotnetPushRequired|IsConfigurationChanged|IsGAMUpdateRequired|IsGloablPolicyConfigurationChanged|IsMalwareConfigurationChanged|IsPolicyConfigurationChanged|IsSSLConfigurationChanged|IsSSLPushRequired|IsSignatureSetConfigurationChanged|IsSigsetConfigPushRequired|LastUpdateTime|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| Dummy Device Name | false | false | true | false | false | false | false | false | false | false | true | 2023-03-25 20:52:59.600 UTC |


### nsm-deploy-device-configuration

***
Deploy the pending changes.
 Note: In order to avoid extra run time, it is recommended to deploy only the changes that are pending.
To get the pending changes, use the !nsm-get-device-configuration command.

#### Base Command

`nsm-deploy-device-configuration`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| request_id | This is for the polling to work. not for the user. | Optional | 
| device_id | The ID of the device. To get the device ID, use the !nsm-get-sensors command. | Required | 
| push_ssl_key | Deploy the SSL configuration pending changes. Possible values are: true, false. | Optional | 
| push_gam_updates | Deploy the Gateway Anti-Malware configuration pending changes. Possible values are: true, false. | Optional | 
| push_configuration_signature_set | Deploy the Signature set configuration pending changes. Possible values are: true, false. | Optional | 
| push_botnet | Deploy the Firewall policy description pending changes. Possible values are: true, false. | Optional | 
| interval_in_seconds | The interval between status checks. | Optional | 

#### Context Output

There is no context output for this command.
#### Command example
```!nsm-deploy-device-configuration device_id=1003 push_configuration_signature_set="true" interval_in_seconds=10```
#### Human Readable Output

>
>The current percentage of deployment for 'push_configuration_signature_set' is: 0%
>                
>And the current message is: NA
>
>
>Checking again in 10 seconds...