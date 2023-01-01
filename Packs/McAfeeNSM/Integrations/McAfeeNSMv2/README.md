McAfee Network Security Manager gives you real-time visibility and control over all McAfee intrusion prevention systems deployed across your network.
This integration was integrated and tested with version 9.1 of McAfeeNSMv2

Some changes have been made that might affect your existing content. 
If you are upgrading from a previous of this integration, see [Breaking Changes](#breaking-changes-from-the-previous-version-of-this-integration-mcafee-nsm-v2).

## Configure McAfee NSM v2 on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for McAfee NSM v2.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | URL (for example: https://192.168.0.1:5000) | True |
    | User Name | True |
    | Password | True |
    | Trust any certificate (not secure) | False |
    | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### nsm-list-domain-firewall-policy
***
Gets the list of Firewall Policies defined in a particular domain.


#### Base Command

`nsm-list-domain-firewall-policy`
#### Input

| **Argument Name** | **Description**                                                               | **Required** |
| --- |-------------------------------------------------------------------------------| --- |
| domain_id | The id of the domain. To get the domain_id, use the !nsm-get-domains command. | Required | 
| limit | The maximum number of projects to return. Default is 50.                      | Optional | 
| page | The specific result page to display.                                          | Optional | 
| page_size | The number of records in a page.                                              | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| NSM.Policy.policyId | Number | The id of the policy. | 
| NSM.Policy.policyName | String | Name of the Firewall Policy. | 
| NSM.Policy.domainId | Number | The id of the domain. | 
| NSM.Policy.visibleToChild | Boolean | Is Policy visible to child domains. | 
| NSM.Policy.description | String | Policy Description. | 
| NSM.Policy.isEditable | Boolean | Is Policy editable or not. | 
| NSM.Policy.policyType | String | Policy Type, can be "ADVANCED" or "CLASSIC". | 
| NSM.Policy.policyVersion | Number | Policy version. | 
| NSM.Policy.lastModUser | String | Last User that modified the policy. | 

#### Command example
```!nsm-list-domain-firewall-policy domain_id=0 limit=2```
#### Context Example
```json
{
    "NSM": {
        "Policy": [
            {
                "description": "update policy",
                "domainId": 0,
                "isEditable": true,
                "lastModUser": "user",
                "policyId": 147,
                "policyName": "n",
                "policyType": "ADVANCED",
                "policyVersion": 1,
                "visibleToChild": true
            },
            {
                "description": "hello policy",
                "domainId": 0,
                "isEditable": true,
                "lastModUser": "user",
                "policyId": 140,
                "policyName": "hello",
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
>| 147 | n | 0 | true | update policy | true | ADVANCED | 1 | user        |
>| 140 | hello | 0 | true | hello policy | true | ADVANCED | 1 | user |

### nsm-get-firewall-policy
***
Gets the Firewall Policy details.


#### Base Command

`nsm-get-firewall-policy`
#### Input

| **Argument Name** | **Description**                                                                                                                                                                 | **Required** |
| --- |---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------|
| policy_id | The id of the policy. To get the policy_id, use the !nsm-list-domain-firewall-policy command.                                                                                   | Required     | 
| include_rule_objects | Whether to insert the rule object that are linked to the policy in the context. True- the rule object will bw inserted. False- not inserted. Possible values are: true, false. Default is false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| NSM.Policy.FirewallPolicyId | Number | Unique Firewall Policy ID. | 
| NSM.Policy.Name | String | Policy Name. | 
| NSM.Policy.DomainId | Number | Id of Domain to which this firewall policy belongs to. | 
| NSM.Policy.VisibleToChild | Boolean | Policy visible to Child Domain. | 
| NSM.Policy.Description | String | Firewall Policy Description. | 
| NSM.Policy.LastModifiedTime | Date | Last Modified Time of the Firewall Policy. | 
| NSM.Policy.IsEditable | Boolean | Policy is editable or not. | 
| NSM.Policy.PolicyType | String | Policy Type, can be "Advanced" / "Classic". | 
| NSM.Policy.PolicyVersion | Number | Policy Version. | 
| NSM.Policy.LastModifiedUser | String | Last User that modified the policy. | 
| NSM.Policy.MemberDetails.MemberRuleList.Description | String | Rule Description. | 
| NSM.Policy.MemberDetails.MemberRuleList.Enabled | Boolean | Is Rule Enabled or not | 
| NSM.Policy.MemberDetails.MemberRuleList.Response | String | Action to be performed if the traffic matches this rule. Can be "Scan" / "Drop" / "Deny" / "Ignore" / "Stateless Ignore" / "Stateless Drop" / "Require Authentication". | 
| NSM.Policy.MemberDetails.MemberRuleList.IsLogging | Boolean | Is Logging enabled for this rule. | 
| NSM.Policy.MemberDetails.MemberRuleList.Direction | String | Rule Direction, can be "Inbound" / "Outbound" / "Either". | 
| NSM.Policy.MemberDetails.MemberRuleList.SourceAddressObjectList.RuleObjectId | String | Unique Rule Object ID. | 
| NSM.Policy.MemberDetails.MemberRuleList.SourceAddressObjectList.Name | String | Rule Object Name. | 
| NSM.Policy.MemberDetails.MemberRuleList.SourceAddressObjectList.RuleObjectType | Unknown | Source or Destination Mode. Can be "Endpoint IP V.4" / "Range IP V.4" / "Network IP V.4" / "Endpoint IP V.6" / "Range IP V.6" / "Network IP V.6". | 
| NSM.Policy.MemberDetails.MemberRuleList.DestinationAddressObjectList.RuleObjectId | String | Unique Rule Object ID. | 
| NSM.Policy.MemberDetails.MemberRuleList.DestinationAddressObjectList.Name | String | Rule Object Name. | 
| NSM.Policy.MemberDetails.MemberRuleList.DestinationAddressObjectList.RuleObjectType | Unknown | Source or Destination Mode. Can be "Endpoint IP V.4" / "Range IP V.4" / "Endpoint IP V.6" / "Range IP V.6" / "Network IP V.6". | 
| NSM.Policy.MemberDetails.MemberRuleList.SourceUserObjectList.RuleObjectId | String | Unique Rule Object ID. | 
| NSM.Policy.MemberDetails.MemberRuleList.SourceUserObjectList.Name | String | Rule Object Name. | 
| NSM.Policy.MemberDetails.MemberRuleList.SourceUserObjectList.RuleObjectType | String | Source User. Can be "USER" / "USER_GROUP". | 
| NSM.Policy.MemberDetails.MemberRuleList.ServiceObjectList.RuleObjectId | String | Unique Service Rule Object ID. | 
| NSM.Policy.MemberDetails.MemberRuleList.ServiceObjectList.Name | String | Rule Object Name. | 
| NSM.Policy.MemberDetails.MemberRuleList.ServiceObjectList.RuleObjectType | Unknown | Service/ Application Mode. Can be "APPLICATION" / "APPLICATION_GROUP" / "APPLICATION_ON_CUSTOM_PORT" / "SERVICE" / "SERVICE_GROUP". | 
| NSM.Policy.MemberDetails.MemberRuleList.ServiceObjectList.ApplicationType | Unknown | Application Type. Can be "DEFAULT" / "CUSTOM". | 
| NSM.Policy.MemberDetails.MemberRuleList.ApplicationObjectList.RuleObjectId | String | Unique Service Rule Object ID. | 
| NSM.Policy.MemberDetails.MemberRuleList.ApplicationObjectList.Name | String | Rule Object Name. | 
| NSM.Policy.MemberDetails.MemberRuleList.ApplicationObjectList.RuleObjectType | Unknown | Service/ Application Mode. Can be "APPLICATION" / "APPLICATION_GROUP" / "APPLICATION_ON_CUSTOM_PORT" / "SERVICE" / "SERVICE_GROUP". | 
| NSM.Policy.MemberDetails.MemberRuleList.ApplicationObjectList.ApplicationType | Unknown | Application Type. Can be "DEFAULT" / "CUSTOM". | 
| NSM.Policy.MemberDetails.MemberRuleList.TimeObjectList.RuleObjectId | String | Unique Service Rule Object ID. | 
| NSM.Policy.MemberDetails.MemberRuleList.TimeObjectList.Name | String | Rule Object Name. | 
| NSM.Policy.MemberDetails.MemberRuleList.TimeObjectList.RuleObjectType | Unknown | Time Mode. Can be "FINITE_TIME_PERIOD" / "RECURRING_TIME_PERIOD" / "RECURRING_TIME_PERIOD_GROUP". | 

#### Command example
```!nsm-get-firewall-policy policy_id=147```
#### Context Example
```json
{
    "NSM": {
        "Policy": {
            "Description": "update policy",
            "DomainId": 0,
            "FirewallPolicyId": 147,
            "IsEditable": true,
            "LastModifiedTime": "2022-12-26 05:37:46",
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
            "Name": "n",
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
>| n | update policy | true | true | ADVANCED | 1 | user | 2022-12-26 05:37:46 |


### nsm-create-firewall-policy
***
Adds a new Firewall Policy and Access Rules. You have to provide at lease one of the source/destination object. If you provide one of the source/destination fields, you must provide the other one as well.


#### Base Command

`nsm-create-firewall-policy`
#### Input

| **Argument Name** | **Description**                                                                                                                                                                                                                                   | **Required** |
| --- |---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------| --- |
| domain | The id of the domain. To get the domain id, use the !nsm-get-domains command.                                                                                                                                                                     | Required | 
| name | The policy name.                                                                                                                                                                                                                                  | Required | 
| visible_to_child | Will the policy be visible to the child domain. Possible values are: yes, no. Default is yes.                                                                                                                           | Optional | 
| description | The description of the policy.                                                                                                                                                                                                                    | Required | 
| is_editable | If the policy is editable or not. Possible values are: yes, no.                                                                                                                                                                                   | Required | 
| policy_type | The type of the policy. Possible values are: Advanced, Classic.                                                                                                                                                                                   | Required | 
| rule_description | The rule description.                                                                                                                                                                                                                             | Required | 
| response | Action to be performed if the traffic matches this rule. Possible values are: Scan, Drop, Deny, Ignore, Stateless Ignore, Stateless Drop, Require Authentication.                                                                                 | Required | 
| rule_enabled | Is Rule Enabled or not. Possible values are: yes, no. Default is yes.                                                                                                                                                                             | Optional | 
| direction | The direction of the rule. Possible values are: Inbound, Outbound, Either.                                                                                                                                                                        | Required | 
| source_rule_object_id | The id of the rule that connected to the policy. To get the rule_object_id use the command '!nsm-list-domain-rule-object'.                                                                                                                        | Optional | 
| source_rule_object_type | The type of the rule that connected to the policy. To get the rule_object_type use the command '!nsm-list-domain-rule-object'. Possible values are: Endpoint IP V.4, Range IP V.4, Network IP V.4, Endpoint IP V.6, Range IP V.6, Network IP V.6. | Optional | 
| destination_rule_object_id | The id of the rule that connected to the policy. To get the rule_object_id use the command '!nsm-list-domain-rule-object'.                                                                                                                        | Optional | 
| destination_rule_object_type | The type of the rule that connected to the policy. To get the rule_object_type use the command '!nsm-list-domain-rule-object'. Possible values are: Endpoint IP V.4, Range IP V.4, Network IP V.4, Endpoint IP V.6, Range IP V.6, Network IP V.6. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| NSM.Policy.createdResourceId | Number | The id of the newly created firewall policy. | 

#### Command example
```!nsm-create-firewall-policy domain=0 name=policy visible_to_child=yes description="a new policy" is_editable=yes policy_type=Advanced response=Scan rule_description="Test Member Rule" direction=Inbound destination_rule_object_id=111 destination_rule_object_type="Range IP V.4"```

#### Context Example
```json
{
    "NSM": {
        "Policy": {
            "createdResourceId":112
        }
    }
}
```

#### Human Readable Output
```The firewall policy no.112 was created successfully```


### nsm-update-firewall-policy
***
Updates the Firewall Policy details. If the argument is_overwrite=true, then the new values of the provided addresses will replace the existing values else the addresses will be added to them. If you want to delete a rule than enter is_overwrite=true and the relevant rule_id=-1. If is_overwrite=true and there is no value in one of the rules (source or destination) their value will be as before. If is_overwrite=true then at least one of the rules (source or destination) must be provided.


#### Base Command

`nsm-update-firewall-policy`
#### Input

| **Argument Name** | **Description**                                                                                                                                                                                                                                  | **Required** |
| --- |--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------| --- |
| policy_id | The id of the policy. To get the policy id, use the !nsm-list-domain-firewall-policy.                                                                                                                                                            | Required | 
| domain | The id of the domain. To get the domain id, use the !nsm-get-domains command.                                                                                                                                                                    | Optional | 
| name | The policy name.                                                                                                                                                                                                                                 | Optional | 
| visible_to_child | Will the policy be visible to the child domain. Possible values are: yes, no. Default is yes.                                                                                                                                              | Optional | 
| description | The description of the policy.                                                                                                                                                                                                                   | Optional | 
| is_editable | If the policy is editable or not. Possible values are: yes, no.                                                                                                                                                                                  | Optional | 
| policy_type | The type of the policy. Possible values are: Advanced, Classic.                                                                                                                                                                                  | Optional | 
| rule_description | The rule description.                                                                                                                                                                                                                            | Optional | 
| response | Action to be performed if the traffic matches this rule. Possible values are: Scan, Drop, Deny, Ignore, Stateless Ignore, Stateless Drop, Require Authentication.                                                                                | Optional | 
| rule_enabled | Is Rule Enabled or not. Possible values are: yes, no. Default is yes.                                                                                                                                                                            | Optional | 
| direction | The direction of the rule. Possible values are: Inbound, Outbound, Either.                                                                                                                                                                       | Optional | 
| source_rule_object_id | The id of the rule that connected to the policy. To get the rule_object_id use the command '!nsm-list-domain-rule-object'.                                                                                                                       | Optional | 
| source_rule_object_type | The type of the rule that connected to the policy. To get the rule_object_type use the command '!nsm-list-domain-rule-object'. Possible values are: Endpoint IP V.4, Range IP V.4, Network IP V.4, Endpoint IP V.6, Range IP V.6, Network IP V.6. | Optional | 
| destination_rule_object_id | The id of the rule that connected to the policy. To get the rule_object_id use the command '!nsm-list-domain-rule-object'.                                                                                                                       | Optional | 
| destination_rule_object_type | The type of the rule that connected to the policy. To get the rule_object_type use the command '!nsm-list-domain-rule-object'. Possible values are: Endpoint IP V.4, Range IP V.4, Network IP V.4, Endpoint IP V.6, Range IP V.6, Network IP V.6. | Optional | 
| is_overwrite | Will the new addresses that was provided in the update processes will override the current ones or will be added to them. Possible values are: true, false.                                                                                      | Optional | 


#### Context Output

There is no context output for this command.
#### Command example
```!nsm-update-firewall-policy policy_id=147 description="update policy"```
#### Human Readable Output

>The firewall policy no.147 was updated successfully


### nsm-delete-firewall-policy
***
Deletes the specified Firewall Policy.


#### Base Command

`nsm-delete-firewall-policy`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_id | The id of the policy to delete. To get the policy id, use the !nsm-list-domain-firewall-policy. | Required | 


#### Context Output

There is no context output for this command.

#### Command example
```!nsm-delete-firewall-policy policy_id=101```
#### Human Readable Output

>The firewall policy no.101 was deleted successfully


### nsm-list-domain-rule-object
***
Updates the Firewall Policy details.


#### Base Command

`nsm-list-domain-rule-object`
#### Input

| **Argument Name** | **Description**                                                                                                                                           | **Required** |
| --- |-----------------------------------------------------------------------------------------------------------------------------------------------------------| --- |
| domain_id | The id of the domain. To get the domain id, use the !nsm-get-domains command.                                                                             | Required | 
| type | The type of the rule. Possible values are: Endpoint IP V.4, Range IP V.4, Network IP V.4, Endpoint IP V.6, Range IP V.6, Network IP V.6, All. Default is All. | Optional | 
| limit | The maximum number of projects to return. Default is 50.                                                                                                  | Optional | 
| page | The specific result page to display.                                                                                                   | Optional | 
| page_size | The number of records in a page.                                                                                                                          | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| NSM.Rule.ruleobjId | String | The id of the rule object. | 
| NSM.Rule.ruleobjType | String | The type of the rule object. | 
| NSM.Rule.name | String | The name of the rule object. | 
| NSM.Rule.description | String | The description of the rule object. | 
| NSM.Rule.domain | Number | The name of the rule object. | 
| NSM.Rule.visibleToChild | Boolean | Is Rule visible to child domains. | 
| NSM.Rule.hostCriticality | String | The critical level of the host. | 
| NSM.Rule.ApplicationGroup | Unknown | Application Group object, should be defined if ruleobjType is "APPLICATION_GROUP". | 
| NSM.Rule.ApplicationOnCustomPort | Unknown | Application defined on Custom Port object, should be defined if ruleobjType is "APPLICATION_ON_CUSTOM_PORT". | 
| NSM.Rule.FiniteTimePeriod | Unknown | Finite Time Period object, should be defined if ruleobjType is "FINITE_TIME_PERIOD". | 
| NSM.Rule.HostIPv4 | Unknown | Host IPv4 Address object, should be defined if ruleobjType is "HOST_IPV_4". | 
| NSM.Rule.HostIPv6 | Unknown | Host IPv6 Address object, should be defined if ruleobjType is "HOST_IPV_6". | 
| NSM.Rule.HostDNSName | Unknown | Host DNS Name object, should be defined if ruleobjType is "HOST_DNS_NAME". | 
| NSM.Rule.IPv4AddressRange | Unknown | IPv4 Address Range object, should be defined if ruleobjType is "IPV_4_ADDRESS_RANGE". | 
| NSM.Rule.IPv6AddressRange | Unknown | IPv6 Address Range object, should be defined if ruleobjType is "IPV_6_ADDRESS_RANGE". | 
| NSM.Rule.Network_IPV_4 | Unknown | IPv4 Network object, should be defined if ruleobjType is "NETWORK_IPV_4. | 
| NSM.Rule.Network_IPV_6 | String | IPv6 Network object, should be defined if ruleobjType is "NETWORK_IPV_6". | 
| NSM.Rule.NetworkGroup | Unknown | Network Group object, should be defined if ruleobjType is "NETWORK_GROUP". | 
| NSM.Rule.RecurringTimePeriod | Unknown | Recurring Time Period object, should be defined if ruleobjType is "RECURRING_TIME_PERIOD". | 
| NSM.Rule.RecurringTimePeriodGroup | Unknown | Recurring Time Period Group object, should be defined if ruleobjType is "RECURRING_TIME_PERIOD_GROUP". | 
| NSM.Rule.Service | Unknown | Service object, should be defined if ruleobjType is "CUSTOM_SERVICE". | 
| NSM.Rule.ServiceGroup | Unknown | Service Group object, should be defined if ruleobjType is "SERVICE_GROUP". | 
| NSM.Rule.ServiceRange | Unknown | Service Range object, should be defined if ruleobjType is "SERVICE_RANGE". | 
| NSM.Rule.IPv6AddressRange.IPV6RangeList | String | List of IPv6 Address Range. | 
| NSM.Rule.HostIPv6.hostIPv6AddressList | String | HostIPv6 address list. | 
| NSM.Rule.Network_IPV_4.networkIPV4List | String | NetworkIPV4 list. | 
| NSM.Rule.IPv4AddressRange.IPV4RangeList | String | List of IPv4 Address Range. | 
| NSM.Rule.HostIPv4.hostIPv4AddressList | String | HostIPv4 address list. | 
| NSM.Rule.Network_IPV_6.networkIPV6List | String | NetworkIPV6 list. | 

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
Gets the details of a Rule Object.


#### Base Command

`nsm-get-rule-object`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_id | The id of the rule object. To get the rule object id, use the !nsm-list-domain-rule-object. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| NSM.Rule.ruleobjId | String | The id of the rule object. | 
| NSM.Rule.ruleobjType | String | The type of the rule object. | 
| NSM.Rule.name | String | The name of the rule object. | 
| NSM.Rule.description | String | The description of the rule object. | 
| NSM.Rule.domain | Number | The name of the rule object. | 
| NSM.Rule.visibleToChild | Boolean | Is Rule visible to child domains. | 
| NSM.Rule.ApplicationGroup | Unknown | Application Group object, should be defined if ruleobjType is "APPLICATION_GROUP". | 
| NSM.Rule.ApplicationOnCustomPort | Unknown | Application defined on Custom Port object, should be defined if ruleobjType is "APPLICATION_ON_CUSTOM_PORT". | 
| NSM.Rule.FiniteTimePeriod | Unknown | Finite Time Period object, should be defined if ruleobjType is "FINITE_TIME_PERIOD". | 
| NSM.Rule.HostIPv4 | Unknown | Host IPv4 Address object, should be defined if ruleobjType is "HOST_IPV_4". | 
| NSM.Rule.HostIPv6 | Unknown | Host IPv6 Address object, should be defined if ruleobjType is "HOST_IPV_6". | 
| NSM.Rule.HostDNSName | Unknown | Host DNS Name object, should be defined if ruleobjType is "HOST_DNS_NAME". | 
| NSM.Rule.IPv4AddressRange | Unknown | IPv4 Address Range object, should be defined if ruleobjType is "IPV_4_ADDRESS_RANGE". | 
| NSM.Rule.IPv6AddressRange | Unknown | IPv6 Address Range object, should be defined if ruleobjType is "IPV_6_ADDRESS_RANGE". | 
| NSM.Rule.Network_IPV_4 | Unknown | IPv4 Network object, should be defined if ruleobjType is "NETWORK_IPV_4. | 
| NSM.Rule.Network_IPV_6 | String | IPv6 Network object, should be defined if ruleobjType is "NETWORK_IPV_6". | 
| NSM.Rule.NetworkGroup | Unknown | Network Group object, should be defined if ruleobjType is "NETWORK_GROUP". | 
| NSM.Rule.RecurringTimePeriod | Unknown | Recurring Time Period object, should be defined if ruleobjType is "RECURRING_TIME_PERIOD". | 
| NSM.Rule.RecurringTimePeriodGroup | Unknown | Recurring Time Period Group object, should be defined if ruleobjType is "RECURRING_TIME_PERIOD_GROUP". | 
| NSM.Rule.Service | Unknown | Service object, should be defined if ruleobjType is "CUSTOM_SERVICE". | 
| NSM.Rule.ServiceGroup | Unknown | Service Group object, should be defined if ruleobjType is "SERVICE_GROUP". | 
| NSM.Rule.ServiceRange | Unknown | Service Range object, should be defined if ruleobjType is "SERVICE_RANGE". | 
| NSM.Rule.IPv6AddressRange.IPV6RangeList | String | List of IPv6 Address Range. | 
| NSM.Rule.HostIPv6.hostIPv6AddressList | String | HostIPv6 address list. | 
| NSM.Rule.Network_IPV_4.networkIPV4List | String | NetworkIPV4 list. | 
| NSM.Rule.Network_IPV_6.networkIPV6List | String | NetworkIPV6 list. | 
| NSM.Rule.IPv4AddressRange.IPV4RangeList | String | List of IPv4 Address Range. | 
| NSM.Rule.HostIPv4.hostIPv4AddressList | String | HostIPv4 address list. | 

#### Command example
```!nsm-get-rule-object rule_id=133```
#### Context Example
```json
{
    "NSM": {
        "Rule": {
            "ruleobjId": "133",
            "ruleobjType": "IPV_4_ADDRESS_RANGE",
            "name": "ruleo",
            "description": null,
            "domain": 0,
            "visibleToChild": true,
            "hostCriticality": null,
            "ApplicationGroup": null,
            "ApplicationOnCustomPort": null,
            "FiniteTimePeriod": null,
            "HostIPv4": null,
            "HostIPv6": null,
            "HostDNSName": null,
            "IPv4AddressRange": {
                "IPV4RangeList": [
                    {
                        "FromAddress": "1.1.1.1",
                        "ToAddress": "2.2.2.2"
                    }
                ]
            },
            "IPv6AddressRange": null,
            "Network_IPV_4": null,
            "Network_IPV_6": null,
            "NetworkGroup": null,
            "RecurringTimePeriod": null,
            "RecurringTimePeriodGroup": null,
            "Service": null,
            "ServiceGroup": null,
            "ServiceRange": null
        }
    }
}
```

#### Human Readable Output

>### List of Rule Objects
>|RuleId|Name|Description|VisibleToChild|RuleType|Addresses|
>|---|---|---|---|---|---|
>| 133 | ruleo | None | true | IPV_4_ADDRESS_RANGE | 1.1.1.1 - 2.2.2.2 |

### nsm-create-rule-object
***
Adds a new Rule Object.


#### Base Command

`nsm-create-rule-object`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | The id of the domain. To get the domain id, use the !nsm-get-domains command. | Required | 
| rule_object_type | The type of the rule. If the type is “Endpoint IP V.X” or “Network IP V.X” than the argument “address_ip_v.X” must contain a value. If the type is “Range IP V.X” =&gt; the arguments “from_address_ip_v.X” and “to_address_ip_v.X” must contain a value. Possible values are: Endpoint IP V.4, Range IP V.4, Network IP V.4, Endpoint IP V.6, Range IP V.6, Network IP V.6. | Required | 
| name | The rule object name. | Required | 
| visible_to_child | Will the rule object be visible to the child domain. Possible values are: yes, no. Default is yes. | Optional | 
| description | The description of the rule object. | Optional | 
| address_ip_v.4 | List of IPv4 host Address, separated by comma. | Optional | 
| from_address_ip_v.4 | Start IPv4 Range. | Optional | 
| to_address_ip_v.4 | End IPv4 Range. | Optional | 
| address_ip_v.6 | List of IPv6 host Address, separated by comma. | Optional | 
| from_address_ip_v.6 | Start IPv6 Range. | Optional | 
| to_address_ip_v.6 | End IPv6 Range. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| NSM.Rule.createdResourceId | Number | The id of the newly created rule object. | 

#### Command example
```!nsm-create-rule-object domain=0 rule_object_type="Range IP V.4" name="ruleo" visible_to_child=yes from_address_ip_v.4=1.1.1.1 to_address_ip_v.4=2.2.2.2```

#### Context Example
```json
{
    "NSM": {
        "Rule": {
            "createdResourceId":135
        }
    }
}
```

#### Human Readable Output

>The rule object no.135 was created successfully

### nsm-update-rule-object
***
Updates a Rule Object.


#### Base Command

`nsm-update-rule-object`
#### Input

| **Argument Name** | **Description**                                                                                                                                                                                                   | **Required** |
| --- |-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------| --- |
| domain | The id of the domain. To get the domain id, use the !nsm-get-domains command.                                                                                                                                     | Required | 
| rule_id | The id of the rule. To get the rule object id, use the !nsm-list-domain-rule-object.                                                                                                                              | Required | 
| name | The rule object name.                                                                                                                                                                                             | Optional | 
| visible_to_child | Will the rule object be visible to the child domain. Possible values are: yes, no. Default is yes.                                                                                                                | Optional | 
| description | The description of the rule object.                                                                                                                                                                               | Optional | 
| address_ip_v.4 | List of IPv4 host Address, separated by comma.                                                                                                                                                                    | Optional | 
| from_address_ip_v.4 | Start IPv4 Range.                                                                                                                                                                                                 | Optional | 
| to_address_ip_v.4 | End IPv4 Range.                                                                                                                                                                                                   | Optional | 
| address_ip_v.6 | List of IPv6 host Address, separated by comma.                                                                                                                                                                    | Optional | 
| from_address_ip_v.6 | Start IPv6 Range.                                                                                                                                                                                                 | Optional | 
| to_address_ip_v.6 | End IPv6 Range.                                                                                                                                                                                                   | Optional | 
| is_overwrite | Will the new addresses that was provided in the update processes will override the current ones or will be added to them. The default is false, and the addresses will be added. Possible values are: true, false. | Optional | 


#### Context Output

There is no context output for this command.

#### Command example
```!nsm-update-rule-object domain=0 rule_id=125 description="new desc"```

#### Human Readable Output

>The rule object no.125 was updated successfully.

### nsm-delete-rule-object
***
Deletes a Rule Object.


#### Base Command

`nsm-delete-rule-object`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_id | The id of the rule object. To get the rule object id, use the !nsm-list-domain-rule-object. | Required | 


#### Context Output

There is no context output for this command.

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

| **Argument Name** | **Description**                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | **Required** |
| --- |-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------| --- |
| limit | The maximum number of projects to return. Defaul is 50.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               | Optional | 
| page | The specific result page to display.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | Optional | 
| page_size | The number of records in a page.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      | Optional | 
| time_period | Time Period. Possible values are: LAST_5_MINUTES, LAST_1_HOUR, LAST_6_HOURS, LAST_12_HOURS, LAST_24_HOURS, LAST_7_DAYS, LAST_14_DAYS, CUSTOM. Default is LAST_7_DAYS.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 | Optional | 
| start_time | Start Time in "mm/dd/yyyy HH:MM" format only. used for custom time only.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              | Optional | 
| end_time | End Time in "mm/dd/yyyy HH:MM" format only. used for custom time only.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                | Optional | 
| state | Alert State. Possible values are: ANY, Acknowledged, Unacknowledged. Default is ANY.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | Optional | 
| search | Search string in alert details.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | Optional | 
| filter | Filter alert by fields. example: "name:hello;direction:Inbound,Outbound;attackcount:&gt;3,&lt;4". If you wish to use the "name" field in the filter, enter only one name in each command run. Filter on following column is allowed- name, assignTo, application, layer7Data, result, attackCount, relevance, alertId, direction, device, domain, interface, attackSeverity, nspId, btp, attackCategory, malwarefileName, malwarefileHash, malwareName, malwareConfidence, malwareEngine ,executableName, executableHash, executableConfidenceName, attackerIPAddress, attackerPort, attackerRisk, attackerProxyIP, attackerHostname, targetIPAddress, targetPort, targetRisk, targetProxyIP, targetHostname, botnetFamily. | Optional | 
| domain_id | The id of the domain. To get the domain_id, use the !nsm-get-domains command. Default is 0.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | Optional | 


#### Context Output

| **Path**                                       | **Type** | **Description** |
|------------------------------------------------| --- | --- |
| NSM.Alerts.ID                                  | number | Alert ID. | 
| NSM.Alerts.Name                                | String | Alert Name. | 
| NSM.Alerts.uniqueAlertId                       | String | Unique alert id. | 
| NSM.Alerts.State                               | String | Alert State \(Acknowledged,Unacknowledged\). | 
| NSM.Alerts.Assignee                            | String | Alert Assignee. | 
| NSM.Alerts.CreatedTime                         | String | Alert Creation Time. | 
| NSM.Alerts.AttackSeverity                      | String | Alert Severity | 
| NSM.Alerts.Event.time                          | Date | The creation time of the event who triggered the alert. | 
| NSM.Alerts.Event.direction                     | String | The direction of the event \(Outbound, Inbound\) | 
| NSM.Alerts.Event.result                        | String | The result of the event. | 
| NSM.Alerts.Event.attackCount                   | Number | Attack count. | 
| NSM.Alerts.Event.relevance                     | String | The event relevance. | 
| NSM.Alerts.Event.alertId                       | String | Alert ID. | 
| NSM.Alerts.Event.domain                        | String | The domain. | 
| NSM.Alerts.Event.interface                     | String | The event's interface. | 
| NSM.Alerts.Event.device                        | String | The relevant device. | 
| NSM.Alerts.Attack.nspId                        | String | nsp ID. | 
| NSM.Alerts.Attack.btp                          | String | Benign Trigger Probability. | 
| NSM.Alerts.Attack.attackCategory               | String | The attack category. | 
| NSM.Alerts.Attacker.ipAddrs                    | String | The attacker IP address. | 
| NSM.Alerts.Attacker.port                       | Number | The port. | 
| NSM.Alerts.Attacker.hostName                   | String | The attacker host name. | 
| NSM.Alerts.Attacker.country                    | String | The attacker country. | 
| NSM.Alerts.Attacker.os                         | Unknown | The attacker os. | 
| NSM.Alerts.Attacker.vmName                     | Unknown | The attacker vm name. | 
| NSM.Alerts.Attacker.proxyIP                    | String | The attacker proxyIP. | 
| NSM.Alerts.Attacker.user                       | Unknown | The user. | 
| NSM.Alerts.Attacker.risk                       | String | Attacker risk. | 
| NSM.Alerts.Attacker.networkObject              | Unknown | The attacker network object. | 
| NSM.Alerts.Target.ipAddrs                      | String | The target IP address. | 
| NSM.Alerts.Target.port                         | Number | The target port. | 
| NSM.Alerts.Target.hostName                     | String | The target hostName. | 
| NSM.Alerts.Target.country                      | String | The target country. | 
| NSM.Alerts.Target.os                           | Unknown | The target os. | 
| NSM.Alerts.Target.vmName                       | Unknown | The target vm Name. | 
| NSM.Alerts.Target.proxyIP                      | String | The target proxyIP. | 
| NSM.Alerts.Target.user                         | Unknown | The target user. | 
| NSM.Alerts.Target.risk                         | String | The target risk. | 
| NSM.Alerts.Target.networkObject                | Unknown | The target network object. | 
| NSM.Alerts.MalwareFile.fileName                | String | The name of the MalwareFile. | 
| NSM.Alerts.MalwareFile.fileHash                | String | The file hash of the MalwareFile. | 
| NSM.Alerts.MalwareFile.fileSHA1Hash            | String | The MalwareFile SHA1Hash. | 
| NSM.Alerts.MalwareFile.fileSHA256Hash          | Unknown | The fileSHA256Hash of the Malware file. | 
| NSM.Alerts.MalwareFile.malwareName             | String | The name of the malware. | 
| NSM.Alerts.MalwareFile.malwareConfidence       | String | Malware Confidence | 
| NSM.Alerts.MalwareFile.engine                  | String | Malware File engine. | 
| NSM.Alerts.MalwareFile.engineId                | Number | Malware File engine ID. | 
| NSM.Alerts.MalwareFile.size                    | Unknown | The Malware File size. | 
| NSM.Alerts.MalwareFile.description             | Unknown | Malware File description. | 
| NSM.Alerts.MalwareFile.additionalReference     | Unknown | Malware File additional Reference. | 
| NSM.Alerts.MalwareFile.cveId                   | Unknown | Malware File CVE ID. | 
| NSM.Alerts.endpointExcutable.name              | String | Endpoint Excutable name. | 
| NSM.Alerts.endpointExcutable.hash              | String | Endpoint Excutable hash. | 
| NSM.Alerts.endpointExcutable.malwareConfidence | String | Endpoint Excutable malware Confidence. | 
| NSM.Alerts.detection.managerId                 | Number | manager Id. | 
| NSM.Alerts.detection.manager                   | Unknown | The detection manager. | 
| NSM.Alerts.detection.domain                    | String | detection domain. | 
| NSM.Alerts.detection.device                    | String | detection device. | 
| NSM.Alerts.detection.deviceId                  | String | detection device ID. | 
| NSM.Alerts.detection.interface                 | String | detection interface. | 
| NSM.Alerts.Application                         | String | The Application assosiated to the alert. | 
| NSM.Alerts.layer7Data                          | String | Layer 7 information | 
| NSM.Alerts.EventResult                         | String | Event Result | 
| NSM.Alerts.SensorID                            | String | Sensor ID. | 

#### Command example
```!nsm-get-alerts domain_id=0 time_period=CUSTOM start_time="12/17/2000 14:14:22" end_time="12/18/2022 00:26:45"```
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
| alert_id | Alert ID. In order to get the alert id, use the command '!nsm-get-alerts' and use the output field “ID”. | Required | 
| sensor_id | Sensor ID. In order to get the alert id, use the command '!nsm-get-alerts' and use the output field “SensorID”. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| NSM.Alerts.ID | number | Alet Id. | 
| NSM.Alerts.Name | String | Alert Name. | 
| NSM.Alerts.CreatedTime | String | Alert Created Time. | 
| NSM.Alerts.uniqueAlertId | String | Unique Alert Id. | 
| NSM.Alerts.State | String | The state of the alert. | 
| NSM.Alerts.Assignee | String | Alert Assignee. | 
| NSM.Alerts.Event.application | String | The event application. | 
| NSM.Alerts.Event.protocol | Unknown | The event protocol. | 
| NSM.Alerts.Event.domain | String | The domain of the event. | 
| NSM.Alerts.Event.manager | Unknown | the event manager. | 
| NSM.Alerts.Event.device | String | The event device. | 
| NSM.Alerts.Event.deviceId | String | The id of the device that related to the event. | 
| NSM.Alerts.event.interface | String | The event interface. | 
| NSM.Alerts.Event.matchedPolicy | String | The policy that matched the event. | 
| NSM.Alerts.Event.zone | Unknown | The event zone. | 
| NSM.Alerts.Event.vlan | String | The event vlan. | 
| NSM.Alerts.Event.detection | String | The vent detection. | 
| NSM.Alerts.CreatedTime | Date | The creation time of the event. | 
| NSM.Alerts.event.direction | String | The event direction. | 
| NSM.Alerts.EventResult | String | The event result. | 
| NSM.Alerts.Event.attackCount | Number | Event attack count. | 
| NSM.Alerts.Event.relevance | String | The relevance of the event. | 
| NSM.Alerts.Event.alertId | String | Alert Id. | 
| NSM.Alerts.Attacker.ipAddrs | Unknown | Attacker IP addresses. | 
| NSM.Alerts.Attacker.port | Number | Attacker port. | 
| NSM.Alerts.Attacker.hostName | Unknown | Attacker host name. | 
| NSM.Alerts.Attacker.country | Unknown | Attacker country. | 
| NSM.Alerts.Attacker.os | String | Attacker os. | 
| NSM.Alerts.Attacker.vmName | Unknown | Attacker vm name. | 
| NSM.Alerts.Attacker.proxyIP | Unknown | Attacker proxy IP. | 
| NSM.Alerts.Attacker.user | String | Attacker user. | 
| NSM.Alerts.Attacker.risk | String | Attacker risk. | 
| NSM.Alerts.Attacker.networkObject | String | Attacker network object. | 
| NSM.Alerts.Target.ipAddrs | Unknown | Target IP address. | 
| NSM.Alerts.Target.port | Number | Target port. | 
| NSM.Alerts.Target.hostName | Unknown | Target host name. | 
| NSM.Alerts.Target.country | Unknown | Target country. | 
| NSM.Alerts.Target.os | String | Target os. | 
| NSM.Alerts.Target.vmName | Unknown | Target vm name. | 
| NSM.Alerts.Target.proxyIP | Unknown | Target proxy IP. | 
| NSM.Alerts.Target.user | String | Target user. | 
| NSM.Alerts.Target.risk | String | Target risk. | 
| NSM.Alerts.Target.networkObject | String | Target network object. | 
| NSM.Alerts.summary.source | Unknown | The source of the alert. | 
| NSM.Alerts.summary.destination | Unknown | The destination of the alert. | 
| NSM.Alerts.summary.zoombie | Unknown | Alert zoombie. | 
| NSM.Alerts.summary.cAndcServer | Unknown | The command and control server. | 
| NSM.Alerts.summary.fastFluxAgent | Unknown | Fast Flux Agent. | 
| NSM.Alerts.summary.attackedHIPEndpoint | Unknown | attackedHIPEndpoint. | 
| NSM.Alerts.summary.compromisedEndpoint | Unknown | Compromised endpoint. | 
| NSM.Alerts.Details.matchedSignature | Unknown | Matched signature. | 
| NSM.Alerts.MalwareFile | Unknown | Malware file. | 
| NSM.Alerts.Details.hostSweep | Unknown | Host sweep. | 
| NSM.Alerts.Details.portScan | Unknown | Port scan. | 
| NSM.Alerts.Details.fastFlux | Unknown | Fast flux. | 
| NSM.Alerts.Details.triggeredComponentAttacks | Unknown | Triggered component attack. | 
| NSM.Alerts.Details.sqlInjection | Unknown | SQL injection. | 
| NSM.Alerts.Details.callbackDetectors | Unknown | Call back detectors. | 
| NSM.Alerts.Details.exceededThreshold | Unknown | Exceeded threshold. | 
| NSM.Alerts.Details.communicationRuleMatch | Unknown | Communication rule match. | 
| NSM.Alerts.Description | String | Description. | 
| NSM.Alerts.Description.btp | String | btp. | 
| NSM.Alerts.Description.rfSB | String | rfSb. | 
| NSM.Alerts.Description.protectionCategory | String | Protection Category. | 
| NSM.Alerts.Description.target | String | The target. | 
| NSM.Alerts.Description.httpResponseAttack | String | Http response attack. | 
| NSM.Alerts.Description.priority | String | Priority. | 
| NSM.Alerts.Protocols | String | Protocols. | 
| NSM.Alerts.Attack.attackCategory | String | Attack category. | 
| NSM.Alerts.Attack.attackSubCategory | String | Attack sub category. | 
| NSM.Alerts.Description.snortEngine | String | Snort engine. | 
| NSM.Alerts.Description.versionAdded | String | When the version was added. | 
| NSM.Alerts.Description.versionUpdated | Unknown | When the version was updated. | 
| NSM.Alerts.Attack.nspId | String | nspID. | 
| NSM.Alerts.Description.reference.cveId | String | CVE ID. | 
| NSM.Alerts.Description.reference.microsoftId | String | Microsoft ID. | 
| NSM.Alerts.Description.reference.bugtraqId | String | Bugtraq Id. | 
| NSM.Alerts.Description.reference.certId | Unknown | Cert ID. | 
| NSM.Alerts.Description.reference.arachNidsId | String | arachNidsId | 
| NSM.Alerts.Description.reference.additionInfo | String | Additional info. | 
| NSM.Alerts.Description.comments.comments | String | comments. | 
| NSM.Alerts.Description.comments.availabeToChildDomains | Boolean | Is the alert available to child domains. | 
| NSM.Alerts.Description.comments.parentDomainComments | Unknown | Parent domain comments. | 

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
If an attack id is given The command returns the details for the specific attack. Else, gets all available attack definitions in the Manager UI. This command can take a few minutes. If you have a timeout error, then increase the timeout by using the parameter "execution-timeout".


#### Base Command

`nsm-get-attacks`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| attack_id | The id of the attack. To get the attack_id, use the !nsm-get-attacks command, without an attack id. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| InfoFile.Name | string | FileName | 
| InfoFile.EntryID | string | The EntryID of the report | 
| InfoFile.Size | number | File Size | 
| InfoFile.Type | string | File type e.g. "PE" | 
| InfoFile.Info | string | Basic information of the file | 
| NSM.Attacks.Direction | Unknown | Attack direction. | 
| NSM.Attacks.Severity | Number | Attack severity. | 
| NSM.Attacks.ID | String | Attack id. | 
| NSM.Attacks.Name | String | Attack name. | 
| NSM.Attacks.Category | String | Attack category | 
| NSM.Attacks.description.definition | String | Attack Defination | 
| NSM.Attacks.description.btp | String | BTP. | 
| NSM.Attacks.description.rfSB | String | RFSB. | 
| NSM.Attacks.description.protectionCategory | String | Protection Category. | 
| NSM.Attacks.description.target | String | Attack target. | 
| NSM.Attacks.description.httpResponseAttack | String | HTTP Response Attack. | 
| NSM.Attacks.description.priority | String | Attack priority. | 
| NSM.Attacks.description.protocols | String | Attack protocols. | 
| NSM.Attacks.description.attackCategory | String | Attack Category. | 
| NSM.Attacks.description.attackSubCategory | String | Attack Sub Category. | 
| NSM.Attacks.description.snortEngine | String | Attack snort engine. | 
| NSM.Attacks.description.versionAdded | String | When the attack version was added. | 
| NSM.Attacks.description.versionUpdated | String | When the attack version was updated. | 
| NSM.Attacks.description.reference.nspId | String | Attack nsp Id. | 
| NSM.Attacks.description.reference.cveId | String | Attack CVE id. | 
| NSM.Attacks.description.reference.microsoftId | String | Attack microsoft Id. | 
| NSM.Attacks.description.reference.bugtraqId | String | Attack bugtraq Id. | 
| NSM.Attacks.description.reference.certId | String | Attack cert Id. | 
| NSM.Attacks.description.reference.arachNidsId | String | arachNidsId. | 
| NSM.Attacks.description.reference.additionInfo | Unknown | Additional Info. | 
| NSM.Attacks.description.comments.comments | String | Comments. | 
| NSM.Attacks.description.comments.availabeToChildDomains | Boolean | Is the attack availabe To Child Domains. | 
| NSM.Attacks.description.comments.parentDomainComments | Unknown | Parent Domain Comments. | 

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
If a domain id is given The command returns the details of the specific domain. Else, gets all available domain.


#### Base Command

`nsm-get-domains`
#### Input

| **Argument Name** | **Description**                                                                                                                   | **Required** |
| --- |-----------------------------------------------------------------------------------------------------------------------------------| --- |
| domain_id | Specific domain id. Leave blank for all domains. To get the domain_id use !nsm-get-domains command and leave the parameter blank. | Optional | 
| limit | The maximum number of projects to return. Default is 50.                                                                          | Optional | 
| page | The specific result page to display.                                                                                              | Optional | 
| page_size | The number of records in a page.                                                                                                  | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| NSM.Domains.id | Number | Domain id. | 
| NSM.Domains.name | String | Domain name. | 
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

| **Argument Name** | **Description**                                                                                                             | **Required** |
| --- |-----------------------------------------------------------------------------------------------------------------------------| --- |
| domain_id | Specific domain id. Leave blank for all domains. To get the domain_id use !nsm-get-domains command and leave the parameter blank. | Optional | 
| limit | The maximum number of projects to return. Default is 50.                                                                    | Optional | 
| page | The specific result page to display.                                                                                        | Optional | 
| page_size | The number of records in a page.                                                                                            | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| NSM.Sensors.ID | Number | Sensor Id. | 
| NSM.Sensors.Name | String | Name of the Sensor. | 
| NSM.Sensors.model | String | Sensor Model. | 
| NSM.Sensors.Description | String | Sensor Description. | 
| NSM.Sensors.DomainID | Number | Id of Domain to which this sensor belongs to | 
| NSM.Sensors.isFailOver | Boolean | Is the sensor fail over | 
| NSM.Sensors.isNTBA | Boolean | Is NTBA. | 
| NSM.Sensors.isLoadBalancer | Boolean | Is the sensor load balancer. | 
| NSM.Sensors.SerialNumber | Unknown | The sensor serial number. | 
| NSM.Sensors.SigsetVersion | String | Signature set version number applied to the Sensor. | 
| NSM.Sensors.DATVersion | String | DAT version of the sensor. | 
| NSM.Sensors.SoftwareVersion | String | Sensor Software version. | 
| NSM.Sensors.LastSignatureUpdateTs | Date | Last Configuration download timestamp. | 
| NSM.Sensors.IPSPolicyID | Number | IPS policy id applied to the sensor. | 
| NSM.Sensors.ReconPolicyID | Number | Recon policy id applied to the sensor. | 
| NSM.Sensors.LastModTs | Unknown | Last modified timestamp. | 
| NSM.Sensors.IP Address | String | Sensor IP Address. | 
| NSM.Sensors.nsmVersion | String | NSM Version. | 
| NSM.Sensors.capacity | String | Sensor capacity. | 
| NSM.Sensors.isStack | Boolean | Is stack. | 
| NSM.Sensorss.isStackMember | Boolean | Is stack member. | 

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
>| ID  |Name|Description|DomainID|IPSPolicyID|IP Address|
-----|---|---|---|---|---|---|
>| 1111 | VVVV1 | MCAFEE-NETWORK-SECURITY-PLATFORM | 0 | 0 | 1.1.1.1 |


### nsm-get-ips-policies
***
Gets all the IPS Policies defined in the specific domain.


#### Base Command

`nsm-get-ips-policies`
#### Input

| **Argument Name** | **Description**                                                                                  | **Required** |
| --- |--------------------------------------------------------------------------------------------------| --- |
| domain_id | Specific domain id. To get the domain_id use !nsm-get-domains command and leave the parameter blank. | Required | 
| limit | The maximum number of projects to return. Default is 50.                                         | Optional | 
| page | The specific result page to display.                                                             | Optional | 
| page_size | The number of records in a page.                                                                 | Optional | 


#### Context Output

| **Path**                          | **Type** | **Description** |
|-----------------------------------| --- | --- |
| NSM.IPSPolicies.IsEditable        | Boolean | Is the ips policy editable. | 
| NSM.IPSPolicies.DomainID          | Number | Id of Domain to which this policy belongs to. | 
| NSM.IPSPolicies.VisibleToChildren | Boolean | Policy visible to Child Domain. | 
| NSM.IPSPolicies.ID                | Number | IPS policy id. | 
| NSM.IPSPolicies.Name              | String | IPS policy name. | 

#### Command example
```!nsm-get-ips-policies domain_id=0 limit=2```
#### Context Example
```json
{
    "NSM": {
        "IPSPolicies": [
            {
                "DomainId": 0,
                "ID": -1,
                "IsEditable": true,
                "Name": "Master",
                "VisibleToChildren": true
            },
            {
                "DomainId": 0,
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
>|ID|Name|IsEditable|
>|---|---|---|
>| -1 | Master | true |
>| 0 | Default | true |


### nsm-get-ips-policy-details
***
Gets all the IPS Policies defined in the specific domain.


#### Base Command

`nsm-get-ips-policy-details`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_id | Specific ips policy id. To get the policy_id use !nsm-get-ips-policies command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| NSM.IPSPolicies.ID | number | IPS Policy ID | 
| NSM.IPSPolicies.Name | string | IPS Policy Name | 
| NSM.IPSPolicies.Description | string | IPS Policy information | 
| NSM.IPSPolicies.CreatedTime | string | Policy creation time | 
| NSM.IPSPolicies.IsEditable | boolean | Whether the IPS policy is editable | 
| NSM.IPSPolicies.VisibleToChildren | boolean | Whether the IPS Policy is visible to domain's children | 
| NSM.IPSPolicies.Version | number | IPS Policy Version | 
| NSM.IPSPolicies.InboundRuleSet | string | Inbound Rule Set | 
| NSM.IPSPolicies.OutboundRuleSet | string | Outbound Rule Set | 
| NSM.IPSPolicies.ExploitAttacks | Unknown | A list of exploit attacks related to the IPS Policy | 

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

### nsm-update-alerts
***
Update state or assignee of alerts. It is required to provide at least one of them. If none of the alerts match the time_period they won't be updated.


#### Base Command

`nsm-update-alerts`
#### Input

| **Argument Name** | **Description**                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          | **Required** |
| --- |--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------| --- |
| state | Alert State. Possible values are: ANY, Acknowledged, Unacknowledged. Default is ANY.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     | Optional | 
| time_period | Time Period. Possible values are: LAST_5_MINUTES, LAST_1_HOUR, LAST_6_HOURS, LAST_12_HOURS, LAST_24_HOURS, LAST_7_DAYS, LAST_14_DAYS, CUSTOM. Default is LAST_7_DAYS                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     | Optional | 
| start_time | Start Time in "mm/dd/yyyy HH:MM" format only. used for custom time only.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 | Optional | 
| end_time | End Time in "mm/dd/yyyy HH:MM" format only. used for custom time only.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | Optional | 
| new_state | The new alert state. Possible values are: Acknowledged, Unacknowledged.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | Optional | 
| new_assignee | The new assignee.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        | Optional | 
| search | Search string in alert details.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          | Optional | 
| filter | Filter alert by fields. example: "name:hello;direction:Inbound,Outbound;attackcount:&gt;3,&lt;4"If you wish to use the "name" field in the filter, enter only one name in each command run. Filter on following column is allowed- name, assignTo, application, layer7Data, result, attackCount, relevance, alertId, direction, device, domain, interface, attackSeverity, nspId, btp, attackCategory, malwarefileName, malwarefileHash, malwareName, malwareConfidence, malwareEngine ,executableName, executableHash, executableConfidenceName, attackerIPAddress, attackerPort, attackerRisk, attackerProxyIP, attackerHostname, targetIPAddress, targetPort, targetRisk, targetProxyIP, targetHostname, botnetFamily. | Optional | 


#### Context Output

| **Path**                                       | **Type** | **Description** |
|------------------------------------------------| --- | --- |
| NSM.Alerts.ID                                  | number | Alert ID. | 
| NSM.Alerts.Name                                | String | Alert Name. | 
| NSM.Alerts.uniqueAlertId                       | String | Unique alert id. | 
| NSM.Alerts.State                               | String | Alert State \(Acknowledged,Unacknowledged\). | 
| NSM.Alerts.Assignee                            | String | Alert Assignee. | 
| NSM.Alerts.CreatedTime                         | String | Alert Creation Time. | 
| NSM.Alerts.AttackSeverity                      | String | Alert Severity | 
| NSM.Alerts.Event.time                          | Date | The creation time of the event who triggered the alert. | 
| NSM.Alerts.Event.direction                     | String | The direction of the event \(Outbound, Inbound\) | 
| NSM.Alerts.Event.result                        | String | The result of the event. | 
| NSM.Alerts.Event.attackCount                   | Number | Attack count. | 
| NSM.Alerts.Event.relevance                     | String | The event relevance. | 
| NSM.Alerts.Event.alertId                       | String | Alert ID. | 
| NSM.Alerts.Event.domain                        | String | The domain. | 
| NSM.Alerts.Event.interface                     | String | The event's interface. | 
| NSM.Alerts.Event.device                        | String | The relevant device. | 
| NSM.Alerts.Attack.nspId                        | String | nsp ID. | 
| NSM.Alerts.Attack.btp                          | String | Benign Trigger Probability. | 
| NSM.Alerts.Attack.attackCategory               | String | The attack category. | 
| NSM.Alerts.Attacker.ipAddrs                    | String | The attacker IP address. | 
| NSM.Alerts.Attacker.port                       | Number | The port. | 
| NSM.Alerts.Attacker.hostName                   | String | The attacker host name. | 
| NSM.Alerts.Attacker.country                    | String | The attacker country. | 
| NSM.Alerts.Attacker.os                         | Unknown | The attacker os. | 
| NSM.Alerts.Attacker.vmName                     | Unknown | The attacker vm name. | 
| NSM.Alerts.Attacker.proxyIP                    | String | The attacker proxyIP. | 
| NSM.Alerts.Attacker.user                       | Unknown | The user. | 
| NSM.Alerts.Attacker.risk                       | String | Attacker risk. | 
| NSM.Alerts.Attacker.networkObject              | Unknown | The attacker network object. | 
| NSM.Alerts.Target.ipAddrs                      | String | The target IP address. | 
| NSM.Alerts.Target.port                         | Number | The target port. | 
| NSM.Alerts.Target.hostName                     | String | The target hostName. | 
| NSM.Alerts.Target.country                      | String | The target country. | 
| NSM.Alerts.Target.os                           | Unknown | The target os. | 
| NSM.Alerts.Target.vmName                       | Unknown | The target vm Name. | 
| NSM.Alerts.Target.proxyIP                      | String | The target proxyIP. | 
| NSM.Alerts.Target.user                         | Unknown | The target user. | 
| NSM.Alerts.Target.risk                         | String | The target risk. | 
| NSM.Alerts.Target.networkObject                | Unknown | The target network object. | 
| NSM.Alerts.MalwareFile.fileName                | String | The name of the MalwareFile. | 
| NSM.Alerts.MalwareFile.fileHash                | String | The file hash of the MalwareFile. | 
| NSM.Alerts.MalwareFile.fileSHA1Hash            | String | The MalwareFile SHA1Hash. | 
| NSM.Alerts.MalwareFile.fileSHA256Hash          | Unknown | The fileSHA256Hash of the Malware file. | 
| NSM.Alerts.MalwareFile.malwareName             | String | The name of the malware. | 
| NSM.Alerts.MalwareFile.malwareConfidence       | String | Malware Confidence | 
| NSM.Alerts.MalwareFile.engine                  | String | Malware File engine. | 
| NSM.Alerts.MalwareFile.engineId                | Number | Malware File engine ID. | 
| NSM.Alerts.MalwareFile.size                    | Unknown | The Malware File size. | 
| NSM.Alerts.MalwareFile.description             | Unknown | Malware File description. | 
| NSM.Alerts.MalwareFile.additionalReference     | Unknown | Malware File additional Reference. | 
| NSM.Alerts.MalwareFile.cveId                   | Unknown | Malware File CVE ID. | 
| NSM.Alerts.endpointExcutable.name              | String | Endpoint Excutable name. | 
| NSM.Alerts.endpointExcutable.hash              | String | Endpoint Excutable hash. | 
| NSM.Alerts.endpointExcutable.malwareConfidence | String | Endpoint Excutable malware Confidence. | 
| NSM.Alerts.detection.managerId                 | Number | manager Id. | 
| NSM.Alerts.detection.manager                   | Unknown | The detection manager. | 
| NSM.Alerts.detection.domain                    | String | detection domain. | 
| NSM.Alerts.detection.device                    | String | detection device. | 
| NSM.Alerts.detection.deviceId                  | String | detection device ID. | 
| NSM.Alerts.detection.interface                 | String | detection interface. | 
| NSM.Alerts.Application                         | String | The Application assosiated to the alert. | 
| NSM.Alerts.layer7Data                          | String | Layer 7 information | 
| NSM.Alerts.EventResult                         | String | Event Result | 
| NSM.Alerts.SensorID                            | String | Sensor ID. | 

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

| **Argument Name** | **Description**                                                               | **Required** |
| --- |-------------------------------------------------------------------------------| --- |
| sensor_id | The id of the sensor. To get the sensor_id, use the !nsm-get-sensors command. | Required | 
| limit | The maximum number of projects to return. Default is 50.                | Optional | 
| page | The specific result page to display. The default is 1.                        | Optional | 
| page_size | The number of records in a page.                                              | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| NSM.PcapFile | string | Pcap File Name. | 

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

>### Updated Alerts list. Showing 2 of 20

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
| sensor_id | The id of the sensor. To get the sensor_id, use the command !nsm-get-sensors. | Required | 
| file_name | The name of the wanted file. To get the file_name, use the command !nsm-list-pcap-file. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| InfoFile.Name | string | FileName | 
| InfoFile.EntryID | string | The EntryID of the report | 
| InfoFile.Size | number | File Size | 
| InfoFile.Type | string | File type e.g. "PE" | 
| InfoFile.Info | string | Basic information of the file | 

#### Command example
```!nsm-export-pcap-file sensor_id=1003 file_name=Virtual_NSP_01-PacketCapture-2022-12-21_16-25-52.pcap```

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

In the *nsm-update-alerts* command:
* *time_period* - The default value changed to 'LAST_7_DAYS'.
