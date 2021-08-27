AWS Network Firewall is a stateful, managed, network firewall and intrusion detection and prevention service for Amazon Virtual Private Cloud (Amazon VPC). With Network Firewall, you can filter traffic at the perimeter of your VPC. This includes filtering traffic going to and coming from an internet gateway, NAT gateway, or over VPN or AWS Direct Connect. Network Firewall uses rules that are compatible with Suricata, a free, open source intrusion detection system (IDS) engine.

## Configure AWS Network Firewall on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for AWS Network Firewall.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | roleArn | Role Arn | False |
    | roleSessionName | Role Session Name | False |
    | defaultRegion | AWS Default Region | False |
    | sessionDuration | Role Session Duration | False |
    | access_key | Access Key | False |
    | secret_key | Secret Key | False |
    | insecure | Trust any certificate \(not secure\) | False |
    | proxy | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### aws-network-firewall-associate-firewall-policy
***
Associates a FirewallPolicy to a Firewall.  A firewall policy defines how to monitor and manage your VPC network traffic, using a collection of inspection rule groups and other settings. Each firewall requires one firewall policy association, and you can use the same firewall policy for multiple firewalls.


#### Base Command

`aws-network-firewall-associate-firewall-policy`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. . | Optional | 
| raw_json | Override arguments and send a formatted JSON file. | Optional | 
| update_token | An optional token that you can use for optimistic locking. Network Firewall returns a token to your requests that access the firewall. The token marks the state of the firewall resource at the time of the request.  To make an unconditional change to the firewall, omit the token in your update request. Without the token, Network Firewall performs your updates regardless of whether the firewall has changed since you last retrieved it. To make a conditional change to the firewall, provide the token in your update request. Network Firewall uses the token to ensure that the firewall hasn't changed since you last retrieved it. If it has changed, the operation fails with an InvalidTokenException. If this happens, retrieve the firewall again to get a current copy of it with a new token. Reapply your changes as needed, then try the operation again using the new token. . | Optional | 
| firewall_arn | The Amazon Resource Name (ARN) of the firewall. You must specify the ARN or the name, and you can specify both. . | Optional | 
| firewall_name | The descriptive name of the firewall. You can't change the name of a firewall after you create it. You must specify the ARN or the name, and you can specify both. . | Optional | 
| firewall_policy_arn | The Amazon Resource Name (ARN) of the firewall policy. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS-NetworkFirewall.AssociationResults.FirewallPolicy.FirewallArn | Unknown | The Amazon Resource Name \(ARN\) of the firewall. | 
| AWS-NetworkFirewall.AssociationResults.FirewallPolicy.FirewallName | Unknown | The descriptive name of the firewall. You can't change the name of a firewall after you create it. | 
| AWS-NetworkFirewall.AssociationResults.FirewallPolicy.FirewallPolicyArn | Unknown | The Amazon Resource Name \(ARN\) of the firewall policy. | 
| AWS-NetworkFirewall.AssociationResults.FirewallPolicy.UpdateToken | Unknown | An optional token that you can use for optimistic locking. Network Firewall returns a token to your requests that access the firewall. The token marks the state of the firewall resource at the time of the request.  To make an unconditional change to the firewall, omit the token in your update request. Without the token, Network Firewall performs your updates regardless of whether the firewall has changed since you last retrieved it. To make a conditional change to the firewall, provide the token in your update request. Network Firewall uses the token to ensure that the firewall hasn't changed since you last retrieved it. If it has changed, the operation fails with an InvalidTokenException. If this happens, retrieve the firewall again to get a current copy of it with a new token. Reapply your changes as needed, then try the operation again using the new token.  | 


#### Command Example
```!aws-network-firewall-associate-firewall-policy firewall_policy_arn=arn:aws:network-firewall:us-west-2:123456789012:firewall-policy/example-fw-policy firewall_arn=arn:aws:network-firewall:us-west-2:123456789012:firewall/myfirewall```


#### Context Example
```json
{
    "AWS-NetworkFirewall": {
        "AssociationResults": {
            "FirewallPolicy": {
                "FirewallArn": "arn:aws:network-firewall:us-west-2:123456789012:firewall/myfirewall",
                "FirewallName": "myfirewall",
                "FirewallPolicyArn": "arn:aws:network-firewall:us-west-2:123456789012:firewall-policy/example-fw-policy",
                "UpdateToken": "bfcd1bb0-05b4-4b68-9ded-715419ab31ab"
            }
        }
    }
}
```

#### Human Readable Output

>### AWS Network Firewall AssociateFirewallPolicy
>|FirewallArn|FirewallName|FirewallPolicyArn|UpdateToken|
>|---|---|---|---|
>| arn:aws:network-firewall:us-west-2:123456789012:firewall/myfirewall | myfirewall | arn:aws:network-firewall:us-west-2:123456789012:firewall-policy/example-fw-policy | bfcd1bb0-05b4-4b68-9ded-715419ab31ab |


### aws-network-firewall-associate-subnets
***
Associates the specified subnets in the Amazon VPC to the firewall. You can specify one subnet for each of the Availability Zones that the VPC spans.  This request creates an AWS Network Firewall firewall endpoint in each of the subnets. To enable the firewall's protections, you must also modify the VPC's route tables for each subnet's Availability Zone, to redirect the traffic that's coming into and going out of the zone through the firewall endpoint.


#### Base Command

`aws-network-firewall-associate-subnets`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. . | Optional | 
| raw_json | Override arguments and send a formatted JSON file. | Optional | 
| update_token | An optional token that you can use for optimistic locking. Network Firewall returns a token to your requests that access the firewall. The token marks the state of the firewall resource at the time of the request.  To make an unconditional change to the firewall, omit the token in your update request. Without the token, Network Firewall performs your updates regardless of whether the firewall has changed since you last retrieved it. To make a conditional change to the firewall, provide the token in your update request. Network Firewall uses the token to ensure that the firewall hasn't changed since you last retrieved it. If it has changed, the operation fails with an InvalidTokenException. If this happens, retrieve the firewall again to get a current copy of it with a new token. Reapply your changes as needed, then try the operation again using the new token. . | Optional | 
| firewall_arn | The Amazon Resource Name (ARN) of the firewall. You must specify the ARN or the name, and you can specify both. . | Optional | 
| firewall_name | The descriptive name of the firewall. You can't change the name of a firewall after you create it. You must specify the ARN or the name, and you can specify both. . | Optional | 
| subnet_mappings_subnet_ids | Comma-separated  IDs of the subnets that you want to associate with the firewall. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS-NetworkFirewall.AssociationResults.Subnets.FirewallArn | Unknown | The Amazon Resource Name \(ARN\) of the firewall. | 
| AWS-NetworkFirewall.AssociationResults.Subnets.FirewallName | Unknown | The descriptive name of the firewall. You can't change the name of a firewall after you create it. | 
| AWS-NetworkFirewall.AssociationResults.Subnets.SubnetId | Unknown | The unique identifier for the subnet.  | 
| AWS-NetworkFirewall.AssociationResults.Subnets.SubnetMappings | Unknown | The IDs of the subnets that are associated with the firewall.  | 
| AWS-NetworkFirewall.AssociationResults.Subnets.UpdateToken | Unknown | An optional token that you can use for optimistic locking. Network Firewall returns a token to your requests that access the firewall. The token marks the state of the firewall resource at the time of the request.  To make an unconditional change to the firewall, omit the token in your update request. Without the token, Network Firewall performs your updates regardless of whether the firewall has changed since you last retrieved it. To make a conditional change to the firewall, provide the token in your update request. Network Firewall uses the token to ensure that the firewall hasn't changed since you last retrieved it. If it has changed, the operation fails with an InvalidTokenException. If this happens, retrieve the firewall again to get a current copy of it with a new token. Reapply your changes as needed, then try the operation again using the new token.  | 


#### Command Example
```!aws-network-firewall-associate-subnets subnet_mappings_subnet_ids=subnet-aaaaaaa,subnet-bbbbbbb firewall_arn=arn:aws:network-firewall:us-west-2:123456789012:firewall/myfirewall2```

#### Context Example
```json
{
    "AWS-NetworkFirewall": {
        "AssociationResults": {
            "Subnets": {
                "FirewallArn": "arn:aws:network-firewall:us-west-2:123456789012:firewall/myfirewall2",
                "FirewallName": "myfirewall2",
                "SubnetMappings": [
                    {
                        "SubnetId": "subnet-aaaaaaa"
                    },
                    {
                        "SubnetId": "subnet-bbbbbbb"
                    }
                ],
                "UpdateToken": "33113709-ce96-4cbf-89db-149a8b400287"
            }
        }
    }
}
```

#### Human Readable Output

>### AWS Network Firewall AssociateSubnets
>|FirewallArn|FirewallName|SubnetMappings|UpdateToken|
>|---|---|---|---|
>| arn:aws:network-firewall:us-west-2:123456789012:firewall/myfirewall2 | myfirewall2 | {'SubnetId': 'subnet-aaaaaaa'},<br/>{'SubnetId': 'subnet-bbbbbbb'} | 33113709-ce96-4cbf-89db-149a8b400287 |


### aws-network-firewall-create-firewall
***
Creates an AWS Network Firewall Firewall and accompanying FirewallStatus for a VPC.  The firewall defines the configuration settings for an AWS Network Firewall firewall. The settings that you can define at creation include the firewall policy, the subnets in your VPC to use for the firewall endpoints, and any tags that are attached to the firewall AWS resource.  After you create a firewall, you can provide additional settings, like the logging configuration.  To update the settings for a firewall, you use the operations that apply to the settings themselves, for example UpdateLoggingConfiguration, AssociateSubnets, and UpdateFirewallDeleteProtection.  To manage a firewall's tags, use the standard AWS resource tagging operations, ListTagsForResource, TagResource, and UntagResource. To retrieve information about firewalls, use ListFirewalls and DescribeFirewall.


#### Base Command

`aws-network-firewall-create-firewall`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. . | Optional | 
| raw_json | Override arguments and send a formatted JSON file. | Optional | 
| firewall_name | The descriptive name of the firewall. You can't change the name of a firewall after you create it. | Required | 
| firewall_policy_arn | The Amazon Resource Name (ARN) of the FirewallPolicy that you want to use for the firewall. | Required | 
| vpc_id | The unique identifier of the VPC where Network Firewall should create the firewall.  You can't change this setting after you create the firewall. . | Required | 
| subnet_mappings_subnet_ids | Comma-separated  IDs of the subnets that you want to associate with the firewall. | Required | 
| delete_protection | &lt;p&gt;A flag indicating whether it is possible to delete the firewall. A setting of &lt;code&gt;TRUE&lt;/code&gt; indicates that the firewall is protected against deletion. Use this setting to protect against accidentally deleting a firewall that is in use. When you create a firewall, the operation initializes this flag to &lt;code&gt;TRUE&lt;/code&gt;.&lt;/p&gt;. Possible values are: True, False. | Optional | 
| subnet_change_protection | &lt;p&gt;A setting indicating whether the firewall is protected against changes to the subnet associations. Use this setting to protect against accidentally modifying the subnet associations for a firewall that is in use. When you create a firewall, the operation initializes this setting to &lt;code&gt;TRUE&lt;/code&gt;.&lt;/p&gt;. Possible values are: True, False. | Optional | 
| firewall_policy_change_protection | &lt;p&gt;A setting indicating whether the firewall is protected against a change to the firewall policy association. Use this setting to protect against accidentally modifying the firewall policy for a firewall that is in use. When you create a firewall, the operation initializes this setting to &lt;code&gt;TRUE&lt;/code&gt;.&lt;/p&gt;. Possible values are: True, False. | Optional | 
| description | A description of the firewall. | Optional | 
| tag_key | The Tags key identifier. | Optional | 
| tag_value | The Tags value identifier. | Optional | 
| tags | List of Tags separated by Key Value. For example: "key=key1,value=value1;key=key2,value=value2". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS-NetworkFirewall.Firewall.Firewall.FirewallName | Unknown | The descriptive name of the firewall. You can't change the name of a firewall after you create it. | 
| AWS-NetworkFirewall.Firewall.Firewall.FirewallArn | Unknown | The Amazon Resource Name \(ARN\) of the firewall. | 
| AWS-NetworkFirewall.Firewall.Firewall.FirewallPolicyArn | Unknown | The Amazon Resource Name \(ARN\) of the firewall policy. The relationship of firewall to firewall policy is many to one. Each firewall requires one firewall policy association, and you can use the same firewall policy for multiple firewalls.  | 
| AWS-NetworkFirewall.Firewall.Firewall.VpcId | Unknown | The unique identifier of the VPC where the firewall is in use.  | 
| AWS-NetworkFirewall.Firewall.Firewall.SubnetMappings.SubnetId | Unknown | The unique identifier for the subnet.  | 
| AWS-NetworkFirewall.Firewall.Firewall.SubnetMappings | Unknown | The public subnets that Network Firewall is using for the firewall. Each subnet must belong to a different Availability Zone.  | 
| AWS-NetworkFirewall.Firewall.Firewall.DeleteProtection | Unknown | A flag indicating whether it is possible to delete the firewall. A setting of TRUE indicates that the firewall is protected against deletion. Use this setting to protect against accidentally deleting a firewall that is in use. When you create a firewall, the operation initializes this flag to TRUE. | 
| AWS-NetworkFirewall.Firewall.Firewall.SubnetChangeProtection | Unknown | A setting indicating whether the firewall is protected against changes to the subnet associations. Use this setting to protect against accidentally modifying the subnet associations for a firewall that is in use. When you create a firewall, the operation initializes this setting to TRUE. | 
| AWS-NetworkFirewall.Firewall.Firewall.FirewallPolicyChangeProtection | Unknown | A setting indicating whether the firewall is protected against a change to the firewall policy association. Use this setting to protect against accidentally modifying the firewall policy for a firewall that is in use. When you create a firewall, the operation initializes this setting to TRUE. | 
| AWS-NetworkFirewall.Firewall.Firewall.Description | Unknown | A description of the firewall. | 
| AWS-NetworkFirewall.Firewall.Firewall.FirewallId | Unknown | The unique identifier for the firewall.  | 
| AWS-NetworkFirewall.Firewall.Firewall.Tags.Key | Unknown | The part of the key:value pair that defines a tag. You can use a tag key to describe a category of information, such as "customer." Tag keys are case-sensitive. | 
| AWS-NetworkFirewall.Firewall.Firewall.Tags.Value | Unknown | The part of the key:value pair that defines a tag. You can use a tag value to describe a specific value within a category, such as "companyA" or "companyB." Tag values are case-sensitive. | 
| AWS-NetworkFirewall.Firewall.Firewall.Tags | Unknown | The key:value pairs to associate with the resource. | 
| AWS-NetworkFirewall.Firewall.Firewall | Unknown | The configuration settings for the firewall. These settings include the firewall policy and the subnets in your VPC to use for the firewall endpoints.  | 
| AWS-NetworkFirewall.Firewall.FirewallStatus.Status | Unknown | The readiness of the configured firewall to handle network traffic across all of the Availability Zones where you've configured it. This setting is READY only when the ConfigurationSyncStateSummary value is IN\\_SYNC and the Attachment Status values for all of the configured subnets are READY.  | 
| AWS-NetworkFirewall.Firewall.FirewallStatus.ConfigurationSyncStateSummary | Unknown | The configuration sync state for the firewall. This summarizes the sync states reported in the Config settings for all of the Availability Zones where you have configured the firewall.  When you create a firewall or update its configuration, for example by adding a rule group to its firewall policy, Network Firewall distributes the configuration changes to all zones where the firewall is in use. This summary indicates whether the configuration changes have been applied everywhere.  This status must be IN\\_SYNC for the firewall to be ready for use, but it doesn't indicate that the firewall is ready. The Status setting indicates firewall readiness. | 
| AWS-NetworkFirewall.Firewall.FirewallStatus.SyncStates | Unknown | The subnets that you've configured for use by the Network Firewall firewall. This contains one array element per Availability Zone where you've configured a subnet. These objects provide details of the information that is summarized in the ConfigurationSyncStateSummary and Status, broken down by zone and configuration object.  | 
| AWS-NetworkFirewall.Firewall.FirewallStatus | Unknown | Detailed information about the current status of a Firewall. You can retrieve this for a firewall by calling DescribeFirewall and providing the firewall name and ARN. | 


#### Command Example
```!aws-network-firewall-create-firewall firewall_name=myfirewall1 firewall_policy_arn=arn:aws:network-firewall:us-west-2:123456789012:firewall-policy/example-fw-policy subnet_mappings_subnet_ids=subnet-aaaaaaa,subnet-bbbbbbb vpc_id=vpc-abcdef```

#### Context Example
```json
{
    "AWS-NetworkFirewall": {
        "Firewall": {
            "Firewall": {
                "DeleteProtection": false,
                "FirewallArn": "arn:aws:network-firewall:us-west-2:123456789012:firewall/myfirewall1",
                "FirewallId": "86418579-5031-42a0-a23f-bca0638383ac",
                "FirewallName": "myfirewall1",
                "FirewallPolicyArn": "arn:aws:network-firewall:us-west-2:123456789012:firewall-policy/example-fw-policy",
                "FirewallPolicyChangeProtection": false,
                "SubnetChangeProtection": false,
                "SubnetMappings": [
                    {
                        "SubnetId": "subnet-aaaaaaa"
                    },
                    {
                        "SubnetId": "subnet-bbbbbbb"
                    }
                ],
                "VpcId": "vpc-abcdef"
            },
            "FirewallStatus": {
                "ConfigurationSyncStateSummary": "PENDING",
                "Status": "PROVISIONING"
            }
        }
    }
}
```

#### Human Readable Output

>### AWS Network Firewall CreateFirewall
>|Firewall|FirewallStatus|
>|---|---|
>| FirewallName: myfirewall1<br/>FirewallArn: arn:aws:network-firewall:us-west-2:123456789012:firewall/myfirewall1<br/>FirewallPolicyArn: arn:aws:network-firewall:us-west-2:123456789012:firewall-policy/example-fw-policy<br/>VpcId: vpc-abcdef<br/>SubnetMappings: {'SubnetId': 'subnet-aaaaaaa'},<br/>{'SubnetId': 'subnet-bbbbbbb'}<br/>DeleteProtection: false<br/>SubnetChangeProtection: false<br/>FirewallPolicyChangeProtection: false<br/>FirewallId: 86418579-5031-42a0-a23f-bca0638383ac | Status: PROVISIONING<br/>ConfigurationSyncStateSummary: PENDING |


### aws-network-firewall-create-firewall-policy
***
Creates the firewall policy for the firewall according to the specifications.  An AWS Network Firewall firewall policy defines the behavior of a firewall, in a collection of stateless and stateful rule groups and other settings. You can use one firewall policy for multiple firewalls.


#### Base Command

`aws-network-firewall-create-firewall-policy`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. . | Optional | 
| raw_json | Override arguments and send a formatted JSON file. | Optional | 
| firewall_policy_name | The descriptive name of the firewall policy. You can't change the name of a firewall policy after you create it. | Required | 
| firewall_policy_json | JSON string of the rule groups and policy actions to use in the firewall policy. | Required | 
| description | A description of the firewall policy. | Optional | 
| tag_key | The Tags key identifier. | Optional | 
| tag_value | The Tags value identifier. | Optional | 
| tags | List of Tags separated by Key Value. For example: "key=key1,value=value1;key=key2,value=value2". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS-NetworkFirewall.FirewallPolicy.UpdateToken | Unknown | A token used for optimistic locking. Network Firewall returns a token to your requests that access the firewall policy. The token marks the state of the policy resource at the time of the request.  To make changes to the policy, you provide the token in your request. Network Firewall uses the token to ensure that the policy hasn't changed since you last retrieved it. If it has changed, the operation fails with an InvalidTokenException. If this happens, retrieve the firewall policy again to get a current copy of it with current token. Reapply your changes as needed, then try the operation again using the new token.  | 
| AWS-NetworkFirewall.FirewallPolicy.FirewallPolicyResponse.FirewallPolicyName | Unknown | The descriptive name of the firewall policy. You can't change the name of a firewall policy after you create it. | 
| AWS-NetworkFirewall.FirewallPolicy.FirewallPolicyResponse.FirewallPolicyArn | Unknown | The Amazon Resource Name \(ARN\) of the firewall policy.  If this response is for a create request that had DryRun set to TRUE, then this ARN is a placeholder that isn't attached to a valid resource.  | 
| AWS-NetworkFirewall.FirewallPolicy.FirewallPolicyResponse.FirewallPolicyId | Unknown | The unique identifier for the firewall policy.  | 
| AWS-NetworkFirewall.FirewallPolicy.FirewallPolicyResponse.Description | Unknown | A description of the firewall policy. | 
| AWS-NetworkFirewall.FirewallPolicy.FirewallPolicyResponse.FirewallPolicyStatus | Unknown | The current status of the firewall policy. You can retrieve this for a firewall policy by calling DescribeFirewallPolicy and providing the firewall policy's name or ARN. | 
| AWS-NetworkFirewall.FirewallPolicy.FirewallPolicyResponse.Tags.Key | Unknown | The part of the key:value pair that defines a tag. You can use a tag key to describe a category of information, such as "customer." Tag keys are case-sensitive. | 
| AWS-NetworkFirewall.FirewallPolicy.FirewallPolicyResponse.Tags.Value | Unknown | The part of the key:value pair that defines a tag. You can use a tag value to describe a specific value within a category, such as "companyA" or "companyB." Tag values are case-sensitive. | 
| AWS-NetworkFirewall.FirewallPolicy.FirewallPolicyResponse.Tags | Unknown | The key:value pairs to associate with the resource. | 
| AWS-NetworkFirewall.FirewallPolicy.FirewallPolicyResponse | Unknown | The high-level properties of a firewall policy. This, along with the FirewallPolicy, define the policy. You can retrieve all objects for a firewall policy by calling DescribeFirewallPolicy.  | 


#### Command Example
```!aws-network-firewall-create-firewall-policy firewall_policy_name=example-fw-policy firewall_policy_json="""{"StatelessRuleGroupReferences":[{"ResourceArn":"arn:aws:network-firewall:us-west-2:123456789012:stateless-rulegroup/example-group-stateless","Priority":100}],"StatelessDefaultActions":["aws:pass"],"StatelessFragmentDefaultActions":["aws:pass"]}"""```

#### Context Example
```json
{
    "AWS-NetworkFirewall": {
        "FirewallPolicy": {
            "FirewallPolicyResponse": {
                "FirewallPolicyArn": "arn:aws:network-firewall:us-west-2:123456789012:firewall-policy/example-fw-policy",
                "FirewallPolicyId": "ef867e5c-9bdc-49b3-91f8-e69c8658489f",
                "FirewallPolicyName": "example-fw-policy",
                "FirewallPolicyStatus": "ACTIVE"
            },
            "UpdateToken": "134d2405-4d98-425d-89b5-1dca72cf3c66"
        }
    }
}
```

#### Human Readable Output

>### AWS Network Firewall CreateFirewallPolicy
>|FirewallPolicyResponse|UpdateToken|
>|---|---|
>| FirewallPolicyName: example-fw-policy<br/>FirewallPolicyArn: arn:aws:network-firewall:us-west-2:123456789012:firewall-policy/example-fw-policy<br/>FirewallPolicyId: ef867e5c-9bdc-49b3-91f8-e69c8658489f<br/>FirewallPolicyStatus: ACTIVE | 134d2405-4d98-425d-89b5-1dca72cf3c66 |


### aws-network-firewall-create-rule-group
***
Creates the specified stateless or stateful rule group, which includes the rules for network traffic inspection, a capacity setting, and tags.  You provide your rule group specification in your request using either RuleGroup or Rules.


#### Base Command

`aws-network-firewall-create-rule-group`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. . | Optional | 
| raw_json | Override arguments and send a formatted JSON file. | Optional | 
| rule_group_name | The descriptive name of the rule group. You can't change the name of a rule group after you create it. | Required | 
| rule_group_json | JSON string/object that defines the rule group rules. | Optional | 
| rules | The name of a file containing stateful rule group rules specifications in Suricata flat format, with one rule per line. Use this to import your existing Suricata compatible rule groups.   You must provide either this rules setting or a populated RuleGroup setting, but not both.   You can provide your rule group specification in a file through this setting when you create or update your rule group. The call response returns a RuleGroup object that Network Firewall has populated from your file. Network Firewall uses the file contents to populate the rule group rules, but does not maintain a reference to the file or use the file in any way after performing the create or update. If you call DescribeRuleGroup to retrieve the rule group, Network Firewall returns rules settings inside a RuleGroup object. . | Optional | 
| type | Indicates whether the rule group is stateless or stateful. If the rule group is stateless, it contains stateless rules. If it is stateful, it contains stateful rules. . Possible values are: STATELESS, STATEFUL. | Required | 
| description | A description of the rule group. . | Optional | 
| capacity | (Integer) The maximum operating resources that this rule group can use. Rule group capacity is fixed at creation. When you update a rule group, you are limited to this capacity. When you reference a rule group from a firewall policy, Network Firewall reserves this capacity for the rule group. | Required | 
| tag_key | The Tags key identifier. | Optional | 
| tag_value | The Tags value identifier. | Optional | 
| tags | List of Tags separated by Key Value. For example: "key=key1,value=value1;key=key2,value=value2". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS-NetworkFirewall.RuleGroup.UpdateToken | Unknown | A token used for optimistic locking. Network Firewall returns a token to your requests that access the rule group. The token marks the state of the rule group resource at the time of the request.  To make changes to the rule group, you provide the token in your request. Network Firewall uses the token to ensure that the rule group hasn't changed since you last retrieved it. If it has changed, the operation fails with an InvalidTokenException. If this happens, retrieve the rule group again to get a current copy of it with a current token. Reapply your changes as needed, then try the operation again using the new token.  | 
| AWS-NetworkFirewall.RuleGroup.RuleGroupResponse.RuleGroupArn | Unknown | The Amazon Resource Name \(ARN\) of the rule group.  If this response is for a create request that had DryRun set to TRUE, then this ARN is a placeholder that isn't attached to a valid resource.  | 
| AWS-NetworkFirewall.RuleGroup.RuleGroupResponse.RuleGroupName | Unknown | The descriptive name of the rule group. You can't change the name of a rule group after you create it. | 
| AWS-NetworkFirewall.RuleGroup.RuleGroupResponse.RuleGroupId | Unknown | The unique identifier for the rule group.  | 
| AWS-NetworkFirewall.RuleGroup.RuleGroupResponse.Description | Unknown | A description of the rule group.  | 
| AWS-NetworkFirewall.RuleGroup.RuleGroupResponse.Type | Unknown | Indicates whether the rule group is stateless or stateful. If the rule group is stateless, it contains stateless rules. If it is stateful, it contains stateful rules.  | 
| AWS-NetworkFirewall.RuleGroup.RuleGroupResponse.Capacity | Unknown | The maximum operating resources that this rule group can use. Rule group capacity is fixed at creation. When you update a rule group, you are limited to this capacity. When you reference a rule group from a firewall policy, Network Firewall reserves this capacity for the rule group.  You can retrieve the capacity that would be required for a rule group before you create the rule group by calling CreateRuleGroup with DryRun set to TRUE.  | 
| AWS-NetworkFirewall.RuleGroup.RuleGroupResponse.RuleGroupStatus | Unknown | Detailed information about the current status of a rule group.  | 
| AWS-NetworkFirewall.RuleGroup.RuleGroupResponse.Tags.Key | Unknown | The part of the key:value pair that defines a tag. You can use a tag key to describe a category of information, such as "customer." Tag keys are case-sensitive. | 
| AWS-NetworkFirewall.RuleGroup.RuleGroupResponse.Tags.Value | Unknown | The part of the key:value pair that defines a tag. You can use a tag value to describe a specific value within a category, such as "companyA" or "companyB." Tag values are case-sensitive. | 
| AWS-NetworkFirewall.RuleGroup.RuleGroupResponse.Tags | Unknown | The key:value pairs to associate with the resource. | 
| AWS-NetworkFirewall.RuleGroup.RuleGroupResponse | Unknown | The high-level properties of a rule group. This, along with the RuleGroup, define the rule group. You can retrieve all objects for a rule group by calling DescribeRuleGroup.  | 


#### Command Example
```!aws-network-firewall-create-rule-group type=STATELESS rule_group_name=example-group-stateless capacity=10 rule_group_json="""{"RulesSource":{"StatelessRulesAndCustomActions":{"StatelessRules":[{"RuleDefinition":{"MatchAttributes":{"Sources":[{"AddressDefinition":"10.0.0.0/8"},{"AddressDefinition":"192.168.0.0/16"},{"AddressDefinition":"172.31.0.0/16"}]},"Actions":["aws:pass"]},"Priority":5}]}}}"""```

#### Context Example
```json
{
    "AWS-NetworkFirewall": {
        "RuleGroup": {
            "RuleGroupResponse": {
                "Capacity": 10,
                "RuleGroupArn": "arn:aws:network-firewall:us-west-2:123456789012:stateless-rulegroup/example-group-stateless",
                "RuleGroupId": "ee6230a2-99a4-400b-b1da-fdcc046860f3",
                "RuleGroupName": "example-group-stateless",
                "RuleGroupStatus": "ACTIVE",
                "Type": "STATELESS"
            },
            "UpdateToken": "cb084f42-a286-4406-b3e2-7fce4e104a29"
        }
    }
}
```

#### Human Readable Output

>### AWS Network Firewall CreateRuleGroup
>|RuleGroupResponse|UpdateToken|
>|---|---|
>| RuleGroupArn: arn:aws:network-firewall:us-west-2:123456789012:stateless-rulegroup/example-group-stateless<br/>RuleGroupName: example-group-stateless<br/>RuleGroupId: ee6230a2-99a4-400b-b1da-fdcc046860f3<br/>Type: STATELESS<br/>Capacity: 10<br/>RuleGroupStatus: ACTIVE | cb084f42-a286-4406-b3e2-7fce4e104a29 |


### aws-network-firewall-delete-firewall
***
Deletes the specified Firewall and its FirewallStatus. This operation requires the firewall's DeleteProtection flag to be FALSE. You can't revert this operation.  You can check whether a firewall is in use by reviewing the route tables for the Availability Zones where you have firewall subnet mappings. Retrieve the subnet mappings by calling DescribeFirewall. You define and update the route tables through Amazon VPC. As needed, update the route tables for the zones to remove the firewall endpoints. When the route tables no longer use the firewall endpoints, you can remove the firewall safely. To delete a firewall, remove the delete protection if you need to using UpdateFirewallDeleteProtection, then delete the firewall by calling DeleteFirewall.


#### Base Command

`aws-network-firewall-delete-firewall`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. . | Optional | 
| raw_json | Override arguments and send a formatted JSON file. | Optional | 
| firewall_name | The descriptive name of the firewall. You can't change the name of a firewall after you create it. You must specify the ARN or the name, and you can specify both. . | Optional | 
| firewall_arn | The Amazon Resource Name (ARN) of the firewall. You must specify the ARN or the name, and you can specify both. . | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS-NetworkFirewall.Firewall.Firewall.FirewallName | Unknown | The descriptive name of the firewall. You can't change the name of a firewall after you create it. | 
| AWS-NetworkFirewall.Firewall.Firewall.FirewallArn | Unknown | The Amazon Resource Name \(ARN\) of the firewall. | 
| AWS-NetworkFirewall.Firewall.Firewall.FirewallPolicyArn | Unknown | The Amazon Resource Name \(ARN\) of the firewall policy. The relationship of firewall to firewall policy is many to one. Each firewall requires one firewall policy association, and you can use the same firewall policy for multiple firewalls.  | 
| AWS-NetworkFirewall.Firewall.Firewall.VpcId | Unknown | The unique identifier of the VPC where the firewall is in use.  | 
| AWS-NetworkFirewall.Firewall.Firewall.SubnetMappings.SubnetId | Unknown | The unique identifier for the subnet.  | 
| AWS-NetworkFirewall.Firewall.Firewall.SubnetMappings | Unknown | The public subnets that Network Firewall is using for the firewall. Each subnet must belong to a different Availability Zone.  | 
| AWS-NetworkFirewall.Firewall.Firewall.DeleteProtection | Unknown | A flag indicating whether it is possible to delete the firewall. A setting of TRUE indicates that the firewall is protected against deletion. Use this setting to protect against accidentally deleting a firewall that is in use. When you create a firewall, the operation initializes this flag to TRUE. | 
| AWS-NetworkFirewall.Firewall.Firewall.SubnetChangeProtection | Unknown | A setting indicating whether the firewall is protected against changes to the subnet associations. Use this setting to protect against accidentally modifying the subnet associations for a firewall that is in use. When you create a firewall, the operation initializes this setting to TRUE. | 
| AWS-NetworkFirewall.Firewall.Firewall.FirewallPolicyChangeProtection | Unknown | A setting indicating whether the firewall is protected against a change to the firewall policy association. Use this setting to protect against accidentally modifying the firewall policy for a firewall that is in use. When you create a firewall, the operation initializes this setting to TRUE. | 
| AWS-NetworkFirewall.Firewall.Firewall.Description | Unknown | A description of the firewall. | 
| AWS-NetworkFirewall.Firewall.Firewall.FirewallId | Unknown | The unique identifier for the firewall.  | 
| AWS-NetworkFirewall.Firewall.Firewall.Tags.Key | Unknown | The part of the key:value pair that defines a tag. You can use a tag key to describe a category of information, such as "customer." Tag keys are case-sensitive. | 
| AWS-NetworkFirewall.Firewall.Firewall.Tags.Value | Unknown | The part of the key:value pair that defines a tag. You can use a tag value to describe a specific value within a category, such as "companyA" or "companyB." Tag values are case-sensitive. | 
| AWS-NetworkFirewall.Firewall.Firewall.Tags | Unknown | The key:value pairs to associate with the resource. | 
| AWS-NetworkFirewall.Firewall.FirewallStatus.Status | Unknown | The readiness of the configured firewall to handle network traffic across all of the Availability Zones where you've configured it. This setting is READY only when the ConfigurationSyncStateSummary value is IN\\_SYNC and the Attachment Status values for all of the configured subnets are READY.  | 
| AWS-NetworkFirewall.Firewall.FirewallStatus.ConfigurationSyncStateSummary | Unknown | The configuration sync state for the firewall. This summarizes the sync states reported in the Config settings for all of the Availability Zones where you have configured the firewall.  When you create a firewall or update its configuration, for example by adding a rule group to its firewall policy, Network Firewall distributes the configuration changes to all zones where the firewall is in use. This summary indicates whether the configuration changes have been applied everywhere.  This status must be IN\\_SYNC for the firewall to be ready for use, but it doesn't indicate that the firewall is ready. The Status setting indicates firewall readiness. | 
| AWS-NetworkFirewall.Firewall.FirewallStatus.SyncStates | Unknown | The subnets that you've configured for use by the Network Firewall firewall. This contains one array element per Availability Zone where you've configured a subnet. These objects provide details of the information that is summarized in the ConfigurationSyncStateSummary and Status, broken down by zone and configuration object.  | 


#### Command Example
```!aws-network-firewall-delete-firewall firewall_name=myfirewall```


#### Context Example
```json
{
    "AWS-NetworkFirewall": {
        "Firewall": {
            "Firewall": {
                "DeleteProtection": false,
                "Description": "some description",
                "FirewallArn": "arn:aws:network-firewall:us-west-2:123456789012:firewall/myfirewall",
                "FirewallId": "93498bf3-266d-42a1-94b6-4b0b30edbde8",
                "FirewallName": "myfirewall",
                "FirewallPolicyArn": "arn:aws:network-firewall:us-west-2:123456789012:firewall-policy/example-fw-policy",
                "FirewallPolicyChangeProtection": false,
                "SubnetChangeProtection": false,
                "SubnetMappings": [
                    {
                        "SubnetId": "subnet-aaaaaaa"
                    },
                    {
                        "SubnetId": "subnet-bbbbbbb"
                    }
                ],
                "Tags": [],
                "VpcId": "vpc-abcdef"
            },
            "FirewallStatus": {
                "ConfigurationSyncStateSummary": "IN_SYNC",
                "Status": "DELETING",
                "SyncStates": {
                    "us-west-2a": {
                        "Attachment": {
                            "EndpointId": "vpce-0000000000abcdef",
                            "Status": "READY",
                            "SubnetId": "subnet-bbbbbbb"
                        },
                        "Config": {
                            "arn:aws:network-firewall:us-west-2:123456789012:firewall-policy/example-fw-policy": {
                                "SyncStatus": "IN_SYNC"
                            },
                            "arn:aws:network-firewall:us-west-2:123456789012:stateless-rulegroup/example-group-stateless": {
                                "SyncStatus": "IN_SYNC"
                            }
                        }
                    },
                    "us-west-2b": {
                        "Attachment": {
                            "EndpointId": "vpce-000000000aaaaaaa",
                            "Status": "READY",
                            "SubnetId": "subnet-aaaaaaa"
                        },
                        "Config": {
                            "arn:aws:network-firewall:us-west-2:123456789012:firewall-policy/example-fw-policy": {
                                "SyncStatus": "IN_SYNC"
                            },
                            "arn:aws:network-firewall:us-west-2:123456789012:stateless-rulegroup/example-group-stateless": {
                                "SyncStatus": "IN_SYNC"
                            }
                        }
                    }
                }
            }
        }
    }
}
```

#### Human Readable Output

>### AWS Network Firewall DeleteFirewall
>|Firewall|FirewallStatus|
>|---|---|
>| FirewallName: myfirewall<br/>FirewallArn: arn:aws:network-firewall:us-west-2:123456789012:firewall/myfirewall<br/>FirewallPolicyArn: arn:aws:network-firewall:us-west-2:123456789012:firewall-policy/example-fw-policy<br/>VpcId: vpc-abcdef<br/>SubnetMappings: {'SubnetId': 'subnet-aaaaaaa'},<br/>{'SubnetId': 'subnet-bbbbbbb'}<br/>DeleteProtection: false<br/>SubnetChangeProtection: false<br/>FirewallPolicyChangeProtection: false<br/>Description: some description<br/>FirewallId: 93498bf3-266d-42a1-94b6-4b0b30edbde8<br/>Tags:  | Status: DELETING<br/>ConfigurationSyncStateSummary: IN_SYNC<br/>SyncStates: {"us-west-2a": {"Attachment": {"SubnetId": "subnet-bbbbbbb", "EndpointId": "vpce-0000000000abcdef", "Status": "READY"}, "Config": {"arn:aws:network-firewall:us-west-2:123456789012:firewall-policy/example-fw-policy": {"SyncStatus": "IN_SYNC"}, "arn:aws:network-firewall:us-west-2:123456789012:stateless-rulegroup/example-group-stateless": {"SyncStatus": "IN_SYNC"}}}, "us-west-2b": {"Attachment": {"SubnetId": "subnet-aaaaaaa", "EndpointId": "vpce-000000000aaaaaaa", "Status": "READY"}, "Config": {"arn:aws:network-firewall:us-west-2:123456789012:firewall-policy/example-fw-policy": {"SyncStatus": "IN_SYNC"}, "arn:aws:network-firewall:us-west-2:123456789012:stateless-rulegroup/example-group-stateless": {"SyncStatus": "IN_SYNC"}}}} |


### aws-network-firewall-delete-firewall-policy
***
Deletes the specified FirewallPolicy.


#### Base Command

`aws-network-firewall-delete-firewall-policy`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. . | Optional | 
| raw_json | Override arguments and send a formatted JSON file. | Optional | 
| firewall_policy_name | The descriptive name of the firewall policy. You can't change the name of a firewall policy after you create it. You must specify the ARN or the name, and you can specify both. . | Optional | 
| firewall_policy_arn | The Amazon Resource Name (ARN) of the firewall policy. You must specify the ARN or the name, and you can specify both. . | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS-NetworkFirewall.FirewallPolicy.FirewallPolicyResponse.FirewallPolicyName | Unknown | The descriptive name of the firewall policy. You can't change the name of a firewall policy after you create it. | 
| AWS-NetworkFirewall.FirewallPolicy.FirewallPolicyResponse.FirewallPolicyArn | Unknown | The Amazon Resource Name \(ARN\) of the firewall policy.  If this response is for a create request that had DryRun set to TRUE, then this ARN is a placeholder that isn't attached to a valid resource.  | 
| AWS-NetworkFirewall.FirewallPolicy.FirewallPolicyResponse.FirewallPolicyId | Unknown | The unique identifier for the firewall policy.  | 
| AWS-NetworkFirewall.FirewallPolicy.FirewallPolicyResponse.Description | Unknown | A description of the firewall policy. | 
| AWS-NetworkFirewall.FirewallPolicy.FirewallPolicyResponse.FirewallPolicyStatus | Unknown | The current status of the firewall policy. You can retrieve this for a firewall policy by calling DescribeFirewallPolicy and providing the firewall policy's name or ARN. | 
| AWS-NetworkFirewall.FirewallPolicy.FirewallPolicyResponse.Tags.Key | Unknown | The part of the key:value pair that defines a tag. You can use a tag key to describe a category of information, such as "customer." Tag keys are case-sensitive. | 
| AWS-NetworkFirewall.FirewallPolicy.FirewallPolicyResponse.Tags.Value | Unknown | The part of the key:value pair that defines a tag. You can use a tag value to describe a specific value within a category, such as "companyA" or "companyB." Tag values are case-sensitive. | 
| AWS-NetworkFirewall.FirewallPolicy.FirewallPolicyResponse.Tags | Unknown | The key:value pairs to associate with the resource. | 
| AWS-NetworkFirewall.FirewallPolicy.FirewallPolicyResponse | Unknown | The object containing the definition of the FirewallPolicyResponse that you asked to delete.  | 


#### Command Example
```!aws-network-firewall-delete-firewall-policy firewall_policy_arn=arn:aws:network-firewall:us-west-2:123456789012:firewall-policy/example-fw-policy2```


#### Context Example
```json
{
    "AWS-NetworkFirewall": {
        "FirewallPolicy": {
            "FirewallPolicyResponse": {
                "FirewallPolicyArn": "arn:aws:network-firewall:us-west-2:123456789012:firewall-policy/example-fw-policy2",
                "FirewallPolicyId": "f9253d2f-acf7-465b-97f0-f8f52a7a756f",
                "FirewallPolicyName": "example-fw-policy2",
                "FirewallPolicyStatus": "DELETING",
                "Tags": []
            }
        }
    }
}
```

#### Human Readable Output

>### AWS Network Firewall DeleteFirewallPolicy
>|FirewallPolicyArn|FirewallPolicyId|FirewallPolicyName|FirewallPolicyStatus|Tags|
>|---|---|---|---|---|
>| arn:aws:network-firewall:us-west-2:123456789012:firewall-policy/example-fw-policy2 | f9253d2f-acf7-465b-97f0-f8f52a7a756f | example-fw-policy2 | DELETING |  |


### aws-network-firewall-delete-resource-policy
***
Deletes a resource policy that you created in a PutResourcePolicy request.


#### Base Command

`aws-network-firewall-delete-resource-policy`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. . | Optional | 
| raw_json | Override arguments and send a formatted JSON file. | Optional | 
| resource_arn | The Amazon Resource Name (ARN) of the rule group or firewall policy whose resource policy you want to delete. . | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!aws-network-firewall-delete-resource-policy resource_arn=arn:aws:network-firewall:us-west-2:123456789012:stateless-rulegroup/example-group-stateless2```

#### Context Example
```json
{}
```

#### Human Readable Output

>### AWS Network Firewall DeleteResourcePolicy
>**No entries.**


### aws-network-firewall-delete-rule-group
***
Deletes the specified RuleGroup.


#### Base Command

`aws-network-firewall-delete-rule-group`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. . | Optional | 
| raw_json | Override arguments and send a formatted JSON file. | Optional | 
| rule_group_name | The descriptive name of the rule group. You can't change the name of a rule group after you create it. You must specify the ARN or the name, and you can specify both. . | Optional | 
| rule_group_arn | The Amazon Resource Name (ARN) of the rule group. You must specify the ARN or the name, and you can specify both. . | Optional | 
| type | Indicates whether the rule group is stateless or stateful. If the rule group is stateless, it contains stateless rules. If it is stateful, it contains stateful rules.   This setting is required for requests that do not include the RuleGroupARN. . Possible values are: STATELESS, STATEFUL. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS-NetworkFirewall.RuleGroup.RuleGroupResponse.RuleGroupArn | Unknown | The Amazon Resource Name \(ARN\) of the rule group.  If this response is for a create request that had DryRun set to TRUE, then this ARN is a placeholder that isn't attached to a valid resource.  | 
| AWS-NetworkFirewall.RuleGroup.RuleGroupResponse.RuleGroupName | Unknown | The descriptive name of the rule group. You can't change the name of a rule group after you create it. | 
| AWS-NetworkFirewall.RuleGroup.RuleGroupResponse.RuleGroupId | Unknown | The unique identifier for the rule group.  | 
| AWS-NetworkFirewall.RuleGroup.RuleGroupResponse.Description | Unknown | A description of the rule group.  | 
| AWS-NetworkFirewall.RuleGroup.RuleGroupResponse.Type | Unknown | Indicates whether the rule group is stateless or stateful. If the rule group is stateless, it contains stateless rules. If it is stateful, it contains stateful rules.  | 
| AWS-NetworkFirewall.RuleGroup.RuleGroupResponse.Capacity | Unknown | The maximum operating resources that this rule group can use. Rule group capacity is fixed at creation. When you update a rule group, you are limited to this capacity. When you reference a rule group from a firewall policy, Network Firewall reserves this capacity for the rule group.  You can retrieve the capacity that would be required for a rule group before you create the rule group by calling CreateRuleGroup with DryRun set to TRUE.  | 
| AWS-NetworkFirewall.RuleGroup.RuleGroupResponse.RuleGroupStatus | Unknown | Detailed information about the current status of a rule group.  | 
| AWS-NetworkFirewall.RuleGroup.RuleGroupResponse.Tags.Key | Unknown | The part of the key:value pair that defines a tag. You can use a tag key to describe a category of information, such as "customer." Tag keys are case-sensitive. | 
| AWS-NetworkFirewall.RuleGroup.RuleGroupResponse.Tags.Value | Unknown | The part of the key:value pair that defines a tag. You can use a tag value to describe a specific value within a category, such as "companyA" or "companyB." Tag values are case-sensitive. | 
| AWS-NetworkFirewall.RuleGroup.RuleGroupResponse.Tags | Unknown | The key:value pairs to associate with the resource. | 
| AWS-NetworkFirewall.RuleGroup.RuleGroupResponse | Unknown | The high-level properties of a rule group. This, along with the RuleGroup, define the rule group. You can retrieve all objects for a rule group by calling DescribeRuleGroup.  | 


#### Command Example
```!aws-network-firewall-delete-rule-group rule_group_arn=arn:aws:network-firewall:us-west-2:123456789012:stateless-rulegroup/example-group-stateless3```

#### Context Example
```json
{
    "AWS-NetworkFirewall": {
        "RuleGroup": {
            "RuleGroupResponse": {
                "Capacity": 10,
                "RuleGroupArn": "arn:aws:network-firewall:us-west-2:123456789012:stateless-rulegroup/example-group-stateless3",
                "RuleGroupId": "43010e51-6c14-475a-9143-93db2dd5fbac",
                "RuleGroupName": "example-group-stateless3",
                "RuleGroupStatus": "DELETING",
                "Tags": [],
                "Type": "STATELESS"
            }
        }
    }
}
```

#### Human Readable Output

>### AWS Network Firewall DeleteRuleGroup
>|Capacity|RuleGroupArn|RuleGroupId|RuleGroupName|RuleGroupStatus|Tags|Type|
>|---|---|---|---|---|---|---|
>| 10 | arn:aws:network-firewall:us-west-2:123456789012:stateless-rulegroup/example-group-stateless3 | 43010e51-6c14-475a-9143-93db2dd5fbac | example-group-stateless3 | DELETING |  | STATELESS |


### aws-network-firewall-describe-firewall
***
Returns the data objects for the specified firewall.


#### Base Command

`aws-network-firewall-describe-firewall`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. . | Optional | 
| raw_json | Override arguments and send a formatted JSON file. | Optional | 
| firewall_name | The descriptive name of the firewall. You can't change the name of a firewall after you create it. You must specify the ARN or the name, and you can specify both. . | Optional | 
| firewall_arn | The Amazon Resource Name (ARN) of the firewall. You must specify the ARN or the name, and you can specify both. . | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS-NetworkFirewall.Firewall.UpdateToken | Unknown | An optional token that you can use for optimistic locking. Network Firewall returns a token to your requests that access the firewall. The token marks the state of the firewall resource at the time of the request.  To make an unconditional change to the firewall, omit the token in your update request. Without the token, Network Firewall performs your updates regardless of whether the firewall has changed since you last retrieved it. To make a conditional change to the firewall, provide the token in your update request. Network Firewall uses the token to ensure that the firewall hasn't changed since you last retrieved it. If it has changed, the operation fails with an InvalidTokenException. If this happens, retrieve the firewall again to get a current copy of it with a new token. Reapply your changes as needed, then try the operation again using the new token.  | 
| AWS-NetworkFirewall.Firewall.Firewall.FirewallName | Unknown | The descriptive name of the firewall. You can't change the name of a firewall after you create it. | 
| AWS-NetworkFirewall.Firewall.Firewall.FirewallArn | Unknown | The Amazon Resource Name \(ARN\) of the firewall. | 
| AWS-NetworkFirewall.Firewall.Firewall.FirewallPolicyArn | Unknown | The Amazon Resource Name \(ARN\) of the firewall policy. The relationship of firewall to firewall policy is many to one. Each firewall requires one firewall policy association, and you can use the same firewall policy for multiple firewalls.  | 
| AWS-NetworkFirewall.Firewall.Firewall.VpcId | Unknown | The unique identifier of the VPC where the firewall is in use.  | 
| AWS-NetworkFirewall.Firewall.Firewall.SubnetMappings.SubnetId | Unknown | The unique identifier for the subnet.  | 
| AWS-NetworkFirewall.Firewall.Firewall.SubnetMappings | Unknown | The public subnets that Network Firewall is using for the firewall. Each subnet must belong to a different Availability Zone.  | 
| AWS-NetworkFirewall.Firewall.Firewall.DeleteProtection | Unknown | A flag indicating whether it is possible to delete the firewall. A setting of TRUE indicates that the firewall is protected against deletion. Use this setting to protect against accidentally deleting a firewall that is in use. When you create a firewall, the operation initializes this flag to TRUE. | 
| AWS-NetworkFirewall.Firewall.Firewall.SubnetChangeProtection | Unknown | A setting indicating whether the firewall is protected against changes to the subnet associations. Use this setting to protect against accidentally modifying the subnet associations for a firewall that is in use. When you create a firewall, the operation initializes this setting to TRUE. | 
| AWS-NetworkFirewall.Firewall.Firewall.FirewallPolicyChangeProtection | Unknown | A setting indicating whether the firewall is protected against a change to the firewall policy association. Use this setting to protect against accidentally modifying the firewall policy for a firewall that is in use. When you create a firewall, the operation initializes this setting to TRUE. | 
| AWS-NetworkFirewall.Firewall.Firewall.Description | Unknown | A description of the firewall. | 
| AWS-NetworkFirewall.Firewall.Firewall.FirewallId | Unknown | The unique identifier for the firewall.  | 
| AWS-NetworkFirewall.Firewall.Firewall.Tags.Key | Unknown | The part of the key:value pair that defines a tag. You can use a tag key to describe a category of information, such as "customer." Tag keys are case-sensitive. | 
| AWS-NetworkFirewall.Firewall.Firewall.Tags.Value | Unknown | The part of the key:value pair that defines a tag. You can use a tag value to describe a specific value within a category, such as "companyA" or "companyB." Tag values are case-sensitive. | 
| AWS-NetworkFirewall.Firewall.Firewall.Tags | Unknown | The key:value pairs to associate with the resource. | 
| AWS-NetworkFirewall.Firewall.Firewall | Unknown | The configuration settings for the firewall. These settings include the firewall policy and the subnets in your VPC to use for the firewall endpoints.  | 
| AWS-NetworkFirewall.Firewall.FirewallStatus.Status | Unknown | The readiness of the configured firewall to handle network traffic across all of the Availability Zones where you've configured it. This setting is READY only when the ConfigurationSyncStateSummary value is IN\\_SYNC and the Attachment Status values for all of the configured subnets are READY.  | 
| AWS-NetworkFirewall.Firewall.FirewallStatus.ConfigurationSyncStateSummary | Unknown | The configuration sync state for the firewall. This summarizes the sync states reported in the Config settings for all of the Availability Zones where you have configured the firewall.  When you create a firewall or update its configuration, for example by adding a rule group to its firewall policy, Network Firewall distributes the configuration changes to all zones where the firewall is in use. This summary indicates whether the configuration changes have been applied everywhere.  This status must be IN\\_SYNC for the firewall to be ready for use, but it doesn't indicate that the firewall is ready. The Status setting indicates firewall readiness. | 
| AWS-NetworkFirewall.Firewall.FirewallStatus.SyncStates | Unknown | The subnets that you've configured for use by the Network Firewall firewall. This contains one array element per Availability Zone where you've configured a subnet. These objects provide details of the information that is summarized in the ConfigurationSyncStateSummary and Status, broken down by zone and configuration object.  | 
| AWS-NetworkFirewall.Firewall.FirewallStatus | Unknown | Detailed information about the current status of a Firewall. You can retrieve this for a firewall by calling DescribeFirewall and providing the firewall name and ARN. | 


#### Command Example
```!aws-network-firewall-describe-firewall firewall_name=myfirewall2```

#### Context Example
```json
{
    "AWS-NetworkFirewall": {
        "Firewall": {
            "Firewall": {
                "DeleteProtection": false,
                "FirewallArn": "arn:aws:network-firewall:us-west-2:123456789012:firewall/myfirewall2",
                "FirewallId": "9f7ce834-a43b-4bcc-8e54-a44dff6de461",
                "FirewallName": "myfirewall2",
                "FirewallPolicyArn": "arn:aws:network-firewall:us-west-2:123456789012:firewall-policy/example-fw-policy2",
                "FirewallPolicyChangeProtection": false,
                "SubnetChangeProtection": false,
                "SubnetMappings": [
                    {
                        "SubnetId": "subnet-aaaaaaa"
                    }
                ],
                "Tags": [],
                "VpcId": "vpc-abcdef"
            },
            "FirewallStatus": {
                "ConfigurationSyncStateSummary": "IN_SYNC",
                "Status": "PROVISIONING",
                "SyncStates": {
                    "us-west-2a": {
                        "Attachment": {
                            "EndpointId": "vpce-0000000000abcdef",
                            "Status": "CREATING",
                            "SubnetId": "subnet-bbbbbbb"
                        },
                        "Config": {
                            "arn:aws:network-firewall:us-west-2:123456789012:firewall-policy/example-fw-policy2": {
                                "SyncStatus": "IN_SYNC"
                            },
                            "arn:aws:network-firewall:us-west-2:123456789012:stateless-rulegroup/example-group-stateless2": {
                                "SyncStatus": "IN_SYNC"
                            }
                        }
                    },
                    "us-west-2b": {
                        "Attachment": {
                            "EndpointId": "vpce-000000000aaaaaaa",
                            "Status": "READY",
                            "SubnetId": "subnet-aaaaaaa"
                        },
                        "Config": {
                            "arn:aws:network-firewall:us-west-2:123456789012:firewall-policy/example-fw-policy2": {
                                "SyncStatus": "IN_SYNC"
                            },
                            "arn:aws:network-firewall:us-west-2:123456789012:stateless-rulegroup/example-group-stateless2": {
                                "SyncStatus": "IN_SYNC"
                            }
                        }
                    }
                }
            },
            "UpdateToken": "3cd6d327-33d1-4c0e-8452-f61bdf9b218c"
        }
    }
}
```

#### Human Readable Output

>### AWS Network Firewall DescribeFirewall
>|Firewall|FirewallStatus|UpdateToken|
>|---|---|---|
>| FirewallName: myfirewall2<br/>FirewallArn: arn:aws:network-firewall:us-west-2:123456789012:firewall/myfirewall2<br/>FirewallPolicyArn: arn:aws:network-firewall:us-west-2:123456789012:firewall-policy/example-fw-policy2<br/>VpcId: vpc-abcdef<br/>SubnetMappings: {'SubnetId': 'subnet-aaaaaaa'}<br/>DeleteProtection: false<br/>SubnetChangeProtection: false<br/>FirewallPolicyChangeProtection: false<br/>FirewallId: 9f7ce834-a43b-4bcc-8e54-a44dff6de461<br/>Tags:  | Status: PROVISIONING<br/>ConfigurationSyncStateSummary: IN_SYNC<br/>SyncStates: {"us-west-2a": {"Attachment": {"SubnetId": "subnet-bbbbbbb", "EndpointId": "vpce-0000000000abcdef", "Status": "CREATING"}, "Config": {"arn:aws:network-firewall:us-west-2:123456789012:firewall-policy/example-fw-policy2": {"SyncStatus": "IN_SYNC"}, "arn:aws:network-firewall:us-west-2:123456789012:stateless-rulegroup/example-group-stateless2": {"SyncStatus": "IN_SYNC"}}}, "us-west-2b": {"Attachment": {"SubnetId": "subnet-aaaaaaa", "EndpointId": "vpce-000000000aaaaaaa", "Status": "READY"}, "Config": {"arn:aws:network-firewall:us-west-2:123456789012:firewall-policy/example-fw-policy2": {"SyncStatus": "IN_SYNC"}, "arn:aws:network-firewall:us-west-2:123456789012:stateless-rulegroup/example-group-stateless2": {"SyncStatus": "IN_SYNC"}}}} | 3cd6d327-33d1-4c0e-8452-f61bdf9b218c |


### aws-network-firewall-describe-firewall-policy
***
Returns the data objects for the specified firewall policy.


#### Base Command

`aws-network-firewall-describe-firewall-policy`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. . | Optional | 
| raw_json | Override arguments and send a formatted JSON file. | Optional | 
| firewall_policy_name | The descriptive name of the firewall policy. You can't change the name of a firewall policy after you create it. You must specify the ARN or the name, and you can specify both. . | Optional | 
| firewall_policy_arn | The Amazon Resource Name (ARN) of the firewall policy. You must specify the ARN or the name, and you can specify both. . | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS-NetworkFirewall.FirewallPolicy.UpdateToken | Unknown | A token used for optimistic locking. Network Firewall returns a token to your requests that access the firewall policy. The token marks the state of the policy resource at the time of the request.  To make changes to the policy, you provide the token in your request. Network Firewall uses the token to ensure that the policy hasn't changed since you last retrieved it. If it has changed, the operation fails with an InvalidTokenException. If this happens, retrieve the firewall policy again to get a current copy of it with current token. Reapply your changes as needed, then try the operation again using the new token.  | 
| AWS-NetworkFirewall.FirewallPolicy.FirewallPolicyResponse.FirewallPolicyName | Unknown | The descriptive name of the firewall policy. You can't change the name of a firewall policy after you create it. | 
| AWS-NetworkFirewall.FirewallPolicy.FirewallPolicyResponse.FirewallPolicyArn | Unknown | The Amazon Resource Name \(ARN\) of the firewall policy.  If this response is for a create request that had DryRun set to TRUE, then this ARN is a placeholder that isn't attached to a valid resource.  | 
| AWS-NetworkFirewall.FirewallPolicy.FirewallPolicyResponse.FirewallPolicyId | Unknown | The unique identifier for the firewall policy.  | 
| AWS-NetworkFirewall.FirewallPolicy.FirewallPolicyResponse.Description | Unknown | A description of the firewall policy. | 
| AWS-NetworkFirewall.FirewallPolicy.FirewallPolicyResponse.FirewallPolicyStatus | Unknown | The current status of the firewall policy. You can retrieve this for a firewall policy by calling DescribeFirewallPolicy and providing the firewall policy's name or ARN. | 
| AWS-NetworkFirewall.FirewallPolicy.FirewallPolicyResponse.Tags.Key | Unknown | The part of the key:value pair that defines a tag. You can use a tag key to describe a category of information, such as "customer." Tag keys are case-sensitive. | 
| AWS-NetworkFirewall.FirewallPolicy.FirewallPolicyResponse.Tags.Value | Unknown | The part of the key:value pair that defines a tag. You can use a tag value to describe a specific value within a category, such as "companyA" or "companyB." Tag values are case-sensitive. | 
| AWS-NetworkFirewall.FirewallPolicy.FirewallPolicyResponse.Tags | Unknown | The key:value pairs to associate with the resource. | 
| AWS-NetworkFirewall.FirewallPolicy.FirewallPolicyResponse | Unknown | The high-level properties of a firewall policy. This, along with the FirewallPolicy, define the policy. You can retrieve all objects for a firewall policy by calling DescribeFirewallPolicy.  | 
| AWS-NetworkFirewall.FirewallPolicy.FirewallPolicy.StatelessRuleGroupReferences | Unknown | References to the stateless rule groups that are used in the policy. These define the matching criteria in stateless rules.  | 
| AWS-NetworkFirewall.FirewallPolicy.FirewallPolicy.StatelessDefaultActions | Unknown | The actions to take on a packet if it doesn't match any of the stateless rules in the policy. If you want non-matching packets to be forwarded for stateful inspection, specify aws:forward\\_to\\_sfe.  You must specify one of the standard actions: aws:pass, aws:drop, or aws:forward\\_to\\_sfe. In addition, you can specify custom actions that are compatible with your standard section choice. For example, you could specify \["aws:pass"\] or you could specify \["aws:pass", ?customActionName?\]. For information about compatibility, see the custom action descriptions under CustomAction. | 
| AWS-NetworkFirewall.FirewallPolicy.FirewallPolicy.StatelessFragmentDefaultActions | Unknown | The actions to take on a fragmented packet if it doesn't match any of the stateless rules in the policy. If you want non-matching fragmented packets to be forwarded for stateful inspection, specify aws:forward\\_to\\_sfe.  You must specify one of the standard actions: aws:pass, aws:drop, or aws:forward\\_to\\_sfe. In addition, you can specify custom actions that are compatible with your standard section choice. For example, you could specify \["aws:pass"\] or you could specify \["aws:pass", ?customActionName?\]. For information about compatibility, see the custom action descriptions under CustomAction. | 
| AWS-NetworkFirewall.FirewallPolicy.FirewallPolicy.StatelessCustomActions | Unknown | The custom action definitions that are available for use in the firewall policy's StatelessDefaultActions setting. You name each custom action that you define, and then you can use it by name in your default actions specifications. | 
| AWS-NetworkFirewall.FirewallPolicy.FirewallPolicy.StatefulRuleGroupReferences | Unknown | References to the stateless rule groups that are used in the policy. These define the inspection criteria in stateful rules.  | 
| AWS-NetworkFirewall.FirewallPolicy.FirewallPolicy | Unknown | The policy for the specified firewall policy.  | 


#### Command Example
```!aws-network-firewall-describe-firewall-policy firewall_policy_arn=arn:aws:network-firewall:us-west-2:123456789012:firewall-policy/example-fw-policy2```

#### Context Example
```json
{
    "AWS-NetworkFirewall": {
        "FirewallPolicy": {
            "FirewallPolicy": {
                "StatelessDefaultActions": [
                    "aws:pass"
                ],
                "StatelessFragmentDefaultActions": [
                    "aws:pass"
                ],
                "StatelessRuleGroupReferences": [
                    {
                        "Priority": 100,
                        "ResourceArn": "arn:aws:network-firewall:us-west-2:123456789012:stateless-rulegroup/example-group-stateless2"
                    }
                ]
            },
            "FirewallPolicyResponse": {
                "FirewallPolicyArn": "arn:aws:network-firewall:us-west-2:123456789012:firewall-policy/example-fw-policy2",
                "FirewallPolicyId": "f9253d2f-acf7-465b-97f0-f8f52a7a756f",
                "FirewallPolicyName": "example-fw-policy2",
                "FirewallPolicyStatus": "ACTIVE",
                "Tags": []
            },
            "UpdateToken": "4fa9513c-d33b-4980-8b6e-f00ef7a2af99"
        }
    }
}
```

#### Human Readable Output

>### AWS Network Firewall DescribeFirewallPolicy
>|FirewallPolicy|FirewallPolicyResponse|UpdateToken|
>|---|---|---|
>| StatelessRuleGroupReferences: {'ResourceArn': 'arn:aws:network-firewall:us-west-2:123456789012:stateless-rulegroup/example-group-stateless2', 'Priority': 100}<br/>StatelessDefaultActions: aws:pass<br/>StatelessFragmentDefaultActions: aws:pass | FirewallPolicyName: example-fw-policy2<br/>FirewallPolicyArn: arn:aws:network-firewall:us-west-2:123456789012:firewall-policy/example-fw-policy2<br/>FirewallPolicyId: f9253d2f-acf7-465b-97f0-f8f52a7a756f<br/>FirewallPolicyStatus: ACTIVE<br/>Tags:  | 4fa9513c-d33b-4980-8b6e-f00ef7a2af99 |


### aws-network-firewall-describe-logging-configuration
***
Returns the logging configuration for the specified firewall.


#### Base Command

`aws-network-firewall-describe-logging-configuration`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. . | Optional | 
| raw_json | Override arguments and send a formatted JSON file. | Optional | 
| firewall_arn | The Amazon Resource Name (ARN) of the firewall. You must specify the ARN or the name, and you can specify both. . | Optional | 
| firewall_name | The descriptive name of the firewall. You can't change the name of a firewall after you create it. You must specify the ARN or the name, and you can specify both. . | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS-NetworkFirewall.Logging.FirewallArn | Unknown | The Amazon Resource Name \(ARN\) of the firewall. | 
| AWS-NetworkFirewall.Logging.LoggingConfiguration.LogDestinationConfigs.LogType | Unknown | The type of log to send. Alert logs report traffic that matches a StatefulRule with an action setting that sends an alert log message. Flow logs are standard network traffic flow logs.  | 
| AWS-NetworkFirewall.Logging.LoggingConfiguration.LogDestinationConfigs.LogDestinationType | Unknown | The type of storage destination to send these logs to. You can send logs to an Amazon S3 bucket, a CloudWatch log group, or a Kinesis Data Firehose delivery stream. | 
| AWS-NetworkFirewall.Logging.LoggingConfiguration.LogDestinationConfigs.LogDestination | Unknown | The named location for the logs, provided in a key:value mapping that is specific to the chosen destination type.   \*  For an Amazon S3 bucket, provide the name of the bucket, with key bucketName, and optionally provide a prefix, with key prefix. The following example specifies an Amazon S3 bucket named DOC-EXAMPLE-BUCKET and the prefix alerts:   "LogDestination": \{ "bucketName": "DOC-EXAMPLE-BUCKET", "prefix": "alerts" \}  
 \*  For a CloudWatch log group, provide the name of the CloudWatch log group, with key logGroup. The following example specifies a log group named alert-log-group:   "LogDestination": \{ "logGroup": "alert-log-group" \}  
 \*  For a Kinesis Data Firehose delivery stream, provide the name of the delivery stream, with key deliveryStream. The following example specifies a delivery stream named alert-delivery-stream:   "LogDestination": \{ "deliveryStream": "alert-delivery-stream" \}  
  | 
| AWS-NetworkFirewall.Logging.LoggingConfiguration.LogDestinationConfigs | Unknown | Defines the logging destinations for the logs for a firewall. Network Firewall generates logs for stateful rule groups.  | 


#### Command Example
```!aws-network-firewall-describe-logging-configuration firewall_name=myfirewall2```

#### Context Example
```json
{
    "AWS-NetworkFirewall": {
        "Logging": {
            "FirewallArn": "arn:aws:network-firewall:us-west-2:123456789012:firewall/myfirewall2",
            "LoggingConfiguration": {
                "LogDestinationConfigs": [
                    {
                        "LogDestination": {
                            "bucketName": "xsoar-demo-test-bucket-network-firewall",
                            "prefix": "alerts"
                        },
                        "LogDestinationType": "S3",
                        "LogType": "ALERT"
                    }
                ]
            }
        }
    }
}
```

#### Human Readable Output

>### AWS Network Firewall DescribeLoggingConfiguration
>|FirewallArn|LoggingConfiguration|
>|---|---|
>| arn:aws:network-firewall:us-west-2:123456789012:firewall/myfirewall2 | LogDestinationConfigs: {'LogType': 'ALERT', 'LogDestinationType': 'S3', 'LogDestination': {'bucketName': 'xsoar-demo-test-bucket-network-firewall', 'prefix': 'alerts'}} |


### aws-network-firewall-describe-resource-policy
***
Retrieves a resource policy that you created in a PutResourcePolicy request.


#### Base Command

`aws-network-firewall-describe-resource-policy`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. . | Optional | 
| raw_json | Override arguments and send a formatted JSON file. | Optional | 
| resource_arn | The Amazon Resource Name (ARN) of the rule group or firewall policy whose resource policy you want to retrieve. . | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS-Network Firewall.Policy | Unknown | The AWS Identity and Access Management policy for the resource.  | 


#### Command Example
```!aws-network-firewall-describe-resource-policy resource_arn=arn:aws:network-firewall:us-west-2:123456789012:stateless-rulegroup/example-group-stateless2```

#### Context Example
```json
{
    "AWS-Network Firewall": {
        "Policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"arn:aws:iam::123456789012:root\"},\"Action\":[\"network-firewall:CreateFirewallPolicy\",\"network-firewall:UpdateFirewallPolicy\",\"network-firewall:ListRuleGroups\"],\"Resource\":\"arn:aws:network-firewall:us-west-2:123456789012:stateless-rulegroup/example-group-stateless2\"}]}"
    }
}
```

#### Human Readable Output

>### AWS Network Firewall DescribeResourcePolicy
>|Policy|
>|---|
>| {"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:root"},"Action":["network-firewall:CreateFirewallPolicy","network-firewall:UpdateFirewallPolicy","network-firewall:ListRuleGroups"],"Resource":"arn:aws:network-firewall:us-west-2:123456789012:stateless-rulegroup/example-group-stateless2"}]} |


### aws-network-firewall-describe-rule-group
***
Returns the data objects for the specified rule group.


#### Base Command

`aws-network-firewall-describe-rule-group`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. . | Optional | 
| raw_json | Override arguments and send a formatted JSON file. | Optional | 
| rule_group_name | The descriptive name of the rule group. You can't change the name of a rule group after you create it. You must specify the ARN or the name, and you can specify both. . | Optional | 
| rule_group_arn | The Amazon Resource Name (ARN) of the rule group. You must specify the ARN or the name, and you can specify both. . | Optional | 
| type | Indicates whether the rule group is stateless or stateful. If the rule group is stateless, it contains stateless rules. If it is stateful, it contains stateful rules.   This setting is required for requests that do not include the RuleGroupARN. . Possible values are: STATELESS, STATEFUL. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS-NetworkFirewall.RuleGroup.UpdateToken | Unknown | A token used for optimistic locking. Network Firewall returns a token to your requests that access the rule group. The token marks the state of the rule group resource at the time of the request.  To make changes to the rule group, you provide the token in your request. Network Firewall uses the token to ensure that the rule group hasn't changed since you last retrieved it. If it has changed, the operation fails with an InvalidTokenException. If this happens, retrieve the rule group again to get a current copy of it with a current token. Reapply your changes as needed, then try the operation again using the new token.  | 
| AWS-NetworkFirewall.RuleGroup.RuleGroup.RuleVariables.IPSets | Unknown | A list of IP addresses and address ranges, in CIDR notation.  | 
| AWS-NetworkFirewall.RuleGroup.RuleGroup.RuleVariables.PortSets | Unknown | A list of port ranges.  | 
| AWS-NetworkFirewall.RuleGroup.RuleGroup.RuleVariables | Unknown | Settings that are available for use in the rules in the rule group. You can only use these for stateful rule groups.  | 
| AWS-NetworkFirewall.RuleGroup.RuleGroup.RulesSource.RulesString | Unknown | Stateful inspection criteria, provided in Suricata compatible intrusion prevention system \(IPS\) rules. Suricata is an open-source network IPS that includes a standard rule-based language for network traffic inspection. These rules contain the inspection criteria and the action to take for traffic that matches the criteria, so this type of rule group doesn't have a separate action setting. You can provide the rules from a file that you've stored in an Amazon S3 bucket, or by providing the rules in a Suricata rules string. To import from Amazon S3, provide the fully qualified name of the file that contains the rules definitions. To provide a Suricata rule string, provide the complete, Suricata compatible rule. | 
| AWS-NetworkFirewall.RuleGroup.RuleGroup.RulesSource.RulesSourceList.Targets | Unknown | The domains that you want to inspect for in your traffic flows. To provide multiple domains, separate them with commas. | 
| AWS-NetworkFirewall.RuleGroup.RuleGroup.RulesSource.RulesSourceList.TargetTypes | Unknown | TLS_SNI and HTTP_HOST | 
| AWS-NetworkFirewall.RuleGroup.RuleGroup.RulesSource.RulesSourceList.GeneratedRulesType | Unknown | Whether you want to allow or deny access to the domains in your target list. | 
| AWS-NetworkFirewall.RuleGroup.RuleGroup.RulesSource.RulesSourceList | Unknown | Stateful inspection criteria for a domain list rule group.  | 
| AWS-NetworkFirewall.RuleGroup.RuleGroup.RulesSource.StatefulRules.Action | Unknown | Defines what Network Firewall should do with the packets in a traffic flow when the flow matches the stateful rule criteria. For all actions, Network Firewall performs the specified action and discontinues stateful inspection of the traffic flow.  The actions for a stateful rule are defined as follows:   \*   \*\*PASS\*\* - Permits the packets to go to the intended destination. <br /> \*   \*\*DROP\*\* - Blocks the packets from going to the intended destination and sends an alert log message, if alert logging is configured in the Firewall LoggingConfiguration. <br /> \*   \*\*ALERT\*\* - Permits the packets to go to the intended destination and sends an alert log message, if alert logging is configured in the Firewall LoggingConfiguration.  You can use this action to test a rule that you intend to use to drop traffic. You can enable the rule with ALERT action, verify in the logs that the rule is filtering as you want, then change the action to DROP. | 
| AWS-NetworkFirewall.RuleGroup.RuleGroup.RulesSource.StatefulRules.Header.Protocol | Unknown | The protocol to inspect for. To match with any protocol, specify ANY.  | 
| AWS-NetworkFirewall.RuleGroup.RuleGroup.RulesSource.StatefulRules.Header.Source | Unknown | The source IP address or address range to inspect for, in CIDR notation. To match with any address, specify ANY.  Specify an IP address or a block of IP addresses in Classless Inter-Domain Routing \(CIDR\) notation. Network Firewall supports all address ranges for IPv4.  Examples:   \*  To configure Network Firewall to inspect for the IP address 192.0.2.44, specify 192.0.2.44/32. <br />\*  To configure Network Firewall to inspect for IP addresses from 192.0.2.0 to 192.0.2.255, specify 192.0.2.0/24. For more information about CIDR notation, see the Wikipedia entry Classless Inter-Domain Routing. | 
| AWS-NetworkFirewall.RuleGroup.RuleGroup.RulesSource.StatefulRules.Header.SourcePort | Unknown | The source port to inspect for. You can specify an individual port, for example 1994 and you can specify a port range, for example 1990-1994. To match with any port, specify ANY.  | 
| AWS-NetworkFirewall.RuleGroup.RuleGroup.RulesSource.StatefulRules.Header.Direction | Unknown | The direction of traffic flow to inspect. If set to ANY, the inspection matches bidirectional traffic, both from the source to the destination and from the destination to the source. If set to FORWARD, the inspection only matches traffic going from the source to the destination.  | 
| AWS-NetworkFirewall.RuleGroup.RuleGroup.RulesSource.StatefulRules.Header.Destination | Unknown | The destination IP address or address range to inspect for, in CIDR notation. To match with any address, specify ANY.  Specify an IP address or a block of IP addresses in Classless Inter-Domain Routing \(CIDR\) notation. Network Firewall supports all address ranges for IPv4.  Examples:   \*  To configure Network Firewall to inspect for the IP address 192.0.2.44, specify 192.0.2.44/32. \*  To configure Network Firewall to inspect for IP addresses from 192.0.2.0 to 192.0.2.255, specify 192.0.2.0/24.  For more information about CIDR notation, see the Wikipedia entry Classless Inter-Domain Routing. | 
| AWS-NetworkFirewall.RuleGroup.RuleGroup.RulesSource.StatefulRules.Header.DestinationPort | Unknown | The destination port to inspect for. You can specify an individual port, for example 1994 and you can specify a port range, for example 1990-1994. To match with any port, specify ANY.  | 
| AWS-NetworkFirewall.RuleGroup.RuleGroup.RulesSource.StatefulRules.Header | Unknown | The stateful 5-tuple inspection criteria for this rule, used to inspect traffic flows.  | 
| AWS-NetworkFirewall.RuleGroup.RuleGroup.RulesSource.StatefulRules.RuleOptions.Keyword | Unknown | Rule options keyword. | 
| AWS-NetworkFirewall.RuleGroup.RuleGroup.RulesSource.StatefulRules.RuleOptions.Settings | Unknown | Rule option settings. | 
| AWS-NetworkFirewall.RuleGroup.RuleGroup.RulesSource.StatefulRules.RuleOptions | Unknown | Rule options. | 
| AWS-NetworkFirewall.RuleGroup.RuleGroup.RulesSource.StatefulRules | Unknown | The 5-tuple stateful inspection criteria. This contains an array of individual 5-tuple stateful rules to be used together in a stateful rule group.  | 
| AWS-NetworkFirewall.RuleGroup.RuleGroup.RulesSource.StatelessRulesAndCustomActions.StatelessRules.RuleDefinition.MatchAttributes.Sources.AddressDefinition | Unknown | Specify an IP address or a block of IP addresses in Classless Inter-Domain Routing \(CIDR\) notation. Network Firewall supports all address ranges for IPv4.  Examples:   \*  To configure Network Firewall to inspect for the IP address 192.0.2.44, specify 192.0.2.44/32.  \*  To configure Network Firewall to inspect for IP addresses from 192.0.2.0 to 192.0.2.255, specify 192.0.2.0/24.   For more information about CIDR notation, see the Wikipedia entry Classless Inter-Domain Routing. | 
| AWS-NetworkFirewall.RuleGroup.RuleGroup.RulesSource.StatelessRulesAndCustomActions.StatelessRules.RuleDefinition.MatchAttributes.Sources | Unknown | The source IP addresses and address ranges to inspect for, in CIDR notation. If not specified, this matches with any source address.  | 
| AWS-NetworkFirewall.RuleGroup.RuleGroup.RulesSource.StatelessRulesAndCustomActions.StatelessRules.RuleDefinition.MatchAttributes.Destinations.AddressDefinition | Unknown | Specify an IP address or a block of IP addresses in Classless Inter-Domain Routing \(CIDR\) notation. Network Firewall supports all address ranges for IPv4.  Examples:   \*  To configure Network Firewall to inspect for the IP address 192.0.2.44, specify 192.0.2.44/32.  \*  To configure Network Firewall to inspect for IP addresses from 192.0.2.0 to 192.0.2.255, specify 192.0.2.0/24.   For more information about CIDR notation, see the Wikipedia entry Classless Inter-Domain Routing. | 
| AWS-NetworkFirewall.RuleGroup.RuleGroup.RulesSource.StatelessRulesAndCustomActions.StatelessRules.RuleDefinition.MatchAttributes.Destinations | Unknown | The destination IP addresses and address ranges to inspect for, in CIDR notation. If not specified, this matches with any destination address.  | 
| AWS-NetworkFirewall.RuleGroup.RuleGroup.RulesSource.StatelessRulesAndCustomActions.StatelessRules.RuleDefinition.MatchAttributes.SourcePorts.FromPort | Unknown | The lower limit of the port range. This must be less than or equal to the ToPort specification.  | 
| AWS-NetworkFirewall.RuleGroup.RuleGroup.RulesSource.StatelessRulesAndCustomActions.StatelessRules.RuleDefinition.MatchAttributes.SourcePorts.ToPort | Unknown | The upper limit of the port range. This must be greater than or equal to the FromPort specification.  | 
| AWS-NetworkFirewall.RuleGroup.RuleGroup.RulesSource.StatelessRulesAndCustomActions.StatelessRules.RuleDefinition.MatchAttributes.SourcePorts | Unknown | The source ports to inspect for. If not specified, this matches with any source port. This setting is only used for protocols 6 \(TCP\) and 17 \(UDP\).  You can specify individual ports, for example 1994 and you can specify port ranges, for example 1990-1994.  | 
| AWS-NetworkFirewall.RuleGroup.RuleGroup.RulesSource.StatelessRulesAndCustomActions.StatelessRules.RuleDefinition.MatchAttributes.DestinationPorts.FromPort | Unknown | The lower limit of the port range. This must be less than or equal to the ToPort specification.  | 
| AWS-NetworkFirewall.RuleGroup.RuleGroup.RulesSource.StatelessRulesAndCustomActions.StatelessRules.RuleDefinition.MatchAttributes.DestinationPorts.ToPort | Unknown | The upper limit of the port range. This must be greater than or equal to the FromPort specification.  | 
| AWS-NetworkFirewall.RuleGroup.RuleGroup.RulesSource.StatelessRulesAndCustomActions.StatelessRules.RuleDefinition.MatchAttributes.DestinationPorts | Unknown | The destination ports to inspect for. If not specified, this matches with any destination port. This setting is only used for protocols 6 \(TCP\) and 17 \(UDP\).  You can specify individual ports, for example 1994 and you can specify port ranges, for example 1990-1994.  | 
| AWS-NetworkFirewall.RuleGroup.RuleGroup.RulesSource.StatelessRulesAndCustomActions.StatelessRules.RuleDefinition.MatchAttributes.Protocols | Unknown | The protocols to inspect for, specified using each protocol's assigned internet protocol number \(IANA\). If not specified, this matches with any protocol.  | 
| AWS-NetworkFirewall.RuleGroup.RuleGroup.RulesSource.StatelessRulesAndCustomActions.StatelessRules.RuleDefinition.MatchAttributes.TCPFlags.Flags | Unknown | Used in conjunction with the Masks setting to define the flags that must be set and flags that must not be set in order for the packet to match. This setting can only specify values that are also specified in the Masks setting. For the flags that are specified in the masks setting, the following must be true for the packet to match:   \*  The ones that are set in this flags setting must be set in the packet.  \*  The ones that are not set in this flags setting must also not be set in the packet.  | 
| AWS-NetworkFirewall.RuleGroup.RuleGroup.RulesSource.StatelessRulesAndCustomActions.StatelessRules.RuleDefinition.MatchAttributes.TCPFlags.Masks | Unknown | The set of flags to consider in the inspection. To inspect all flags in the valid values list, leave this with no setting. | 
| AWS-NetworkFirewall.RuleGroup.RuleGroup.RulesSource.StatelessRulesAndCustomActions.StatelessRules.RuleDefinition.MatchAttributes.TCPFlags | Unknown | The TCP flags and masks to inspect for. If not specified, this matches with any settings. This setting is only used for protocol 6 \(TCP\). | 
| AWS-NetworkFirewall.RuleGroup.RuleGroup.RulesSource.StatelessRulesAndCustomActions.StatelessRules.RuleDefinition.MatchAttributes | Unknown | Criteria for Network Firewall to use to inspect an individual packet in stateless rule inspection. Each match attributes set can include one or more items such as IP address, CIDR range, port number, protocol, and TCP flags.  | 
| AWS-NetworkFirewall.RuleGroup.RuleGroup.RulesSource.StatelessRulesAndCustomActions.StatelessRules.RuleDefinition.Actions | Unknown | The actions to take on a packet that matches one of the stateless rule definition's match attributes. You must specify a standard action and you can add custom actions.   Network Firewall only forwards a packet for stateful rule inspection if you specify aws:forward\\_to\\_sfe for a rule that the packet matches, or if the packet doesn't match any stateless rule and you specify aws:forward\\_to\\_sfe for the StatelessDefaultActions setting for the FirewallPolicy.  For every rule, you must specify exactly one of the following standard actions.   \*   \*\*aws:pass\*\* - Discontinues all inspection of the packet and permits it to go to its intended destination.  \*   \*\*aws:drop\*\* - Discontinues all inspection of the packet and blocks it from going to its intended destination. \*   \*\*aws:forward\\_to\\_sfe\*\* - Discontinues stateless inspection of the packet and forwards it to the stateful rule engine for inspection.  Additionally, you can specify a custom action. To do this, you define a custom action by name and type, then provide the name you've assigned to the action in this Actions setting. For information about the options, see CustomAction.  To provide more than one action in this setting, separate the settings with a comma. For example, if you have a custom PublishMetrics action that you've named MyMetricsAction, then you could specify the standard action aws:pass and the custom action with \[?aws:pass?, ?MyMetricsAction?\].  | 
| AWS-NetworkFirewall.RuleGroup.RuleGroup.RulesSource.StatelessRulesAndCustomActions.StatelessRules.RuleDefinition | Unknown | Defines the stateless 5-tuple packet inspection criteria and the action to take on a packet that matches the criteria.  | 
| AWS-NetworkFirewall.RuleGroup.RuleGroup.RulesSource.StatelessRulesAndCustomActions.StatelessRules.Priority | Unknown | A setting that indicates the order in which to run this rule relative to all of the rules that are defined for a stateless rule group. Network Firewall evaluates the rules in a rule group starting with the lowest priority setting. You must ensure that the priority settings are unique for the rule group.  Each stateless rule group uses exactly one StatelessRulesAndCustomActions object, and each StatelessRulesAndCustomActions contains exactly one StatelessRules object. To ensure unique priority settings for your rule groups, set unique priorities for the stateless rules that you define inside any single StatelessRules object. You can change the priority settings of your rules at any time. To make it easier to insert rules later, number them so there's a wide range in between, for example use 100, 200, and so on.  | 
| AWS-NetworkFirewall.RuleGroup.RuleGroup.RulesSource.StatelessRulesAndCustomActions.StatelessRules | Unknown | Defines the set of stateless rules for use in a stateless rule group.  | 
| AWS-NetworkFirewall.RuleGroup.RuleGroup.RulesSource.StatelessRulesAndCustomActions.CustomActions.ActionName | Unknown | The descriptive name of the custom action. You can't change the name of a custom action after you create it. | 
| AWS-NetworkFirewall.RuleGroup.RuleGroup.RulesSource.StatelessRulesAndCustomActions.CustomActions.ActionDefinition.PublishMetricAction.Dimensions.Value | Unknown | The value to use in the custom metric dimension. | 
| AWS-NetworkFirewall.RuleGroup.RuleGroup.RulesSource.StatelessRulesAndCustomActions.CustomActions.ActionDefinition.PublishMetricAction.Dimensions | Unknown | The custom metric dimension. | 
| AWS-NetworkFirewall.RuleGroup.RuleGroup.RulesSource.StatelessRulesAndCustomActions.CustomActions.ActionDefinition.PublishMetricAction | Unknown | Stateless inspection criteria that publishes the specified metrics to Amazon CloudWatch for the matching packet. This setting defines a CloudWatch dimension value to be published. You can pair this custom action with any of the standard stateless rule actions. For example, you could pair this in a rule action with the standard action that forwards the packet for stateful inspection. Then, when a packet matches the rule, Network Firewall publishes metrics for the packet and forwards it.  | 
| AWS-NetworkFirewall.RuleGroup.RuleGroup.RulesSource.StatelessRulesAndCustomActions.CustomActions.ActionDefinition | Unknown | The custom action associated with the action name. | 
| AWS-NetworkFirewall.RuleGroup.RuleGroup.RulesSource.StatelessRulesAndCustomActions.CustomActions | Unknown | Defines an array of individual custom action definitions that are available for use by the stateless rules in this StatelessRulesAndCustomActions specification. You name each custom action that you define, and then you can use it by name in your StatelessRule RuleDefinition Actions specification. | 
| AWS-NetworkFirewall.RuleGroup.RuleGroup.RulesSource.StatelessRulesAndCustomActions | Unknown | Stateless inspection criteria to be used in a stateless rule group.  | 
| AWS-NetworkFirewall.RuleGroup.RuleGroup.RulesSource | Unknown | The stateful rules or stateless rules for the rule group.  | 
| AWS-NetworkFirewall.RuleGroup.RuleGroup | Unknown | The object that defines the rules in a rule group. This, along with RuleGroupResponse, define the rule group. You can retrieve all objects for a rule group by calling DescribeRuleGroup.  AWS Network Firewall uses a rule group to inspect and control network traffic. You define stateless rule groups to inspect individual packets and you define stateful rule groups to inspect packets in the context of their traffic flow.  To use a rule group, you include it by reference in an Network Firewall firewall policy, then you use the policy in a firewall. You can reference a rule group from more than one firewall policy, and you can use a firewall policy in more than one firewall.  | 
| AWS-NetworkFirewall.RuleGroup.RuleGroupResponse.RuleGroupArn | Unknown | The Amazon Resource Name \(ARN\) of the rule group.  If this response is for a create request that had DryRun set to TRUE, then this ARN is a placeholder that isn't attached to a valid resource.  | 
| AWS-NetworkFirewall.RuleGroup.RuleGroupResponse.RuleGroupName | Unknown | The descriptive name of the rule group. You can't change the name of a rule group after you create it. | 
| AWS-NetworkFirewall.RuleGroup.RuleGroupResponse.RuleGroupId | Unknown | The unique identifier for the rule group.  | 
| AWS-NetworkFirewall.RuleGroup.RuleGroupResponse.Description | Unknown | A description of the rule group.  | 
| AWS-NetworkFirewall.RuleGroup.RuleGroupResponse.Type | Unknown | Indicates whether the rule group is stateless or stateful. If the rule group is stateless, it contains stateless rules. If it is stateful, it contains stateful rules.  | 
| AWS-NetworkFirewall.RuleGroup.RuleGroupResponse.Capacity | Unknown | The maximum operating resources that this rule group can use. Rule group capacity is fixed at creation. When you update a rule group, you are limited to this capacity. When you reference a rule group from a firewall policy, Network Firewall reserves this capacity for the rule group.  You can retrieve the capacity that would be required for a rule group before you create the rule group by calling CreateRuleGroup with DryRun set to TRUE.  | 
| AWS-NetworkFirewall.RuleGroup.RuleGroupResponse.RuleGroupStatus | Unknown | Detailed information about the current status of a rule group.  | 
| AWS-NetworkFirewall.RuleGroup.RuleGroupResponse.Tags.Key | Unknown | The part of the key:value pair that defines a tag. You can use a tag key to describe a category of information, such as "customer." Tag keys are case-sensitive. | 
| AWS-NetworkFirewall.RuleGroup.RuleGroupResponse.Tags.Value | Unknown | The part of the key:value pair that defines a tag. You can use a tag value to describe a specific value within a category, such as "companyA" or "companyB." Tag values are case-sensitive. | 
| AWS-NetworkFirewall.RuleGroup.RuleGroupResponse.Tags | Unknown | The key:value pairs to associate with the resource. | 
| AWS-NetworkFirewall.RuleGroup.RuleGroupResponse | Unknown | The high-level properties of a rule group. This, along with the RuleGroup, define the rule group. You can retrieve all objects for a rule group by calling DescribeRuleGroup.  | 


#### Command Example
```!aws-network-firewall-describe-rule-group rule_group_arn=arn:aws:network-firewall:us-west-2:123456789012:stateless-rulegroup/example-group-stateless2```

#### Context Example
```json
{
    "AWS-NetworkFirewall": {
        "RuleGroup": {
            "RuleGroup": {
                "RulesSource": {
                    "StatelessRulesAndCustomActions": {
                        "StatelessRules": [
                            {
                                "Priority": 5,
                                "RuleDefinition": {
                                    "Actions": [
                                        "aws:pass"
                                    ],
                                    "MatchAttributes": {
                                        "Sources": [
                                            {
                                                "AddressDefinition": "10.0.0.0/8"
                                            },
                                            {
                                                "AddressDefinition": "192.168.0.0/16"
                                            },
                                            {
                                                "AddressDefinition": "172.31.0.0/16"
                                            }
                                        ]
                                    }
                                }
                            }
                        ]
                    }
                }
            },
            "RuleGroupResponse": {
                "Capacity": 10,
                "RuleGroupArn": "arn:aws:network-firewall:us-west-2:123456789012:stateless-rulegroup/example-group-stateless2",
                "RuleGroupId": "27409b82-b9de-456e-8e29-2a0e0776c548",
                "RuleGroupName": "example-group-stateless2",
                "RuleGroupStatus": "ACTIVE",
                "Tags": [],
                "Type": "STATELESS"
            },
            "UpdateToken": "049b2760-7b8d-4eb0-a2b1-89012f073da2"
        }
    }
}
```

#### Human Readable Output

>### AWS Network Firewall DescribeRuleGroup
>|RuleGroup|RuleGroupResponse|UpdateToken|
>|---|---|---|
>| RulesSource: {"StatelessRulesAndCustomActions": {"StatelessRules": [{"RuleDefinition": {"MatchAttributes": {"Sources": [{"AddressDefinition": "10.0.0.0/8"}, {"AddressDefinition": "192.168.0.0/16"}, {"AddressDefinition": "172.31.0.0/16"}]}, "Actions": ["aws:pass"]}, "Priority": 5}]}} | RuleGroupArn: arn:aws:network-firewall:us-west-2:123456789012:stateless-rulegroup/example-group-stateless2<br/>RuleGroupName: example-group-stateless2<br/>RuleGroupId: 27409b82-b9de-456e-8e29-2a0e0776c548<br/>Type: STATELESS<br/>Capacity: 10<br/>RuleGroupStatus: ACTIVE<br/>Tags:  | 049b2760-7b8d-4eb0-a2b1-89012f073da2 |


### aws-network-firewall-disassociate-subnets
***
Removes the specified subnet associations from the firewall. This removes the firewall endpoints from the subnets and removes any network filtering protections that the endpoints were providing.


#### Base Command

`aws-network-firewall-disassociate-subnets`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. . | Optional | 
| raw_json | Override arguments and send a formatted JSON file. | Optional | 
| update_token | An optional token that you can use for optimistic locking. Network Firewall returns a token to your requests that access the firewall. The token marks the state of the firewall resource at the time of the request.  To make an unconditional change to the firewall, omit the token in your update request. Without the token, Network Firewall performs your updates regardless of whether the firewall has changed since you last retrieved it. To make a conditional change to the firewall, provide the token in your update request. Network Firewall uses the token to ensure that the firewall hasn't changed since you last retrieved it. If it has changed, the operation fails with an InvalidTokenException. If this happens, retrieve the firewall again to get a current copy of it with a new token. Reapply your changes as needed, then try the operation again using the new token. . | Optional | 
| firewall_arn | The Amazon Resource Name (ARN) of the firewall. You must specify the ARN or the name, and you can specify both. . | Optional | 
| firewall_name | The descriptive name of the firewall. You can't change the name of a firewall after you create it. You must specify the ARN or the name, and you can specify both. . | Optional | 
| subnet_ids | Comma-separated list of unique identifiers for the subnets that you want to disassociate. . | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS-NetworkFirewall.AssociationResults.Subnets.FirewallArn | Unknown | The Amazon Resource Name \(ARN\) of the firewall. | 
| AWS-NetworkFirewall.AssociationResults.Subnets.FirewallName | Unknown | The descriptive name of the firewall. You can't change the name of a firewall after you create it. | 
| AWS-NetworkFirewall.AssociationResults.Subnets.SubnetMappings.SubnetId | Unknown | The unique identifier for the subnet.  | 
| AWS-NetworkFirewall.AssociationResults.Subnets.SubnetMappings | Unknown | The IDs of the subnets that are associated with the firewall.  | 
| AWS-NetworkFirewall.AssociationResults.Subnets.UpdateToken | Unknown | An optional token that you can use for optimistic locking. Network Firewall returns a token to your requests that access the firewall. The token marks the state of the firewall resource at the time of the request.  To make an unconditional change to the firewall, omit the token in your update request. Without the token, Network Firewall performs your updates regardless of whether the firewall has changed since you last retrieved it. To make a conditional change to the firewall, provide the token in your update request. Network Firewall uses the token to ensure that the firewall hasn't changed since you last retrieved it. If it has changed, the operation fails with an InvalidTokenException. If this happens, retrieve the firewall again to get a current copy of it with a new token. Reapply your changes as needed, then try the operation again using the new token.  | 


#### Command Example
```!aws-network-firewall-disassociate-subnets firewall_name=myfirewall2 subnet_ids=subnet-bbbbbbb```

#### Context Example
```json
{
    "AWS-NetworkFirewall": {
        "AssociationResults": {
            "Subnets": {
                "FirewallArn": "arn:aws:network-firewall:us-west-2:123456789012:firewall/myfirewall2",
                "FirewallName": "myfirewall2",
                "SubnetMappings": [
                    {
                        "SubnetId": "subnet-aaaaaaa"
                    }
                ],
                "UpdateToken": "3cd6d327-33d1-4c0e-8452-f61bdf9b218c"
            }
        }
    }
}
```

#### Human Readable Output

>### AWS Network Firewall DisassociateSubnets
>|FirewallArn|FirewallName|SubnetMappings|UpdateToken|
>|---|---|---|---|
>| arn:aws:network-firewall:us-west-2:123456789012:firewall/myfirewall2 | myfirewall2 | {'SubnetId': 'subnet-aaaaaaa'} | 3cd6d327-33d1-4c0e-8452-f61bdf9b218c |


### aws-network-firewall-list-firewall-policies
***
Retrieves the metadata for the firewall policies that you have defined. Depending on your setting for max results and the number of firewall policies, a single call might not return the full list.


#### Base Command

`aws-network-firewall-list-firewall-policies`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. . | Optional | 
| raw_json | Override arguments and send a formatted JSON file. | Optional | 
| next_token | When you request a list of objects with a MaxResults setting, if the number of objects that are still available for retrieval exceeds the maximum you requested, Network Firewall returns a NextToken value in the response. To retrieve the next batch of objects, use the token returned from the prior request in your next request. | Optional | 
| max_results | The maximum number of objects that you want Network Firewall to return for this request. If more objects are available, in the response, Network Firewall provides a NextToken value that you can use in a subsequent call to get the next batch of objects. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS-NetworkFirewall.FirewallPolicies.NextToken | Unknown | When you request a list of objects with a MaxResults setting, if the number of objects that are still available for retrieval exceeds the maximum you requested, Network Firewall returns a NextToken value in the response. To retrieve the next batch of objects, use the token returned from the prior request in your next request. | 
| AWS-NetworkFirewall.FirewallPolicies.Name | Unknown | The descriptive name of the firewall policy. You can't change the name of a firewall policy after you create it. | 
| AWS-NetworkFirewall.FirewallPolicies.Arn | Unknown | The Amazon Resource Name \(ARN\) of the firewall policy. | 
| AWS-NetworkFirewall.FirewallPolicies | Unknown | The metadata for the firewall policies. Depending on your setting for max results and the number of firewall policies that you have, this might not be the full list.  | 


#### Command Example
```!aws-network-firewall-list-firewall-policies```

#### Context Example
```json
{
    "AWS-NetworkFirewall": {
        "FirewallPolicies": [
            {
                "Arn": "arn:aws:network-firewall:us-west-2:123456789012:firewall-policy/example-fw-policy",
                "Name": "example-fw-policy"
            },
            {
                "Arn": "arn:aws:network-firewall:us-west-2:123456789012:firewall-policy/example-fw-policy2",
                "Name": "example-fw-policy2"
            }
        ]
    }
}
```

#### Human Readable Output

>### AWS Network Firewall ListFirewallPolicies
>|Arn|Name|
>|---|---|
>| arn:aws:network-firewall:us-west-2:123456789012:firewall-policy/example-fw-policy | example-fw-policy |
>| arn:aws:network-firewall:us-west-2:123456789012:firewall-policy/example-fw-policy2 | example-fw-policy2 |


### aws-network-firewall-list-firewalls
***
Retrieves the metadata for the firewalls that you have defined. If you provide VPC identifiers in your request, this returns only the firewalls for those VPCs. Depending on your setting for max results and the number of firewalls, a single call might not return the full list.


#### Base Command

`aws-network-firewall-list-firewalls`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. . | Optional | 
| raw_json | Override arguments and send a formatted JSON file. | Optional | 
| next_token | When you request a list of objects with a MaxResults setting, if the number of objects that are still available for retrieval exceeds the maximum you requested, Network Firewall returns a NextToken value in the response. To retrieve the next batch of objects, use the token returned from the prior request in your next request. | Optional | 
| vpc_ids | A Comma-separated  unique identifiers of the VPCs that you want Network Firewall to retrieve the firewalls for. Leave this blank to retrieve all firewalls that you have defined. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS-NetworkFirewall.Firewalls.NextToken | Unknown | When you request a list of objects with a MaxResults setting, if the number of objects that are still available for retrieval exceeds the maximum you requested, Network Firewall returns a NextToken value in the response. To retrieve the next batch of objects, use the token returned from the prior request in your next request. | 
| AWS-NetworkFirewall.Firewalls.FirewallName | Unknown | The descriptive name of the firewall. You can't change the name of a firewall after you create it. | 
| AWS-NetworkFirewall.Firewalls.FirewallArn | Unknown | The Amazon Resource Name \(ARN\) of the firewall. | 
| AWS-NetworkFirewall.Firewalls | Unknown | The firewall metadata objects for the VPCs that you specified. Depending on your setting for max results and the number of firewalls you have, a single call might not be the full list.  | 


#### Command Example
```!aws-network-firewall-list-firewalls```

#### Context Example
```json
{
    "AWS-NetworkFirewall": {
        "Firewalls": [
            {
                "FirewallArn": "arn:aws:network-firewall:us-west-2:123456789012:firewall/myfirewall1",
                "FirewallName": "myfirewall1"
            },
            {
                "FirewallArn": "arn:aws:network-firewall:us-west-2:123456789012:firewall/myfirewall2",
                "FirewallName": "myfirewall2"
            }
        ]
    }
}
```

#### Human Readable Output

>### AWS Network Firewall ListFirewalls
>|FirewallArn|FirewallName|
>|---|---|
>| arn:aws:network-firewall:us-west-2:123456789012:firewall/myfirewall1 | myfirewall1 |
>| arn:aws:network-firewall:us-west-2:123456789012:firewall/myfirewall2 | myfirewall2 |


### aws-network-firewall-list-rule-groups
***
Retrieves the metadata for the rule groups that you have defined. Depending on your setting for max results and the number of rule groups, a single call might not return the full list.


#### Base Command

`aws-network-firewall-list-rule-groups`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. . | Optional | 
| raw_json | Override arguments and send a formatted JSON file. | Optional | 
| next_token | When you request a list of objects with a MaxResults setting, if the number of objects that are still available for retrieval exceeds the maximum you requested, Network Firewall returns a NextToken value in the response. To retrieve the next batch of objects, use the token returned from the prior request in your next request. | Optional | 
| max_results | The maximum number of objects that you want Network Firewall to return for this request. If more objects are available, in the response, Network Firewall provides a NextToken value that you can use in a subsequent call to get the next batch of objects. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS-NetworkFirewall.RuleGroups.NextToken | Unknown | When you request a list of objects with a MaxResults setting, if the number of objects that are still available for retrieval exceeds the maximum you requested, Network Firewall returns a NextToken value in the response. To retrieve the next batch of objects, use the token returned from the prior request in your next request. | 
| AWS-NetworkFirewall.RuleGroups.Name | Unknown | The descriptive name of the rule group. You can't change the name of a rule group after you create it. | 
| AWS-NetworkFirewall.RuleGroups.Arn | Unknown | The Amazon Resource Name \(ARN\) of the rule group. | 
| AWS-Network Firewall.RuleGroups | Unknown | The rule group metadata objects that you've defined. Depending on your setting for max results and the number of rule groups, this might not be the full list.  | 


#### Command Example
```!aws-network-firewall-list-rule-groups```

#### Context Example
```json
{
    "AWS-NetworkFirewall": {
        "RuleGroups": [
            {
                "Arn": "arn:aws:network-firewall:us-west-2:123456789012:stateless-rulegroup/example-group-stateless",
                "Name": "example-group-stateless"
            },
            {
                "Arn": "arn:aws:network-firewall:us-west-2:123456789012:stateless-rulegroup/example-group-stateless2",
                "Name": "example-group-stateless2"
            },
            {
                "Arn": "arn:aws:network-firewall:us-west-2:123456789012:stateless-rulegroup/example-group-stateless3",
                "Name": "example-group-stateless3"
            }
        ]
    }
}
```

#### Human Readable Output

>### AWS Network Firewall ListRuleGroups
>|Arn|Name|
>|---|---|
>| arn:aws:network-firewall:us-west-2:123456789012:stateless-rulegroup/example-group-stateless | example-group-stateless |
>| arn:aws:network-firewall:us-west-2:123456789012:stateless-rulegroup/example-group-stateless2 | example-group-stateless2 |
>| arn:aws:network-firewall:us-west-2:123456789012:stateless-rulegroup/example-group-stateless3 | example-group-stateless3 |


### aws-network-firewall-list-tags-for-resource
***
Retrieves the tags associated with the specified resource. Tags are key:value pairs that you can use to categorize and manage your resources, for purposes like billing. For example, you might set the tag key to "customer" and the value to the customer name or ID. You can specify one or more tags to add to each AWS resource, up to 50 tags for a resource. You can tag the AWS resources that you manage through AWS Network Firewall: firewalls, firewall policies, and rule groups.


#### Base Command

`aws-network-firewall-list-tags-for-resource`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. . | Optional | 
| raw_json | Override arguments and send a formatted JSON file. | Optional | 
| next_token | When you request a list of objects with a MaxResults setting, if the number of objects that are still available for retrieval exceeds the maximum you requested, Network Firewall returns a NextToken value in the response. To retrieve the next batch of objects, use the token returned from the prior request in your next request. | Optional | 
| resource_arn | The Amazon Resource Name (ARN) of the resource. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS-NetworkFirewall.NextToken | Unknown | When you request a list of objects with a MaxResults setting, if the number of objects that are still available for retrieval exceeds the maximum you requested, Network Firewall returns a NextToken value in the response. To retrieve the next batch of objects, use the token returned from the prior request in your next request. | 
| AWS-NetworkFirewall.Tags.Key | Unknown | The part of the key:value pair that defines a tag. You can use a tag key to describe a category of information, such as "customer." Tag keys are case-sensitive. | 
| AWS-NetworkFirewall.Tags.Value | Unknown | The part of the key:value pair that defines a tag. You can use a tag value to describe a specific value within a category, such as "companyA" or "companyB." Tag values are case-sensitive. | 
| AWS-NetworkFirewall.Tags | Unknown | The tags that are associated with the resource.  | 


#### Command Example
```!aws-network-firewall-list-tags-for-resource resource_arn=arn:aws:network-firewall:us-west-2:123456789012:firewall/myfirewall2```

#### Context Example
```json
{
    "AWS-NetworkFirewall": {
        "Tags": [
            {
                "Key": "testkey",
                "Value": "testvalue"
            }
        ]
    }
}
```

#### Human Readable Output

>### AWS Network Firewall ListTagsForResource
>|Key|Value|
>|---|---|
>| testkey | testvalue |


### aws-network-firewall-put-resource-policy
***
Creates or updates an AWS Identity and Access Management policy for your rule group or firewall policy. Use this to share rule groups and firewall policies between accounts. This operation works in conjunction with the AWS Resource Access Manager (RAM) service to manage resource sharing for Network Firewall.  Use this operation to create or update a resource policy for your rule group or firewall policy. In the policy, you specify the accounts that you want to share the resource with and the operations that you want the accounts to be able to perform.  When you add an account in the resource policy, you then run the following Resource Access Manager (RAM) operations to access and accept the shared rule group or firewall policy.   *   GetResourceShareInvitations - Returns the Amazon Resource Names (ARNs) of the resource share invitations.  
 *   AcceptResourceShareInvitation - Accepts the share invitation for a specified resource share.  
  For additional information about resource sharing using RAM, see AWS Resource Access Manager User Guide.


#### Base Command

`aws-network-firewall-put-resource-policy`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. . | Optional | 
| raw_json | Override arguments and send a formatted JSON file. | Optional | 
| resource_arn | The Amazon Resource Name (ARN) of the account that you want to share rule groups and firewall policies with. | Required | 
| policy | The AWS Identity and Access Management policy statement that lists the accounts that you want to share your rule group or firewall policy with and the operations that you want the accounts to be able to perform.  For a rule group resource, you can specify the following operations in the Actions section of the statement:  *  network-firewall:CreateFirewallPolicy <br/> *  network-firewall:UpdateFirewallPolicy <br/> *  network-firewall:ListRuleGroups <br/>  For a firewall policy resource, you can specify the following operations in the Actions section of the statement:  *  network-firewall:CreateFirewall <br/> *  network-firewall:UpdateFirewall <br/> *  network-firewall:AssociateFirewallPolicy <br/> *  network-firewall:ListFirewallPolicies <br/>  In the Resource section of the statement, you specify the ARNs for the rule groups and firewall policies that you want to share with the account that you specified in Arn. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!aws-network-firewall-put-resource-policy resource_arn=arn:aws:network-firewall:us-west-2:123456789012:stateless-rulegroup/example-group-stateless2 policy="""{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":["123456789012"]},"Action":["network-firewall:CreateFirewallPolicy","network-firewall:UpdateFirewallPolicy","network-firewall:ListRuleGroups"],"Resource":"arn:aws:network-firewall:us-west-2:123456789012:stateless-rulegroup/example-group-stateless2"}]}"""```

#### Context Example
```json
{}
```

#### Human Readable Output

>### AWS Network Firewall PutResourcePolicy
>**No entries.**


### aws-network-firewall-tag-resource
***
Adds the specified tags to the specified resource. Tags are key:value pairs that you can use to categorize and manage your resources, for purposes like billing. For example, you might set the tag key to "customer" and the value to the customer name or ID. You can specify one or more tags to add to each AWS resource, up to 50 tags for a resource. You can tag the AWS resources that you manage through AWS Network Firewall: firewalls, firewall policies, and rule groups.


#### Base Command

`aws-network-firewall-tag-resource`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. . | Optional | 
| raw_json | Override arguments and send a formatted JSON file. | Optional | 
| resource_arn | The Amazon Resource Name (ARN) of the resource. | Required | 
| tags | List of Tags separated by Key Value. For example: "key=key1,value=value1;key=key2,value=value2". | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!aws-network-firewall-tag-resource resource_arn=arn:aws:network-firewall:us-west-2:123456789012:firewall/myfirewall2 tags="key=testkey,value=testvalue"```

#### Context Example
```json
{}
```

#### Human Readable Output

>### AWS Network Firewall TagResource
>**No entries.**


### aws-network-firewall-untag-resource
***
Removes the tags with the specified keys from the specified resource. Tags are key:value pairs that you can use to categorize and manage your resources, for purposes like billing. For example, you might set the tag key to "customer" and the value to the customer name or ID. You can specify one or more tags to add to each AWS resource, up to 50 tags for a resource. You can manage tags for the AWS resources that you manage through AWS Network Firewall: firewalls, firewall policies, and rule groups.


#### Base Command

`aws-network-firewall-untag-resource`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. . | Optional | 
| raw_json | Override arguments and send a formatted JSON file. | Optional | 
| resource_arn | The Amazon Resource Name (ARN) of the resource. | Required | 
| tag_keys | A Comma-separated keys to be removed from tags. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!aws-network-firewall-untag-resource resource_arn=arn:aws:network-firewall:us-west-2:123456789012:firewall/myfirewall2 tag_keys=testkey```

#### Context Example
```json
{}
```

#### Human Readable Output

>### AWS Network Firewall UntagResource
>**No entries.**


### aws-network-firewall-update-firewall-delete-protection
***
Modifies the flag, DeleteProtection, which indicates whether it is possible to delete the firewall. If the flag is set to TRUE, the firewall is protected against deletion. This setting helps protect against accidentally deleting a firewall that's in use.


#### Base Command

`aws-network-firewall-update-firewall-delete-protection`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. . | Optional | 
| raw_json | Override arguments and send a formatted JSON file. | Optional | 
| update_token | An optional token that you can use for optimistic locking. Network Firewall returns a token to your requests that access the firewall. The token marks the state of the firewall resource at the time of the request.  To make an unconditional change to the firewall, omit the token in your update request. Without the token, Network Firewall performs your updates regardless of whether the firewall has changed since you last retrieved it. To make a conditional change to the firewall, provide the token in your update request. Network Firewall uses the token to ensure that the firewall hasn't changed since you last retrieved it. If it has changed, the operation fails with an InvalidTokenException. If this happens, retrieve the firewall again to get a current copy of it with a new token. Reapply your changes as needed, then try the operation again using the new token. . | Optional | 
| firewall_arn | The Amazon Resource Name (ARN) of the firewall. You must specify the ARN or the name, and you can specify both. . | Optional | 
| firewall_name | The descriptive name of the firewall. You can't change the name of a firewall after you create it. You must specify the ARN or the name, and you can specify both. . | Optional | 
| delete_protection | &lt;p&gt;A flag indicating whether it is possible to delete the firewall. A setting of &lt;code&gt;TRUE&lt;/code&gt; indicates that the firewall is protected against deletion. Use this setting to protect against accidentally deleting a firewall that is in use. When you create a firewall, the operation initializes this flag to &lt;code&gt;TRUE&lt;/code&gt;.&lt;/p&gt;. Possible values are: True, False. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS-NetworkFirewall.FirewallAttributes.FirewallArn | Unknown | The Amazon Resource Name \(ARN\) of the firewall. | 
| AWS-NetworkFirewall.FirewallAttributes.FirewallName | Unknown | The descriptive name of the firewall. You can't change the name of a firewall after you create it. | 
| AWS-NetworkFirewall.FirewallAttributes.DeleteProtection | Unknown | Delete protection | 
| AWS-NetworkFirewall.FirewallAttributes.UpdateToken | Unknown | An optional token that you can use for optimistic locking. Network Firewall returns a token to your requests that access the firewall. The token marks the state of the firewall resource at the time of the request.  To make an unconditional change to the firewall, omit the token in your update request. Without the token, Network Firewall performs your updates regardless of whether the firewall has changed since you last retrieved it. To make a conditional change to the firewall, provide the token in your update request. Network Firewall uses the token to ensure that the firewall hasn't changed since you last retrieved it. If it has changed, the operation fails with an InvalidTokenException. If this happens, retrieve the firewall again to get a current copy of it with a new token. Reapply your changes as needed, then try the operation again using the new token.  | 


#### Command Example
```!aws-network-firewall-update-firewall-delete-protection delete_protection=False firewall_arn=arn:aws:network-firewall:us-west-2:123456789012:firewall/myfirewall```


#### Context Example
```json
{
    "AWS-NetworkFirewall": {
        "FirewallAttributes": {
            "DeleteProtection": false,
            "FirewallArn": "arn:aws:network-firewall:us-west-2:123456789012:firewall/myfirewall",
            "FirewallName": "myfirewall",
            "UpdateToken": "f0aafd55-1cec-42a5-981a-399ebbd7b00f"
        }
    }
}
```

#### Human Readable Output

>### AWS Network Firewall UpdateFirewallDeleteProtection
>|DeleteProtection|FirewallArn|FirewallName|UpdateToken|
>|---|---|---|---|
>| false | arn:aws:network-firewall:us-west-2:123456789012:firewall/myfirewall | myfirewall | f0aafd55-1cec-42a5-981a-399ebbd7b00f |


### aws-network-firewall-update-firewall-description
***
Modifies the description for the specified firewall. Use the description to help you identify the firewall when you're working with it.


#### Base Command

`aws-network-firewall-update-firewall-description`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. . | Optional | 
| raw_json | Override arguments and send a formatted JSON file. | Optional | 
| update_token | An optional token that you can use for optimistic locking. Network Firewall returns a token to your requests that access the firewall. The token marks the state of the firewall resource at the time of the request.  To make an unconditional change to the firewall, omit the token in your update request. Without the token, Network Firewall performs your updates regardless of whether the firewall has changed since you last retrieved it. To make a conditional change to the firewall, provide the token in your update request. Network Firewall uses the token to ensure that the firewall hasn't changed since you last retrieved it. If it has changed, the operation fails with an InvalidTokenException. If this happens, retrieve the firewall again to get a current copy of it with a new token. Reapply your changes as needed, then try the operation again using the new token. . | Optional | 
| firewall_arn | The Amazon Resource Name (ARN) of the firewall. You must specify the ARN or the name, and you can specify both. . | Optional | 
| firewall_name | The descriptive name of the firewall. You can't change the name of a firewall after you create it. You must specify the ARN or the name, and you can specify both. . | Optional | 
| description | The new description for the firewall. If you omit this setting, Network Firewall removes the description for the firewall. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS-NetworkFirewall.FirewallAttributes.FirewallArn | Unknown | The Amazon Resource Name \(ARN\) of the firewall. | 
| AWS-NetworkFirewall.FirewallAttributes.FirewallName | Unknown | The descriptive name of the firewall. You can't change the name of a firewall after you create it. | 
| AWS-NetworkFirewall.FirewallAttributes.Description | Unknown | A description of the firewall. | 
| AWS-NetworkFirewall.FirewallAttributes.UpdateToken | Unknown | An optional token that you can use for optimistic locking. Network Firewall returns a token to your requests that access the firewall. The token marks the state of the firewall resource at the time of the request.  To make an unconditional change to the firewall, omit the token in your update request. Without the token, Network Firewall performs your updates regardless of whether the firewall has changed since you last retrieved it. To make a conditional change to the firewall, provide the token in your update request. Network Firewall uses the token to ensure that the firewall hasn't changed since you last retrieved it. If it has changed, the operation fails with an InvalidTokenException. If this happens, retrieve the firewall again to get a current copy of it with a new token. Reapply your changes as needed, then try the operation again using the new token.  | 


#### Command Example
```!aws-network-firewall-update-firewall-description firewall_arn=arn:aws:network-firewall:us-west-2:123456789012:firewall/myfirewall description="some description"```


#### Context Example
```json
{
    "AWS-NetworkFirewall": {
        "FirewallAttributes": {
            "Description": "some description",
            "FirewallArn": "arn:aws:network-firewall:us-west-2:123456789012:firewall/myfirewall",
            "FirewallName": "myfirewall",
            "UpdateToken": "c3b57ab4-8659-4c2d-8feb-dbc8d6aeaabf"
        }
    }
}
```

#### Human Readable Output

>### AWS Network Firewall UpdateFirewallDescription
>|Description|FirewallArn|FirewallName|UpdateToken|
>|---|---|---|---|
>| some description | arn:aws:network-firewall:us-west-2:123456789012:firewall/myfirewall | myfirewall | c3b57ab4-8659-4c2d-8feb-dbc8d6aeaabf |


### aws-network-firewall-update-firewall-policy
***
Updates the properties of the specified firewall policy.


#### Base Command

`aws-network-firewall-update-firewall-policy`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. . | Optional | 
| raw_json | Override arguments and send a formatted JSON file. | Optional | 
| update_token | A token used for optimistic locking. Network Firewall returns a token to your requests that access the firewall policy. The token marks the state of the policy resource at the time of the request.  To make changes to the policy, you provide the token in your request. Network Firewall uses the token to ensure that the policy hasn't changed since you last retrieved it. If it has changed, the operation fails with an InvalidTokenException. If this happens, retrieve the firewall policy again to get a current copy of it with current token. Reapply your changes as needed, then try the operation again using the new token. . | Required | 
| firewall_policy_arn | The Amazon Resource Name (ARN) of the firewall policy. You must specify the ARN or the name, and you can specify both. . | Optional | 
| firewall_policy_name | The descriptive name of the firewall policy. You can't change the name of a firewall policy after you create it. You must specify the ARN or the name, and you can specify both. . | Optional | 
| firewall_policy_json | The updated firewall policy to use for the firewall. | Required | 
| description | A description of the firewall policy. | Optional | 
| dry_run | &lt;p&gt;Indicates whether you want Network Firewall to just check the validity of the request, rather than run the request. &lt;/p&gt; &lt;p&gt;If set to &lt;code&gt;TRUE&lt;/code&gt;, Network Firewall checks whether the request can run successfully, but doesn't actually make the requested changes. The call returns the value that the request would return if you ran it with dry run set to &lt;code&gt;FALSE&lt;/code&gt;, but doesn't make additions or changes to your resources. This option allows you to make sure that you have the required permissions to run the request and that your request parameters are valid. &lt;/p&gt; &lt;p&gt;If set to &lt;code&gt;FALSE&lt;/code&gt;, Network Firewall makes the requested changes to your resources. &lt;/p&gt;. Possible values are: True, False. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS-NetworkFirewall.FirewallPolicy.UpdateToken | Unknown | A token used for optimistic locking. Network Firewall returns a token to your requests that access the firewall policy. The token marks the state of the policy resource at the time of the request.  To make changes to the policy, you provide the token in your request. Network Firewall uses the token to ensure that the policy hasn't changed since you last retrieved it. If it has changed, the operation fails with an InvalidTokenException. If this happens, retrieve the firewall policy again to get a current copy of it with current token. Reapply your changes as needed, then try the operation again using the new token.  | 
| AWS-NetworkFirewall.FirewallPolicy.FirewallPolicyResponse.FirewallPolicyName | Unknown | The descriptive name of the firewall policy. You can't change the name of a firewall policy after you create it. | 
| AWS-NetworkFirewall.FirewallPolicy.FirewallPolicyResponse.FirewallPolicyArn | Unknown | The Amazon Resource Name \(ARN\) of the firewall policy.  If this response is for a create request that had DryRun set to TRUE, then this ARN is a placeholder that isn't attached to a valid resource.  | 
| AWS-NetworkFirewall.FirewallPolicy.FirewallPolicyResponse.FirewallPolicyId | Unknown | The unique identifier for the firewall policy.  | 
| AWS-NetworkFirewall.FirewallPolicy.FirewallPolicyResponse.Description | Unknown | A description of the firewall policy. | 
| AWS-NetworkFirewall.FirewallPolicy.FirewallPolicyResponse.FirewallPolicyStatus | Unknown | The current status of the firewall policy. You can retrieve this for a firewall policy by calling DescribeFirewallPolicy and providing the firewall policy's name or ARN. | 
| AWS-NetworkFirewall.FirewallPolicy.FirewallPolicyResponse.Tags.Key | Unknown | The part of the key:value pair that defines a tag. You can use a tag key to describe a category of information, such as "customer." Tag keys are case-sensitive. | 
| AWS-NetworkFirewall.FirewallPolicy.FirewallPolicyResponse.Tags.Value | Unknown | The part of the key:value pair that defines a tag. You can use a tag value to describe a specific value within a category, such as "companyA" or "companyB." Tag values are case-sensitive. | 
| AWS-NetworkFirewall.FirewallPolicy.FirewallPolicyResponse.Tags | Unknown | The key:value pairs to associate with the resource. | 
| AWS-NetworkFirewall.FirewallPolicy.FirewallPolicyResponse | Unknown | The high-level properties of a firewall policy. This, along with the FirewallPolicy, define the policy. You can retrieve all objects for a firewall policy by calling DescribeFirewallPolicy.  | 


#### Command Example
```!aws-network-firewall-update-firewall-policy update_token=4fa9513c-d33b-4980-8b6e-f00ef7a2af99 firewall_policy_arn=arn:aws:network-firewall:us-west-2:123456789012:firewall-policy/example-fw-policy2  firewall_policy_json="""{"StatelessRuleGroupReferences":[{"ResourceArn":"arn:aws:network-firewall:us-west-2:123456789012:stateless-rulegroup/example-group-stateless","Priority":100}],"StatelessDefaultActions":["aws:pass"],"StatelessFragmentDefaultActions":["aws:pass"]}"""```

#### Context Example
```json
{
    "AWS-NetworkFirewall": {
        "FirewallPolicy": {
            "FirewallPolicyResponse": {
                "FirewallPolicyArn": "arn:aws:network-firewall:us-west-2:123456789012:firewall-policy/example-fw-policy2",
                "FirewallPolicyId": "f9253d2f-acf7-465b-97f0-f8f52a7a756f",
                "FirewallPolicyName": "example-fw-policy2",
                "FirewallPolicyStatus": "ACTIVE",
                "Tags": []
            },
            "UpdateToken": "2648188a-c378-4244-9421-6f0d54bb206d"
        }
    }
}
```

#### Human Readable Output

>### AWS Network Firewall UpdateFirewallPolicy
>|FirewallPolicyResponse|UpdateToken|
>|---|---|
>| FirewallPolicyName: example-fw-policy2<br/>FirewallPolicyArn: arn:aws:network-firewall:us-west-2:123456789012:firewall-policy/example-fw-policy2<br/>FirewallPolicyId: f9253d2f-acf7-465b-97f0-f8f52a7a756f<br/>FirewallPolicyStatus: ACTIVE<br/>Tags:  | 2648188a-c378-4244-9421-6f0d54bb206d |


### aws-network-firewall-update-firewall-policy-change-protection
***
Update the firewall policy change protection


#### Base Command

`aws-network-firewall-update-firewall-policy-change-protection`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. . | Optional | 
| raw_json | Override arguments and send a formatted JSON file. | Optional | 
| update_token | An optional token that you can use for optimistic locking. Network Firewall returns a token to your requests that access the firewall. The token marks the state of the firewall resource at the time of the request.  To make an unconditional change to the firewall, omit the token in your update request. Without the token, Network Firewall performs your updates regardless of whether the firewall has changed since you last retrieved it. To make a conditional change to the firewall, provide the token in your update request. Network Firewall uses the token to ensure that the firewall hasn't changed since you last retrieved it. If it has changed, the operation fails with an InvalidTokenException. If this happens, retrieve the firewall again to get a current copy of it with a new token. Reapply your changes as needed, then try the operation again using the new token. . | Optional | 
| firewall_arn | The Amazon Resource Name (ARN) of the firewall. You must specify the ARN or the name, and you can specify both. . | Optional | 
| firewall_name | The descriptive name of the firewall. You can't change the name of a firewall after you create it. You must specify the ARN or the name, and you can specify both. . | Optional | 
| firewall_policy_change_protection | &lt;p&gt;A setting indicating whether the firewall is protected against a change to the firewall policy association. Use this setting to protect against accidentally modifying the firewall policy for a firewall that is in use. When you create a firewall, the operation initializes this setting to &lt;code&gt;TRUE&lt;/code&gt;.&lt;/p&gt;. Possible values are: True, False. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS-NetworkFirewall.FirewallAttributes.UpdateToken | Unknown | An optional token that you can use for optimistic locking. Network Firewall returns a token to your requests that access the firewall. The token marks the state of the firewall resource at the time of the request.  To make an unconditional change to the firewall, omit the token in your update request. Without the token, Network Firewall performs your updates regardless of whether the firewall has changed since you last retrieved it. To make a conditional change to the firewall, provide the token in your update request. Network Firewall uses the token to ensure that the firewall hasn't changed since you last retrieved it. If it has changed, the operation fails with an InvalidTokenException. If this happens, retrieve the firewall again to get a current copy of it with a new token. Reapply your changes as needed, then try the operation again using the new token.  | 
| AWS-NetworkFirewall.FirewallAttributes.FirewallArn | Unknown | The Amazon Resource Name \(ARN\) of the firewall. | 
| AWS-NetworkFirewall.FirewallAttributes.FirewallName | Unknown | The descriptive name of the firewall. You can't change the name of a firewall after you create it. | 
| AWS-NetworkFirewall.FirewallAttributes.FirewallPolicyChangeProtection | Unknown | A setting indicating whether the firewall is protected against a change to the firewall policy association. Use this setting to protect against accidentally modifying the firewall policy for a firewall that is in use. When you create a firewall, the operation initializes this setting to TRUE. | 


#### Command Example
```!aws-network-firewall-update-firewall-policy-change-protection firewall_policy_change_protection=False firewall_arn=arn:aws:network-firewall:us-west-2:123456789012:firewall/myfirewall2```

#### Context Example
```json
{
    "AWS-NetworkFirewall": {
        "FirewallAttributes": {
            "FirewallArn": "arn:aws:network-firewall:us-west-2:123456789012:firewall/myfirewall2",
            "FirewallName": "myfirewall2",
            "FirewallPolicyChangeProtection": false,
            "UpdateToken": "0cecf634-8fa0-4716-825a-bb9d937e4d3c"
        }
    }
}
```

#### Human Readable Output

>### AWS Network Firewall UpdateFirewallPolicyChangeProtection
>|FirewallArn|FirewallName|FirewallPolicyChangeProtection|UpdateToken|
>|---|---|---|---|
>| arn:aws:network-firewall:us-west-2:123456789012:firewall/myfirewall2 | myfirewall2 | false | 0cecf634-8fa0-4716-825a-bb9d937e4d3c |


### aws-network-firewall-update-logging-configuration
***
Sets the logging configuration for the specified firewall.  To change the logging configuration, retrieve the LoggingConfiguration by calling DescribeLoggingConfiguration, then change it and provide the modified object to this update call. You must change the logging configuration one LogDestinationConfig at a time inside the retrieved LoggingConfiguration object.  You can perform only one of the following actions in any call to UpdateLoggingConfiguration:   *  Create a new log destination object by adding a single LogDestinationConfig array element to LogDestinationConfigs. 
 *  Delete a log destination object by removing a single LogDestinationConfig array element from LogDestinationConfigs. 
 *  Change the LogDestination setting in a single LogDestinationConfig array element. 
  You can't change the LogDestinationType or LogType in a LogDestinationConfig. To change these settings, delete the existing LogDestinationConfig object and create a new one, using two separate calls to this update operation.


#### Base Command

`aws-network-firewall-update-logging-configuration`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. . | Optional | 
| raw_json | Override arguments and send a formatted JSON file. | Optional | 
| firewall_arn | The Amazon Resource Name (ARN) of the firewall. You must specify the ARN or the name, and you can specify both. . | Optional | 
| firewall_name | The descriptive name of the firewall. You can't change the name of a firewall after you create it. You must specify the ARN or the name, and you can specify both. . | Optional | 
| logging_configuration_json | Defines how Network Firewall performs logging for a firewall. If you omit this setting, Network Firewall disables logging for the firewall. Possible values are: . | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS-NetworkFirewall.Logging.FirewallArn | Unknown | The Amazon Resource Name \(ARN\) of the firewall. | 
| AWS-NetworkFirewall.Logging.FirewallName | Unknown | The descriptive name of the firewall. You can't change the name of a firewall after you create it. | 
| AWS-NetworkFirewall.Logging.LoggingConfiguration.LogDestinationConfigs.LogType | Unknown | The type of log to send. Alert logs report traffic that matches a StatefulRule with an action setting that sends an alert log message. Flow logs are standard network traffic flow logs.  | 
| AWS-NetworkFirewall.Logging.LoggingConfiguration.LogDestinationConfigs.LogDestinationType | Unknown | The type of storage destination to send these logs to. You can send logs to an Amazon S3 bucket, a CloudWatch log group, or a Kinesis Data Firehose delivery stream. | 
| AWS-NetworkFirewall.Logging.LoggingConfiguration.LogDestinationConfigs.LogDestination | Unknown | The named location for the logs, provided in a key:value mapping that is specific to the chosen destination type.   \*  For an Amazon S3 bucket, provide the name of the bucket, with key bucketName, and optionally provide a prefix, with key prefix. The following example specifies an Amazon S3 bucket named DOC-EXAMPLE-BUCKET and the prefix alerts:   "LogDestination": \{ "bucketName": "DOC-EXAMPLE-BUCKET", "prefix": "alerts" \}   \*  For a CloudWatch log group, provide the name of the CloudWatch log group, with key logGroup. The following example specifies a log group named alert-log-group:   "LogDestination": \{ "logGroup": "alert-log-group" \} \*  For a Kinesis Data Firehose delivery stream, provide the name of the delivery stream, with key deliveryStream. The following example specifies a delivery stream named alert-delivery-stream:   "LogDestination": \{ "deliveryStream": "alert-delivery-stream" \}  | 
| AWS-NetworkFirewall.Logging.LoggingConfiguration.LogDestinationConfigs | Unknown | Defines the logging destinations for the logs for a firewall. Network Firewall generates logs for stateful rule groups.  | 


#### Command Example
```!aws-network-firewall-update-logging-configuration firewall_arn=arn:aws:network-firewall:us-west-2:123456789012:firewall/myfirewall2 logging_configuration_json="{\"LogDestinationConfigs\":[{\"LogType\":\"ALERT\",\"LogDestinationType\":\"S3\",\"LogDestination\":{\"bucketName\":\"xsoar-demo-test-bucket-network-firewall\",\"prefix\":\"alerts\"}}]}"```


#### Context Example
```json
{
    "AWS-NetworkFirewall": {
        "Logging": {
            "FirewallArn": "arn:aws:network-firewall:us-west-2:123456789012:firewall/myfirewall2",
            "FirewallName": "myfirewall2",
            "LoggingConfiguration": {
                "LogDestinationConfigs": [
                    {
                        "LogDestination": {
                            "bucketName": "xsoar-demo-test-bucket-network-firewall",
                            "prefix": "alerts"
                        },
                        "LogDestinationType": "S3",
                        "LogType": "ALERT"
                    }
                ]
            }
        }
    }
}
```

#### Human Readable Output

>### AWS Network Firewall UpdateLoggingConfiguration
>|FirewallArn|FirewallName|LoggingConfiguration|
>|---|---|---|
>| arn:aws:network-firewall:us-west-2:123456789012:firewall/myfirewall2 | myfirewall2 | LogDestinationConfigs: {'LogType': 'ALERT', 'LogDestinationType': 'S3', 'LogDestination': {'bucketName': 'xsoar-demo-test-bucket-network-firewall', 'prefix': 'alerts'}} |


### aws-network-firewall-update-rule-group
***
Updates the rule settings for the specified rule group. You use a rule group by reference in one or more firewall policies. When you modify a rule group, you modify all firewall policies that use the rule group.  To update a rule group, first call DescribeRuleGroup to retrieve the current RuleGroup object, update the object as needed, and then provide the updated object to this call.


#### Base Command

`aws-network-firewall-update-rule-group`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. . | Optional | 
| raw_json | Override arguments and send a formatted JSON file. | Optional | 
| update_token | A token used for optimistic locking. Network Firewall returns a token to your requests that access the rule group. The token marks the state of the rule group resource at the time of the request.  To make changes to the rule group, you provide the token in your request. Network Firewall uses the token to ensure that the rule group hasn't changed since you last retrieved it. If it has changed, the operation fails with an InvalidTokenException. If this happens, retrieve the rule group again to get a current copy of it with a current token. Reapply your changes as needed, then try the operation again using the new token. . | Required | 
| rule_group_arn | The Amazon Resource Name (ARN) of the rule group. You must specify the ARN or the name, and you can specify both. . | Optional | 
| rule_group_name | The descriptive name of the rule group. You can't change the name of a rule group after you create it. You must specify the ARN or the name, and you can specify both. . | Optional | 
| rule_group_json | An object that defines the rule group rules. | Required | 
| rules | The name of a file containing stateful rule group rules specifications in Suricata flat format, with one rule per line. Use this to import your existing Suricata compatible rule groups.   You must provide either this rules setting or a populated RuleGroup setting, but not both.   You can provide your rule group specification in a file through this setting when you create or update your rule group. The call response returns a RuleGroup object that Network Firewall has populated from your file. Network Firewall uses the file contents to populate the rule group rules, but does not maintain a reference to the file or use the file in any way after performing the create or update. If you call DescribeRuleGroup to retrieve the rule group, Network Firewall returns rules settings inside a RuleGroup object. . | Optional | 
| type | Indicates whether the rule group is stateless or stateful. If the rule group is stateless, it contains stateless rules. If it is stateful, it contains stateful rules.   This setting is required for requests that do not include the RuleGroupARN. . Possible values are: STATELESS, STATEFUL. | Optional | 
| description | A description of the rule group. . | Optional | 
| dry_run | &lt;p&gt;Indicates whether you want Network Firewall to just check the validity of the request, rather than run the request. &lt;/p&gt; &lt;p&gt;If set to &lt;code&gt;TRUE&lt;/code&gt;, Network Firewall checks whether the request can run successfully, but doesn't actually make the requested changes. The call returns the value that the request would return if you ran it with dry run set to &lt;code&gt;FALSE&lt;/code&gt;, but doesn't make additions or changes to your resources. This option allows you to make sure that you have the required permissions to run the request and that your request parameters are valid. &lt;/p&gt; &lt;p&gt;If set to &lt;code&gt;FALSE&lt;/code&gt;, Network Firewall makes the requested changes to your resources. &lt;/p&gt;. Possible values are: True, False. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS-NetworkFirewall.RuleGroup.UpdateToken | Unknown | A token used for optimistic locking. Network Firewall returns a token to your requests that access the rule group. The token marks the state of the rule group resource at the time of the request.  To make changes to the rule group, you provide the token in your request. Network Firewall uses the token to ensure that the rule group hasn't changed since you last retrieved it. If it has changed, the operation fails with an InvalidTokenException. If this happens, retrieve the rule group again to get a current copy of it with a current token. Reapply your changes as needed, then try the operation again using the new token.  | 
| AWS-NetworkFirewall.RuleGroup.RuleGroupResponse.RuleGroupArn | Unknown | The Amazon Resource Name \(ARN\) of the rule group.  If this response is for a create request that had DryRun set to TRUE, then this ARN is a placeholder that isn't attached to a valid resource.  | 
| AWS-NetworkFirewall.RuleGroup.RuleGroupResponse.RuleGroupName | Unknown | The descriptive name of the rule group. You can't change the name of a rule group after you create it. | 
| AWS-NetworkFirewall.RuleGroup Firewall.RuleGroupResponse.RuleGroupId | Unknown | The unique identifier for the rule group.  | 
| AWS-NetworkFirewall.RuleGroup.RuleGroupResponse.Description | Unknown | A description of the rule group.  | 
| AWS-NetworkFirewall.RuleGroup.RuleGroupResponse.Type | Unknown | Indicates whether the rule group is stateless or stateful. If the rule group is stateless, it contains stateless rules. If it is stateful, it contains stateful rules.  | 
| AWS-NetworkFirewall.RuleGroup.RuleGroupResponse.Capacity | Unknown | The maximum operating resources that this rule group can use. Rule group capacity is fixed at creation. When you update a rule group, you are limited to this capacity. When you reference a rule group from a firewall policy, Network Firewall reserves this capacity for the rule group.  You can retrieve the capacity that would be required for a rule group before you create the rule group by calling CreateRuleGroup with DryRun set to TRUE.  | 
| AWS-NetworkFirewall.RuleGroup.RuleGroupResponse.RuleGroupStatus | Unknown | Detailed information about the current status of a rule group.  | 
| AWS-NetworkFirewall.RuleGroup.RuleGroupResponse.Tags.Key | Unknown | The part of the key:value pair that defines a tag. You can use a tag key to describe a category of information, such as "customer." Tag keys are case-sensitive. | 
| AWS-NetworkFirewall.RuleGroup.RuleGroupResponse.Tags.Value | Unknown | The part of the key:value pair that defines a tag. You can use a tag value to describe a specific value within a category, such as "companyA" or "companyB." Tag values are case-sensitive. | 
| AWS-NetworkFirewall.RuleGroup.RuleGroupResponse.Tags | Unknown | The key:value pairs to associate with the resource. | 
| AWS-NetworkFirewall.RuleGroup.RuleGroupResponse | Unknown | The high-level properties of a rule group. This, along with the RuleGroup, define the rule group. You can retrieve all objects for a rule group by calling DescribeRuleGroup.  | 


#### Command Example
```!aws-network-firewall-update-rule-group rule_group_arn=arn:aws:network-firewall:us-west-2:123456789012:stateless-rulegroup/example-group-stateless2 update_token=049b2760-7b8d-4eb0-a2b1-89012f073da2 rule_group_json="""{"RulesSource":{"StatelessRulesAndCustomActions":{"StatelessRules":[{"RuleDefinition":{"MatchAttributes":{"Sources":[{"AddressDefinition":"10.0.0.0/8"},{"AddressDefinition":"192.168.0.0/16"},{"AddressDefinition":"172.31.0.0/16"}]},"Actions":["aws:pass"]},"Priority":5}]}}}"""```

#### Context Example
```json
{
    "AWS-NetworkFirewall": {
        "RuleGroup": {
            "RuleGroupResponse": {
                "Capacity": 10,
                "RuleGroupArn": "arn:aws:network-firewall:us-west-2:123456789012:stateless-rulegroup/example-group-stateless2",
                "RuleGroupId": "27409b82-b9de-456e-8e29-2a0e0776c548",
                "RuleGroupName": "example-group-stateless2",
                "RuleGroupStatus": "ACTIVE",
                "Tags": [],
                "Type": "STATELESS"
            },
            "UpdateToken": "1ab2c7c4-df30-474b-9091-fe386f6bb41f"
        }
    }
}
```

#### Human Readable Output

>### AWS Network Firewall UpdateRuleGroup
>|RuleGroupResponse|UpdateToken|
>|---|---|
>| RuleGroupArn: arn:aws:network-firewall:us-west-2:123456789012:stateless-rulegroup/example-group-stateless2<br/>RuleGroupName: example-group-stateless2<br/>RuleGroupId: 27409b82-b9de-456e-8e29-2a0e0776c548<br/>Type: STATELESS<br/>Capacity: 10<br/>RuleGroupStatus: ACTIVE<br/>Tags:  | 1ab2c7c4-df30-474b-9091-fe386f6bb41f |


### aws-network-firewall-update-subnet-change-protection
***
Update the firewall subnet change  protection


#### Base Command

`aws-network-firewall-update-subnet-change-protection`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. . | Optional | 
| raw_json | Override arguments and send a formatted JSON file. | Optional | 
| update_token | An optional token that you can use for optimistic locking. Network Firewall returns a token to your requests that access the firewall. The token marks the state of the firewall resource at the time of the request.  To make an unconditional change to the firewall, omit the token in your update request. Without the token, Network Firewall performs your updates regardless of whether the firewall has changed since you last retrieved it. To make a conditional change to the firewall, provide the token in your update request. Network Firewall uses the token to ensure that the firewall hasn't changed since you last retrieved it. If it has changed, the operation fails with an InvalidTokenException. If this happens, retrieve the firewall again to get a current copy of it with a new token. Reapply your changes as needed, then try the operation again using the new token. . | Optional | 
| firewall_arn | The Amazon Resource Name (ARN) of the firewall. You must specify the ARN or the name, and you can specify both. . | Optional | 
| firewall_name | The descriptive name of the firewall. You can't change the name of a firewall after you create it. You must specify the ARN or the name, and you can specify both. . | Optional | 
| subnet_change_protection | A setting indicating whether the firewall is protected against changes to the subnet associations. Use this setting to protect against accidentally modifying the subnet associations for a firewall that is in use. When you create a firewall, the operation initializes this setting to TRUE. Possible values are: True, False. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS-NetworkFirewall.UpdateToken | Unknown | An optional token that you can use for optimistic locking. Network Firewall returns a token to your requests that access the firewall. The token marks the state of the firewall resource at the time of the request.  To make an unconditional change to the firewall, omit the token in your update request. Without the token, Network Firewall performs your updates regardless of whether the firewall has changed since you last retrieved it. To make a conditional change to the firewall, provide the token in your update request. Network Firewall uses the token to ensure that the firewall hasn't changed since you last retrieved it. If it has changed, the operation fails with an InvalidTokenException. If this happens, retrieve the firewall again to get a current copy of it with a new token. Reapply your changes as needed, then try the operation again using the new token.  | 
| AWS-NetworkFirewall.FirewallArn | Unknown | The Amazon Resource Name \(ARN\) of the firewall. | 
| AWS-NetworkFirewall.FirewallName | Unknown | The descriptive name of the firewall. You can't change the name of a firewall after you create it. | 
| AWS-NetworkFirewall.SubnetChangeProtection | Unknown | A setting indicating whether the firewall is protected against changes to the subnet associations. Use this setting to protect against accidentally modifying the subnet associations for a firewall that is in use. When you create a firewall, the operation initializes this setting to TRUE. | 


#### Command Example
```!aws-network-firewall-update-subnet-change-protection subnet_change_protection=False firewall_arn=arn:aws:network-firewall:us-west-2:123456789012:firewall/myfirewall2```

#### Context Example
```json
{
    "AWS-NetworkFirewall": {
        "FirewallAttributes": {
            "FirewallArn": "arn:aws:network-firewall:us-west-2:123456789012:firewall/myfirewall2",
            "FirewallName": "myfirewall2",
            "SubnetChangeProtection": false,
            "UpdateToken": "57b15519-a812-4758-9b23-30301ef3705a"
        }
    }
}
```

#### Human Readable Output

>### AWS Network Firewall UpdateSubnetChangeProtection
>|FirewallArn|FirewallName|SubnetChangeProtection|UpdateToken|
>|---|---|---|---|
>| arn:aws:network-firewall:us-west-2:123456789012:firewall/myfirewall2 | myfirewall2 | false | 57b15519-a812-4758-9b23-30301ef3705a |

