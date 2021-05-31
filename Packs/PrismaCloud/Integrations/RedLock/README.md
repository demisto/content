## Configure Prisma Cloud (RedLock) on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Prisma Cloud (RedLock).
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | Server URL | True |
| username | API Access Key | True |
| password | API Secret | True |
| customer | Customer name | False |
| proxy | Use system proxy settings | False |
| unsecure | Trust any certificate \(not secure\) | False |
| ruleName | Fetch only incidents matching this rule name | False |
| policySeverity | Fetch only incidents with this severity | False |
| isFetch | Fetch incidents | False |
| incidentType | Incident type | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### redlock-search-alerts
***
Search alerts on the Prisma Cloud (RedLock) platform


#### Base Command

`redlock-search-alerts`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| time-range-date-from | Start time for search in the following string format -  MM/DD/YYYY | Optional | 
| time-range-date-to | End time for search in the following format -  MM/DD/YYYY | Optional | 
| time-range-value | The amount of units to go back in time | Optional | 
| time-range-unit | The search unit. login and epoch are only available if timeRangeValue is not provided. | Optional | 
| policy-name | The policy name | Optional | 
| policy-label | The policy label | Optional | 
| policy-compliance-standard | The policy compliance standard | Optional | 
| cloud-account | The cloud account | Optional | 
| cloud-region | The cloud region | Optional | 
| alert-rule-name | The alert rule name | Optional | 
| resource-id | The resource ID | Optional | 
| resource-name | The resource name | Optional | 
| resource-type | The resource type | Optional | 
| alert-status | The alert status | Optional | 
| alert-id | The alert ID | Optional | 
| cloud-type | The cloud type | Optional | 
| risk-grade | The risk grade | Optional | 
| policy-type | The policy type | Optional | 
| policy-severity | The policy severity | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Redlock.Alert.ID | string | ID of returned alert | 
| Redlock.Alert.Status | string | Status of returned alert | 
| Redlock.Alert.AlertTime | string | Time of alert | 
| Redlock.Alert.Policy.ID | string | The policy ID | 
| Redlock.Alert.Policy.Name | string | The policy name | 
| Redlock.Alert.Policy.Type | string | The policy type | 
| Redlock.Alert.Policy.Severity | string | The policy severity | 
| Redlock.Alert.Policy.Remediable | boolean | Whether or not the policy is remediable | 
| Redlock.Alert.RiskDetail.Rating | string | The risk rating | 
| Redlock.Alert.RiskDetail.Score | string | The risk score | 
| Redlock.Metadata.CountOfAlerts | number | The number of alerts found | 


#### Command Example
```!redlock-search-alerts alert-id=P-214016```

#### Context Example
```
{
    "Redlock": {
        "Alert": {
            "AlertTime": "05/29/2020 14:16:15",
            "ID": "P-214016",
            "Policy": {
                "ID": "765988-b967-9djksb-830f-sdf98798sdf9",
                "Name": "AWS Security groups allow internet traffic gnoy",
                "Remediable": true,
                "Severity": "high",
                "Type": "config"
            },
            "Resource": {
                "Account": "testAWS",
                "AccountID": "9876654321",
                "ID": "sg-98vc98sd76sd",
                "Name": "demo-98787654432"
            },
            "RiskDetail": {
                "Rating": "F",
                "Score": 170
            },
            "Status": "open"
        },
        "Metadata": {
            "CountOfAlerts": 1
        }
    }
}
```

#### Human Readable Output

>### Alerts
>|ID|Status|FirstSeen|LastSeen|AlertTime|PolicyName|PolicyType|PolicyDescription|PolicySeverity|PolicyRecommendation|PolicyDeleted|PolicyRemediable|RiskRating|ResourceName|ResourceAccount|ResourceType|ResourceCloudType|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| P-214016 | open | 05/28/2020 01:17:31 | 05/29/2020 14:16:42 | 05/29/2020 14:16:15 | AWS Security groups allow internet traffic gnoy | config | This policy identifies that Security Groups do not allow all traffic from internet. A Security Group acts as a virtual firewall that controls the traffic for one or more instances. Security groups should have restrictive ACLs to only allow incoming traffic from specific IPs to specific ports where the application is listening for connections. | high | If the Security Groups reported indeed need to restrict all traffic, follow the instructions below:<br/>1. Log in to the AWS console<br/>2. In the console, select the specific region from region drop down on the top right corner, for which the alert is generated<br/>3. Navigate to the 'VPC' service<br/>4. Click on the 'Security Group' specific to the alert<br/>5. Click on 'Inbound Rules' and remove the row with the ip value as 0.0.0.0/0 or ::/0 | false | true | F | demo-98787654432 | testAWS | SECURITY_GROUP | aws |


### redlock-get-alert-details
***
Gets the details of an alert based on alert ID


#### Base Command

`redlock-get-alert-details`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert-id | The alert ID | Required | 
| detailed | Allows for retrieving entire / trimmed alert model | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Redlock.Alert.ID | string | The alert ID | 
| Redlock.Alert.Status | string | The alert status | 
| Redlock.Alert.AlertTime | date | The time of the alert | 
| Redlock.Alert.Policy.ID | string | The policy ID | 
| Redlock.Alert.Policy.Name | string | The policy name | 
| Redlock.Alert.Policy.Type | string | The type of policy | 
| Redlock.Alert.Policy.Severity | string | The policy severity | 
| Redlock.Alert.Policy.Remediable | boolean | Whether or not the policy is remediable | 
| Redlock.Alert.RiskDetail.Rating | string | The risk rating | 
| Redlock.Alert.RiskDetail.Score | string | The risk score | 


#### Command Example
```!redlock-get-alert-details alert-id=P-214016```

#### Context Example
```
{
    "Redlock": {
        "Alert": {
            "AlertTime": "05/29/2020 14:16:15",
            "ID": "P-214016",
            "Policy": {
                "ID": "765988-b967-9djksb-830f-sdf98798sdf9",
                "Name": null,
                "Remediable": false,
                "Severity": null,
                "Type": "config"
            },
            "Resource": {
                "Account": "testAWS",
                "AccountID": "9876654321",
                "ID": "sg-98vc98sd76sd",
                "Name": "demo-98787654432"
            },
            "RiskDetail": {
                "Rating": "F",
                "Score": 170
            },
            "Status": "open"
        }
    }
}
```

#### Human Readable Output

>### Alert
>|ID|Status|FirstSeen|LastSeen|AlertTime|PolicyID|PolicyName|PolicyType|PolicySystemDefault|PolicyLabels|PolicyDescription|PolicySeverity|PolicyRecommendation|PolicyDeleted|PolicyRemediable|PolicyLastModifiedOn|PolicyLastModifiedBy|RiskScore|RiskRating|ResourceName|ResourceRRN|ResourceID|ResourceAccount|ResourceAccountID|ResourceType|ResourceRegionID|ResourceApiName|ResourceUrl|ResourceData|ResourceAccessKeyAge|ResourceInactiveSinceTs|ResourceCloudType|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| P-214016 | open | 05/28/2020 01:17:31 | 05/29/2020 14:16:42 | 05/29/2020 14:16:15 |  |  | config | false |  |  |  |  |  | false |  |  | 170 | F | demo-98787654432 |  | sg-98vc98sd76sd | testAWS | 9876654321 | SECURITY_GROUP | us-west-2 | aws-ec2-describe-security-groups |  | vpcId: vpc-0824920b6d19bc<br/>description: EKS created security group applied to ENI that is attached to EKS Control Plane master nodes, as well as any managed workloads.<br/>tags: {u'value': u'demo-98787654432', u'key': u'Name'},<br/>{u'value': u'cn-demo', u'key': u'aws:eks:cluster-name'},<br/>{u'value': u'owned', u'key': u'kubernetes.io/cluster/cn-demo'}<br/>ipPermissions: {u'ipv4Ranges': [{u'description': u'kubernetes.io/rule/nlb/mtu=a7d568916a1b411ea83260a614b2e8ec', u'cidrIp': u'0.0.0.0/0'}], u'prefixListIds': [], u'fromPort': 3, u'ipRanges': [u'0.0.0.0/0'], u'toPort': 4, u'ipProtocol': u'icmp', u'userIdGroupPairs': [], u'ipv6Ranges': []},<br/>{u'ipv4Ranges': [{u'description': u'kubernetes.io/rule/nlb/client=a7d568916a1b411ea83260a614b2e8ec', u'cidrIp': u'0.0.0.0/0'}, {u'description': u'kubernetes.io/rule/nlb/health=a7d568916a1b411ea83260a614b2e8ec', u'cidrIp': u'192.168.0.0/16'}], u'prefixListIds': [], u'fromPort': 30463, u'ipRanges': [u'0.0.0.0/0', u'192.168.0.0/16'], u'toPort': 30463, u'ipProtocol': u'tcp', u'userIdGroupPairs': [], u'ipv6Ranges': []},<br/>{u'prefixListIds': [], u'ipv4Ranges': [{u'cidrIp': u'x.x.x.x/16'}], u'ipRanges': [u'x.x.x.x/16'], u'ipProtocol': u'-1', u'userIdGroupPairs': [{u'userId': u'9876654321', u'groupId': u'sg-0ce26260850e500d4', u'description': u'Allow unmanaged nodes to communicate with control plane (all ports)'}, {u'userId': u'9876654321', u'groupId': u'sg-98vc98sd76sd'}], u'ipv6Ranges': []}<br/>groupName: demo-98787654432<br/>ipPermissionsEgress: {u'prefixListIds': [], u'ipv4Ranges': [{u'cidrIp': u'0.0.0.0/0'}], u'ipRanges': [u'0.0.0.0/0'], u'ipProtocol': u'-1', u'userIdGroupPairs': [], u'ipv6Ranges': []}<br/>ownerId: 9876654321<br/>groupId: sg-98vc98sd76sd |  |  | aws |


### redlock-dismiss-alerts
***
Dismiss the alerts matching the given filter. Must provide either policy IDs or alert IDs.


#### Base Command

`redlock-dismiss-alerts`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert-id | comma separated list of string IDs to be dismissed | Optional | 
| dismissal-note | Reason for dismissal | Required | 
| snooze-value | The amount of time to snooze. Both snooze value and unit must be specified | Optional | 
| snooze-unit | The time unit for if snoozing alert.  Both snooze value and unit must be specified if snoozing. | Optional | 
| time-range-date-from | Start time for search in the following string format -  MM/DD/YYYY | Optional | 
| time-range-date-to | End time for search in the following format -  MM/DD/YYYY | Optional | 
| time-range-value | The amount of units to go back in time | Optional | 
| time-range-unit | The search unit | Optional | 
| policy-name | The policy name | Optional | 
| policy-label | The policy label | Optional | 
| policy-compliance-standard | The policy compliance standard | Optional | 
| cloud-account | The cloud account | Optional | 
| cloud-region | The cloud region | Optional | 
| alert-rule-name | The alert rule name | Optional | 
| resource-id | The resource ID | Optional | 
| resource-name | The resource name | Optional | 
| resource-type | The resource type | Optional | 
| alert-status | The alert status | Optional | 
| cloud-type | The cloud type | Optional | 
| risk-grade | The risk grade | Optional | 
| policy-type | The policy type | Optional | 
| policy-severity | The policy severity | Optional | 
| policy-id | comma separated string of policy IDs | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Redlock.DismissedAlert.ID | string | The IDs of the dismissed alerts | 


#### Command Example
```!redlock-dismiss-alerts dismissal-note="testing" alert-id=P-214016```

#### Context Example
```
{
    "Redlock": {
        "DismissedAlert": {
            "ID": [
                "P-214016"
            ]
        }
    }
}
```

#### Human Readable Output

>### Alerts dismissed successfully. Dismissal Note: testing.

### redlock-reopen-alerts
***
Re-open the alerts matching the given filter.  Must provide either policy IDs or alert IDs.


#### Base Command

`redlock-reopen-alerts`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert-id | The IDs of alerts to reopen | Optional | 
| time-range-date-from | Start time for search in the following string format -  MM/DD/YYYY | Optional | 
| time-range-date-to | End time for search in the following format -  MM/DD/YYYY | Optional | 
| time-range-value | The amount of units to go back in time | Optional | 
| time-range-unit | The search unit | Optional | 
| policy-name | The policy name | Optional | 
| policy-label | The policy label | Optional | 
| policy-compliance-standard | The policy compliance standard | Optional | 
| cloud-account | The cloud account | Optional | 
| cloud-region | The cloud region | Optional | 
| alert-rule-name | The alert rule name | Optional | 
| resource-id | The resource ID | Optional | 
| resource-name | The resource name | Optional | 
| resource-type | The resource type | Optional | 
| alert-status | The alert status | Optional | 
| cloud-type | The cloud type | Optional | 
| risk-grade | The risk grade | Optional | 
| policy-type | The policy type | Optional | 
| policy-severity | The policy severity | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Redlock.ReopenedAlert.ID | string | IDs of the re\-opened alerts | 


#### Command Example
```!redlock-reopen-alerts alert-id=P-214016```

#### Context Example
```
{
    "Redlock": {
        "ReopenedAlert": {
            "ID": [
                "P-214016"
            ]
        }
    }
}
```

#### Human Readable Output

>### Alerts re-opened successfully.

### redlock-list-alert-filters
***
List the acceptable filters and values for alerts


#### Base Command

`redlock-list-alert-filters`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

There is no context output for this command.

#### Command Example
```!redlock-list-alert-filters```

#### Context Example
```
{}
```

#### Human Readable Output

>### Filter options
>|Name|Options|Static|
>|---|---|---|
>| cloud.account |  | false |
>| alert.id |  | false |
>| cloud.region |  | false |
>| policy.label |  | false |
>| resource.id |  | false |
>| cloud.type | alibaba_cloud,aws,azure,gcp | true |
>| resource.name |  | false |
>| account.group |  | false |
>| risk.grade | A,B,C,F | true |
>| policy.complianceSection |  | false |
>| policy.remediable | true,false | true |
>| policy.name |  | false |
>| policy.type | anomaly,audit_event,config,network | true |
>| alert.status | dismissed,snoozed,open,resolved | true |
>| alertRule.name |  | false |
>| policy.subtype | build,run | true |
>| resource.type |  | false |
>| policy.complianceStandard |  | false |
>| cloud.accountId |  | false |
>| policy.severity | high,medium,low | true |
>| policy.rule.type | cft,k8s,tf | true |
>| cloud.service |  | false |
>| policy.complianceRequirement |  | false |


### redlock-get-remediation-details
***
Get remediation details for a given alert


#### Base Command

`redlock-get-remediation-details`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert-id | The alert id to get remediation details for | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Redlock.Alert.Remediation.Description | string | Description of CLI remediation instructions | 
| Redlock.Alert.ID | string | The ID of the alert for which the remediation details applies | 
| Redlock.Alert.Remediation.CLI | string | Exact CLI command string | 


#### Command Example
```!redlock-get-remediation-details alert-id=P-214016```

#### Context Example
```
{
    "Redlock": {
        "Alert": {
            "ID": "P-214016",
            "Remediation": {
                "CLI": "aws --region us-west-2 ec2 revoke-security-group-ingress --group-id sg-984392384bkhjb --ip-permissions '[{\"IpProtocol\": \"tcp\", \"IpRanges\":[{\"CidrIp\": \"0.0.0.0/0\"}]}]' ; aws --region us-west-1 ec2 authorize-security-group-ingress --group-id sg-98237498798 --ip-permissions '[{\"IpProtocol\": \"tcp\", \"FromPort\": 22, \"ToPort\": 22, \"IpRanges\":[{\"CidrIp\": \"10.0.0.0/8\", \"Description\": \"Enforced by Redlock Remediation\"}]}]'",
                "Description": "\"This CLI command requires 'ec2:RevokeSecurityGroupIngress' permission. Successful execution will update the security group to revoke the ingress rule records open to internet either on IPv4 or on IPv6 protocol.\"} To resolve the alert from Prisma Cloud's console, add the permission."
            }
        }
    }
}
```

#### Human Readable Output

>### Remediation Details
>|ID|RemediationCLI|RemediationDescription|
>|---|---|---|
>| P-211648 | gcloud compute networks subnets update default --project=project1-111111 --region europe-north2 --enable-flow-logs | This CLI command requires 'compute.securityAdmin' permission. Successful execution will enables GCP VPC Flow logs for subnets to capture information about the IP traffic going to and from network interfaces in VPC Subnets. To resolve the alert from Prisma Cloud's console, add the permission. |


### redlock-get-rql-response
***
Run RQL query on Prisma Cloud


#### Base Command

`redlock-get-rql-response`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | determines the limit on the results. '; limit search records to {}' is appended to every query where {} is the value of limit or 1 if not passed | Optional | 
| rql | the RQL query to run. Example RQL queries can be found here: https://docs.paloaltonetworks.com/prisma/prisma-cloud/prisma-cloud-rql-reference/rql-reference/rql-examples. Note that ` limit search records to 1` is automatically appended to each query and a `;` may need to be added to the end of the rql input to make the entire query valid.  The limit parameter adjusts this to be a value other than 1. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Redlock.RQL.Query | String | The | 
| Redlock.RQL.Response.AccountId | Date | The cloud account ID. | 
| Redlock.RQL.Response.AccountName | String | The cloud account name. | 
| Redlock.RQL.Response.AllowDrillDown | Boolean | Flag to allow drill down. | 
| Redlock.RQL.Response.CloudType | String | The cloud type. | 
| Redlock.RQL.Response.Data | Object | The data object returned by the RQL response. Reference: https://api.docs.prismacloud.io/reference#search-config | 
| Redlock.RQL.Response.Deleted | Boolean | Flag if deleted. | 
| Redlock.RQL.Response.HasAlert | Boolean | Flag to check if RQL response has alerts. | 
| Redlock.RQL.Response.HasExtFindingRiskFactors | Boolean | Flag if query returns external risk factors. | 
| Redlock.RQL.Response.HasExternalFinding | Boolean | Flag for external findings. | 
| Redlock.RQL.Response.HasExternalIntegration | Boolean | Flag for external integration. | 
| Redlock.RQL.Response.HasNetwork | Boolean | Flag for determining if network exists. | 
| Redlock.RQL.Response.Id | String | The RQL response ID. | 
| Redlock.RQL.Response.InsertTs | Date | The response time. | 
| Redlock.RQL.Response.Name | String | The RQL response name. | 
| Redlock.RQL.Response.RegionId | String | The cloud region ID. | 
| Redlock.RQL.Response.RegionName | String | The cloud region name. | 
| Redlock.RQL.Response.ResourceType | String | The resource type. | 
| Redlock.RQL.Response.Rrn | String | The account RRN. | 
| Redlock.RQL.Response.Service | String | The RQL response service. | 
| Redlock.RQL.Response.StateId | String | The response state ID. | 


#### Command Example
```!redlock-get-rql-response rql="config where api.name = 'aws-ec2-describe-instances' as X; config where api.name = 'aws-ec2-describe-security-groups' as Y; config where api.name = 'aws-ec2-describe-vpcs' as Z; filter 'not _Set.intersection($.X.vpcId,$.Y.vpcId) intersects (vpc-5b9a3c33,vpc-b8ba2dd0,vpc-b8ba2dd01)'; show X;"```


#### Context Example
```json
{
    "Redlock": {
        "RQL": {
            "Query": "config where api.name = 'aws-ec2-describe-instances' as X; config where api.name = 'aws-ec2-describe-security-groups' as Y; config where api.name = 'aws-ec2-describe-vpcs' as Z; filter 'not _Set.intersection($.X.vpcId,$.Y.vpcId) intersects (vpc-5b9a3c33,vpc-b8ba2dd0,vpc-b8ba2dd01)'; show X; limit search records to 1",
            "Response": [
                {
                    "AccountId": "1234567890",
                    "AccountName": "AWS PAN RBC",
                    "AllowDrillDown": true,
                    "CloudType": "aws",
                    "Data": {
                        "AmiLaunchIndex": 0,
                        "Architecture": "x86_64",
                        "BlockDeviceMappings": [
                            {
                                "DeviceName": "/dev/xvda",
                                "Ebs": {
                                    "AttachTime": "2020-11-22T09:16:37.000Z",
                                    "DeleteOnTermination": true,
                                    "Status": "attached",
                                    "VolumeId": "vol"
                                }
                            },
                            {
                                "DeviceName": "/dev/xvdbg",
                                "Ebs": {
                                    "AttachTime": "2020-11-23T15:33:52.000Z",
                                    "DeleteOnTermination": false,
                                    "Status": "attached",
                                    "VolumeId": "vol"
                                }
                            },
                            {
                                "DeviceName": "/dev/xvdcp",
                                "Ebs": {
                                    "AttachTime": "2020-11-23T15:33:52.000Z",
                                    "DeleteOnTermination": false,
                                    "Status": "attached",
                                    "VolumeId": "vol"
                                }
                            }
                        ],
                        "CapacityReservationSpecification": {
                            "CapacityReservationPreference": "open"
                        },
                        "ClientToken": "fleet",
                        "CpuOptions": {
                            "CoreCount": 1,
                            "ThreadsPerCore": 2
                        },
                        "EbsOptimized": false,
                        "ElasticGpuAssociations": [],
                        "ElasticInferenceAcceleratorAssociations": [],
                        "EnaSupport": true,
                        "HibernationOptions": {
                            "Configured": false
                        },
                        "Hypervisor": "xen",
                        "IamInstanceProfile": {
                            "Arn": "arn",
                            "Id": "AIPARLTR3KMHTT67AZ27N"
                        },
                        "ImageId": "ami-008ad23b7f9a160e5",
                        "InstanceId": "i-123456789",
                        "InstanceType": "t3.medium",
                        "KeyName": "kubernetes",
                        "LaunchTime": "2020-11-22T09:16:36.000Z",
                        "Licenses": [],
                        "MetadataOptions": {
                            "HttpEndpoint": "enabled",
                            "HttpPutResponseHopLimit": 2,
                            "HttpTokens": "optional",
                            "State": "applied"
                        },
                        "Monitoring": {
                            "State": "disabled"
                        },
                        "NetworkInterfaces": [
                            {
                                "Association": {
                                    "IpOwnerId": "amazon",
                                    "PublicDnsName": "ec2-x-x-x-x.eu-west-1.compute.amazonaws.com",
                                    "PublicIp": "y.y.y.y"
                                },
                                "Attachment": {
                                    "AttachTime": "2020-11-22T09:16:36.000Z",
                                    "AttachmentId": "eni-attach-0146b63374e77b227",
                                    "DeleteOnTermination": true,
                                    "DeviceIndex": 0,
                                    "Status": "attached"
                                },
                                "Description": "",
                                "Groups": [
                                    {
                                        "GroupId": "sg-13456789987654",
                                        "GroupName": "test"
                                    },
                                    {
                                        "GroupId": "sg-1234567898765",
                                        "GroupName": "test"
                                    }
                                ],
                                "InterfaceType": "interface",
                                "Ipv6Addresses": [],
                                "MacAddress": "02:94:a1:55:69:43",
                                "NetworkInterfaceId": "eni-0a5537731ce0b7fa2",
                                "OwnerId": "1234567890",
                                "PrivateDnsName": "ip-x.x.x.x.eu-west-1.compute.internal",
                                "PrivateIpAddress": "x.x.x.x",
                                "PrivateIpAddresses": [
                                    {
                                        "Association": {
                                            "IpOwnerId": "amazon",
                                            "PublicDnsName": "ec2-x-x-x-x.eu-west-1.compute.amazonaws.com",
                                            "PublicIp": "y.y.y.y"
                                        },
                                        "Primary": true,
                                        "PrivateDnsName": "ip-x.x.x.x.eu-west-1.compute.internal",
                                        "PrivateIpAddress": "x.x.x.x"
                                    },
                                    {
                                        "Primary": false,
                                        "PrivateDnsName": "ip-x.x.x.x.eu-west-1.compute.internal",
                                        "PrivateIpAddress": "x.x.x.x"
                                    },
                                    {
                                        "Primary": false,
                                        "PrivateDnsName": "ip-x.x.x.x.eu-west-1.compute.internal",
                                        "PrivateIpAddress": "x.x.x.x"
                                    },
                                    {
                                        "Primary": false,
                                        "PrivateDnsName": "ip-x.x.x.x.eu-west-1.compute.internal",
                                        "PrivateIpAddress": "x.x.x.x"
                                    },
                                    {
                                        "Primary": false,
                                        "PrivateDnsName": "ip-a.a.a.a.eu-west-1.compute.internal",
                                        "PrivateIpAddress": "a.a.a.a"
                                    },
                                    {
                                        "Primary": false,
                                        "PrivateDnsName": "ip-z.z.z.z.eu-west-1.compute.internal",
                                        "PrivateIpAddress": "z.z.z.z"
                                    }
                                ],
                                "SourceDestCheck": true,
                                "Status": "in-use",
                                "SubnetId": "subnet-123456789",
                                "VpcId": "vpc-123456789"
                            },
                            {
                                "Attachment": {
                                    "AttachTime": "2020-11-23T15:34:00.000Z",
                                    "AttachmentId": "eni-attach-0251b661bb021effe",
                                    "DeleteOnTermination": true,
                                    "DeviceIndex": 1,
                                    "Status": "attached"
                                },
                                "Description": "aws-K8S-i-123456789",
                                "Groups": [
                                    {
                                        "GroupId": "sg-13456789987654",
                                        "GroupName": "test"
                                    },
                                    {
                                        "GroupId": "sg-1234567898765",
                                        "GroupName": "test"
                                    }
                                ],
                                "InterfaceType": "interface",
                                "Ipv6Addresses": [],
                                "MacAddress": "x:z:d",
                                "NetworkInterfaceId": "eni-xyz",
                                "OwnerId": "1234567890",
                                "PrivateDnsName": "ip-x.x.x.x.eu-west-1.compute.internal",
                                "PrivateIpAddress": "x.x.x.x",
                                "PrivateIpAddresses": [
                                    {
                                        "Primary": false,
                                        "PrivateDnsName": "ip-x.x.x.x.eu-west-1.compute.internal",
                                        "PrivateIpAddress": "x.x.x.x"
                                    },
                                    {
                                        "Primary": false,
                                        "PrivateDnsName": "ip-x.x.x.x.eu-west-1.compute.internal",
                                        "PrivateIpAddress": "x.x.x.x"
                                    },
                                    {
                                        "Primary": false,
                                        "PrivateDnsName": "ip-x.x.x.x.eu-west-1.compute.internal",
                                        "PrivateIpAddress": "x.x.x.x"
                                    },
                                    {
                                        "Primary": false,
                                        "PrivateDnsName": "ip-x.x.x.x.eu-west-1.compute.internal",
                                        "PrivateIpAddress": "x.x.x.x"
                                    },
                                    {
                                        "Primary": false,
                                        "PrivateDnsName": "ip-x.x.x.x.eu-west-1.compute.internal",
                                        "PrivateIpAddress": "x.x.x.x"
                                    },
                                    {
                                        "Primary": true,
                                        "PrivateDnsName": "ip-x.x.x.x.eu-west-1.compute.internal",
                                        "PrivateIpAddress": "x.x.x.x"
                                    }
                                ],
                                "SourceDestCheck": true,
                                "Status": "in-use",
                                "SubnetId": "subnet-123456789",
                                "VpcId": "vpc-123456789"
                            }
                        ],
                        "Placement": {
                            "AvailabilityZone": "eu-west-1c",
                            "GroupName": "",
                            "Tenancy": "default"
                        },
                        "PrivateDnsName": "ip-x.x.x.x.eu-west-1.compute.internal",
                        "PrivateIpAddress": "x.x.x.x",
                        "ProductCodes": [],
                        "PublicDnsName": "ec2-x-x-x-x.eu-west-1.compute.amazonaws.com",
                        "PublicIpAddress": "y.y.y.y",
                        "RootDeviceName": "/dev/xvda",
                        "RootDeviceType": "ebs",
                        "SecurityGroups": [
                            {
                                "GroupId": "sg-13456789987654",
                                "GroupName": "test"
                            },
                            {
                                "GroupId": "sg-1234567898765",
                                "GroupName": "test"
                            }
                        ],
                        "SourceDestCheck": true,
                        "State": {
                            "Code": 16,
                            "Name": "running"
                        },
                        "StateTransitionReason": "",
                        "StatusEvents": [],
                        "SubnetId": "subnet-123456789",
                        "Tags": [
                            {
                                "Key": "Name",
                                "Value": "cluster-ng-11111111-Node"
                            },
                            {
                                "Key": "test.com/nodegroup-name",
                                "Value": "ng-a143ec42"
                            },
                            {
                                "Key": "test.com/nodegroup-type",
                                "Value": "managed"
                            },
                            {
                                "Key": "aws:autoscaling:groupName",
                                "Value": "eks-123456789"
                            },
                            {
                                "Key": "aws:ec2:fleet-id",
                                "Value": "fleet-0987654321"
                            },
                            {
                                "Key": "aws:ec2launchtemplate:id",
                                "Value": "lt-123456789"
                            },
                            {
                                "Key": "aws:ec2launchtemplate:version",
                                "Value": "1"
                            },
                            {
                                "Key": "eks:cluster-name",
                                "Value": "cluster"
                            },
                            {
                                "Key": "eks:nodegroup-name",
                                "Value": "ng-a143ec42"
                            },
                            {
                                "Key": "test.com/cluster-autoscaler/cluster",
                                "Value": "owned"
                            },
                            {
                                "Key": "test.com/cluster-autoscaler/enabled",
                                "Value": "true"
                            },
                            {
                                "Key": "kubernetes.io/cluster/cluster",
                                "Value": "owned"
                            }
                        ],
                        "VirtualizationType": "hvm",
                        "VpcId": "vpc-123456789"
                    },
                    "Deleted": false,
                    "HasAlert": false,
                    "HasExtFindingRiskFactors": false,
                    "HasExternalFinding": false,
                    "HasExternalIntegration": false,
                    "HasNetwork": false,
                    "Id": "i-123456789",
                    "InsertTs": 1234567876543,
                    "Name": "cluster-ng-11111111-Node",
                    "RegionId": "eu-west-1",
                    "RegionName": "AWS Ireland",
                    "ResourceType": "Instance",
                    "Rrn": "rrn:somthing"
                    "Service": "Amazon EC2",
                    "StateId": "asdfghjklkjhgfdssaa"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### RQL Output:
>|Account|Deleted|Region|Resource Name|Service|
>|---|---|---|---|---|
>| AWS PAN | false | AWS Ireland | cluster-ng-11111111-Node | Amazon EC2 |


### redlock-search-config
***
Search configuration inventory on the Prisma Cloud (RedLock) platform using RQL language


#### Base Command

`redlock-search-config`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| time-range-date-from | Start time for search in the following string format -  MM/DD/YYYY. | Optional | 
| time-range-date-to | End time for search in the following format -  MM/DD/YYYY. | Optional | 
| time-range-value | The number of units to go back in time for the search. | Optional | 
| time-range-unit | The search unit. Possible values are: "hour", "day", "week", "month", "year", "login", and "epoch". The login and epoch values are only available if the time-range-value argument is not provided. | Optional | 
| query | Query to run in Prisma Cloud config API (use RQL). | Required | 
|limit |The maximum number of entries to return. Default is 100. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Redlock.Asset.accountId | Date | Cloud Account ID. | 
| Redlock.Asset.accountName | String | Cloud account Name | 
| Redlock.Asset.allowDrillDown | Boolean |  | 
| Redlock.Asset.cloudType | String | Cloud type. | 
| Redlock.Asset.deleted | Boolean | Whether the asset was delete. | 
| Redlock.Asset.hasAlert | Boolean | Whether the asset has a Prisma Cloud alert. | 
| Redlock.Asset.hasExtFindingRiskFactors | Boolean | Whether the asset has external finding risk factors. | 
| Redlock.Asset.hasExternalFinding | Boolean | Whether the asset has an external finding. | 
| Redlock.Asset.hasExternalIntegration | Boolean | Whether the asset has an external integration. | 
| Redlock.Asset.hasNetwork | Boolean |Whether the asset has a network. | 
| Redlock.Asset.id | String | The Redlock asset ID. | 
| Redlock.Asset.data | Unknown | The Redlock asset specific data. |
| Redlock.Asset.insertTs | Date | The asset insert TS. | 
| Redlock.Asset.name | String | The asset name. | 
| Redlock.Asset.regionId | String | The cloud region ID of the asset. | 
| Redlock.Asset.regionName | String | The cloud region name of the asset. | 
| Redlock.Asset.resourceType | String | The cloud resource type of the asset. | 
| Redlock.Asset.rrn | String | The cloud RRN of the asset. | 
| Redlock.Asset.service | String | The state ID of the asset. | 
| Redlock.Asset.stateId | String | State ID | 


#### Command Example
```!redlock-search-config query=`config where cloud.type = "aws" and cloud.service = "Amazon EC2" and api.name = "aws-ec2-describe-instances" and cloud.region="AWS Paris"````

#### Context Example
```json
{
    "Redlock": {
        "Asset": {
            "accountId": "1234568717",
            "accountName": "cloud-account-test",
            "allowDrillDown": true,
            "cloudType": "aws",
            "data": {
                "amiLaunchIndex": 0,
                "architecture": "x86_64",
                "blockDeviceMappings": [
                    {
                        "deviceName": "/dev/sda1",
                        "ebs": {
                            "attachTime": "2019-10-24T19:21:26.000Z",
                            "deleteOnTermination": true,
                            "status": "attached",
                            "volumeId": "vol-0d76d5536e9900a9d"
                        }
                    }
                ],
                "capacityReservationSpecification": {
                    "capacityReservationPreference": "open"
                },
                "clientToken": "",
                "cpuOptions": {
                    "coreCount": 1,
                    "threadsPerCore": 1
                },
                "ebsOptimized": false,
                "elasticGpuAssociations": [],
                "elasticInferenceAcceleratorAssociations": [],
                "enaSupport": true,
                "hibernationOptions": {
                    "configured": false
                },
                "hypervisor": "xen",
                "imageId": "ami-0bb607148d8cf36fb",
                "instanceId": "i-0b12b0f4ed4b78e0b",
                "instanceType": "t2.micro",
                "keyName": "server1",
                "launchTime": "2019-10-24T19:21:25.000Z",
                "licenses": [],
                "metadataOptions": {
                    "httpEndpoint": "enabled",
                    "httpPutResponseHopLimit": 1,
                    "httpTokens": "optional",
                    "state": "applied"
                },
                "monitoring": {
                    "state": "disabled"
                },
                "networkInterfaces": [
                    {
                        "association": {
                            "ipOwnerId": "amazon",
                            "publicDnsName": "ec2-35-180-1-1.eu-west-3.compute.amazonaws.com",
                            "publicIp": "35.180.1.1"
                        },
                        "attachment": {
                            "attachTime": "2019-10-24T19:21:25.000Z",
                            "attachmentId": "eni-attach-0f8b6f1a9db5563d8",
                            "deleteOnTermination": true,
                            "deviceIndex": 0,
                            "status": "attached"
                        },
                        "description": "",
                        "groups": [
                            {
                                "groupId": "sg-0528d34b26dc81",
                                "groupName": "SSH-HTTPS-IPSec"
                            }
                        ],
                        "interfaceType": "interface",
                        "ipv6Addresses": [],
                        "macAddress": "0e:da:ad:84:82:7e",
                        "networkInterfaceId": "eni-09e89a2e7923d7",
                        "ownerId": "1234",
                        "privateDnsName": "ip-172-31-34-235.eu-west-3.compute.internal",
                        "privateIpAddress": "172.31.34.235",
                        "privateIpAddresses": [
                            {
                                "association": {
                                    "ipOwnerId": "amazon",
                                    "publicDnsName": "ec2-35-180-1-1.eu-west-3.compute.amazonaws.com",
                                    "publicIp": "35.180.1.1"
                                },
                                "primary": true,
                                "privateDnsName": "ip-172-31-34-235.eu-west-3.compute.internal",
                                "privateIpAddress": "172.31.34.235"
                            }
                        ],
                        "sourceDestCheck": true,
                        "status": "in-use",
                        "subnetId": "subnet-89c025c4",
                        "vpcId": "vpc-079b3111"
                    }
                ],
                "placement": {
                    "availabilityZone": "eu-west-3c",
                    "groupName": "",
                    "tenancy": "default"
                },
                "privateDnsName": "ip-172-31-34-235.eu-west-3.compute.internal",
                "privateIpAddress": "172.31.34.235",
                "productCodes": [],
                "publicDnsName": "ec2-35-180-1-1.eu-west-3.compute.amazonaws.com",
                "publicIpAddress": "35.180.1.1",
                "rootDeviceName": "/dev/sda1",
                "rootDeviceType": "ebs",
                "securityGroups": [
                    {
                        "groupId": "sg-0528d34b26dc81415",
                        "groupName": "SSH-HTTPS-IPSec"
                    }
                ],
                "sourceDestCheck": true,
                "state": {
                    "code": 16,
                    "name": "running"
                },
                "stateTransitionReason": "",
                "statusEvents": [],
                "subnetId": "subnet-89c025c4",
                "tags": [
                    {
                        "key": "Name",
                        "value": "server1"
                    }
                ],
                "virtualizationType": "hvm",
                "vpcId": "vpc-079b3111"
            },
            "deleted": false,
            "hasAlert": false,
            "hasExtFindingRiskFactors": false,
            "hasExternalFinding": false,
            "hasExternalIntegration": false,
            "hasNetwork": false,
            "id": "i-0b12baaaaa4b78e0b",
            "insertTs": 1603440806825,
            "name": "server1",
            "regionId": "eu-west-3",
            "regionName": "AWS Paris",
            "resourceType": "Instance",
            "rrn": "rrn::instance:eu-west-3:12345:9db2db5fdba47606863c8da86d3ae594fb5aee2b:i-0b12b0f4ed4b78e0b",
            "service": "Amazon EC2",
            "stateId": "5e79fd1aaab84a26abbf5641d4a115edfb8f7353"
        }
    }
}
```
#### Human Readable Output

>### RQL Output:
>|Account|Deleted|Region|Resource Name|Service|
>|---|---|---|---|---|
>| Felix - AWS - pan-lab | false | AWS Virginia | tl-console | Amazon EC2 |
