## Configure Prisma Cloud (RedLock) in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | Server API URL. See [here](https://api.docs.prismacloud.io/api/cloud/api-urls) for the relevant API URL for your tenant. | True |
| username | API Access Key | True |
| password | API Secret | True |
| customer | Customer name | False |
| isFetch | Fetch incidents | False |
| incidentType | Incident type | False |
| fetch_time | First fetch timestamp \(&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days, 3 months, 1 year\) | False |
| ruleName | Fetch only incidents matching this rule name | False |
| policyName | Fetch only incidents matching this policy name | False |
| policySeverity | Fetch only incidents with this severity | False |
| proxy | Use system proxy settings | False |
| unsecure | Trust any certificate \(not secure\) | False |


**Note:** Further info on creating access keys for Prisma Cloud is available [here](https://docs.paloaltonetworks.com/prisma/prisma-cloud/prisma-cloud-admin/manage-prisma-cloud-administrators/create-access-keys.html).


## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### redlock-search-alerts
***
Search alerts on the Prisma Cloud (RedLock) platform.
If no time-range arguments are given, the search will filter only alerts from the last 7 days.


#### Base Command

`redlock-search-alerts`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| time-range-date-from | Start time for search in the following string format -  MM/DD/YYYY, Should be provided along with time-range-date-to. If not both are provided, the time range will be set to the last 7 days and this argument will be ignored.| Optional |
| time-range-date-to | End time for search in the following format -  MM/DD/YYYY, Should be provided along with time-range-date-from. If not both are provided, the time range will be set to the last 7 days and this argument will be ignored.| Optional |
| time-range-value | The amount of units to go back in time | Optional |
| time-range-unit | The search unit. login and epoch are only available if timeRangeValue is not provided. | Optional |
| policy-name | The policy name | Optional |
| policy-label | The policy label | Optional |
| policy-compliance-standard | The policy compliance standard | Optional |
| cloud-account | The cloud account name | Optional |
| cloud-account-id | The cloud account ID | Optional |
| cloud-region | The cloud region name | Optional |
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

| **Argument Name** | **Description**                                                                                                                                                                                                                        | **Required** |
|-------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------|
| alert-id          | The alert ID                                                                                                                                                                                                                           | Required     |
| detailed          | Allows for retrieving entire / trimmed alert model                                                                                                                                                                                     | Optional     |
| resource_keys     | List of additional keys to return from the resource JSON, specified as a comma separated list (e.g. "key1,key2,key3").<br/>To preview all available resource JSON data, run redlock-get-alert-details with the "raw-response=true" option.  | Optional     |



#### Context Output

| **Path**                         | **Type** | **Description**                                                                               |
|----------------------------------|----------|-----------------------------------------------------------------------------------------------|
| Redlock.Alert.ID                 | string   | The alert ID                                                                                  |
| Redlock.Alert.Status             | string   | The alert status                                                                              |
| Redlock.Alert.AlertTime          | date     | The time of the alert                                                                         |
| Redlock.Alert.Policy.ID          | string   | The policy ID                                                                                 |
| Redlock.Alert.Policy.Name        | string   | The policy name                                                                               |
| Redlock.Alert.Policy.Type        | string   | The type of policy                                                                            |
| Redlock.Alert.Policy.Severity    | string   | The policy severity                                                                           |
| Redlock.Alert.Policy.Remediable  | boolean  | Whether or not the policy is remediable                                                       |
| Redlock.Alert.RiskDetail.Rating  | string   | The risk rating                                                                               |
| Redlock.Alert.RiskDetail.Score   | string   | The risk score                                                                                |
| Redlock.Alert.Resource.ID        | string   | The Resource ID of the cloud resource                                                         |
| Redlock.Alert.Resource.Name      | string   | The Resource Name of the cloud resource                                                       |
| Redlock.Alert.Resource.Account   | string   | The cloud account name where the resource resides                                             |
| Redlock.Alert.Resource.AccountID | string   | The cloud account ID where the resource resides                                               |
| Redlock.Alert.Resource.Data      | json     | Additional keys from Resource.Data.  Only appears when *resource_keys* argument is specified. |


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
| alert-id | Comma-separated list of string IDs to be dismissed | Optional |
| dismissal-note | Reason for dismissal. | Required |
| snooze-value | The amount of time to snooze. Both snooze value and unit must be specified. | Optional |
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
| policy-id | Comma-separated string of policy IDs | Optional |


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
| Redlock.RQL.Response.Data | Object | The data object returned by the RQL response. Reference: https://api.docs.prismacloud.io/api/cloud/cspm/search/ |
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
                    "Rrn": "rrn:somthing",
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
                            "publicDnsName": "ec2-x-x-x-x.eu-west-1.compute.amazonaws.com",
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
                                    "publicDnsName": "ec2-x-x-x-x.eu-west-1.compute.amazonaws.com",
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
                "publicDnsName": "ec2-x-x-x-x.eu-west-1.compute.amazonaws.com",
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



### redlock-search-event
***
Search events on the Prisma Cloud (RedLock) platform using RQL language.


#### Base Command

`redlock-search-event`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| time-range-date-from | Start time for the search, in the following format -  MM/DD/YYYY. | Optional |
| time-range-date-to | End time for the search, in the following format -  MM/DD/YYYY. | Optional |
| time-range-value | The number of time range value units for the search. For example, 3 days, 5 weeks, etc. | Optional |
| time-range-unit | The search unit. Possible values are: "hour", "week", "month", "year", "login", or "epoch". The "login" and "epoch" options are only available if timeRangeValue<br/>is not provided. Possible values are: hour, day, week, month, year, login, epoch. | Optional |
| query | Query to run in Prisma Cloud search API using RQL language. | Required |
| limit | Maximum number of entries to return. Default is 100. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Redlock.Event | Unknown | Cloud audit events. |


#### Command Example
```!redlock-search-event query=`event from cloud.audit_logs where ip EXISTS AND ip IN (172.31.34.235)` time-range-date-from=10/29/2021 time-range-date-to=10/30/2021```

#### Context Example
```json
{
    "Redlock": {
        "Event": [
            {
                "account": "712829893241",
                "regionId": 4,
                "eventTs": 1642051966000,
                "subject": "ejb-iam-cloudops",
                "type": "CREATE",
                "source": "s3.amazonaws.com",
                "name": "CreateBucket",
                "id": 2557671673,
                "ip": "172.31.34.235",
                "accessKeyUsed": false,
                "cityId": -4,
                "cityName": "Private",
                "stateId": -4,
                "stateName": "Private",
                "countryId": -4,
                "countryName": "Private",
                "cityLatitude": -1.0,
                "cityLongitude": -1.0,
                "success": false,
                "internal": false,
                "location": "Private",
                "accountName": "aws-emea-tac",
                "regionName": "AWS Oregon",
                "dynamicData": {}
            }
        ]
    }
}
```
#### Human Readable Output
>### Event Details
> Showing 1 out of 1243 events
>|accessKeyUsed|account|accountName|cityId|cityLatitude|cityLongitude|cityName|countryId|countryName|dynamicData|eventTs|id|internal|ip|location|name|regionId|regionName|source|stateId|stateName|subject|success|type|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| false | 712829893241 | aws-emea-tac | -4 | -1.0 | -1.0 | Private | -4 | Private |  | 1642051938000 | 2557671539 | false | 172.31.34.235 | Private | CreateBucket | 4 | AWS Oregon | s3.amazonaws.com | -4 | Private | ejb-iam-cloudops | false | CREATE |


### redlock-search-network
***
Search networks on the Prisma Cloud (RedLock) platform using RQL language.


#### Base Command

`redlock-search-network`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| time-range-date-from | Start time for the search, in the following format -  MM/DD/YYYY. | Optional |
| time-range-date-to | End time for the search, in the following format -  MM/DD/YYYY. | Optional |
| time-range-value | The number of time range value units for the search. For example, 3 days, 5 weeks, etc. | Optional |
| time-range-unit | The search unit. Possible values are: "hour", "week", "month", "year", "login", or "epoch". The "login" and "epoch" options are only available if timeRangeValue<br/>is not provided. Possible values are: hour, day, week, month, year, login, epoch. | Optional |
| query | Query to run in Prisma Cloud search API using RQL language. | Required |
| cloud-type | The cloud in which the network should be searched. Possible values are: aws, azure, gcp, alibaba_cloud, oci. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Redlock.Network.Node | Unknown | Cloud network node. |
| Redlock.Network.Connection | Unknown | Cloud network connection. |


#### Command Example
```!redlock-search-network query="network from vpc.flow_record where bytes > 0" time-range-unit=hour time-range-value=2```

#### Context Example
```json
{
    "Redlock": {
        "Node": [
              {
                "id": 1422407688,
                "name": "aqwe",
                "ipAddr": "172.31.34.235",
                "grouped": false,
                "suspicious": false,
                "vulnerable": true,
                "iconId": "web_server",
                "metadata": {
                    "redlock_alert_count": 16,
                    "host_vulnerability_count": 0,
                    "vpc_name": [
                        {
                            "id": "vpc-ddf45bb4",
                            "name": "defaultwala"
                        }
                    ],
                    "initial": true,
                    "vpc_id": [
                        "vpc-ddf45bb4"
                    ],
                    "ip_addresses": [
                        "172.31.34.235",
                        "35.180.1.1"
                    ],
                    "inspector_rba_count": 0,
                    "region_id": [
                        "us-east-2"
                    ],
                    "guard_duty_iam_count": 0,
                    "net_iface_id": [
                        "eni-04fec4df10974b6fe"
                    ],
                    "guard_duty_host_count": 0,
                    "tags": [
                        "None"
                    ],
                    "rrn": "rrn::managedLb:us-east-2:123456789012:393ffce52a85f09fef1be815f4fe9ca3186b4540:arn%3Aaws%3Aelasticloadbalancing%3Aus-east-2%3A123456789012%3Aloadbalancer%2Fnet%2Faqwe%2Ffb23c6bcbaee17a1",
                    "security_groups": [
                        "Unavailable"
                    ],
                    "serverless_vulnerability_count": 0,
                    "instance_id": [
                        "N/A"
                    ],
                    "account_id": [
                        "123456789012"
                    ],
                    "cloud_type": [
                        "aws"
                    ],
                    "asset_role": [
                        "Web Server"
                    ],
                    "account_name": [
                        "RedlockSandbox"
                    ],
                    "resource_id": [
                        "arn:aws:elasticloadbalancing:us-east-2:123456789012:loadbalancer/net/aqwe/fb23c6bcbaee17a1"
                    ],
                    "inspector_sbp_count": 0,
                    "region_name": [
                        "AWS Ohio"
                    ],
                    "compliance_count": 0
                }
            }
        ],
        "Connection": [
            {
                "from": 994246246,
                "to": 1418248367,
                "label": "Postgres",
                "suspicious": false,
                "metadata": {
                    "account_id": [
                        "123456789012"
                    ],
                    "cloud_type": [
                        "aws"
                    ],
                    "bytes_attempted": 0,
                    "connection_overview_table": [
                        {
                            "port": "Postgres",
                            "traffic_volume": 83938,
                            "accepted": "yes"
                        }
                    ],
                    "region_id": [
                        "us-east-2"
                    ],
                    "bytes_accepted": 83938,
                    "to_ip_addresses": [
                        "172.31.34.235"
                    ],
                    "flow_class": [
                        "Postgres"
                    ],
                    "from_ip_addresses": [
                        "172.31.34.235"
                    ],
                    "bytes_rejected": 0
                }
            }
        ]
    }
}
```

#### Human Readable Output
>## Network Details
>### Node
>|grouped|id|ipAddr|metadata|name|suspicious|vulnerable|
>|---|---|---|---|---|---|---|
>| false | 1411487329 | 172.31.34.235 | redlock_alert_count: 5<br>vpc_name: {'id': 'https://www.googleapis.com/compute/v1/projects/tac-prisma-cloud-and-compute/global/networks/us-central1', 'name': 'us-central1'}<br>vpc_id: https://www.googleapis.com/compute/v1/projects/tac-prisma-cloud-and-compute/global/networks/us-central1<br>ip_addresses: 172.31.34.235<br>inspector_rba_count: 0<br>secgroup_ids: 7466735050281694697,<br>5386953130680217005<br>guard_duty_iam_count: 0<br>asset_role: VM Instance<br>account_name: gcp-emea-tac<br>region_name: GCP Iowa<br>compliance_count: 0<br>host_vulnerability_count: 0<br>initial: true<br>region_id: us-central1<br>net_iface_id: gke-oldtac-nopublicclust-default-pool-f08b69f0-6g3n#nic0<br>guard_duty_host_count: 0<br>tags: {'name': 'gke-oldtac-nopublicclusterhere-fc43a760-node', 'values': ['']},<br>{'name': 'goog-gke-node', 'values': ['']}<br>rrn: rrn::instance:us-central1:tac-prisma-cloud-and-compute:7040cac26d62fa19dea22bcb6cd52dba6c213212:1397701696990493277<br>security_groups: {'id': '7466735050281694697', 'name': 'allow-ingress-from-iap-tac'},<br>{'id': '5386953130680217005', 'name': 'gke-oldtac-nopublicclusterhere-fc43a760-all'}<br>serverless_vulnerability_count: 0<br>instance_id: 1397701696990493277<br>account_id: tac-prisma-cloud-and-compute<br>cloud_type: gcp<br>resource_id: 1397701696990493277<br>inspector_sbp_count: 0 | gke-oldtac-nopublicclust-default-pool-f08b69f0-6g3n | false | true |
>### Connection
>|from|label|metadata|suspicious|to|
>|---|---|---|---|---|
>| 1418600304 | Web | bytes_attempted: 1473<br>connection_overview_table: {'port': 'Web (443)', 'traffic_volume': 43694, 'accepted': 'yes'},<br>{'port': 'Web (443)', 'traffic_volume': 1473, 'accepted': 'no'}<br>region_id: us-central1<br>countries: N/A<br>to_ip_addresses: 0.0.0.0<br>flow_class: Web (443)<br>states: N/A<br>account_id: tac-prisma-cloud-and-compute<br>cloud_type: gcp<br>asset_role: Internet IPs<br>bytes_accepted: 43694<br>isps: N/A<br>from_ip_addresses: 10.128.0.5<br>bytes_rejected: 0 | false | -1977384788 |

### redlock-list-scans
***
List DevOps Scans


#### Base Command

`redlock-list-scans`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_by | Group by which to aggregate scan results. Possible values are: scanId,  assetType, assetName, resourceList. Default is scanId. | Optional |
| page_size | Pagination size. Default is 25. | Optional |
| page_number | Pagination number. Default is 1. | Optional |
| sort | Sorting parameters. The sort order is ascending unless the field is prefixed with minus (-), in which case it is descending. | Optional |
| filter_type |  Time filter type. Possible values are: to_now, absolute, relative. Default is relative. | Optional |
| filter_time_amount | Number of time units. Default is 1. | Optional |
| to_now_time_unit | The time unit for retrieving the list of IaC scans. Possible values are: epoch, login, hour, day, week, month, year. Default is day. | Optional |
| filter_start_time | Start time , for example: 11/01/2021 10:10:10. | Optional |
| filter_end_time | End time in Unix time (the number of seconds that have elapsed since the Unix epoch) for the absolute time type. | Optional |
| filter_asset_type | Asset type to search with. | Optional |
| filter_asset_name | Asset name to search with. | Optional |
| filter_user | User to filter with, example: ayman@example.domain. | Optional |
| filter_status | Status to filter with, example: passed. Possible values are: . | Optional |
| relative_time_unit | Relative Time unit. Possible values are: epoch, login, year. Default is login. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Redlock.Scans.deployed | Boolean | Scan deployed attribute. |
| Redlock.Scans.fail | Number | Scan fail attribute. |
| Redlock.Scans.failureCriteria | String | Scan failure criteria attribute. |
| Redlock.Scans.matchedPoliciesSummary.high | Number | Scan matched policies summary attribute. |
| Redlock.Scans.matchedPoliciesSummary.low | Number | Scan matched low policies summary attribute. |
| Redlock.Scans.matchedPoliciesSummary.medium | Number | Scan matched medium policies summary attribute. |
| Redlock.Scans.merged | Boolean | Scan merged attribute. |
| Redlock.Scans.name | String | Scan name attribute. |
| Redlock.Scans.pass | Number | Scan pass attribute. |
| Redlock.Scans.scanAttributes.appliedAlertRules | String | Scan applied alert rules attribute. |
| Redlock.Scans.scanAttributes.branch | String | Scan Scan branch attribute. |
| Redlock.Scans.scanAttributes.org | String | Scan org attribute. |
| Redlock.Scans.scanAttributes.pullRequestId | String | Scan PR ID attribute. |
| Redlock.Scans.scanAttributes.repository | String | Scan repository attribute. |
| Redlock.Scans.scanAttributes.resourcesScanned | String | Scan resources scanned attribute. |
| Redlock.Scans.scanAttributes.templateType | String | Scan template type attribute. |
| Redlock.Scans.scanAttributes.triggeredOn | String | Scan triggered on attribute. |
| Redlock.Scans.scanAttributes.userId | String | Scan user id attribute. |
| Redlock.Scans.scanTime | Date | Scan scan time attribute. |
| Redlock.Scans.status | String | Scan status attribute. |
| Redlock.Scans.tags.name | String | Scan tags name attribute. |
| Redlock.Scans.tags.value | String | Scan tags value attribute. |
| Redlock.Scans.type | String | Scan type attribute. |
| Redlock.Scans.user | String | Scan user attribute. |
| Redlock.Scans.id | String | Scan id. |
| Redlock.Scans.links.self | String | Scan links. |
| Redlock.Scans.relationships.scanResult.links.related | String | Scan relationships scan result links . |


#### Command Example
```!redlock-list-scans filter_type="absolute" filter_start_time="01/01/2021 10:10:10" filter_end_time="10/08/2021 10:10:10" filter_asset_type="GitHub" filter_asset_name="Github Asset Dev" filter_user="user@domain.example"```

#### Context Example
```json
{
    "Redlock": {
        "Scans": [
            {
                "attributes": {
                    "deployed": false,
                    "fail": 1,
                    "failureCriteria": "H:1 or M:1 or L:1",
                    "matchedPoliciesSummary": {
                        "high": 1,
                        "low": 7,
                        "medium": 4
                    },
                    "merged": false,
                    "name": [
                        "Github Asset Dev"
                    ],
                    "pass": 0,
                    "resourceList": [],
                    "scanAttributes": {
                        "appliedAlertRules": "*",
                        "branch": "vulnerable",
                        "org": "my-devsecops",
                        "pullRequestId": "96",
                        "repository": "moon",
                        "resourcesScanned": "1",
                        "templateType": "k8s",
                        "triggeredOn": "Pull Request",
                        "userId": "my-devsecops"
                    },
                    "scanTime": "2021-09-27T11:26:23Z",
                    "status": "failed",
                    "tags": [
                        {
                            "name": "Org",
                            "value": "Engineering"
                        },
                        {
                            "name": "Team",
                            "value": "DevSecOps"
                        },
                        {
                            "name": "env",
                            "value": "QA"
                        },
                        {
                            "name": "phase",
                            "value": "testing"
                        }
                    ],
                    "type": [
                        "GitHub"
                    ],
                    "user": [
                        "user@domain.example"
                    ]
                },
                "id": "81bb4c30-0a83-4e33-bbf7-0bb96ca15b9d",
                "links": {
                    "self": "/v2/scans/81bb4c30-0a83-4e33-bbf7-0bb96ca15b9d"
                },
                "relationships": {
                    "scanResult": {
                        "links": {
                            "related": "/v2/scans/results"
                        }
                    }
                }
            }
        ]
    }
}
```

#### Human Readable Output

>### Scans List:
>|ID|Name|Scan Time|Type|User|
>|---|---|---|---|---|
>| 81bb4c30-0a83-4e33-bbf7-0bb96ca15b9d | Github Asset Dev | 2021-09-27T11:26:23Z | GitHub | user@domain.example |


### redlock-get-scan-status
***
Get scan status


#### Base Command

`redlock-get-scan-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scan_id | The scan ID. | Required |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Redlock.Scans.id | String | Scan ID |
| Redlock.Scans.status | String | Scan status |


#### Command Example
```!redlock-get-scan-status scan_id="81bb4c30-0a83-4e33-bbf7-0bb96ca15b9d"```

#### Context Example
```json
{
    "Redlock": {
        "Scans": {
            "attributes": {
                "status": "failed"
            },
            "id": "81bb4c30-0a83-4e33-bbf7-0bb96ca15b9d"
        }
    }
}
```

#### Human Readable Output

>### Scan Status:
>|ID|Status|
>|---|---|
>| 81bb4c30-0a83-4e33-bbf7-0bb96ca15b9d | failed |


### redlock-get-scan-results
***
Get scan results


#### Base Command

`redlock-get-scan-results`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scan_id | The scan ID. | Required |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Redlock.Scans.id | String | Scan ID |
| Redlock.Scans.results.attributes.blameList.file | String | Scan results blame list file |
| Redlock.Scans.results.attributes.blameList.locations.line | Number | Scan results blame list locations line |
| Redlock.Scans.results.attributes.blameList.locations.path | String | Scan results blame list locations path |
| Redlock.Scans.results.attributes.desc | String | Scan results description |
| Redlock.Scans.results.attributes.docUrl | String | Scan results doc URL |
| Redlock.Scans.results.attributes.files | String | Scan results files |
| Redlock.Scans.results.attributes.name | String | Scan results name |
| Redlock.Scans.results.attributes.policyId | String | Scan results policy ID |
| Redlock.Scans.results.attributes.rule | String | Scan results rule |
| Redlock.Scans.results.attributes.severity | String | Scan results severity |
| Redlock.Scans.results.attributes.systemDefault | Boolean | Scan results system default |
| Redlock.Scans.results.id | String | Scan results ID |


#### Command Example
```!redlock-get-scan-results scan_id="81bb4c30-0a83-4e33-bbf7-0bb96ca15b9d"```

#### Context Example
```json
{
    "Redlock": {
        "Scans": {
            "id": "81bb4c30-0a83-4e33-bbf7-0bb96ca15b9d",
            "results": [
                {
                    "attributes": {
                        "blameList": [
                            {
                                "file": "./my-devsecops-moon-405fc6e/iac/vulnerable-iac.yaml",
                                "locations": [
                                    {
                                        "line": 2,
                                        "path": "/kind"
                                    },
                                    {
                                        "line": 18,
                                        "path": "/spec/template/spec/containers"
                                    }
                                ]
                            }
                        ],
                        "desc": "Ensure that all capabilities are dropped.",
                        "docUrl": "https://some-url",
                        "files": [
                            "./my-devsecops-moon-405fc6e/iac/vulnerable-iac.yaml:[2,18]"
                        ],
                        "name": "All capabilities should be dropped",
                        "policyId": "cca6bb6a-4e05-47a1-acaa-29f198799aa2",
                        "rule": "($.kind equals Pod and (spec.containers[?any(securityContext.capabilities.drop does not exist or securityContext.capabilities.drop[*] does not contain ALL)] exists or spec. initContainers[?any(securityContext.capabilities.drop does not exist or securityContext.capabilities.drop[*] does not contain ALL )] exists)) or ($.kind is member of (Deployment, Job, DaemonSet, ReplicaSet, ReplicationController, StatefulSet) and (spec.template.spec.containers[?any(securityContext.capabilities.drop does not exist or securityContext.capabilities.drop[*] does not contain ALL)] exists or spec. initContainers[?any(securityContext.capabilities.drop does not exist or securityContext.capabilities.drop[*] does not contain ALL)] exists))",
                        "severity": "high",
                        "systemDefault": false
                    },
                    "id": "cca6bb6a-4e05-47a1-acaa-29f198799aa2"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Scan Results:
>|Description|ID|Name|Policy ID|Severity|
>|---|---|---|---|---|
>| Ensure that all capabilities are dropped. | cca6bb6a-4e05-47a1-acaa-29f198799aa2 | All capabilities should be dropped | cca6bb6a-4e05-47a1-acaa-29f198799aa2 | high |