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
>| P-214016 | open | 05/28/2020 01:17:31 | 05/29/2020 14:16:42 | 05/29/2020 14:16:15 |  |  | config | false |  |  |  |  |  | false |  |  | 170 | F | demo-98787654432 |  | sg-98vc98sd76sd | testAWS | 9876654321 | SECURITY_GROUP | us-west-2 | aws-ec2-describe-security-groups |  | vpcId: vpc-0824920b6d19bc4f1<br/>description: EKS created security group applied to ENI that is attached to EKS Control Plane master nodes, as well as any managed workloads.<br/>tags: {u'value': u'demo-98787654432', u'key': u'Name'},<br/>{u'value': u'cn-demo', u'key': u'aws:eks:cluster-name'},<br/>{u'value': u'owned', u'key': u'kubernetes.io/cluster/cn-demo'}<br/>ipPermissions: {u'ipv4Ranges': [{u'description': u'kubernetes.io/rule/nlb/mtu=a7d568916a1b411ea83260a614b2e8ec', u'cidrIp': u'0.0.0.0/0'}], u'prefixListIds': [], u'fromPort': 3, u'ipRanges': [u'0.0.0.0/0'], u'toPort': 4, u'ipProtocol': u'icmp', u'userIdGroupPairs': [], u'ipv6Ranges': []},<br/>{u'ipv4Ranges': [{u'description': u'kubernetes.io/rule/nlb/client=a7d568916a1b411ea83260a614b2e8ec', u'cidrIp': u'0.0.0.0/0'}, {u'description': u'kubernetes.io/rule/nlb/health=a7d568916a1b411ea83260a614b2e8ec', u'cidrIp': u'192.168.0.0/16'}], u'prefixListIds': [], u'fromPort': 30463, u'ipRanges': [u'0.0.0.0/0', u'192.168.0.0/16'], u'toPort': 30463, u'ipProtocol': u'tcp', u'userIdGroupPairs': [], u'ipv6Ranges': []},<br/>{u'prefixListIds': [], u'ipv4Ranges': [{u'cidrIp': u'192.168.1.1/16'}], u'ipRanges': [u'192.168.1.1/16'], u'ipProtocol': u'-1', u'userIdGroupPairs': [{u'userId': u'9876654321', u'groupId': u'sg-0ce26260850e500d4', u'description': u'Allow unmanaged nodes to communicate with control plane (all ports)'}, {u'userId': u'9876654321', u'groupId': u'sg-98vc98sd76sd'}], u'ipv6Ranges': []}<br/>groupName: demo-98787654432<br/>ipPermissionsEgress: {u'prefixListIds': [], u'ipv4Ranges': [{u'cidrIp': u'0.0.0.0/0'}], u'ipRanges': [u'0.0.0.0/0'], u'ipProtocol': u'-1', u'userIdGroupPairs': [], u'ipv6Ranges': []}<br/>ownerId: 9876654321<br/>groupId: sg-98vc98sd76sd |  |  | aws |


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


