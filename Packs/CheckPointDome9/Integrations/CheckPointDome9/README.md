Dome9 integration allows to easily manage the security and compliance of the public cloud.
This integration was integrated and tested with version 2 of checkpointdome9

## Configure Check Point Dome9 (CloudGuard) in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL |  | True |
| API key ID |  | True |
| API key secret |  | True |
| Use system proxy settings |  | False |
| Trust any certificate (not secure) |  | False |
| Maximum incidents for one fetch. | Maximum number of incidents per fetch. Default is 50. The maximum is 100. | False |
| Fetch incidents |  | False |
| Alert region (AWS) to fetch as incidents. |  | False |
| Alert severity to fetch as incidents. |  | False |
| First fetch time | First alert created date to fetch. e.g., "1 min ago","2 weeks ago","3 months ago" | False |
| Incident type |  | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### dome9-access-lease-list
***
Get a list of all active Access Leases.


#### Base Command

`dome9-access-lease-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | Page number of paginated results. Minimum value: 1. | Optional |
| page_size | Number of items per page. | Optional | 
| limit | The maximum number of records to retrieve. Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPointDome9.AccessLease.cloudAccountId | String | The AWS Access Leases cloud account ID. |
| CheckPointDome9.AccessLease.region | String | The AWS Access Leases region. |
| CheckPointDome9.AccessLease.securityGroupId | String | The AWS Access Leases security group ID. |
| CheckPointDome9.AccessLease.created | String | The AWS Access Leases created date. |
| CheckPointDome9.AccessLease.user | String | The AWS Access Leases user. |
| CheckPointDome9.AccessLease.length | String | The AWS Access Leases length. |
| CheckPointDome9.AccessLease.protocol | String | The AWS Access Leases protocol. |
| CheckPointDome9.AccessLease.id | String | The AWS Access Leases ID. |


#### Command example
```!dome9-access-lease-list```
#### Context Example
```json
{
    "CheckPointDome9": {
        "AccessLease": [
            {
                "accountId": "accountId",
                "cloudAccountId": "cloudAccountId",
                "created": "created",
                "id": "id",
                "ip": "ip",
                "length": "length",
                "name": "name",
                "note": null,
                "portFrom": 0,
                "portTo": 0,
                "protocol": "protocol",
                "region": "region",
                "securityGroupId": "securityGroupId",
                "srl": "srl",
                "user": "user"
            }
        ]
    }
}
```

#### Human Readable Output

>### Access Lease:
>Showing 1 rows out of 1.
>|Id|Name|Ip|User|Region|Length|Created|
>|---|---|---|---|---|---|---|
>| id | name | ip | userMail | region | length | created |

### dome9-access-lease-delete
***
Terminate an Access Lease.


#### Base Command

`dome9-access-lease-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| lease_id | The Access Lease ID. | Required |


#### Context Output

There is no context output for this command.

#### Command example
```!dome9-access-lease-delete lease_id=id```
#### Context Example
```json
{
    "CheckPointDome9": {
        "AccessLease": ""
    }
}
```

#### Human Readable Output

>Access Lease Deleted successfully

### dome9-access-lease-invitation-list
***
Get a lease invitation.


#### Base Command

`dome9-access-lease-invitation-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| invitation_id | The Access Lease invitation ID. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPointDome9.AccessLease.Invitation.length | String | The Access Lease invitation length. |
| CheckPointDome9.AccessLease.Invitation.id | String | The Access Lease invitation ID. |
| CheckPointDome9.AccessLease.Invitation.created | String | The Access Lease invitation created time. |
| CheckPointDome9.AccessLease.Invitation.recipientName | String | The Access Lease invitation recipient name. |


#### Command example
```!dome9-access-lease-invitation-list```
#### Context Example
```json
{
    "CheckPointDome9": {
        "AccessLease": {
            "Invitation": {
                "body": null,
                "created": "created",
                "expirationTime": "expirationTime",
                "id": "id",
                "issuerName": "userMail",
                "length": "length",
                "notifyEmail": null,
                "pivotEntity": "pivotEntity",
                "recipientName": "userMail",
                "serviceName": "name",
                "targetSrl": "targetSrl"
            }
        }
    }
}
```

#### Human Readable Output
>### Access Lease invitation
>Showing 1 rows out of 1.
>|Id|Issuername|Recipientname|Length|Created|
>|---|---|---|---|---|
>| id | userMail | userMail | length | created |


### dome9-access-lease-invitation-delete
***
Delete an Access Lease invitation.


#### Base Command

`dome9-access-lease-invitation-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| invitation_id | Access Lease invitation. | Required |


#### Context Output

There is no context output for this command.
#### Command example
```!dome9-access-lease-invitation-delete invitation_id=invitation_id```
#### Context Example
```json
{
    "CheckPointDome9": {
        "AccessLease": {
            "Invitation": ""
        }
    }
}
```

#### Human Readable Output

>Access Lease Invitation Deleted successfully

### dome9-findings-search
***
Search for findings in CloudGuard.


#### Base Command

`dome9-findings-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | Page number of paginated results. Minimum value: 1. | Optional |
| page_size | Number of items per page. | Optional | 
| limit | The maximum number of records to retrieve. Default is 50. | Optional | 
| severity | The findings severities. Possible values are: High, Medium, Low. | Optional | 
| region | The findings regions. Possible values are: N. Virginia, Global, Canada Central, Frankfurt, Ireland, London, Mumbai, N. California, Ohio, Oregon, Osaka, Paris, Seoul, Singapore, Stockholm, Sydney, São Paulo, Tokyo. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPointDome9.Findings.id | String | The findings ID. |
| CheckPointDome9.Findings.severity | String | The severity of the findings. |
| CheckPointDome9.Findings.region | String | The findings region. |
| CheckPointDome9.Findings.status | Number | The status of the findings. |
| CheckPointDome9.Findings.action | String | The action of the findings. |
| CheckPointDome9.Findings.alertType | Number | The alert type of the findings. |


#### Command example
```!dome9-findings-search```
#### Context Example
```json
{
    "CheckPointDome9": {
        "Findings": [
            {
                "acknowledged": false,
                "action": "action",
                "additionalFields": [],
                "alertType": "alertType",
                "bundleId": "bundleId",
                "bundleName": "bundleName",
                "category": "",
                "cloudAccountExternalId": "cloudAccountExternalId",
                "cloudAccountId": "cloudAccountId",
                "cloudAccountType": "cloudAccountType",
                "comments": [],
                "createdTime": "createdTime",
                "description": "description",
                "entityDome9Id": "entityDome9Id",
                "entityExternalId": "entityExternalId",
                "entityName": "entityName",
                "entityNetwork": null,
                "entityTags": [],
                "entityType": "entityType",
                "entityTypeByEnvironmentType": "entityTypeByEnvironmentType",
                "findingKey": "findingKey",
                "id": "id",
                "isExcluded": false,
                "labels": [],
                "lastSeenTime": "lastSeenTime",
                "magellan": null,
                "occurrences": [],
                "organizationalUnitId": "organizationalUnitId",
                "organizationalUnitPath": "",
                "origin": "origin",
                "ownerUserName": null,
                "region": "region",
                "remediation": "remediation",
                "remediationActions": [],
                "ruleId": "ruleId",
                "ruleLogic": "ruleLogic",
                "ruleName": "ruleName",
                "scanId": null,
                "severity": "severity",
                "status": "status",
                "tag": "tag",
                "updatedTime": "updatedTime",
                "webhookResponses": null
            }
        ]
    }
}
```

#### Human Readable Output

>### Findings:
>Showing 1 rows out of 48.
>|Id|Alerttype|Severity|Region|Status|Action|Cloudaccountid|Description|
>|---|---|---|---|---|---|---|---|
>| id | alertType | severity | region | status | action | Cloudaccountid | Description |


### dome9-ip-list-create
***
Add a new IP list.


#### Base Command

`dome9-ip-list-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The IP list name. | Required |
| description | The IP list description. | Required |
| ip | Comma-separated list of IP addresses. | Optional |
| comment | Comma-separated list of comments for the IP addresses. One comment per IP address. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPointDome9.IpList.id | String | The IP list ID. | 
| CheckPointDome9.IpList.name | String | The IP list name. |
| CheckPointDome9.IpList.description | String | The IP list description. |
| CheckPointDome9.IpList.items | String | The IP list items \(IP addresses\). | 


#### Command example
```!dome9-ip-list-create description=description2022 name=name31072022```
#### Context Example
```json
{
    "CheckPointDome9": {
        "IpList": {
            "description": "description2022",
            "id": "id",
            "items": [],
            "name": "name31072022"
        }
    }
}
```

#### Human Readable Output

>IP list created successfully

### dome9-ip-list-update
***
Update an IP list. This will override the existing IP list.


#### Base Command

`dome9-ip-list-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| list_id | The IP list ID. | Required | 
| description | The IP list description. | Optional |
| ip | Comma-separated list of IP addresses. | Optional |
| comment | Comma-separated list of comments for the IP addresses. One comment per IP address. | Optional |
| update_mode | The command mode. Default mode is add_new_items. Possible values are: add_new_items, replace_old_items. | Optional |


#### Context Output

There is no context output for this command.

#### Command example
```!dome9-ip-list-update list_id=id description=NEW```
#### Context Example
```json
{
    "CheckPointDome9": {
        "IpList": ""
    }
}
```

#### Human Readable Output

>IP list updated successfully
### dome9-ip-list-get
***
Get an IP List by ID.


#### Base Command

`dome9-ip-list-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| list_id | The IP list ID to fetch. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPointDome9.IpList.id | String | The IP list ID. | 
| CheckPointDome9.IpList.name | String | The IP list name. | 
| CheckPointDome9.IpList.description | String | The IP list description. | 
| CheckPointDome9.IpList.items | String | The IP list items \(IP addresses\). | 

#### Command example
```!dome9-ip-list-get```
#### Context Example
```json
{
    "CheckPointDome9": {
        "IpList": [
            {
                "description": "description",
                "id": "id",
                "items": [
                    {
                        "comment": "new comment",
                        "ip": "ip"
                    }
                ],
                "name": "NewList-2"
            }
        ]
    }
}
```

#### Human Readable Output

>### IP list
>|Id|Name|Items|Description|
>|---|---|---|---|
>| id | NewList-2 | ip | description |

### dome9-ip-list-delete
***
Delete an IP List by ID.


#### Base Command

`dome9-ip-list-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| list_id | The ID of the IP list to delete. | Required |


#### Context Output

There is no context output for this command.

#### Command example
```!dome9-ip-list-delete list_id=id```
#### Context Example
```json
{
    "CheckPointDome9": {
        "IpList": ""
    }
}
```

#### Human Readable Output

>IP list deleted successfully

### dome9-ip-list-metadata-list
***
Get all IP addresses metadata.


#### Base Command

`dome9-ip-list-metadata-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | Page number of paginated results. Minimum value: 1. | Optional |
| page_size | Number of items per page. | Optional | 
| limit | The maximum number of records to retrieve. Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPointDome9.IpList.Metadata.id | String | The IP address internal ID. | 
| CheckPointDome9.IpList.Metadata.cidr | string | The IP address CIDR. | 
| CheckPointDome9.IpList.Metadata.name | String | The IP address name. |
| CheckPointDome9.IpList.Metadata.classification | String | The IP address classification. |


#### Command example
```!dome9-ip-list-metadata-list```
#### Context Example
```json
{
    "CheckPointDome9": {
        "IpList": {
            "Metadata": [
                {
                    "cidr": "cidr",
                    "classificaiton": "classification",
                    "classification": "classification",
                    "id": "id",
                    "name": "name"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### IP List metadata
>Showing 8 rows out of 8.
>|Id|Name|Cidr|Classification|
>|---|---|---|---|
>| id | name | cidr | classification |


#### Command example
```!dome9-ip-list-metadata-list```
#### Context Example
```json
{
    "CheckPointDome9": {
        "IpList": {
            "Metadata": [
                {
                    "cidr": "cidr",
                    "classificaiton": "classification",
                    "classification": "classification",
                    "id": "id",
                    "name": "name"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### IP List metadata
>Showing 8 rows out of 8.
>|Id|Name|Cidr|Classification|
>|---|---|---|---|
>| id | name | cidr | classification |


### dome9-ip-list-metadata-create
***
Add metadata for a new IP address. An IP address metadata must contain the CIDR, name, and classification. Classification can be External, Unsafe, Dmz, InternalVpc, InternalDc, or NoClassification.


#### Base Command

`dome9-ip-list-metadata-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cidr | The IP address CIDR. | Required | 
| name | The IP address name. | Required |
| classification | The IP address classification. Possible values are: External, Unsafe, Dmz, InternalVpc, InternalDc, NoClassification.. | Required |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPointDome9.IpList.Metadata.id | String | The IP address internal ID. | 
| CheckPointDome9.IpList.Metadata.cidr | string | The IP address CIDR. | 
| CheckPointDome9.IpList.Metadata.name | String | The IP address name. |
| CheckPointDome9.IpList.Metadata.classification | String | The IP address classification. |


#### Command example
```!dome9-ip-list-metadata-create cidr=cidr classification=classification name=metadata```
#### Context Example
```json
{
    "CheckPointDome9": {
        "IpList": {
            "Metadata": {
                "cidr": "cidr",
                "classificaiton": "classification",
                "classification": "classification",
                "id": "id",
                "name": "metadata"
            }
        }
    }
}
```

#### Human Readable Output

>### IP List metadata created successfully
>|Cidr|Classificaiton|Classification|Id|Name|
>|---|---|---|---|---|
>| cidr | classification | classification | id | metadata |


### dome9-ip-list-metadata-update
***
Update an existing IP address metadata. Classification can only be External, Unsafe, Dmz, InternalVpc, InternalDc, or NoClassification.


#### Base Command

`dome9-ip-list-metadata-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| list_metadata_id | The IP address internal ID. | Required | 
| name | The IP address nName. | Optional |
| classification | The IP address classification. Possible values are: External, Unsafe, Dmz, InternalVpc, InternalDc, NoClassification.. | Required |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPointDome9.IpList.Metadata.id | String | The IP address internal ID. | 
| CheckPointDome9.IpList.Metadata.cidr | string | The IP address CIDR. | 
| CheckPointDome9.IpList.Metadata.name | String | The IP address Name. | 
| CheckPointDome9.IpList.Metadata.classification | String | The IP address classification. |

#### Command example
```!dome9-ip-list-metadata-update classification=classification list_metadata_id=list_metadata_id name=NewName```
#### Context Example
```json
{
    "CheckPointDome9": {
        "IpList": {
            "Metadata": {
                "cidr": "cidr",
                "classificaiton": "classification",
                "classification": "classification",
                "id": "list_metadata_id",
                "name": "NewName"
            }
        }
    }
}
```

#### Human Readable Output

>### IP List metadata updated successfully
>|Cidr|Classificaiton|Classification|Id|Name|
>|---|---|---|---|---|
>| cidr | classification | classification | list_metadata_id | NewName |


### dome9-ip-list-metadata-delete
***
Delete an IP address metadata with a specific CIDR.


#### Base Command

`dome9-ip-list-metadata-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The account ID. | Required | 
| address | The IP address to delete. | Required | 
| mask | The subnet mask. | Required | 


#### Context Output

There is no context output for this command.

#### Command example
```!dome9-ip-list-metadata-delete account_id=account_id address=ip mask=32```
#### Context Example
```json
{
    "CheckPointDome9": {
        "IpList": {
            "Metadata": ""
        }
    }
}
```

#### Human Readable Output

>IP List metadata deleted successfully

### dome9-compliance-remediation-get
***
Get a list of remediations for the account.


#### Base Command

`dome9-compliance-remediation-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPointDome9.ComplianceRemediation.id | String | Remediation ID. | 
| CheckPointDome9.ComplianceRemediation.ruleLogicHash | String | Hash for the rule logic. |
| CheckPointDome9.ComplianceRemediation.ruleName | String | Rule name. | 
| CheckPointDome9.ComplianceRemediation.ruleId | String | Rule ID. | 
| CheckPointDome9.ComplianceRemediation.logic | String | The GSL logic of the exclusion. | 
| CheckPointDome9.ComplianceRemediation.rulesetId | Number | Ruleset ID. | 
| CheckPointDome9.ComplianceRemediation.platform | String | Remediation platform. | 
| CheckPointDome9.ComplianceRemediation.cloudBots | String | Cloud bots execution expressions. | 

#### Command example
```!dome9-compliance-remediation-get```
#### Context Example
```json
{
    "CheckPointDome9": {
        "ComplianceRemediation": [
            {
                "cloudAccountId": null,
                "cloudBots": [
                    "cloudBots"
                ],
                "comment": "comment",
                "id": "id",
                "logic": null,
                "platform": "platform",
                "ruleId": null,
                "ruleLogicHash": "ruleLogicHash",
                "ruleName": null,
                "rulesetId": -51
            }
        ]
    }
}
```

#### Human Readable Output

>### Compliance remediation:
>|Id|Rulelogichash|Rulesetid|Platform|Comment|Cloudbots|
>|---|---|---|---|---|---|
>| id | ruleLogicHash | ruleset_id | platform | comment | cloudbots |



### dome9-compliance-remediation-create
***
Add a new remediation.


#### Base Command

`dome9-compliance-remediation-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ruleset_id | Ruleset ID to apply remediation on. Use the dome9-compliance-ruleset-list command to get the Ruleset ID list. | Required |
| comment | Comment text. | Required | 
| cloudbots | Cloud bots execution expressions. Possible values are: ami_set_to_private, acm_delete_certificate, cloudtrail_enable, cloudtrail_enable_log_file_validation, cloudtrail_send_to_cloudwatch, cloudwatch_create_metric_filter, config_enable, ec2_attach_sg, ec2_attach_instance_role, ec2_create_snapshot, ec2_release_eips, ec2_quarantine_instance, ec2_stop_instance, ec2_terminate_instance, ec2_update_instance_role, ec2_service_role_detach_inline_group, iam_detach_policy, iam_group_delete_inline_group, iam_generate_credential_report, iam_role_attach_policy, iam_user_attach_policy, iam_user_deactivate_unused_access_key, iam_user_delete_inline_policies, iam_user_disable_console_password, iam_user_force_password_change, iam_quarantine_role, iam_quarantine_user, iam_role_clone_with_non_enumerable_name, iam_turn_on_password_policy, igw_delete, kms_cmk_enable_key, kms_enable_rotation, lambda_detach_blanket_permissions, lambda_tag, lambda_enable_active_tracing, load_balancer_enable_access_logs, mark_for_stop_ec2_resource. | Required | 
| rule_logic_hash | Hash for the rule logic. Use the compliance-ruleset-rule-list command to fetch logic hash. | Required |


#### Context Output

There is no context output for this command.

#### Command example
```!dome9-compliance-remediation-create cloudbots=cloudbots comment=COMMENT rule_logic_hash=rule_logic_hash/k4lIw ruleset_id=rule_id```
#### Context Example
```json
{
    "CheckPointDome9": {
        "ComplianceRemediation": {
            "cloudAccountId": null,
            "cloudBots": [
                "cloudbots"
            ],
            "comment": "COMMENT",
            "id": "id",
            "logic": null,
            "platform": "platform",
            "ruleId": null,
            "ruleLogicHash": "ruleLogicHash",
            "ruleName": null,
            "rulesetId": "rulesetId"
        }
    }
}
```

#### Human Readable Output

>### Remediation created successfully
>|Cloudbots|Id|Rulelogichash|Rulesetid|Platform|Comment|
>|---|---|---|---|---|---|
>| cloudbots | id | ruleLogicHash | ruleset_id | platform | COMMENT |


### dome9-compliance-remediation-update
***
Update a remediation.


#### Base Command

`dome9-compliance-remediation-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| remediation_id | Remediation ID. | Required | 
| ruleset_id | Ruleset ID. | Required | 
| comment | Comment text. | Required | 
| cloudbots | Cloud bots execution expressions. Possible values are: ami_set_to_private, acm_delete_certificate, cloudtrail_enable, cloudtrail_enable_log_file_validation, cloudtrail_send_to_cloudwatch, cloudwatch_create_metric_filter, config_enable, ec2_attach_sg, ec2_attach_instance_role, ec2_create_snapshot, ec2_release_eips, ec2_quarantine_instance, ec2_stop_instance, ec2_terminate_instance, ec2_update_instance_role, ec2_service_role_detach_inline_group, iam_detach_policy, iam_group_delete_inline_group, iam_generate_credential_report, iam_role_attach_policy, iam_user_attach_policy, iam_user_deactivate_unused_access_key, iam_user_delete_inline_policies, iam_user_disable_console_password, iam_user_force_password_change, iam_quarantine_role, iam_quarantine_user, iam_role_clone_with_non_enumerable_name, iam_turn_on_password_policy, igw_delete, kms_cmk_enable_key, kms_enable_rotation, lambda_detach_blanket_permissions, lambda_tag, lambda_enable_active_tracing, load_balancer_enable_access_logs, mark_for_stop_ec2_resource. | Required | 
| rule_logic_hash | Hash for the rule logic. Use the compliance-ruleset-rule-list command to fetch logic hash. | Required |


#### Context Output

There is no context output for this command.

#### Command example
```!dome9-compliance-remediation-update remediation_id=r_id cloudbots=cloudbots comment=COMMENT rule_logic_hash=ruleLogicHash ruleset_id=ruleset_id```
#### Context Example
```json
{
    "CheckPointDome9": {
        "ComplianceRemediation": {
            "cloudAccountId": null,
            "cloudBots": [
                "cloudbots"
            ],
            "comment": "COMMENT",
            "id": "r_id",
            "logic": null,
            "platform": "platform",
            "ruleId": null,
            "ruleLogicHash": "ruleLogicHash",
            "ruleName": null,
            "rulesetId": "ruleset_id"
        }
    }
}
```

#### Human Readable Output

>### Remediation updated successfully
>|Cloudbots|Id|Rulelogichash|Rulesetid|Platform|Comment|
>|---|---|---|---|---|---|
>| cloudbots | r_id | ruleLogicHash | ruleset_id | platform | COMMENT |


### dome9-compliance-remediation-delete
***
Delete a remediation.


#### Base Command

`dome9-compliance-remediation-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| remediation_id | Remediation ID. | Required | 


#### Context Output

There is no context output for this command.

#### Command example
```!dome9-compliance-remediation-delete remediation_id=remediation_id```
#### Context Example
```json
{
    "CheckPointDome9": {
        "ComplianceRemediation": ""
    }
}
```

#### Human Readable Output

>Remediation deleted successfully
### dome9-compliance-ruleset-list
***
Get all Rulesets for the account.


#### Base Command

`dome9-compliance-ruleset-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ruleset_id | The Ruleset ID. | Optional | 
| page | Page number of paginated results. Minimum value: 1. | Optional |
| page_size | Number of items per page. | Optional | 
| limit | The maximum number of records to retrieve. Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPointDome9.ComplianceRuleset.accountId | String | The account ID. | 
| CheckPointDome9.ComplianceRuleset.id | Number | The Ruleset ID. | 
| CheckPointDome9.ComplianceRuleset.name | String | The Ruleset name. | 
| CheckPointDome9.ComplianceRuleset.description | String | The Ruleset description. | 

#### Command example
```!dome9-compliance-ruleset-list```
#### Context Example
```json
{
    "CheckPointDome9": {
        "ComplianceRuleset": [
            {
                "accountId": "account_id",
                "cloudVendor": "cloudVendor",
                "common": false,
                "createdTime": "createdTime",
                "default": false,
                "description": "description",
                "hideInCompliance": false,
                "icon": "",
                "id": "id",
                "isTemplate": true,
                "language": "language",
                "minFeatureTier": "minFeatureTier",
                "name": "name",
                "rulesCount": 1,
                "section": 2,
                "showBundle": true,
                "systemBundle": false,
                "tooltipText": "tooltipText",
                "updatedTime": "updatedTime",
                "version": 32
            }
        ]
    }
}
```

#### Human Readable Output

>### Compliance Ruleset:
>Showing 50 rows out of 136.
>|Accountid|Id|Name|Description|
>|---|---|---|---|
>| account_id | id | name | description |



### dome9-compliance-ruleset-rule-list
***
Get rule details. Get the rule logic hash to create a new remediation.


#### Base Command

`dome9-compliance-ruleset-rule-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_id | The Ruleset ID. | Required | 
| page | Page number of paginated results. Minimum value: 1. | Optional |
| page_size | Number of items per page. | Optional | 
| limit | The maximum number of records to retrieve. Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPointDome9.ComplianceRuleset.Rule.name | String | The rule name. | 
| CheckPointDome9.ComplianceRuleset.Rule.severity | String | The rule severity. | 
| CheckPointDome9.ComplianceRuleset.Rule.logic | Number | The rule logic. | 
| CheckPointDome9.ComplianceRuleset.Rule.logicHash | String | The rule logic hash. | 
| CheckPointDome9.ComplianceRuleset.Rule.description | String | The rule description. | 

#### Command example
```!dome9-compliance-ruleset-rule-list rule_id=-41```
#### Context Example
```json
{
    "CheckPointDome9": {
        "ComplianceRuleset": {
            "Rule": [
                {
                    "category": "",
                    "cloudbots": null,
                    "complianceTag": "complianceTag",
                    "controlTitle": "",
                    "description": "description",
                    "domain": "",
                    "isDefault": false,
                    "labels": [],
                    "logic": "logic",
                    "logicHash": "logicHash",
                    "name": "name",
                    "priority": "",
                    "remediation": "remediation",
                    "ruleId": "ruleId",
                    "severity": "severity"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Compliance Ruleset Rules:
>Showing 10 rows out of 10.
>|Name|Severity|Description|Logic|Logichash|
>|---|---|---|---|---|
>| name | severity | description | logic | logicHash |



### dome9-security-group-instance-attach
***
Attach the security group to an AWS EC2 instance.


#### Base Command

`dome9-security-group-instance-attach`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| instance_id | AWS instance ID. | Required | 
| sg_id | AWS security group internal ID. | Required |
| nic_name | The instance NIC name. Use the dome9-instance-list command to get this argument. | Required |


#### Context Output

There is no context output for this command.

#### Command example
```!dome9-security-group-instance-attach instance_id=i-instance_id nic_name=nic_name sg_id=sg_id```
#### Context Example
```json
{
    "CheckPointDome9": {
        "Instance": {
            "amiLaunchIndex": 0,
            "architecture": "architecture",
            "blockDeviceMappings": [
                {
                    "deviceName": "deviceName",
                    "ebs": {
                        "attachTime": "attachTime",
                        "deleteOnTermination": true,
                        "status": "status",
                        "volumeId": "volumeId"
                    }
                }
            ],
            "clientToken": null,
            "ebsOptimized": false,
            "enaSupport": true,
            "externalId": "externalId",
            "hypervisor": "hypervisor",
            "iamInstanceProfile": null,
            "imageId": "imageId",
            "imageName": null,
            "instanceId": "instanceId",
            "instanceLifecycle": null,
            "instanceType": "instanceType",
            "isMicro": true,
            "isRunning": true,
            "kernelId": null,
            "keyName": "keyName",
            "launchTime": "launchTime",
            "monitoring": {
                "state": "state"
            },
            "networkInterfaces": [
                {
                    "association": {
                        "ipOwnerId": "ipOwnerId",
                        "publicDnsName": "publicDnsName",
                        "publicIp": "publicIp"
                    },
                    "attachment": {
                        "attachTime": "attachTime",
                        "attachmentId": "attachmentId",
                        "deleteOnTermination": true,
                        "deviceIndex": 0,
                        "status": "status"
                    },
                    "description": null,
                    "groups": [
                        {
                            "groupId": "groupId",
                            "groupName": "groupName"
                        }
                    ],
                    "ipv6Addresses": [],
                    "macAddress": "macAddress",
                    "networkInterfaceId": "networkInterfaceId",
                    "ownerId": "ownerId",
                    "privateDnsName": "privateDnsName",
                    "privateIpAddress": "privateIpAddress",
                    "privateIpAddresses": [
                        {
                            "association": {
                                "ipOwnerId": "ipOwnerId",
                                "publicDnsName": "publicDnsName",
                                "publicIp": "publicIp"
                            },
                            "primary": true,
                            "privateDnsName": "privateDnsName",
                            "privateIpAddress": "privateIpAddress"
                        }
                    ],
                    "sourceDestCheck": true,
                    "status": "status",
                    "subnetId": "subnetId",
                    "vpcId": "vpcId"
                }
            ],
            "niCs": [
                {

                }
            ],
            "osType": "osType",
            "placement": {
                "affinity": null,
                "availabilityZone": "availabilityZone",
                "groupName": null,
                "hostId": null,
                "tenancy": "tenancy"
            },
            "platform": null,
            "privateDnsName": "privateDnsName",
            "privateIpAddress": "privateIpAddress",
            "productCodes": [],
            "profileArn": null,
            "publicDnsName": "publicDnsName",
            "publicIpAddress": "publicIpAddress",
            "ramdiskId": null,
            "rootDeviceName": "rootDeviceName",
            "rootDeviceType": "rootDeviceType",
            "securityGroups": [

            ],
            "sourceDestCheck": true,
            "spotInstanceRequestId": null,
            "sriovNetSupport": null,
            "state": {

            },
            "stateReason": null,
            "stateTransitionReason": null,
            "subnetId": "subnetId",
            "tags": [
                {
                    "key": "Name",
                    "value": "value"
                }
            ],
            "virtualizationType": "virtualizationType",
            "vpcId": "vpcId"
        }
    }
}
```

#### Human Readable Output

>Security group attach successfully

### dome9-security-group-service-delete
***
Delete a service from an AWS security group.


#### Base Command

`dome9-security-group-service-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sg_id | Security group ID. | Required | 
| service_id | Service ID. | Required | 


#### Context Output

There is no context output for this command.
#### Command example
```!dome9-security-group-service-delete service_id=6-56 sg_id=sg_id```
#### Context Example
```json
{
    "CheckPointDome9": {
        "SecurityGroup": {
            "Service": ""
        }
    }
}
```

#### Human Readable Output

>Service deleted successfully

### dome9-security-group-tags-update
***
Update the list of tags for an AWS security group.


#### Base Command

`dome9-security-group-tags-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sg_id | Security group ID. | Required | 
| key | The key name. | Required | 
| value | The value name. | Required | 


#### Context Output

There is no context output for this command.
#### Command example
```!dome9-security-group-tags-update key=KEYkey value=VALUEvalue sg_id=sg_id```
#### Context Example
```json
{
    "CheckPointDome9": {
        "SecurityGroup": {
            "Tag": {
                "keYkey": "VALUEvalue"
            }
        }
    }
}
```

#### Human Readable Output

>Tag updated successfully

### dome9-security-group-service-create
***
Create a new service (rule) for the security group.


#### Base Command

`dome9-security-group-service-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sg_id | Security group ID. | Required | 
| policy_type | The service type. Possible values are: Inbound, Outbound. | Required |
| name | The service name. | Required | 
| protocol_type | Service protocol type. Possible values are: ALL, HOPOPT, ICMP, IGMP, GGP, IPV4, ST, TCP, CBT, EGP, IGP, BBN_RCC_MON, NVP2, PUP, ARGUS, EMCON, XNET, CHAOS, UDP, MUX, DCN_MEAS, HMP, PRM, XNS_IDP, TRUNK1, TRUNK2, LEAF1, LEAF2, RDP, IRTP, ISO_TP4, NETBLT, MFE_NSP, MERIT_INP, DCCP, ThreePC, IDPR, XTP, DDP, IDPR_CMTP, TPplusplus, IL, IPV6, SDRP, IPV6_ROUTE, IPV6_FRAG, IDRP, RSVP, GRE, DSR, BNA, ESP, AH, I_NLSP, SWIPE, NARP, MOBILE, TLSP, SKIP, ICMPV6, IPV6_NONXT, IPV6_OPTS, CFTP, SAT_EXPAK, KRYPTOLAN, RVD, IPPC, SAT_MON, VISA, IPCV, CPNX, CPHB, WSN, PVP, BR_SAT_MON, SUN_ND, WB_MON, WB_EXPAK, ISO_IP, VMTP, SECURE_VMTP, VINES, TTP, NSFNET_IGP, DGP, TCF, EIGRP, OSPFIGP, SPRITE_RPC, LARP, MTP, AX25, IPIP, MICP, SCC_SP, ETHERIP, ENCAP, GMTP, IFMP, PNNI, PIM, ARIS, SCPS, QNX, AN, IPCOMP, SNP, COMPAQ_PEER, IPX_IN_IP, VRRP, PGM, L2TP, DDX, IATP, STP, SRP, UTI, SMP, SM, PTP, ISIS, FIRE, CRTP, CRUDP, SSCOPMCE, IPLT, SPS, PIPE, SCTP, FC, RSVP_E2E_IGNORE, MOBILITY_HEADER, UDPLITE, MPLS_IN_IP, MANET, HIP, SHIM6, WESP, ROHC. | Required | 
| port | The service port (indicates a port range). | Required |
| open_for_all | Indicates if the service is open to all ports. Possible values are: True, False. | Optional | 
| description | Service description. | Optional | 
| data_id | IP list ID to attach. | Optional |
| data_name | IP list name to attach. | Optional |
| scope_type | Scope type to attach. Possible values are: CIDR, IPList. | Optional |
| is_valid | Whether the service is valid. Possible values are: True, False. | Optional |
| inbound | Whether the service is inbound. Possible values are: True, False. | Optional |
| icmptype | ICMP type (when protocol is ICMP). Possible values are: All, EchoReply, DestinationUnreachable, SourceQuench, Redirect, AlternateHostAddress, Echo, RouterAdvertisement, RouterSelection, TimeExceeded, ParameterProblem, Timestamp, TimestampReply, InformationRequest, InformationReply, AddressMaskRequest, AddressMaskReply, Traceroute, DatagramConversionError, MobileHostRedirect, IPv6WhereAreYou, IPv6IAmHere, MobileRegistrationRequest, MobileRegistrationReply, DomainNameRequest, DomainNameReply, SKIP, Photuris. | Optional | 
| icmpv6type | ICMP V6 type (when protocol is ICMPV6). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPointDome9.SecurityGroup.Service.id | String | The security group service ID. |
| CheckPointDome9.SecurityGroup.Service.name | string | The security group service name. |
| CheckPointDome9.SecurityGroup.Service.protocolType | String | The service protocol type. | 
| CheckPointDome9.SecurityGroup.Service.port | string | The service port. | 
| CheckPointDome9.SecurityGroup.Service.scope | String | The service scope type. | 
| CheckPointDome9.SecurityGroup.Service.description | string | The service description. | 

#### Command example
```!dome9-security-group-service-create name=NewService0107 policy_type=Inbound port=port protocol_type=protocol sg_id=sg_id```
#### Context Example
```json
{
    "CheckPointDome9": {
        "SecurityGroup": {
            "Service": {
                "description": null,
                "icmpType": null,
                "icmpv6Type": null,
                "id": "id",
                "inbound": true,
                "name": "NewService0107",
                "openForAll": false,
                "port": "port",
                "protocolType": "protocol",
                "scope": []
            }
        }
    }
}
```

#### Human Readable Output

>### Security group service created successfully
>|Description|Id|Name|Port|Protocoltype|
>|---|---|---|---|---|
>|  | id | NewService0107 | port | protocol |


### dome9-security-group-service-update
***
Update a service (rule) for an AWS security group. Can update only the port and name.


#### Base Command

`dome9-security-group-service-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sg_id | Security group ID. | Required | 
| policy_type | The service type. Possible values are: Inbound, Outbound. | Required |
| service_name | Service name. | Required | 
| protocol_type | The service protocol type. Possible values are: ALL, HOPOPT, ICMP, IGMP, GGP, IPV4, ST, TCP, CBT, EGP, IGP, BBN_RCC_MON, NVP2, PUP, ARGUS, EMCON, XNET, CHAOS, UDP, MUX, DCN_MEAS, HMP, PRM, XNS_IDP, TRUNK1, TRUNK2, LEAF1, LEAF2, RDP, IRTP, ISO_TP4, NETBLT, MFE_NSP, MERIT_INP, DCCP, ThreePC, IDPR, XTP, DDP, IDPR_CMTP, TPplusplus, IL, IPV6, SDRP, IPV6_ROUTE, IPV6_FRAG, IDRP, RSVP, GRE, DSR, BNA, ESP, AH, I_NLSP, SWIPE, NARP, MOBILE, TLSP, SKIP, ICMPV6, IPV6_NONXT, IPV6_OPTS, CFTP, SAT_EXPAK, KRYPTOLAN, RVD, IPPC, SAT_MON, VISA, IPCV, CPNX, CPHB, WSN, PVP, BR_SAT_MON, SUN_ND, WB_MON, WB_EXPAK, ISO_IP, VMTP, SECURE_VMTP, VINES, TTP, NSFNET_IGP, DGP, TCF, EIGRP, OSPFIGP, SPRITE_RPC, LARP, MTP, AX25, IPIP, MICP, SCC_SP, ETHERIP, ENCAP, GMTP, IFMP, PNNI, PIM, ARIS, SCPS, QNX, AN, IPCOMP, SNP, COMPAQ_PEER, IPX_IN_IP, VRRP, PGM, L2TP, DDX, IATP, STP, SRP, UTI, SMP, SM, PTP, ISIS, FIRE, CRTP, CRUDP, SSCOPMCE, IPLT, SPS, PIPE, SCTP, FC, RSVP_E2E_IGNORE, MOBILITY_HEADER, UDPLITE, MPLS_IN_IP, MANET, HIP, SHIM6, WESP, ROHC. | Required | 
| port | Service port (indicates a port range). | Required |
| open_for_all | Whether the service is open to all ports. Possible values are: True, False. | Optional |
| description | Service description. | Optional | 
| data_id | IP list ID. | Optional |
| data_name | IP list name. | Optional |
| scope_type | Scope type. Possible values are: CIDR, IPList. | Optional |
| is_valid | Whether the service is valid. Possible values are: True, False. | Optional |
| inbound | Whether the service is inbound. Possible values are: True, False. | Optional |
| icmptype | ICMP type (when protocol is ICMP). Possible values are: All, EchoReply, DestinationUnreachable, SourceQuench, Redirect, AlternateHostAddress, Echo, RouterAdvertisement, RouterSelection, TimeExceeded, ParameterProblem, Timestamp, TimestampReply, InformationRequest, InformationReply, AddressMaskRequest, AddressMaskReply, Traceroute, DatagramConversionError, MobileHostRedirect, IPv6WhereAreYou, IPv6IAmHere, MobileRegistrationRequest, MobileRegistrationReply, DomainNameRequest, DomainNameReply, SKIP, Photuris. | Optional | 
| icmpv6type | ICMP V6 type (when protocol is ICMPV6). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPointDome9.SecurityGroup.Service.id | String | The security group service ID. |
| CheckPointDome9.SecurityGroup.Service.name | string | The security group service name. |
| CheckPointDome9.SecurityGroup.Service.protocolType | String | The service protocol type. | 
| CheckPointDome9.SecurityGroup.Service.port | string | The service port. | 
| CheckPointDome9.SecurityGroup.Service.scopeType | String | The service scope type. | 
| CheckPointDome9.SecurityGroup.Service.description | string | The service description. | 

#### Command example
```!dome9-security-group-service-update service_name=name policy_type=Inbound port=port protocol_type=protocol sg_id=sg_id```
#### Context Example
```json
{
    "CheckPointDome9": {
        "SecurityGroup": {
            "Service": {
                "description": null,
                "icmpType": null,
                "icmpv6Type": null,
                "id": "id",
                "inbound": true,
                "name": "name",
                "openForAll": false,
                "port": "port",
                "protocolType": "protocol",
                "scope": []
            }
        }
    }
}
```

#### Human Readable Output

>### Security group service updated successfully
>|Description|Id|Name|Port|Protocoltype|
>|---|---|---|---|---|
>|  | id | name | port | protocol |

### dome9-security-group-instance-detach
***
Detach the security group from an AWS EC2 Instance.


#### Base Command

`dome9-security-group-instance-detach`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| instance_id | AWS instance ID. | Required | 
| sg_id | AWS security group internal ID. | Required |
| nic_name | The instance NIC name. Use the dome9-instance-list command to get this argument. | Required |


#### Context Output

There is no context output for this command.
#### Command example
```!dome9-security-group-instance-detach instance_id=i-instanceID nic_name=eth0 sg_id=sg_id```
#### Context Example
```json
{
    "CheckPointDome9": {
        "Instance": {
            "amiLaunchIndex": 0,
            "architecture": "architecture",
            "blockDeviceMappings": [
                {
                    "deviceName": "deviceName",
                    "ebs": {
                        "attachTime": "attachTime",
                        "deleteOnTermination": true,
                        "status": "status",
                        "volumeId": "volumeId"
                    }
                }
            ],
            "clientToken": null,
            "ebsOptimized": false,
            "enaSupport": true,
            "externalId": "externalId",
            "hypervisor": "hypervisor",
            "iamInstanceProfile": null,
            "imageId": "imageId",
            "imageName": null,
            "instanceId": "instanceId",
            "instanceLifecycle": null,
            "instanceType": "instanceType",
            "isMicro": true,
            "isRunning": true,
            "kernelId": null,
            "keyName": "keyName",
            "launchTime": "launchTime",
            "monitoring": {
                "state": "state"
            },
            "networkInterfaces": [
                {
                    "association": {
                        "ipOwnerId": "ipOwnerId",
                        "publicDnsName": "publicDnsName",
                        "publicIp": "publicIp"
                    },
                    "attachment": {
                        "attachTime": "attachTime",
                        "attachmentId": "attachmentId",
                        "deleteOnTermination": true,
                        "deviceIndex": 0,
                        "status": "status"
                    },
                    "description": null,
                    "groups": [
                        {
                            "groupId": "groupId",
                            "groupName": "groupName"
                        }
                    ],
                    "ipv6Addresses": [],
                    "macAddress": "macAddress",
                    "networkInterfaceId": "networkInterfaceId",
                    "ownerId": "ownerId",
                    "privateDnsName": "privateDnsName",
                    "privateIpAddress": "privateIpAddress",
                    "privateIpAddresses": [
                        {
                            "association": {
                                "ipOwnerId": "ipOwnerId",
                                "publicDnsName": "publicDnsName",
                                "publicIp": "publicIp"
                            },
                            "primary": true,
                            "privateDnsName": "privateDnsName",
                            "privateIpAddress": "privateIpAddress"
                        }
                    ],
                    "sourceDestCheck": true,
                    "status": "status",
                    "subnetId": "subnetId",
                    "vpcId": "vpcId"
                }
            ],
            "niCs": [
                {

                }
            ],
            "osType": "osType",
            "placement": {
                "affinity": null,
                "availabilityZone": "availabilityZone",
                "groupName": null,
                "hostId": null,
                "tenancy": "tenancy"
            },
            "platform": null,
            "privateDnsName": "privateDnsName",
            "privateIpAddress": "privateIpAddress",
            "productCodes": [],
            "profileArn": null,
            "publicDnsName": "publicDnsName",
            "publicIpAddress": "publicIpAddress",
            "ramdiskId": null,
            "rootDeviceName": "rootDeviceName",
            "rootDeviceType": "rootDeviceType",
            "securityGroups": [

            ],
            "sourceDestCheck": true,
            "spotInstanceRequestId": null,
            "sriovNetSupport": null,
            "state": {

            },
            "stateReason": null,
            "stateTransitionReason": null,
            "subnetId": "subnetId",
            "tags": [
                {
                    "key": "Name",
                    "value": "value"
                }
            ],
            "virtualizationType": "virtualizationType",
            "vpcId": "vpcId"
        }
    }
}
```

#### Human Readable Output

>Security group detach successfully

### dome9-instance-list
***
Fetch an AWS EC2 instance.


#### Base Command

`dome9-instance-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| instance_id | AWS instance ID. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPointDome9.Instance.externalId | String | The instance external ID. | 
| CheckPointDome9.Instance.region | string | The instance region. | 
| CheckPointDome9.Instance.nics | String | The instance NIC names. |
| CheckPointDome9.Instance.name | string | The instance name. | 

#### Command example
```!dome9-instance-list```
#### Context Example
```json
{
    "CheckPointDome9": {
        "Instance": [
            {
                "accountId": "account_id",
                "cloudAccountId": "cloudAccountId",
                "externalId": "i-externalId",
                "image": "ami-image",
                "instanceType": "instanceType",
                "isBillable": true,
                "isRunning": true,
                "kernelId": null,
                "launchTime": "launchTime",
                "name": "name",
                "nics": [
                    {
                        "name": "name"
                    }
                ],
                "platform": "platform",
                "profileArn": "profileArn",
                "publicDnsName": "publicDnsName",
                "region": "region",
                "roleArns": [
                    "roleArns"
                ],
                "ssmAgentInstanceInformation": null,
                "tags": {
                    "Name": "Name"
                },
                "vpc": "vpc"
            }
        ]
    }
}
```

#### Human Readable Output

>### AWS instances
>Showing 5 rows out of 5.
>|Accountid|Cloudaccountid|Externalid|Image|Instancetype|Isbillable|Isrunning|Kernelid|Launchtime|Name|Nics|Platform|Profilearn|Publicdnsname|Region|Rolearns|Ssmagentinstanceinformation|Tags|Vpc|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| account_id | cloudAccountId | i-Externalid | ami | Instancetype | true | true |  | someDate | name | Nics |  |  |  | region | arn|  | Name | vpc |

### dome9-security-group-protection-mode-update
***
Change the protection mode for an AWS security group (FullManage or ReadOnly).


#### Base Command

`dome9-security-group-protection-mode-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| protection_mode | The protection mode to update. Possible values are: FullManage, ReadOnly. | Required | 
| sg_id | Security group ID. | Required | 


#### Context Output

There is no context output for this command.
#### Command example
```!dome9-security-group-protection-mode-update protection_mode=FullManage sg_id=sg_id```
#### Context Example
```json
{
    "CheckPointDome9": {
        "SecurityGroup": {
            "cloud_account_id": "cloudAccountId",
            "cloud_account_name": "cloud_account_name",
            "description": "description",
            "isProtected": true,
            "region_id": "region",
            "security_group_external_id": "sg_id",
            "security_group_id": "sg_id",
            "security_group_name": "security_group_name",
            "vpc_id": "vpc"
        }
    }
}
```

#### Human Readable Output

>### protection mode updated for security group :
>|Cloud Account Id|Cloud Account Name|Description|Isprotected|Region Id|Security Group External Id|Security Group Id|Security Group Name|Vpc Id|
>|---|---|---|---|---|---|---|---|---|
>| cloudAccountId | name | description | true | region | sg_id | sg_id | sg_name | vpc |

### dome9-cloud-accounts-list
***
Get the cloud account list.


#### Base Command

`dome9-cloud-accounts-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | account ID. | Optional | 
| page | Page number of paginated results. Minimum value: 1. | Optional |
| page_size | Number of items per page. | Optional | 
| limit | The maximum number of records to retrieve. Default is 50. | Optional | 
| cloud_account_od | The cloud account ID. | Optional | 


#### Context Output

There is no context output for this command.
#### Command example
```!dome9-cloud-accounts-list```
#### Context Example
```json
{
    "CheckPointDome9": {
        "CloudAccount": {
            "allowReadOnly": false,
            "creationDate": "creationDate",
            "credentials": {
                "apikey": null,
                "arn": "arn",
                "iamUser": null,
                "isReadOnly": true,
                "secret": null,
                "type": "type"
            },
            "error": null,
            "externalAccountNumber": "externalAccountNumber",
            "fullProtection": false,
            "iamSafe": {

            },
            "id": "cloudAccountId",
            "isFetchingSuspended": false,
            "lambdaScanner": false,
            "magellan": true,
            "name": "name",
            "netSec": {
                "regions": [

                ]
            },
            "onboardingMode": "onboardingMode",
            "organizationalUnitId": null,
            "organizationalUnitName": "organizationalUnitName",
            "organizationalUnitPath": "",
            "serverless": {

            },
            "vendor": "vendor"
        }
    }
}
```

#### Human Readable Output

>### Cloud accounts:
>Showing 1 rows out of 1.
>|Id|Vendor|Externalaccountnumber|Creationdate|Organizationalunitname|
>|---|---|---|---|---|
>| cloudAccountId | vendor | number |date | name |

### dome9-security-group-ip-list-details-get
***
Get AWS cloud accounts for a specific security group and region and check if there is an IP list to attach to a security group.


#### Base Command

`dome9-security-group-ip-list-details-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | Page number of paginated results. Minimum value: 1. | Optional |
| page_size | Number of items per page. | Optional | 
| limit | The maximum number of records to retrieve. Default is 50. | Optional | 
| sg_id | Security group ID. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPointDome9.SecurityGroup.security_group_id | String | The security group ID. |

#### Command example
```!dome9-security-group-ip-list-details-get```
#### Context Example
```json
{
    "CheckPointDome9": {
        "SecurityGroup": [
            {
                "cloud_account_id": "cloudAccountId",
                "cloud_account_name": "cloud_account_name",
                "description": "description",
                "isProtected": true,
                "region_id": "region",
                "security_group_external_id": "sg_id",
                "security_group_id": "sg_id",
                "security_group_name": "security_group_name",
                "vpc_id": "vpc"
            }
        ]
    }
}
```

#### Human Readable Output

>### Security Groups:
>Showing 1 rows out of 24.
>|Cloud Account Id|Cloud Account Name|Description|Isprotected|Region Id|Security Group External Id|Security Group Id|Security Group Name|Vpc Id|
>|---|---|---|---|---|---|---|---|---|
>| cloudAccountId | name | description | true | region | sg_id | sg_id | sg_name | vpc |


### dome9-security-group-list
***
Get all security group entities.


#### Base Command

`dome9-security-group-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | Page number of paginated results. Minimum value: 1. | Optional |
| page_size | Number of items per page. | Optional | 
| limit | The maximum number of records to retrieve. Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPointDome9.SecurityGroup.security_group_id | String | The security group ID. |

#### Command example
```!dome9-security-group-list```
#### Context Example
```json
{
    "CheckPointDome9": {
        "SecurityGroup": [
            {
                "cloudAccountId": "cloudAccountId",
                "cloudAccountName": "cloudAccountName",
                "externalId": "sg",
                "regionId": "region",
                "securityGroupName": "securityGroupName",
                "vpcId": "vpc"
            }
        ]
    }
}
```

#### Human Readable Output

>### Security Groups:
>Showing 1 rows out of 107.
>|Cloud Account Id|Region Id|Security Group Id|Security Group Name|Vpc Id|
>|---|---|---|---|---|
>| cloudAccountId | region | sg | name | vpc |


### dome9-global-search-get
***
Get top results for each service.


#### Base Command

`dome9-global-search-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | Page number of paginated results. Minimum value: 1. | Optional |
| page_size | Number of items per page. | Optional | 
| limit | The maximum number of records to retrieve. Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPointDome9.GlobalSearch.Alert.id | String | The global search alert ID. |
| CheckPointDome9.GlobalSearch.Alert.type | String | The global search alert type. |
| CheckPointDome9.GlobalSearch.Alert.severity | String | The global search alert severity. |


#### Command example
```!dome9-global-search-get```
#### Context Example
```json
{
    "CheckPointDome9": {
        "GlobalSearch": {
            "Alert": [
                {
                    "alertType": "alertType",
                    "bundleId": "bundleId",
                    "cloudAccountExternalId": "cloudAccountExternalId",
                    "cloudAccountId": "cloudAccountId",
                    "createdTime": "createdTime",
                    "description": "description",
                    "entityName": "entityName",
                    "id": "id",
                    "remediation": "remediation",
                    "ruleName": "ruleName",
                    "severity": "severity",
                    "updatedTime": "updatedTime"
                },
                {
                    "alertType": "alertType",
                    "bundleId": "bundleId",
                    "cloudAccountExternalId": "cloudAccountExternalId",
                    "cloudAccountId": "cloudAccountId",
                    "createdTime": "createdTime",
                    "description": "description",
                    "entityName": "entityName",
                    "id": "id",
                    "remediation": "remediation",
                    "ruleName": "ruleName",
                    "severity": "severity",
                    "updatedTime": "updatedTime"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Global Search
>|Alerttype|Bundleid|Cloudaccountexternalid|Cloudaccountid|Createdtime|Description|Entityname|Id|Remediation|Rulename|Severity|Updatedtime|
>|---|---|---|---|---|---|---|---|---|---|---|---|
>| Alerttype | Bundleid | Cloudaccountexternalid | Cloudaccountid | date | Description | Entityname | id | Remediation | rule name | Severity | Updatedtime |
>| Alerttype | Bundleid | Cloudaccountexternalid | Cloudaccountid | date | Description | Entityname | id | remediation | rule name | Severity | Updatedtime |


### dome9-cloud-trail-get
***
Get CloudTrail events for a Dome9 user.


#### Base Command

`dome9-cloud-trail-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | Page number of paginated results. Minimum value: 1. | Optional |
| page_size | Number of items per page. | Optional | 
| limit | The maximum number of records to retrieve. Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPointDome9.CloudTrail.id | String | The CloudTrail ID. |
| CheckPointDome9.CloudTrail.name | String | The CloudTrail name. |
| CheckPointDome9.CloudTrail.trailArn | String | The CloudTrail ARN. |
| CheckPointDome9.CloudTrail.accountId | String | The CloudTrail account ID. |

#### Command example
```!dome9-cloud-trail-get```
#### Context Example
```json
{
    "CheckPointDome9": {
        "CloudTrail": {
            "accountId": "account_id",
            "cloudAccountId": "cloudAccountId",
            "cloudTrailStatus": {

            },
            "cloudWatchLogsLogGroupArn": null,
            "cloudWatchLogsRoleArn": null,
            "externalId": "arn",
            "homeRegion": "homeRegion",
            "id": "id",
            "includeGlobalServiceEvents": true,
            "isMultiRegionTrail": true,
            "kmsKeyId": null,
            "logFileValidationEnabled": true,
            "name": "name",
            "region": "region",
            "s3BucketName": "s3BucketName",
            "s3KeyPrefix": null,
            "snsTopicArn": null,
            "snsTopicName": null,
            "trailArn": "arn"
        }
    }
}
```

#### Human Readable Output

>### Cloud Trail
>Showing 1 rows out of 1.
>|Accountid|Cloudaccountid|Cloudtrailstatus|Cloudwatchlogsloggrouparn|Cloudwatchlogsrolearn|Externalid|Homeregion|Id|Includeglobalserviceevents|Ismultiregiontrail|Kmskeyid|Logfilevalidationenabled|Name|Region|S3bucketname|S3keyprefix|Snstopicarn|Snstopicname|Trailarn|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| account_id | cloudAccountId | status |  |  | arn | us-east-1 | id | true | true |  | true | name | region | name |  |  |  | arn |
### dome9-organizational-unit-view-get
***
Get organizational unit view entities.


#### Base Command

`dome9-organizational-unit-view-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | Page number of paginated results. Minimum value: 1. | Optional |
| page_size | Number of items per page. | Optional | 
| limit | The maximum number of records to retrieve. Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPointDome9.OrganizationalUnitView.id | String | The organizational unit ID. |
| CheckPointDome9.OrganizationalUnitView.name | String | The organizational unit name. |
| CheckPointDome9.OrganizationalUnitView.path | String | The organizational unit path. |
| CheckPointDome9.OrganizationalUnitView.children | String | The organizational unit children. |

#### Command example
```!dome9-organizational-unit-view-get```
#### Context Example
```json
{
    "CheckPointDome9": {
        "OrganizationalUnitView": {
            "children": [],
            "id": "id",
            "name": "name",
            "path": "path"
        }
    }
}
```

#### Human Readable Output

>### Organizational Unit View
>|Children|Id|Name|Path|
>|---|---|---|---|
>|  | id | name | name |

### dome9-organizational-unit-flat-get
***
Get flat organizational units.


#### Base Command

`dome9-organizational-unit-flat-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | Page number of paginated results. Minimum value: 1. | Optional |
| page_size | Number of items per page. | Optional | 
| limit | The maximum number of records to retrieve. Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPointDome9.OrganizationalUnitFlat.id | String | The organizational unit ID. |
| CheckPointDome9.OrganizationalUnitFlat.name | String | The organizational unit name. |
| CheckPointDome9.OrganizationalUnitFlat.path | String | The organizational unit path. |
| CheckPointDome9.OrganizationalUnitFlat.parentId | String | The organizational unit parent ID. |


#### Command example
```!dome9-organizational-unit-flat-get```
#### Human Readable Output

>### Organizational Unit Flat
>Showing 0 rows out of 0.
>**No entries.**
### dome9-organizational-unit-get
***
Get an organizational unit by its ID.


#### Base Command

`dome9-organizational-unit-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | Page number of paginated results. Minimum value: 1. | Optional |
| page_size | Number of items per page. | Optional | 
| limit | The maximum number of records to retrieve. Default is 50. | Optional | 
| unit_id | The organizational unit ID. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPointDome9.OrganizationalUnit.id | String | The organizational unit ID. |
| CheckPointDome9.OrganizationalUnit.name | String | The organizational unit name. |
| CheckPointDome9.OrganizationalUnit.path | String | The organizational unit path. |
| CheckPointDome9.OrganizationalUnit.parentId | String | The organizational unit parent ID. |

#### Command example
```!dome9-organizational-unit-get```
#### Context Example
```json
{
    "CheckPointDome9": {
        "OrganizationalUnit": {
            "accountId": 0,
            "alibabaAggregateCloudAccountsCount": 0,
            "alibabaCloudAccountsCount": 0,
            "awsAggregatedCloudAcountsCount": 1,
            "awsCloudAcountsCount": 1,
            "azureAggregateCloudAccountsCount": 0,
            "azureCloudAccountsCount": 0,
            "containerRegistryAccountsCount": 0,
            "containerRegistryAggregateCloudAccountsCount": 0,
            "created": "created",
            "googleAggregateCloudAccountsCount": 0,
            "googleCloudAccountsCount": 0,
            "id": "id",
            "isParentRoot": true,
            "isRoot": true,
            "k8sAggregateCloudAccountsCount": 0,
            "k8sCloudAccountsCount": 0,
            "name": "name",
            "parentId": null,
            "path": null,
            "pathStr": null,
            "shiftLeftAggregateCloudAccountsCount": 0,
            "shiftLeftCloudAccountsCount": 0,
            "subOrganizationalUnitsCount": 0,
            "updated": "updated"
        }
    }
}
```

#### Human Readable Output

>### Organizational Unit
>|Accountid|Alibabaaggregatecloudaccountscount|Alibabacloudaccountscount|Awsaggregatedcloudacountscount|Awscloudacountscount|Azureaggregatecloudaccountscount|Azurecloudaccountscount|Containerregistryaccountscount|Containerregistryaggregatecloudaccountscount|Created|Googleaggregatecloudaccountscount|Googlecloudaccountscount|Id|Isparentroot|Isroot|K8saggregatecloudaccountscount|K8scloudaccountscount|Name|Parentid|Path|Pathstr|Shiftleftaggregatecloudaccountscount|Shiftleftcloudaccountscount|Suborganizationalunitscount|Updated|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 0 | 0 | 0 | 1 | 1 | 0 | 0 | 0 | 0 | date | 0 | 0 | id | true | true | 0 | 0 | name |  |  |  | 0 | 0 | 0 | date |

### dome9-findings-get
***
Get a findings by its ID.


#### Base Command

`dome9-findings-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| finding_id | The findings ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPointDome9.Finding.id | String | The findings ID. |
| CheckPointDome9.Finding.bundleId | String | The findings bundle ID. |
| CheckPointDome9.Finding.severity | String | The findings severity. |
| CheckPointDome9.Finding.description | String | The findings description. |
| CheckPointDome9.Finding.remediation | String | The findings remediation. |
| CheckPointDome9.Finding.region | String | The findings region. |
| CheckPointDome9.Finding.cloudAccountId | String | The findings cloud account ID. |


#### Command example
```!dome9-findings-get finding_id=finding_id```
#### Context Example
```json
{
    "CheckPointDome9": {
        "Finding": {
            "acknowledged": false,
            "action": "action",
            "additionalFields": [],
            "alertType": "alertType",
            "bundleId": "bundleId",
            "bundleName": "bundleName",
            "category": "",
            "cloudAccountExternalId": "id",
            "cloudAccountId": "cloudAccountId",
            "cloudAccountType": "cloudAccountType",
            "comments": [],
            "createdTime": "createdTime",
            "description": "description",
            "entityDome9Id": "entityDome9Id",
            "entityExternalId": "entityExternalId",
            "entityName": "entityName",
            "entityNetwork": null,
            "entityObject": {
            },
            "entityTags": [],
            "bundleId": "bundleId",
            "entityTypeByEnvironmentType": "",
            "findingKey": "",
            "id": "finding_id",
            "isExcluded": false,
            "labels": [],
            "lastSeenTime": "lastSeenTime",
            "magellan": null,
            "occurrences": [],
            "organizationalUnitId": "id",
            "organizationalUnitPath": "",
            "origin": "origin",
            "ownerUserName": null,
            "region": "Region",
            "remediation": "remediation",
            "remediationActions": [],
            "ruleId": "ruleId",
            "ruleLogic": "ruleLogic",
            "ruleName": "ruleName",
            "scanId": null,
            "severity": "severity",
            "status": "status",
            "tag": "tag",
            "updatedTime": "updatedTime",
            "webhookResponses": null
        }
    }
}
```

#### Human Readable Output

>Finding
### dome9-findings-bundle-get
***
Get the findings for a specific rule in a bundle, for all of the user's accounts.


#### Base Command

`dome9-findings-bundle-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | Page number of paginated results. Minimum value: 1. | Optional |
| page_size | Number of items per page. | Optional | 
| limit | The maximum number of records to retrieve. Default is 50. | Optional | 
| bundle_id | The bundle ID. Use the dome9-compliance-ruleset-list command to get the bundle ID list. | Required |
| rule_logic_hash | MD5 hash of the rule GSL string. Use the compliance-ruleset-rule-list command to fetch the logic hash. | Required |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPointDome9.FindingsBundle.id | String | The CloudTrail ID. |
| CheckPointDome9.FindingsBundle.severity | String | The CloudTrail name. |
| CheckPointDome9.FindingsBundle.remediation | String | The Cloud Trail ARN. | 
| CheckPointDome9.FindingsBundle.accountId | String | The CloudTrail account ID. |
| CheckPointDome9.FindingsBundle.description | String | The CloudTrail ARN. |
| CheckPointDome9.FindingsBundle.region | String | The CloudTrail account ID. |
#### Command example
```!dome9-findings-bundle-get bundle_id=bundle_id rule_logic_hash=ruleLogicHash```
#### Human Readable Output

>### Findings Bundle
>**No entries.**
