Provides commands for interaction with Prisma SASE API.
This integration was integrated and tested with version xx of Palo Alto Networks - Prisma SASE

## Configure Palo Alto Networks - Prisma SASE on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Palo Alto Networks - Prisma SASE.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Server URL |  | True |
    | API Client ID |  | True |
    | API Client Secret |  | True |
    | Tenant Services Group ID | Default Tenant Services Group ID to use for API calls. Example: 1234567890. | True |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### prisma-sase-security-rule-create
***
Create a new security rule.


#### Base Command

`prisma-sase-security-rule-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| folder | Prisma sase folder location. Possible values are: Shared, Mobile Users, Remote Networks, Service Connections, Mobile Users Container, Mobile Users Explicit Proxy. Default is Shared. | Optional | 
| position | Rule position. Possible values are: pre, post. Default is pre. | Optional | 
| name | The name of the security rule. | Required | 
| action | Rule action. Possible values are: deny, allow, drop, reset-client, reset-server, reset-both. | Required | 
| description | The security rule's description. | Optional | 
| log_setting | Rule log setting. | Optional | 
| application | A comma-separated list of applications. Default is any. | Optional | 
| category | A comma-separated list of categories. You can get category values by running the prisma-sase-custom-url-category-list command. Default is any. | Optional | 
| destination | A comma-separated list of destination networks. Default is any. | Optional | 
| destination_hip | A comma-separated list of destination HIPs. | Optional | 
| profile_setting | Security profiles to apply to the traffic. | Optional | 
| service | Services the rule applies to. Default is any. | Optional | 
| source | A comma-separated list of source networks. Default is any. | Optional | 
| source_hip | A comma-separated list of source HIPs. | Optional | 
| source_user | A semi-colon (;) separated list of source users or groups. Default is any. | Optional | 
| tag | A comma-separated list of rule tags. | Optional | 
| from | A comma-separated list of source zones. Default is any. | Optional | 
| to | A comma-separated list of destination zones. Default is any. | Optional | 
| disabled | Whether the rule is disabled. | Optional | 
| negate_source | Negate the source. | Optional | 
| negate_destination | Negate the destination. | Optional | 
| tsg_id | Tenant services group ID. If not provided, the tsg_id integration parameter will be used as the default. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaSase.SecurityRule | String | Created security rule. | 
| PrismaSase.SecurityRule.action | String | Security rule action. | 
| PrismaSase.SecurityRule.application | String | Security rule application. | 
| PrismaSase.SecurityRule.category | String | Security rule category. | 
| PrismaSase.SecurityRule.description | String | Security rule description. | 
| PrismaSase.SecurityRule.destination | String | Security rule destination. | 
| PrismaSase.SecurityRule.folder | String | Security rule folder. | 
| PrismaSase.SecurityRule.from | String | Security rule from field \(source zone\(s\)\). | 
| PrismaSase.SecurityRule.id | String | Security rule ID. | 
| PrismaSase.SecurityRule.name | String | Security rule name. | 
| PrismaSase.SecurityRule.position | String | Security rule position. | 
| PrismaSase.SecurityRule.profile_setting.group | String | Security rule group. | 
| PrismaSase.SecurityRule.service | String | Security rule service. | 
| PrismaSase.SecurityRule.source | String | Security rule source. | 
| PrismaSase.SecurityRule.source_user | String | Security rule source user. | 
| PrismaSase.SecurityRule.to | String | Security rule to field \(destination zone\(s\)\). | 

#### Command example
```!prisma-sase-security-rule-create name="somename" action="allow"```
#### Context Example
```json
{
    "PrismaSase": {
        "SecurityRule": {
            "action": "allow",
            "application": [
                "any"
            ],
            "category": [
                "any"
            ],
            "destination": [
                "any"
            ],
            "folder": "Shared",
            "from": [
                "any"
            ],
            "id": "id",
            "name": "somename",
            "position": "pre",
            "service": [
                "any"
            ],
            "source": [
                "any"
            ],
            "source_user": [
                "any"
            ],
            "to": [
                "any"
            ]
        }
    }
}
```

#### Human Readable Output

>### Security Rule Created
>|Action|Application|Category|Destination|Folder|From|Id|Name|Position|Service|Source|Source User|To|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| allow | any | any | any | Shared | any | a1f60c27-b877-4a18-b5d6-50c1c447e9c9 | somename | pre | any | any | any | any |


### prisma-sase-security-rule-list
***
Lists all security rules.


#### Base Command

`prisma-sase-security-rule-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| folder | Prisma sase folder location. Possible values are: Shared, Mobile Users, Remote Networks, Service Connections, Mobile Users Container, Mobile Users Explicit Proxy. Default is Shared. | Optional | 
| position | Security rule position. Possible values are: pre, post. Default is pre. | Optional | 
| limit | The maximum number of results to return. Default is 50. Default is 50. | Optional | 
| page | Page number you would like to view. Each page contains page_size values. Must be used along with page_size. | Optional | 
| page_size | Number of results per page to display. | Optional | 
| rule_id | A specific security rule to return. If not specified, all security rules will be returned. | Optional | 
| tsg_id | Tenant services group ID. If not provided, the tsg_id integration parameter will be used as the default. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaSase.SecurityRule | String | Found security rule. | 
| PrismaSase.SecurityRule.action | String | Security rule action. | 
| PrismaSase.SecurityRule.application | String | Security rule application. | 
| PrismaSase.SecurityRule.category | String | Security rule category. | 
| PrismaSase.SecurityRule.description | String | Security rule description. | 
| PrismaSase.SecurityRule.destination | String | Security rule destination. | 
| PrismaSase.SecurityRule.folder | String | Security rule folder. | 
| PrismaSase.SecurityRule.from | String | Security rule from field \(source zone\(s\)\). | 
| PrismaSase.SecurityRule.id | String | Security rule ID. | 
| PrismaSase.SecurityRule.log_setting | String | Security rule log setting. | 
| PrismaSase.SecurityRule.name | String | Security rule name. | 
| PrismaSase.SecurityRule.position | String | Security rule position. | 
| PrismaSase.SecurityRule.service | String | Security rule service. | 
| PrismaSase.SecurityRule.source | String | Security rule source. | 
| PrismaSase.SecurityRule.source_user | String | Security rule source user. | 
| PrismaSase.SecurityRule.tag | String | Security rule tag. | 
| PrismaSase.SecurityRule.to | String | Security rule to field \(destination zone\(s\)\). | 
| PrismaSase.SecurityRule.negate_destination | Boolean | Security rule negate destination. | 

#### Command example
```!prisma-sase-security-rule-list limit=1```
#### Context Example
```json
{
    "PrismaSase": {
        "SecurityRule": {
            "action": "drop",
            "application": [
                "any"
            ],
            "category": [
                "any"
            ],
            "description": "Rule to block traffic to IP addresses that have recently been featured in threat activity advisories distributed by high-trust organizations",
            "destination": [
                "panw-highrisk-ip-list"
            ],
            "folder": "Shared",
            "from": [
                "any"
            ],
            "id": "id",
            "log_setting": "Cortex Data Lake",
            "name": "Drop Traffic to Potential High Risk IP Addresses",
            "negate_destination": false,
            "position": "pre",
            "service": [
                "any"
            ],
            "source": [
                "any"
            ],
            "source_user": [
                "any"
            ],
            "tag": [
                "best-practice"
            ],
            "to": [
                "any"
            ]
        }
    }
}
```

#### Human Readable Output

>### Security Rules
>|Id|Name|Description|Action|Destination|Folder|
>|---|---|---|---|---|---|
>| bfc2caa7-42c4-4eb3-ae8e-0fb76ec20265 | Drop Traffic to Potential High Risk IP Addresses | Rule to block traffic to IP addresses that have recently been featured in threat activity advisories distributed by high-trust organizations | drop | panw-highrisk-ip-list | Shared |


### prisma-sase-candidate-config-push
***
Push the candidate configuration.


#### Base Command

`prisma-sase-candidate-config-push`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| folders | Comma-separated list of targets (Remote Networks, Mobile Users, Service Connections). | Required | 
| description | Configuration push job description. | Optional | 
| interval_in_seconds | interval for polling command. Default is 30. | Optional | 
| job_id | For polling use. | Optional | 
| parent_finished | For polling use. | Optional | 
| tsg_id | Tenant services group ID. If not provided, the tsg_id integration parameter will be used as the default. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaSase.CandidateConfig.job_id | String | Configuration job ID. | 
| PrismaSase.CandidateConfig.result | Boolean | The configuration push result. | 

### prisma-sase-security-rule-update
***
Update an existing security rule.


#### Base Command

`prisma-sase-security-rule-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_id | ID of the rule to be changed. | Required | 
| folder | Prisma sase folder location. Possible values are: Shared, Mobile Users, Remote Networks, Service Connections, Mobile Users Container, Mobile Users Explicit Proxy. Default is Shared. | Optional | 
| position | Security rule position. Possible values are: pre, post. Default is pre. | Optional | 
| action | Rule action. Possible values are: deny, allow, drop, reset-client, reset-server, reset-both. | Optional | 
| description | The security rule's description. | Optional | 
| log_setting | Rule log setting. | Optional | 
| application | A comma-separated list of applications. | Optional | 
| category | A comma-separated list of categories. | Optional | 
| destination | A comma-separated list of destination networks. | Optional | 
| destination_hip | A comma-separated list of destination HIPs. | Optional | 
| profile_setting | Security profiles to apply to the traffic. | Optional | 
| service | Services the rule applies to. | Optional | 
| source | A comma-separated list of source networks. | Optional | 
| source_hip | A comma-separated list of source HIPs. | Optional | 
| source_user | A semi-colon (;) separated list of source user(s). | Optional | 
| tag | A comma-separated list of rule tags. | Optional | 
| from | A comma-separated list of source zones. | Optional | 
| to | A comma-separated list of destination zones. | Optional | 
| disabled | Whether the rule is disabled. | Optional | 
| negate_source | Negate source. | Optional | 
| negate_destination | Negate the destination. | Optional | 
| overwrite | This argument specifies rather to append or overwrite the.... Possible values are: true, false. Default is false. | Optional | 
| tsg_id | Tenant services group ID. If not provided, the tsg_id integration parameter will be used as the default. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaSase.SecurityRule | String | Edited security rule. | 
| PrismaSase.SecurityRule.action | String | Security rule action. | 
| PrismaSase.SecurityRule.application | String | Security rule application. | 
| PrismaSase.SecurityRule.category | String | Security rule category. | 
| PrismaSase.SecurityRule.description | String | Security rule description. | 
| PrismaSase.SecurityRule.destination | String | Security rule destination. | 
| PrismaSase.SecurityRule.folder | String | Security rule folder. | 
| PrismaSase.SecurityRule.from | String | Security rule from field \(source zone\(s\)\). | 
| PrismaSase.SecurityRule.id | String | Security rule ID. | 
| PrismaSase.SecurityRule.name | String | Security rule name. | 
| PrismaSase.SecurityRule.profile_setting.group | String | Security rule profile setting. | 
| PrismaSase.SecurityRule.service | String | Security rule service. | 
| PrismaSase.SecurityRule.source | String | Security rule source. | 
| PrismaSase.SecurityRule.source_user | String | Security rule source user. | 
| PrismaSase.SecurityRule.to | String | Security rule to field \(destination zone\(s\)\). | 

### prisma-sase-address-object-update
***
Update an existing address object.


#### Base Command

`prisma-sase-address-object-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| object_id | ID of the address object to edit. | Required | 
| folder | Prisma sase folder location. Possible values are: Shared, Mobile Users, Remote Networks, Service Connections, Mobile Users Container, Mobile Users Explicit Proxy. Default is Shared. | Optional | 
| description | The address object's description. | Optional | 
| type | The type of the address. Possible values are: ip_netmask, ip_range, ip_wildcard, fqdn. | Optional | 
| address_value | The address value (should match the type). | Required | 
| tag | A comma-separated list of address object tags. | Optional | 
| tsg_id | Tenant services group ID. If not provided, the tsg_id integration parameter will be used as the default. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaSase.Address.description | String | Address description. | 
| PrismaSase.Address.folder | String | Address folder. | 
| PrismaSase.Address.id | String | Address ID. | 
| PrismaSase.Address.address_value | String | Address value. | 
| PrismaSase.Address.type | String | Address type. | 
| PrismaSase.Address.name | String | Address name. | 

### prisma-sase-config-job-list
***
Lists all configuration jobs.


#### Base Command

`prisma-sase-config-job-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | A specific config job to return. If not specified, all config jobs will be returned. | Optional | 
| limit | The maximum number of results to return. Default is 50. Default is 200. | Optional | 
| tsg_id | Tenant services group ID. If not provided, the tsg_id integration parameter will be used as the default. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaSase.ConfigJob.description | String | Configuration job description. | 
| PrismaSase.ConfigJob.end_ts | Date | Configuration job end timestamp. | 
| PrismaSase.ConfigJob.id | String | Configuration job ID. | 
| PrismaSase.ConfigJob.job_result | String | Configuration job result. | 
| PrismaSase.ConfigJob.job_status | String | Configuration job status. | 
| PrismaSase.ConfigJob.job_type | String | Configuration job type. | 
| PrismaSase.ConfigJob.parent_id | String | Configuration job parent ID. | 
| PrismaSase.ConfigJob.percent | String | Configuration job percent. | 
| PrismaSase.ConfigJob.result_str | String | Configuration job result string. | 
| PrismaSase.ConfigJob.start_ts | Date | Configuration job start timestamp. | 
| PrismaSase.ConfigJob.status_str | String | Configuration job status string. | 
| PrismaSase.ConfigJob.summary | String | Configuration job summary. | 
| PrismaSase.ConfigJob.type_str | String | Configuration job type string. | 
| PrismaSase.ConfigJob.uname | String | Configuration job uname. | 

#### Command example
```!prisma-sase-config-job-list limit=1```
#### Context Example
```json
{
    "PrismaSase": {
        "ConfigJob": [
            {
                "description": "Remote Networks configuration pushed to cloud",
                "end_ts": "2023-02-01 12:57:54",
                "id": "200",
                "job_result": "2",
                "job_status": "2",
                "job_type": "22",
                "parent_id": "199",
                "percent": "100",
                "result_str": "OK",
                "start_ts": "2023-02-01 12:55:31",
                "status_str": "FIN",
                "summary": "Configuration push finished",
                "type_str": "CommitAll",
                "uname": "APIGateway@ProdInternal.com"
            }
        ]
    }
}
```

#### Human Readable Output

>### Config Job
>|Id|Type Str|Status Str|Result Str|Start Ts|End Ts|
>|---|---|---|---|---|---|
>| 200 | CommitAll | FIN | OK | 2023-02-01 12:55:31 | 2023-02-01 12:57:54 |


### prisma-sase-security-rule-delete
***
Delete a specific security rule.


#### Base Command

`prisma-sase-security-rule-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_id | Rule ID of the rule to be deleted. | Required | 
| tsg_id | Tenant services group ID. If not provided, the tsg_id integration parameter will be used as the default. | Optional | 


#### Context Output

There is no context output for this command.
### prisma-sase-address-object-create
***
Create a new address object.


#### Base Command

`prisma-sase-address-object-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| folder | Prisma sase folder location. Possible values are: Shared, Mobile Users, Remote Networks, Service Connections, Mobile Users Container, Mobile Users Explicit Proxy. Default is Shared. | Optional | 
| name | The name of the address object. | Required | 
| description | The address object's description. | Optional | 
| type | The type of the address. Possible values are: ip_netmask, ip_range, ip_wildcard, fqdn. | Required | 
| tag | A comma-separated list of address object tags. | Optional | 
| address_value | The address value (should match the type). | Required | 
| tsg_id | Tenant services group ID. If not provided, the tsg_id integration parameter will be used as the default. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaSase.Address | String | Created address object. | 
| PrismaSase.Address.description | String | Address description. | 
| PrismaSase.Address.folder | String | Address folder. | 
| PrismaSase.Address.id | String | Address ID. | 
| PrismaSase.Address.type | String | Address type. | 
| PrismaSase.Address.address_value | String | Address value. | 
| PrismaSase.Address.name | String | Address name. | 

### prisma-sase-address-object-delete
***
Delete a specific address object.


#### Base Command

`prisma-sase-address-object-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| object_id | ID of the address object to delete. | Required | 
| tsg_id | Tenant services group ID. If not provided, the tsg_id integration parameter will be used as the default. | Optional | 


#### Context Output

There is no context output for this command.
### prisma-sase-address-object-list
***
Lists all addresses objects.


#### Base Command

`prisma-sase-address-object-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| object_id | The specific address object to return. If not specified, all addresses will be returned. | Optional | 
| folder | Prisma sase folder location. Possible values are: Shared, Mobile Users, Remote Networks, Service Connections, Mobile Users Container, Mobile Users Explicit Proxy. Default is Shared. | Optional | 
| limit | The maximum number of results to return. Default is 50. Default is 50. | Optional | 
| page | Page number you would like to view. Each page contains page_size values. Must be used along with page_size. | Optional | 
| page_size | Number of results per page to display. | Optional | 
| tsg_id | Tenant services group ID. If not provided, the tsg_id integration parameter will be used as the default. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaSase.Address.description | String | Address description. | 
| PrismaSase.Address.folder | String | Address folder. | 
| PrismaSase.Address.id | String | Address ID. | 
| PrismaSase.Address.name | String | Address name. | 
| PrismaSase.Address.address_value | String | Address value. | 
| PrismaSase.Address.type | String | Address type. | 

#### Command example
```!prisma-sase-address-object-list limit=1```
#### Context Example
```json
{
    "PrismaSase": {
        "Address": {
            "address_value": "sinkhole.paloaltonetworks.com",
            "description": "Palo Alto Networks sinkhole",
            "folder": "Shared",
            "id": "id",
            "name": "Palo Alto Networks Sinkhole",
            "type": "fqdn"
        }
    }
}
```

#### Human Readable Output

>### Address Objects
>|Id|Name|Description|Type|Address Value|Tag|
>|---|---|---|---|---|---|
>| 28f8667c-e89c-403a-aa6d-e294bd08e7ba | Palo Alto Networks Sinkhole | Palo Alto Networks sinkhole | fqdn | sinkhole.paloaltonetworks.com |  |


### prisma-sase-tag-list
***
Lists all tags.


#### Base Command

`prisma-sase-tag-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| tag_id | A specific tag to return. If not specified, all tags will be returned. | Optional | 
| folder | Prisma sase folder location. Possible values are: Shared, Mobile Users, Remote Networks, Service Connections, Mobile Users Container, Mobile Users Explicit Proxy. Default is Shared. | Optional | 
| limit | The maximum number of results to return. Default is 50. Default is 50. | Optional | 
| page | Page number you would like to view. Each page contains page_size values. Must be used along with page_size. | Optional | 
| page_size | Number of results per page to display. | Optional | 
| tsg_id | Tenant services group ID. If not provided, the tsg_id integration parameter will be used as the default. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaSase.Tag.id | String | Tag ID. | 
| PrismaSase.Tag.name | String | Tag name. | 
| PrismaSase.Tag.folder | String | Tag folder. | 
| PrismaSase.Tag.comments | String | Tag comments. | 
| PrismaSase.Tag.color | String | The tag color. | 

#### Command example
```!prisma-sase-tag-list limit=1```
#### Context Example
```json
{
    "PrismaSase": {
        "Tag": {
            "color": "Olive",
            "folder": "predefined",
            "name": "Sanctioned"
        }
    }
}
```

#### Human Readable Output

>### Tags
>|Id|Name|Folder|Color|Comments|
>|---|---|---|---|---|
>|  | Sanctioned | predefined | Olive |  |


### prisma-sase-tag-create
***
Create a new tag.


#### Base Command

`prisma-sase-tag-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| folder | Prisma sase folder location. Possible values are: Shared, Mobile Users, Remote Networks, Service Connections, Mobile Users Container, Mobile Users Explicit Proxy. Default is Shared. | Optional | 
| name | The tag unique name. | Required | 
| color | Tag color. Possible values are: Red, Green, Blue, Yellow, Copper, Orange, Purple, Gray, Light Green, Cyan, Light Gray, Blue Gray, Lime, Black, Gold, Brown, Olive, Maroon, Red-Orange, Yellow-Orange, Forest Green, Turquoise Blue, Azure Blue, Cerulean Blue, Midnight Blue, Medium Blue, Cobalt Blue, Violet Blue, Blue Violet, Medium Violet, Medium Rose, Lavender, Orchid, Thistle, Peach, Salmon, Magenta, Red Violet, Mahogany, Burnt Sienna, Chestnut. | Optional | 
| comments | Tag comments. | Optional | 
| tsg_id | Tenant services group ID. If not provided, the tsg_id integration parameter will be used as the default. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaSase.Tag.id | String | The tag id. | 
| PrismaSase.Tag.name | String | The tag name. | 
| PrismaSase.Tag.folder | String | The tag folder. | 
| PrismaSase.Tag.color | String | The tag color. | 
| PrismaSase.Tag.comments | String | The tag momments. | 

#### Command example
```!prisma-sase-tag-create name="somename" color="Azure Blue"```
#### Context Example
```json
{
    "PrismaSase": {
        "Tag": {
            "color": "Azure Blue",
            "folder": "Shared",
            "id": "id",
            "name": "somename"
        }
    }
}
```

#### Human Readable Output

>### Address Object Created
>|Color|Folder|Id|Name|
>|---|---|---|---|
>| Azure Blue | Shared | b6d9a8d8-5b6d-470b-981f-29bb664adb92 | somename |


### prisma-sase-tag-update
***
Update an existing tag.


#### Base Command

`prisma-sase-tag-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| folder | Prisma sase folder location. Possible values are: Shared, Mobile Users, Remote Networks, Service Connections, Mobile Users Container, Mobile Users Explicit Proxy. Default is Shared. | Optional | 
| tag_id | The tag ID. | Required | 
| color | Tag color. Possible values are: Red, Green, Blue, Yellow, Copper, Orange, Purple, Gray, Light Green, Cyan, Light Gray, Blue Gray, Lime, Black, Gold, Brown, Olive, Maroon, Red-Orange, Yellow-Orange, Forest Green, Turquoise Blue, Azure Blue, Cerulean Blue, Midnight Blue, Medium Blue, Cobalt Blue, Violet Blue, Blue Violet, Medium Violet, Medium Rose, Lavender, Orchid, Thistle, Peach, Salmon, Magenta, Red Violet, Mahogany, Burnt Sienna, Chestnut. | Optional | 
| comments | Tag comments. | Optional | 
| tsg_id | Tenant services group ID. If not provided, the tsg_id integration parameter will be used as the default. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaSase.Tag.id | String | The tag id. | 
| PrismaSase.Tag.name | String | The tag name. | 
| PrismaSase.Tag.folder | String | The tag folder. | 
| PrismaSase.Tag.color | String | The tag color. | 
| PrismaSase.Tag.comments | String | The tag comments. | 

### prisma-sase-tag-delete
***
Delete a specific tag.


#### Base Command

`prisma-sase-tag-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| tag_id | The specific tag to delete. | Required | 
| tsg_id | Tenant services group ID. If not provided, the tsg_id integration parameter will be used as the default. | Optional | 


#### Context Output

There is no context output for this command.
### prisma-sase-address-group-list
***
Lists all address groups.


#### Base Command

`prisma-sase-address-group-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_id | A specific address group to return. If not specified, all address groups will be returned. | Optional | 
| folder | Prisma sase folder location. Possible values are: Shared, Mobile Users, Remote Networks, Service Connections, Mobile Users Container, Mobile Users Explicit Proxy. Default is Shared. | Optional | 
| limit | The maximum number of results to return. Default is 50. | Optional | 
| page | Page number you would like to view. Each page contains page_size values. Must be used along with page_size. | Optional | 
| page_size | Number of results per page to display. | Optional | 
| tsg_id | Tenant services group ID. If not provided, the tsg_id integration parameter will be used as the default. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaSase.AddressGroup.id | String | The address group id. | 
| PrismaSase.AddressGroup.name | String | The address group name. | 
| PrismaSase.AddressGroup.description | String | The address group description. | 
| PrismaSase.AddressGroup.addresses | String | The address group addresses. | 
| PrismaSase.AddressGroup.dynamic_filter | String | The address group filter. | 

#### Command example
```!prisma-sase-address-group-list limit=1```
#### Context Example
```json
{
    "PrismaSase": {
        "AddressGroup": {
            "description": "test",
            "dynamic_filter": "'test' or 'test2",
            "folder": "Shared",
            "id": "id",
            "name": "name"
        }
    }
}
```

#### Human Readable Output

>### Address Groups
>|Id|Name|Description|Addresses|Dynamic Filter|
>|---|---|---|---|---|
>| 4e0ba3d6-0961-4c64-935b-2388db661af0 | Moishy_Test | test |  | 'Api test' or 'Hamuzim' and 'best-practice' |


### prisma-sase-address-group-create
***
Create a new address group.


#### Base Command

`prisma-sase-address-group-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| folder | Prisma sase folder location. Possible values are: Shared, Mobile Users, Remote Networks, Service Connections, Mobile Users Container, Mobile Users Explicit Proxy. Default is Shared. | Optional | 
| type | The address group type. Possible values are: static, dynamic. | Required | 
| static_addresses | static addresses for the address group. If the type is static, value must be provided. | Optional | 
| dynamic_filter | dynamic filter for the address group. If the type is dynamic, value must be provided. | Optional | 
| description | The address group's description. | Optional | 
| name | The name of the address group. | Required | 
| tsg_id | Tenant services group ID. If not provided, the tsg_id integration parameter will be used as the default. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaSase.AddressGroup.id | String | The address group id. | 
| PrismaSase.AddressGroup.name | String | The address group name. | 
| PrismaSase.AddressGroup.folder | String | The address group folder. | 
| PrismaSase.AddressGroup.description | String | The address group description. | 
| PrismaSase.AddressGroup.addresses | String | The address group addresses. | 
| PrismaSase.AddressGroup.dynamic_filter | String | The address group filter. | 

#### Command example
```!prisma-sase-address-group-create type="dynamic" dynamic_filter="Hamuzim" name="somename"```
#### Context Example
```json
{
    "PrismaSase": {
        "AddressGroup": {
            "dynamic_filter": "test",
            "folder": "Shared",
            "id": "id",
            "name": "somename"
        }
    }
}
```

#### Human Readable Output

>### Address Group Created
>|Dynamic Filter|Folder|Id|Name|
>|---|---|---|---|
>| Hamuzim | Shared | 4ac3f38c-f75d-4fe4-9a52-37389a45edbb | somename |


#### Command example
```!prisma-sase-address-group-create folder="Shared" type="static" static_addresses="shachar_test" name="somename1"```
#### Context Example
```json
{
    "PrismaSase": {
        "AddressGroup": {
            "addresses": [
                "test"
            ],
            "folder": "Shared",
            "id": "id",
            "name": "somename1"
        }
    }
}
```

#### Human Readable Output

>### Address Group Created
>|Addresses|Folder|Id|Name|
>|---|---|---|---|
>| shachar_test | Shared | e5996528-9877-4693-a4ad-99f187d46ac7 | somename1 |


### prisma-sase-address-group-update
***
Update an existing address group.


#### Base Command

`prisma-sase-address-group-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_id | The id of the address group. | Required | 
| folder | Prisma sase folder location. Possible values are: Shared, Mobile Users, Remote Networks, Service Connections, Mobile Users Container, Mobile Users Explicit Proxy. Default is Shared. | Optional | 
| static_addresses | static addresses for the address group. If the type is static, value must be provided. | Optional | 
| dynamic_filter | dynamic filter for the address group. If the type is dynamic, value must be provided. | Optional | 
| overwrite | Rather to overwrite existing data. Possible values are: true, false. Default is false. | Optional | 
| description | The address group's description. | Optional | 
| type | The address group type. Possible values are: dynamic, static. | Optional | 
| tsg_id | Tenant services group ID. If not provided, the tsg_id integration parameter will be used as the default. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaSase.AddressGroup.id | String | The address group id. | 
| PrismaSase.AddressGroup.name | String | The address group name. | 
| PrismaSase.AddressGroup.folder | String | The address group folder. | 
| PrismaSase.AddressGroup.description | String | The address group description. | 
| PrismaSase.AddressGroup.addresses | String | The address group addresses. | 
| PrismaSase.AddressGroup.dynamic_filter | String | The address group filter. | 

### prisma-sase-address-group-delete
***
Delete a specific address group.


#### Base Command

`prisma-sase-address-group-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_id | The name of the address group. | Required | 
| tsg_id | Tenant services group ID. If not provided, the tsg_id integration parameter will be used as the default. | Optional | 


#### Context Output

There is no context output for this command.
### prisma-sase-custom-url-category-list
***
Lists all custom URL categories.


#### Base Command

`prisma-sase-custom-url-category-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | A specific url category to return. If not specified, all url categories will be returned. | Optional | 
| folder | Prisma sase folder location. Possible values are: Shared, Mobile Users, Remote Networks, Service Connections, Mobile Users Container, Mobile Users Explicit Proxy. Default is Shared. | Optional | 
| limit | The maximum number of results to return. Default is 50. | Optional | 
| page | Page number you would like to view. Each page contains page_size values. Must be used along with page_size. | Optional | 
| page_size | Number of results per page to display. | Optional | 
| tsg_id | Tenant services group ID. If not provided, the tsg_id integration parameter will be used as the default. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaSase.CustomURLCategory.id | String | The URL category id. | 
| PrismaSase.CustomURLCategory.name | String | The URL category name. | 
| PrismaSase.CustomURLCategory.folder | String | The URL category folder. | 
| PrismaSase.CustomURLCategory.type | String | The URL category type. | 
| PrismaSase.CustomURLCategory.list | String | The URL category match list. | 
| PrismaSase.CustomURLCategory.description | String | The URL category description. | 

#### Command example
```!prisma-sase-custom-url-category-list limit=1```
#### Context Example
```json
{
    "PrismaSase": {
        "CustomURLCategory": {
            "folder": "Shared",
            "id": "id",
            "list": [
                "www.youtube.com",
                "www.google.com"
            ],
            "name": "name",
            "type": "URL List"
        }
    }
}
```

#### Human Readable Output

>### Custom Url Categories
>|Id|Name|Folder|Type|List|
>|---|---|---|---|---|
>| c36a960a-8290-4dd2-82ac-a58082a76370 | Moishy Api | Shared | URL List | www.youtube.com,<br/>www.google.com |


### prisma-sase-custom-url-category-create
***
Create a new url category.


#### Base Command

`prisma-sase-custom-url-category-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| folder | Prisma sase folder location. Possible values are: Shared, Mobile Users, Remote Networks, Service Connections, Mobile Users Container, Mobile Users Explicit Proxy. Default is Shared. | Optional | 
| type | The custom URL category's type. Possible values are: URL List, Category Match. | Required | 
| value | If the type is url list the value will be a comma separated array of url addresses. If the type is Category Match the value will be a comma separated array of categories name. The user can get the names by running prisma-sase-url-access-profile-list. | Required | 
| description | The custom URL category's description. | Optional | 
| name | The name of the custom URL category. | Required | 
| tsg_id | Tenant services group ID. If not provided, the tsg_id integration parameter will be used as the default. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaSase.CustomURLCategory.id | String | The URL category id. | 
| PrismaSase.CustomURLCategory.name | String | The URL category name. | 
| PrismaSase.CustomURLCategory.folder | String | The URL category folder. | 
| PrismaSase.CustomURLCategory.type | String | The URL category type. | 
| PrismaSase.CustomURLCategory.list | String | The URL category match list. | 
| PrismaSase.CustomURLCategory.description | String | The URL category description. | 

#### Command example
```!prisma-sase-custom-url-category-create type="Category Match" value="low-risk" name="somename"```
#### Context Example
```json
{
    "PrismaSase": {
        "CustomURLCategory": {
            "folder": "Shared",
            "id": "id",
            "list": [
                "low-risk"
            ],
            "name": "somename",
            "type": "Category Match"
        }
    }
}
```

#### Human Readable Output

>### Custom URrl Category Created
>|Folder|Id|List|Name|Type|
>|---|---|---|---|---|
>| Shared | 107ca93c-cc4a-4573-b453-156737cc3900 | low-risk | somename | Category Match |


### prisma-sase-custom-url-category-update
***
Update an existing url category.


#### Base Command

`prisma-sase-custom-url-category-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The custom URL category id. | Required | 
| folder | Prisma sase folder location. Possible values are: Shared, Mobile Users, Remote Networks, Service Connections, Mobile Users Container, Mobile Users Explicit Proxy. Default is Shared. | Optional | 
| value | . | Optional | 
| overwrite | This argument specifies rather to append or overwrite the.... Possible values are: true, false. Default is false. | Optional | 
| description | The custom URL category's description. | Optional | 
| type | The custom URL category's type. Possible values are: URL List, Category Match. | Optional | 
| tsg_id | Tenant services group ID. If not provided, the tsg_id integration parameter will be used as the default. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaSase.CustomURLCategory.id | String | The URL category id. | 
| PrismaSase.CustomURLCategory.name | String | The URL category name. | 
| PrismaSase.CustomURLCategory.folder | String | The URL category folder. | 
| PrismaSase.CustomURLCategory.type | String | The URL category type. | 
| PrismaSase.CustomURLCategory.list | String | The URL category match list. | 
| PrismaSase.CustomURLCategory.description | String | The URL category description. | 

### prisma-sase-custom-url-category-delete
***
Delete a specific url category.


#### Base Command

`prisma-sase-custom-url-category-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The custom URL category id. | Required | 
| tsg_id | Tenant services group ID. If not provided, the tsg_id integration parameter will be used as the default. | Optional | 


#### Context Output

There is no context output for this command.
### prisma-sase-external-dynamic-list-list
***
Lists all external dynamic lists.


#### Base Command

`prisma-sase-external-dynamic-list-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | A specific external dynamic list to return. If not specified, all external dynamic lists will be returned. | Optional | 
| folder | Prisma sase folder location. Possible values are: Shared, Mobile Users, Remote Networks, Service Connections, Mobile Users Container, Mobile Users Explicit Proxy. Default is Shared. | Optional | 
| limit | The maximum number of results to return. Default is 50. | Optional | 
| page | Page number you would like to view. Each page contains page_size values. Must be used along with page_size. | Optional | 
| page_size | Number of results per page to display. | Optional | 
| tsg_id | Tenant services group ID. If not provided, the tsg_id integration parameter will be used as the default. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaSase.ExternalDynamicList.id | String | The external dynamic list id. | 
| PrismaSase.ExternalDynamicList.name | String | The external dynamic list name. | 
| PrismaSase.ExternalDynamicList.folder | String | The external dynamic list folder. | 
| PrismaSase.ExternalDynamicList.description | String | The external dynamic list description. | 
| PrismaSase.ExternalDynamicList.type | String | The external dynamic list type. | 
| PrismaSase.ExternalDynamicList.source | String | The external dynamic list source. | 
| PrismaSase.ExternalDynamicList.frequency | String | The external dynamic list frequency. | 

#### Command example
```!prisma-sase-external-dynamic-list-list limit=1```
#### Context Example
```json
{
    "PrismaSase": {
        "ExternalDynamicList": {
            "description": "IP addresses that are currently used almost exclusively by malicious actors for malware distribution, command-and-control, and for launching various attacks.",
            "display_name": "Palo Alto Networks - Known malicious IP addresses",
            "folder": "predefined",
            "name": "panw-known-ip-list",
            "source": "predefined",
            "type": "predefined"
        }
    }
}
```

#### Human Readable Output

>### External Dynamic Lists
>|Id|Name|Type|Folder|Description|Source|Frequency|
>|---|---|---|---|---|---|---|
>|  | panw-known-ip-list | predefined | predefined | IP addresses that are currently used almost exclusively by malicious actors for malware distribution, command-and-control, and for launching various attacks. | predefined |  |


### prisma-sase-external-dynamic-list-create
***
Create a new dynamic list.


#### Base Command

`prisma-sase-external-dynamic-list-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The external dynamic list name. | Required | 
| folder | Prisma sase folder location. Possible values are: Shared, Mobile Users, Remote Networks, Service Connections, Mobile Users Container, Mobile Users Explicit Proxy. Default is Shared. | Optional | 
| description | The dynamic list's description. | Optional | 
| type | The dynamic list's type. Possible values are: predefined_ip, predefined_url, ip, domain, url. | Required | 
| predefined_ip_list | The predefined IP list. If the type is predefined_ip, value must be provided. Possible values are: panw-torexit-ip-list, panw-bulletproof-ip-list, panw-highrisk-ip-list, panw-known-ip-list. | Optional | 
| predefined_url_list | The predefined URL list. If the type is predefined_url, value must be provided. Possible values are: panw–auth-portal-exclude-list. | Optional | 
| source_url | The source URL. If the type is IP, URL or Domain, value must be provided. | Optional | 
| frequency | Frequency to check for updates. Possible values are: five_minute, hourly, daily, weekly, monthly. | Optional | 
| frequency_hour | The frequency hour. If the frequency argument is daily, weekly or monthly, value must be provided. Possible values are 00-23. | Optional | 
| day_of_week | The day of the week. If the frequency argument is weekly or monthly, value must be provided. Possible values are: monday, tuesday, wednesday, thursday, friday, saturday, sunday. | Optional | 
| day_of_month | The day of the month. If the frequency argument is monthly, value must be provided. Possible values are between 1 and 31. | Optional | 
| exception_list | The user can exclude certain addresses from the list depending on the type of list. | Optional | 
| tsg_id | Tenant services group ID. If not provided, the tsg_id integration parameter will be used as the default. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaSase.ExternalDynamicList.id | String | The external dynamic list id. | 
| PrismaSase.ExternalDynamicList.name | String | The external dynamic list name. | 
| PrismaSase.ExternalDynamicList.folder | String | The external dynamic list folder. | 
| PrismaSase.ExternalDynamicList.description | String | The external dynamic list description. | 
| PrismaSase.ExternalDynamicList.type | String | The external dynamic list type. | 
| PrismaSase.ExternalDynamicList.source | String | The external dynamic list source. | 
| PrismaSase.ExternalDynamicList.frequency | String | The external dynamic list frequency. | 

#### Command example
```!prisma-sase-external-dynamic-list-create name="somename" folder="Shared" type="predefined_ip" predefined_ip_list="panw-highrisk-ip-list"```
#### Context Example
```json
{
    "PrismaSase": {
        "ExternalDynamicList": {
            "description": null,
            "exception_list": null,
            "folder": "Shared",
            "frequency": null,
            "id": "id",
            "name": "somename",
            "source": "panw-highrisk-ip-list",
            "type": "predefined_ip"
        }
    }
}
```

#### Human Readable Output

>### External Dynamic List Created
>|Id|Name|Type|Folder|Description|Source|Frequency|
>|---|---|---|---|---|---|---|
>| 10359e8c-7981-46cc-b36e-7d5962dab0bd | somename | predefined_ip | Shared |  | panw-highrisk-ip-list |  |


#### Command example
```!prisma-sase-external-dynamic-list-create name="somename1" folder="Shared" type="domain" source_url="domain.com" frequency="monthly" frequency_hour="09" day_of_month="1"```
#### Context Example
```json
{
    "PrismaSase": {
        "ExternalDynamicList": {
            "description": null,
            "exception_list": null,
            "folder": "Shared",
            "frequency": {
                "monthly": {
                    "at": "09",
                    "day_of_month": 1
                }
            },
            "id": "id",
            "name": "somename1",
            "source": "domain.com",
            "type": "domain"
        }
    }
}
```

#### Human Readable Output

>### External Dynamic List Created
>|Id|Name|Type|Folder|Description|Source|Frequency|
>|---|---|---|---|---|---|---|
>| 5f5b45a3-ae8b-452b-8df0-14b45f76f8aa | somename1 | domain | Shared |  | domain.com | **monthly**:<br/>	***at***: 09<br/>	***day_of_month***: 1 |


### prisma-sase-external-dynamic-list-update
***
Update an existing dynamic list.


#### Base Command

`prisma-sase-external-dynamic-list-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The external dynamic list id. | Required | 
| folder | Prisma sase folder location. Possible values are: Shared, Mobile Users, Remote Networks, Service Connections, Mobile Users Container, Mobile Users Explicit Proxy. Default is Shared. | Optional | 
| overwrite | This argument specifies rather to append or overwrite the.... Possible values are: true, false. Default is false. | Optional | 
| description | The dynamic list's description. | Optional | 
| type | The dynamic list's type. Possible values are: predefined_ip, predefined_url, ip, domain, url. | Optional | 
| predefined_ip_list | Dont know yet. Possible values are: panw-torexit-ip-list, panw-bulletproof-ip-list, panw-highrisk-ip-list, panw-known-ip-list. | Optional | 
| predefined_url_list | Dont know yet. Possible values are: panw–auth-portal-exclude-list. | Optional | 
| source_url | Dont know yet. | Optional | 
| frequency | Dont know yet. Possible values are: five_minute, hourly, daily, weekly, monthly. | Optional | 
| frequency_hour | The frequency hour. | Optional | 
| day_of_week | The day of the week. Possible values are: monday, tuesday, wednesday, thursday, friday, saturday, sunday. | Optional | 
| day_of_month | The day of the month. Possible values are between 1 and 31. | Optional | 
| exception_list | The user can exclude certain addresses from the list depending on the type of list. | Optional | 
| tsg_id | Tenant services group ID. If not provided, the tsg_id integration parameter will be used as the default. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaSase.ExternalDynamicList.id | String | The external dynamic list id. | 
| PrismaSase.ExternalDynamicList.name | String | The external dynamic list name. | 
| PrismaSase.ExternalDynamicList.folder | String | The external dynamic list folder. | 
| PrismaSase.ExternalDynamicList.description | String | The external dynamic list description. | 
| PrismaSase.ExternalDynamicList.type | String | The external dynamic list type. | 
| PrismaSase.ExternalDynamicList.source | String | The external dynamic list source. | 
| PrismaSase.ExternalDynamicList.frequency | String | The external dynamic list frequency. | 

### prisma-sase-external-dynamic-list-delete
***
Delete a specific dynamic list.


#### Base Command

`prisma-sase-external-dynamic-list-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The external dynamic list id. | Required | 
| tsg_id | Tenant services group ID. If not provided, the tsg_id integration parameter will be used as the default. | Optional | 


#### Context Output

There is no context output for this command.
### prisma-sase-url-category-list
***
Get all predefined URL categories.


#### Base Command

`prisma-sase-url-category-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| folder | Prisma sase folder location. Possible values are: Shared, Mobile Users, Remote Networks, Service Connections, Mobile Users Container, Mobile Users Explicit Proxy. Default is Shared. | Optional | 
| tsg_id | Tenant services group ID. If not provided, the tsg_id integration parameter will be used as the default. | Optional | 


#### Context Output

There is no context output for this command.
#### Command example
```!prisma-sase-url-category-list limit=1```
#### Human Readable Output

>### URL categories
>|alert|allow|block|continue|override|
>|---|---|---|---|---|
>| recreation-and-hobbies,<br/>educational-institutions,<br/>real-estate,<br/>web-advertisements,<br/>health-and-medicine,<br/>stock-advice-and-tools,<br/>travel,<br/>computer-and-internet-info,<br/>personal-sites-and-blogs,<br/>swimsuits-and-intimate-apparel,<br/>social-networking,<br/>religion,<br/>medium-risk,<br/>business-and-economy,<br/>private-ip-addresses,<br/>web-hosting,<br/>entertainment-and-arts,<br/>streaming-media,<br/>abortion,<br/>translation,<br/>internet-portals,<br/>online-storage-and-backup,<br/>job-search,<br/>motor-vehicles,<br/>web-based-email,<br/>nudity,<br/>sports,<br/>training-and-tools,<br/>government,<br/>shareware-and-freeware,<br/>legal,<br/>shopping,<br/>alcohol-and-tobacco,<br/>low-risk,<br/>auctions,<br/>high-risk,<br/>search-engines,<br/>cryptocurrency,<br/>not-resolved,<br/>society,<br/>financial-services,<br/>military,<br/>news,<br/>philosophy-and-political-advocacy,<br/>content-delivery-networks,<br/>internet-communications-and-telephony,<br/>music,<br/>home-and-garden,<br/>hunting-and-fishing,<br/>reference-and-research,<br/>dating,<br/>sex-education,<br/>games |  | hacking,<br/>extremism,<br/>weapons,<br/>command-and-control,<br/>ransomware,<br/>copyright-infringement,<br/>dynamic-dns,<br/>parked,<br/>phishing,<br/>medium-risk,<br/>unknown,<br/>abused-drugs,<br/>insufficient-content,<br/>adult,<br/>newly-registered-domain,<br/>grayware,<br/>high-risk,<br/>gambling,<br/>malware,<br/>peer-to-peer,<br/>proxy-avoidance-and-anonymizers,<br/>questionable |  |  |

