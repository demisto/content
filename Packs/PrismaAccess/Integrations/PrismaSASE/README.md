Provides commands for interaction with Prisma SASE API.
This integration was integrated and tested with version 1 of Prisma SASE

## Configure Prisma SASE on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Prisma SASE.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | API Gateway URL |  | True |
    | API Client ID |  | True |
    | API Client Secret |  | True |
    | Use system proxy settings |  | False |
    | Tenant Services Group ID | Default Tenant Services Group ID to use for API calls. Example: 1234567890. | True |
    | Prisma API OAUTH URL | URL used to obtain the OAUTH2 access token. | False |
    | Trust any certificate (not secure) |  | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### prisma-access-create-security-rule
***
Create a new security rule.


#### Base Command

`prisma-access-create-security-rule`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| folder | Prisma access folder location for the rule. | Required | 
| position | Rule position. Possible values are: pre, post. | Required | 
| tsg_id | Tenant services group ID. If not provided, the tsg_id integration parameter will be used as the default. | Optional | 
| name | Friendly name of the rule. | Required | 
| action | Rule action. | Required | 
| description | Rule description. | Optional | 
| log_setting | Rule log setting. | Optional | 
| application | A comma-separated list of applications. | Required | 
| category | A comma-separated list of categories. | Required | 
| destination | A comma-separated list of destination networks. | Required | 
| destination_hip | A comma-separated list of destination HIPs. | Optional | 
| profile_setting | Security profiles to apply to the traffic. | Optional | 
| service | Services the rule applies to. | Required | 
| source | A comma-separated list of source networks. | Required | 
| source_hip | A comma-separated list of source HIPs. | Optional | 
| source_user | A semi-colon (;) separated list of source users or groups. | Required | 
| tag | A comma-separated list of rule tags. | Optional | 
| from | A comma-separated list of source zones. | Required | 
| to | A comma-separated list of destination zones. | Required | 
| disabled | Whether the rule is disabled. | Optional | 
| negate_source | Negate the source. | Optional | 
| negate_destination | Negate the destination. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAccess.CreatedSecurityRule | unknown | Created security rule. | 
| PrismaAccess.CreatedSecurityRule.action | String | Security rule action. | 
| PrismaAccess.CreatedSecurityRule.application | String | Security rule application. | 
| PrismaAccess.CreatedSecurityRule.category | String | Security rule category. | 
| PrismaAccess.CreatedSecurityRule.description | String | Security rule description. | 
| PrismaAccess.CreatedSecurityRule.destination | String | Security rule destination. | 
| PrismaAccess.CreatedSecurityRule.folder | String | Security rule folder. | 
| PrismaAccess.CreatedSecurityRule.from | String | Security rule from field \(source zone\(s\)\). | 
| PrismaAccess.CreatedSecurityRule.id | String | Security rule ID. | 
| PrismaAccess.CreatedSecurityRule.name | String | Security rule name. | 
| PrismaAccess.CreatedSecurityRule.position | String | Security rule position. | 
| PrismaAccess.CreatedSecurityRule.profile_setting.group | String | Security rule group. | 
| PrismaAccess.CreatedSecurityRule.service | String | Security rule service. | 
| PrismaAccess.CreatedSecurityRule.source | String | Security rule source. | 
| PrismaAccess.CreatedSecurityRule.source_user | String | Security rule source user. | 
| PrismaAccess.CreatedSecurityRule.to | String | Security rule to field \(destination zone\(s\)\). | 

#### Command example
```!prisma-access-create-security-rule name="new-test-rule B" action="deny" description="Test Rule Created by XSOAR" application="any" category="any" destination="XSOAR Test Object A" profile_setting="best-practice" service="application-default" source="XSOAR Test Object A" source_user="any" from="trust" to="any" folder="Shared" position="pre"```
#### Context Example
```json
{
    "PrismaAccess": {
        "CreatedSecurityRule": {
            "action": "deny",
            "application": [
                "any"
            ],
            "category": [
                "any"
            ],
            "description": "Test Rule Created by XSOAR",
            "destination": [
                "XSOAR Test Object A"
            ],
            "folder": "Shared",
            "from": [
                "trust"
            ],
            "id": "########-####-####-####-############",
            "name": "new-test-rule B",
            "position": "pre",
            "profile_setting": {
                "group": [
                    "best-practice"
                ]
            },
            "service": [
                "application-default"
            ],
            "source": [
                "XSOAR Test Object A"
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
>|Action|Application|Category|Description|Destination|Folder|From|Id|Name|Position|Profile Setting|Service|Source|Source User|To|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| deny | any | any | Test Rule Created by XSOAR | XSOAR Test Object A | Shared | trust | ########-####-####-####-############ | new-test-rule B | pre | group: best-practice | application-default | XSOAR Test Object A | any | any |


### prisma-access-list-security-rules
***
List the security rules.


#### Base Command

`prisma-access-list-security-rules`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| folder | Prisma access folder location for the rule. | Required | 
| position | Security rule position. Possible values are: pre, post. | Required | 
| name | Name of the security rule. | Optional | 
| limit | The maximum number of results to return. Default is 10. | Optional | 
| offset | Results paging offset. | Optional | 
| tsg_id | Tenant services group ID. If not provided, the tsg_id integration parameter will be used as the default. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAccess.FoundSecurityRule | unknown | Found security rule. | 
| PrismaAccess.FoundSecurityRule.action | String | Security rule action. | 
| PrismaAccess.FoundSecurityRule.application | String | Security rule application. | 
| PrismaAccess.FoundSecurityRule.category | String | Security rule category. | 
| PrismaAccess.FoundSecurityRule.description | String | Security rule description. | 
| PrismaAccess.FoundSecurityRule.destination | String | Security rule destination. | 
| PrismaAccess.FoundSecurityRule.folder | String | Security rule folder. | 
| PrismaAccess.FoundSecurityRule.from | String | Security rule from field \(source zone\(s\)\). | 
| PrismaAccess.FoundSecurityRule.id | String | Security rule ID. | 
| PrismaAccess.FoundSecurityRule.log_setting | String | Security rule log setting. | 
| PrismaAccess.FoundSecurityRule.name | String | Security rule name. | 
| PrismaAccess.FoundSecurityRule.position | String | Security rule position. | 
| PrismaAccess.FoundSecurityRule.service | String | Security rule service. | 
| PrismaAccess.FoundSecurityRule.source | String | Security rule source. | 
| PrismaAccess.FoundSecurityRule.source_user | String | Security rule source user. | 
| PrismaAccess.FoundSecurityRule.tag | String | Security rule tag. | 
| PrismaAccess.FoundSecurityRule.to | String | Security rule to field \(destination zone\(s\)\). | 
| PrismaAccess.FoundSecurityRule.negate_destination | Boolean | Security rule negate destination. | 

#### Command example
```!prisma-access-list-security-rules folder="Shared" position="pre" limit=5```
#### Context Example
```json
{
    "PrismaAccess": {
        "FoundSecurityRule": [
            {
                "action": "drop",
                "application": [
                    "any"
                ],
                "category": [
                    "any"
                ],
                "description": "Rule to block traffic to well known malicious IP addresses, as provided by dynamic feeds from Palo Alto Networks threat intel",
                "destination": [
                    "panw-known-ip-list"
                ],
                "folder": "Shared",
                "from": [
                    "any"
                ],
                "id": "########-####-####-####-############",
                "log_setting": "Cortex Data Lake",
                "name": "Drop Traffic to Known Malicious IP Addresses",
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
            },
            {
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
                "id": "########-####-####-####-############",
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
            },
            {
                "action": "drop",
                "application": [
                    "any"
                ],
                "category": [
                    "any"
                ],
                "description": "Rule to block traffic to bulletproof IP addresses as bulletproof hosting providers place few, if any, restrictions on content and attackers can use these services to host and distribute malicious, illegal, and unethical material",
                "destination": [
                    "panw-bulletproof-ip-list"
                ],
                "folder": "Shared",
                "from": [
                    "any"
                ],
                "id": "########-####-####-####-############",
                "log_setting": "Cortex Data Lake",
                "name": "Drop Traffic to Bulletproof hosting providers",
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
            },
            {
                "action": "drop",
                "application": [
                    "any"
                ],
                "category": [
                    "any"
                ],
                "description": "Rule to block traffic from well known malicious IP addresses, as provided by dynamic feeds from Palo Alto Networks threat intel",
                "destination": [
                    "any"
                ],
                "folder": "Shared",
                "from": [
                    "any"
                ],
                "id": "########-####-####-####-############",
                "log_setting": "Cortex Data Lake",
                "name": "Drop Traffic from Known Malicious IP Addresses",
                "negate_destination": false,
                "position": "pre",
                "service": [
                    "any"
                ],
                "source": [
                    "panw-known-ip-list"
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
            },
            {
                "action": "drop",
                "application": [
                    "any"
                ],
                "category": [
                    "any"
                ],
                "description": "Rule to block traffic from IP addresses that have recently been featured in threat activity advisories distributed by high-trust organizations",
                "destination": [
                    "any"
                ],
                "folder": "Shared",
                "from": [
                    "any"
                ],
                "id": "########-####-####-####-############",
                "log_setting": "Cortex Data Lake",
                "name": "Drop Traffic from Potential High Risk IP Addresses",
                "negate_destination": false,
                "position": "pre",
                "service": [
                    "any"
                ],
                "source": [
                    "panw-highrisk-ip-list"
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
        ]
    }
}
```

#### Human Readable Output

>### Security Rules
>|Id|Name|Description|Action|Destination|Folder|
>|---|---|---|---|---|---|
>| ########-####-####-####-############ | Drop Traffic to Known Malicious IP Addresses | Rule to block traffic to well known malicious IP addresses, as provided by dynamic feeds from Palo Alto Networks threat intel | drop | panw-known-ip-list | Shared |
>| ########-####-####-####-############ | Drop Traffic to Potential High Risk IP Addresses | Rule to block traffic to IP addresses that have recently been featured in threat activity advisories distributed by high-trust organizations | drop | panw-highrisk-ip-list | Shared |
>| ########-####-####-####-############ | Drop Traffic to Bulletproof hosting providers | Rule to block traffic to bulletproof IP addresses as bulletproof hosting providers place few, if any, restrictions on content and attackers can use these services to host and distribute malicious, illegal, and unethical material | drop | panw-bulletproof-ip-list | Shared |
>| ########-####-####-####-############ | Drop Traffic from Known Malicious IP Addresses | Rule to block traffic from well known malicious IP addresses, as provided by dynamic feeds from Palo Alto Networks threat intel | drop | any | Shared |
>| ########-####-####-####-############ | Drop Traffic from Potential High Risk IP Addresses | Rule to block traffic from IP addresses that have recently been featured in threat activity advisories distributed by high-trust organizations | drop | any | Shared |


### prisma-access-push-candidate-config
***
Push the candidate configuration.


#### Base Command

`prisma-access-push-candidate-config`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| folders | Comma-separated list of targets (Remote Networks, Mobile Users, Service Connections). | Required | 
| description | Configuration push job description. | Optional | 
| tsg_id | Tenant services group ID. If not provided, the tsg_id integration parameter will be used as the default. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAccess.ConfigPush | unknown | Configuration job information. | 
| PrismaAccess.ConfigPush.job_id | String | Configuration job ID. | 
| PrismaAccess.ConfigPush.message | String | Configuration job message. | 
| PrismaAccess.ConfigPush.success | Boolean | Whether the configuration job was successful. | 

#### Command example
```!prisma-access-push-candidate-config folders="Mobile Users"```
#### Context Example
```json
{
    "PrismaAccess": {
        "ConfigPush": {
            "job_id": "58",
            "message": "CommitAndPush job enqueued with jobid 58",
            "success": true
        }
    }
}
```

#### Human Readable Output

>### Configuration Push Requested
>|Job Id|Message|Success|
>|---|---|---|
>| 58 | CommitAndPush job enqueued with jobid 58 | true |


### prisma-access-edit-security-rule
***
Edit an existing security rule.


#### Base Command

`prisma-access-edit-security-rule`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID of the rule to be changed. | Required | 
| tsg_id | Tenant services group ID. If not provided, the tsg_id integration parameter will be used as the default. | Optional | 
| name | Friendly name of the rule. | Required | 
| action | Rule action. | Required | 
| description | Rule description. | Optional | 
| log_setting | Rule log setting. | Optional | 
| application | A comma-separated list of applications. | Required | 
| category | A comma-separated list of categories. | Required | 
| destination | A comma-separated list of destination networks. | Required | 
| destination_hip | A comma-separated list of destination HIPs. | Optional | 
| profile_setting | Security profiles to apply to the traffic. | Optional | 
| service | Services the rule applies to. | Required | 
| source | A comma-separated list of source networks. | Required | 
| source_hip | A comma-separated list of source HIPs. | Optional | 
| source_user | A semi-colon (;) separated list of source user(s). | Required | 
| tag | A comma-separated list of rule tags. | Optional | 
| from | A comma-separated list of source zones. | Required | 
| to | A comma-separated list of destination zones. | Required | 
| disabled | Whether the rule is disabled. | Optional | 
| negate_source | Negate source. | Optional | 
| negate_destination | Negate the destination. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAccess.EditedSecurityRule | unknown | Edited security rule. | 
| PrismaAccess.UpdatedSecurityRule.action | String | Security rule action. | 
| PrismaAccess.UpdatedSecurityRule.application | String | Security rule application. | 
| PrismaAccess.UpdatedSecurityRule.category | String | Security rule category. | 
| PrismaAccess.UpdatedSecurityRule.description | String | Security rule description. | 
| PrismaAccess.UpdatedSecurityRule.destination | String | Security rule destination. | 
| PrismaAccess.UpdatedSecurityRule.folder | String | Security rule folder. | 
| PrismaAccess.UpdatedSecurityRule.from | String | Security rule from field \(source zone\(s\)\). | 
| PrismaAccess.UpdatedSecurityRule.id | String | Security rule ID. | 
| PrismaAccess.UpdatedSecurityRule.name | String | Security rule name. | 
| PrismaAccess.UpdatedSecurityRule.profile_setting.group | String | Security rule profile setting. | 
| PrismaAccess.UpdatedSecurityRule.service | String | Security rule service. | 
| PrismaAccess.UpdatedSecurityRule.source | String | Security rule source. | 
| PrismaAccess.UpdatedSecurityRule.source_user | String | Security rule source user. | 
| PrismaAccess.UpdatedSecurityRule.to | String | Security rule to field \(destination zone\(s\)\). | 

#### Command example
```!prisma-access-edit-security-rule id="########-####-####-####-############" name="new-test-rule A" action="deny" description="Rule Edited by XSOAR" application="any" category="any" destination="XSOAR Test Object A" profile_setting="best-practice" service="application-default" source="XSOAR Test Object A" source_user="any" from="trust" to="any"```
#### Context Example
```json
{
    "PrismaAccess": {
        "EditedSecurityRule": {
            "action": "deny",
            "application": [
                "any"
            ],
            "category": [
                "any"
            ],
            "description": "Rule Edited by XSOAR",
            "destination": [
                "XSOAR Test Object A"
            ],
            "folder": "Shared",
            "from": [
                "trust"
            ],
            "id": "########-####-####-####-############",
            "name": "new-test-rule A",
            "profile_setting": {
                "group": [
                    "best-practice"
                ]
            },
            "service": [
                "application-default"
            ],
            "source": [
                "XSOAR Test Object A"
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

>### Security Rule Updated
>|Action|Application|Category|Description|Destination|Folder|From|Id|Name|Profile Setting|Service|Source|Source User|To|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| deny | any | any | Rule Edited by XSOAR | XSOAR Test Object A | Shared | trust | ########-####-####-####-############ | new-test-rule A | group: best-practice | application-default | XSOAR Test Object A | any | any |


### prisma-sase-query-agg-monitor-api
***
Query the aggregate monitor API.


#### Base Command

`prisma-sase-query-agg-monitor-api`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| tsg_id | Tenant services group ID. If not provided, the tsg_id integration parameter will be used as the default. | Optional | 
| query_data | Query data. | Optional | 
| uri | Aggregate monitor URI to query (for example: mt/monitor/v1/agg/threats). | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaSASE.AggregateQueryResponse | unknown | Aggregate query response. | 
| PrismaSASE.AggregateQueryResponse.header.dataCount | Number | Query response data count. | 

#### Command example
```!prisma-sase-query-agg-monitor-api uri="mt/monitor/v1/agg/alerts/list" query_data="{\"filter\":{\"operator\":\"AND\",\"rules\":[{\"operator\":\"in\",\"property\":\"domain\",\"values\":[\"External\",\"external\"]},{\"operator\":\"last_n_days\",\"property\":\"event_time\",\"values\":[7]}]},\"properties\":[{\"property\":\"total_count\"},{\"property\":\"mu_count\"},{\"property\":\"rn_count\"},{\"property\":\"sc_count\"}]}"```
#### Context Example
```json
{
    "PrismaSASE": {
        "AggregateQueryResponse": {
            "data": [],
            "header": {
                "clientRequestId": "########-####-####-####-############",
                "createdAt": "2022-11-29T19:39:03Z",
                "dataCount": 0,
                "requestId": "########-####-####-####-############",
                "status": {
                    "subCode": 204
                }
            }
        }
    }
}
```

#### Human Readable Output

>### Aggregate Monitor API Query Response
>|data|header|
>|---|---|
>|  | createdAt: 2022-11-29T19:39:03Z<br/>dataCount: 0<br/>requestId: ########-####-####-####-############<br/>clientRequestId: ########-####-####-####-############<br/>status: {"subCode": 204} |


### prisma-access-get-security-rule-by-name
***
Get a security rule using the name.


#### Base Command

`prisma-access-get-security-rule-by-name`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the security rule to search. | Required | 
| folder | Prisma access folder location for the rule. | Required | 
| position | Rule position. Possible values are: pre, post. | Required | 
| tsg_id | Tenant services group ID. If not provided, the tsg_id integration parameter will be used as the default. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAccess.FoundSecurityRule | unknown | Found security rule. | 
| PrismaAccess.FoundSecurityRule.action | String | Security rule action. | 
| PrismaAccess.FoundSecurityRule.application | String | Security rule application. | 
| PrismaAccess.FoundSecurityRule.category | String | Security rule category. | 
| PrismaAccess.FoundSecurityRule.description | String | Security rule description. | 
| PrismaAccess.FoundSecurityRule.destination | String | Security rule destination. | 
| PrismaAccess.FoundSecurityRule.folder | String | Security rule folder. | 
| PrismaAccess.FoundSecurityRule.from | String | Security rule from field \(source zone\(s\)\). | 
| PrismaAccess.FoundSecurityRule.id | String | Security rule ID. | 
| PrismaAccess.FoundSecurityRule.name | String | Security rule name. | 
| PrismaAccess.FoundSecurityRule.position | String | Security rule position. | 
| PrismaAccess.FoundSecurityRule.profile_setting.group | String | Security rule profile setting. | 
| PrismaAccess.FoundSecurityRule.service | String | Security rule service. | 
| PrismaAccess.FoundSecurityRule.source | String | Security rule source. | 
| PrismaAccess.FoundSecurityRule.source_user | String | Security rule source user. | 
| PrismaAccess.FoundSecurityRule.to | String | Security rule to field \(destination zone\(s\)\). | 

#### Command example
```!prisma-access-get-security-rule-by-name folder="Shared" name="new-test-rule B" position="pre"```
#### Context Example
```json
{
    "PrismaAccess": {
        "FoundSecurityRule": {
            "action": "deny",
            "application": [
                "any"
            ],
            "category": [
                "any"
            ],
            "description": "Test Rule Created by XSOAR",
            "destination": [
                "XSOAR Test Object A"
            ],
            "folder": "Shared",
            "from": [
                "trust"
            ],
            "id": "########-####-####-####-############",
            "name": "new-test-rule B",
            "position": "pre",
            "profile_setting": {
                "group": [
                    "best-practice"
                ]
            },
            "service": [
                "application-default"
            ],
            "source": [
                "XSOAR Test Object A"
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

>### Security Rules
>|action|application|category|description|destination|folder|from|id|name|position|profile_setting|service|source|source_user|to|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| deny | any | any | Test Rule Created by XSOAR | XSOAR Test Object A | Shared | trust | ########-####-####-####-############ | new-test-rule B | pre | group: best-practice | application-default | XSOAR Test Object A | any | any |


### prisma-access-get-config-jobs-by-id
***
Get a specific configuration job by the job ID.


#### Base Command

`prisma-access-get-config-jobs-by-id`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | A comma-separated list of job IDs. | Required | 
| tsg_id | Tenant services group ID. If not provided, the tsg_id integration parameter will be used as the default. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAccess.ConfigJob | unknown | Configuration job details. | 
| PrismaAccess.ConfigJob.details | String | Config job details. | 
| PrismaAccess.ConfigJob.end_ts | Date | Configuration job end timestamp. | 
| PrismaAccess.ConfigJob.id | String | Configuration job ID. | 
| PrismaAccess.ConfigJob.insert_ts | Date | Configuration job insert timestamp. | 
| PrismaAccess.ConfigJob.job_result | String | Configuration job result. | 
| PrismaAccess.ConfigJob.job_status | String | Configuration job status. | 
| PrismaAccess.ConfigJob.job_type | String | Configuration job type. | 
| PrismaAccess.ConfigJob.last_update | Date | Configuration job last update. | 
| PrismaAccess.ConfigJob.opaque_int | String | Configuration job opaque integer. | 
| PrismaAccess.ConfigJob.opaque_str | String | Configuration job opaque string. | 
| PrismaAccess.ConfigJob.owner | String | Configuration job owner. | 
| PrismaAccess.ConfigJob.parent_id | String | Configuration job parent ID. | 
| PrismaAccess.ConfigJob.percent | String | Configuration job percent. | 
| PrismaAccess.ConfigJob.result_i | String | Configuration job result integer. | 
| PrismaAccess.ConfigJob.result_str | String | Configuration job string. | 
| PrismaAccess.ConfigJob.session_id | String | Configuration job session ID. | 
| PrismaAccess.ConfigJob.start_ts | Date | Configuration job start timestamp. | 
| PrismaAccess.ConfigJob.status_i | String | Config job status integer. | 
| PrismaAccess.ConfigJob.status_str | String | Configuration job status string. | 
| PrismaAccess.ConfigJob.summary | String | Configuration job summary. | 
| PrismaAccess.ConfigJob.type_i | String | Configuration job type integer. | 
| PrismaAccess.ConfigJob.type_str | String | Configuration job type string. | 
| PrismaAccess.ConfigJob.uname | String | Configuration job uname. | 

#### Command example
```!prisma-access-get-config-jobs-by-id id=21```
#### Context Example
```json
{
    "PrismaAccess": {
        "ConfigJob": {
            "details": "{\"info\":[\"Configuration committed successfully\"],\"errors\":[],\"warnings\":[],\"description\":\"Test Push from XSOAR\"}",
            "end_ts": "2022-09-30 05:03:30",
            "id": "21",
            "insert_ts": "2022-09-30 05:02:41",
            "job_result": "2",
            "job_status": "2",
            "job_type": "53",
            "last_update": "2022-09-30 05:03:33",
            "opaque_int": "0",
            "opaque_str": "",
            "owner": "cfgserv",
            "parent_id": "0",
            "percent": "100",
            "result_i": "2",
            "result_str": "OK",
            "session_id": "",
            "start_ts": "2022-09-30 05:02:41",
            "status_i": "2",
            "status_str": "FIN",
            "summary": "",
            "type_i": "53",
            "type_str": "CommitAndPush",
            "uname": "user@example.com"
        }
    }
}
```

#### Human Readable Output

>### Config Jobs
>|Id|Type Str|
>|---|---|
>| 21 | CommitAndPush |


### prisma-access-list-config-jobs
***
List configuration jobs.


#### Base Command

`prisma-access-list-config-jobs`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| tsg_id | Tenant services group ID. If not provided, the tsg_id integration parameter will be used as the default. | Optional | 
| limit | The maximum number of results to return. Default is 200. | Optional | 
| offset | Results paging offset. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAccess.ConfigJob | unknown | Configuration job details. | 
| PrismaAccess.ConfigJob.description | String | Configuration job description. | 
| PrismaAccess.ConfigJob.end_ts | Date | Configuration job end timestamp. | 
| PrismaAccess.ConfigJob.id | String | Configuration job ID. | 
| PrismaAccess.ConfigJob.job_result | String | Configuration job result. | 
| PrismaAccess.ConfigJob.job_status | String | Configuration job status. | 
| PrismaAccess.ConfigJob.job_type | String | Configuration job type. | 
| PrismaAccess.ConfigJob.parent_id | String | Configuration job parent ID. | 
| PrismaAccess.ConfigJob.percent | String | Configuration job percent. | 
| PrismaAccess.ConfigJob.result_str | String | Configuration job result string. | 
| PrismaAccess.ConfigJob.start_ts | Date | Configuration job start timestamp. | 
| PrismaAccess.ConfigJob.status_str | String | Configuration job status string. | 
| PrismaAccess.ConfigJob.summary | String | Configuration job summary. | 
| PrismaAccess.ConfigJob.type_str | String | Configuration job type string. | 
| PrismaAccess.ConfigJob.uname | String | Configuration job uname. | 

#### Command example
```!prisma-access-list-config-jobs limit=5```
#### Context Example
```json
{
    "PrismaAccess": {
        "ConfigJob": [
            {
                "description": "Mobile Users Global Protect configuration pushed to cloud",
                "end_ts": "2022-11-29 19:36:12",
                "id": "57",
                "job_result": "2",
                "job_status": "2",
                "job_type": "22",
                "parent_id": "56",
                "percent": "100",
                "result_str": "OK",
                "start_ts": "2022-11-29 19:32:40",
                "status_str": "FIN",
                "summary": "Configuration push finished",
                "type_str": "CommitAll",
                "uname": "user@example.com"
            },
            {
                "description": "",
                "end_ts": "2022-11-29 19:32:40",
                "id": "56",
                "job_result": "2",
                "job_status": "2",
                "job_type": "53",
                "parent_id": "0",
                "percent": "100",
                "result_str": "OK",
                "start_ts": "2022-11-29 19:31:31",
                "status_str": "FIN",
                "summary": "",
                "type_str": "CommitAndPush",
                "uname": "user@example.com"
            },
            {
                "description": "Service Connections configuration pushed to cloud",
                "end_ts": "2022-11-23 16:00:56",
                "id": "55",
                "job_result": "2",
                "job_status": "2",
                "job_type": "22",
                "parent_id": "54",
                "percent": "100",
                "result_str": "OK",
                "start_ts": "2022-11-23 15:59:34",
                "status_str": "FIN",
                "summary": "Configuration push finished",
                "type_str": "CommitAll",
                "uname": "user@example.com"
            },
            {
                "description": "",
                "end_ts": "2022-11-23 15:59:35",
                "id": "54",
                "job_result": "2",
                "job_status": "2",
                "job_type": "53",
                "parent_id": "0",
                "percent": "100",
                "result_str": "OK",
                "start_ts": "2022-11-23 15:58:26",
                "status_str": "FIN",
                "summary": "",
                "type_str": "CommitAndPush",
                "uname": "user@example.com"
            },
            {
                "description": "Service Connections configuration pushed to cloud",
                "end_ts": "2022-11-23 15:50:43",
                "id": "53",
                "job_result": "1",
                "job_status": "2",
                "job_type": "22",
                "parent_id": "52",
                "percent": "100",
                "result_str": "FAIL",
                "start_ts": "2022-11-23 14:55:28",
                "status_str": "FIN",
                "summary": "Configuration push failed",
                "type_str": "CommitAll",
                "uname": "user@example.com"
            }
        ]
    }
}
```

#### Human Readable Output

>### Config Job
>|Id|Type Str|Description|Summary|
>|---|---|---|---|
>| 57 | CommitAll | Mobile Users Global Protect configuration pushed to cloud | Configuration push finished |
>| 56 | CommitAndPush |  |  |
>| 55 | CommitAll | Service Connections configuration pushed to cloud | Configuration push finished |
>| 54 | CommitAndPush |  |  |
>| 53 | CommitAll | Service Connections configuration pushed to cloud | Configuration push failed |


### prisma-access-delete-security-rule
***
Delete a security rule.


#### Base Command

`prisma-access-delete-security-rule`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_id | Rule ID of the rule to be deleted. | Required | 
| tsg_id | Tenant services group ID. If not provided, the tsg_id integration parameter will be used as the default. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAccess.DeletedSecurityRule | unknown | Deleted security rule info. | 
| PrismaAccess.DeletedSecurityRule.action | String | Security rule action. | 
| PrismaAccess.DeletedSecurityRule.application | String | Security rule application. | 
| PrismaAccess.DeletedSecurityRule.category | String | Security rule category. | 
| PrismaAccess.DeletedSecurityRule.description | String | Security rule description. | 
| PrismaAccess.DeletedSecurityRule.destination | String | Security rule destination. | 
| PrismaAccess.DeletedSecurityRule.folder | String | Security rule folder. | 
| PrismaAccess.DeletedSecurityRule.from | String | Security rule from field \(source zone\(s\)\). | 
| PrismaAccess.DeletedSecurityRule.id | String | Security rule ID. | 
| PrismaAccess.DeletedSecurityRule.name | String | Security rule name. | 
| PrismaAccess.DeletedSecurityRule.profile_setting.group | String | Security rule profile setting. | 
| PrismaAccess.DeletedSecurityRule.service | String | Security rule service. | 
| PrismaAccess.DeletedSecurityRule.source | String | Security rule source. | 
| PrismaAccess.DeletedSecurityRule.source_user | String | Security rule source user. | 
| PrismaAccess.DeletedSecurityRule.to | String | Security rule to field \(destination zone\(s\)\). | 

#### Command example
```!prisma-access-delete-security-rule rule_id="########-####-####-####-############"```
#### Context Example
```json
{
    "PrismaAccess": {
        "DeletedSecurityRule": {
            "action": "deny",
            "application": [
                "any"
            ],
            "category": [
                "any"
            ],
            "description": "Rule Edited by XSOAR",
            "destination": [
                "XSOAR Test Object A"
            ],
            "folder": "Shared",
            "from": [
                "trust"
            ],
            "id": "########-####-####-####-############",
            "name": "new-test-rule A",
            "profile_setting": {
                "group": [
                    "best-practice"
                ]
            },
            "service": [
                "application-default"
            ],
            "source": [
                "XSOAR Test Object A"
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

>### Security Rule Deleted
>|Action|Application|Category|Description|Destination|Folder|From|Id|Name|Profile Setting|Service|Source|Source User|To|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| deny | any | any | Rule Edited by XSOAR | XSOAR Test Object A | Shared | trust | ########-####-####-####-############ | new-test-rule A | group: best-practice | application-default | XSOAR Test Object A | any | any |


### prisma-access-create-address-object
***
Create a new address object


#### Base Command

`prisma-access-create-address-object`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| folder | Prisma Access Folder Location for the Object. | Required | 
| tsg_id | Tenant services group ID. If not provided, the tsg_id integration parameter will be used as the default. | Optional | 
| name | Friendly name of the address object. | Required | 
| description | Address object description. | Optional | 
| ip_netmask | IP/Netmask of the object using slash notation. | Required | 
| tag | A comma-separated list of address object tags. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAccess.CreatedAddressObject | unknown | Created address object. | 
| PrismaAccess.CreatedAddress.description | String | Address description. | 
| PrismaAccess.CreatedAddress.folder | String | Address folder. | 
| PrismaAccess.CreatedAddress.id | String | Address ID. | 
| PrismaAccess.CreatedAddress.ip_netmask | String | Address IP netmask. | 
| PrismaAccess.CreatedAddress.name | String | Address name. | 

#### Command example
```!prisma-access-create-address-object folder="Shared" ip_netmask="1.1.1.1/32" name="XSOAR Test Object A" description="Test Object Creation from XSOAR"```
#### Context Example
```json
{
    "PrismaAccess": {
        "CreatedAddress": {
            "description": "Test Object Creation from XSOAR",
            "folder": "Shared",
            "id": "########-####-####-####-############",
            "ip_netmask": "1.1.1.1/32",
            "name": "XSOAR Test Object A"
        }
    }
}
```

#### Human Readable Output

>### Address Object Created
>|Description|Folder|Id|Ip Netmask|Name|
>|---|---|---|---|---|
>| Test Object Creation from XSOAR | Shared | ########-####-####-####-############ | 1.1.1.1/32 | XSOAR Test Object A |


### prisma-access-edit-address-object
***
Edit address object


#### Base Command

`prisma-access-edit-address-object`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID of the address object to edit. | Required | 
| tsg_id | Tenant services group ID. If not provided, the tsg_id integration parameter will be used as the default. | Optional | 
| name | Friendly name of the address object. | Required | 
| description | Address Object description. | Optional | 
| ip_netmask | IP/Netmask of the object using slash notation. | Required | 
| tag | A comma-separated list of address object tags. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAccess.EditedAddressObject | unknown | Edited address object. | 
| PrismaAccess.EditedAddress.description | String | Address description. | 
| PrismaAccess.EditedAddress.folder | String | Address folder. | 
| PrismaAccess.EditedAddress.id | String | Address ID. | 
| PrismaAccess.EditedAddress.ip_netmask | String | Address IP netmask. | 
| PrismaAccess.EditedAddress.name | String | Address name. | 

#### Command example
```!prisma-access-edit-address-object id="########-####-####-####-############" ip_netmask="1.1.1.11/32" name="XSOAR Test Object B" description="XSOAR edited object"```
#### Context Example
```json
{
    "PrismaAccess": {
        "EditedAddress": {
            "description": "XSOAR edited object",
            "folder": "Shared",
            "id": "########-####-####-####-############",
            "ip_netmask": "1.1.1.11/32",
            "name": "XSOAR Test Object B"
        }
    }
}
```

#### Human Readable Output

>### Address Object Edited
>|Description|Folder|Id|Ip Netmask|Name|
>|---|---|---|---|---|
>| XSOAR edited object | Shared | ########-####-####-####-############ | 1.1.1.11/32 | XSOAR Test Object B |


### prisma-access-delete-address-object
***
Delete address object


#### Base Command

`prisma-access-delete-address-object`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID of the address object to delete. | Required | 
| tsg_id | Tenant services group ID. If not provided, the tsg_id integration parameter will be used as the default. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAccess.DeletedAddressObject | unknown | Deleted address object. | 
| PrismaAccess.DeletedAddress.description | String | Deleted address description. | 
| PrismaAccess.DeletedAddress.folder | String | Deleted address folder. | 
| PrismaAccess.DeletedAddress.id | String | Deleted address ID. | 
| PrismaAccess.DeletedAddress.ip_netmask | String | Deleted address IP netmask. | 
| PrismaAccess.DeletedAddress.name | String | Deleted address name. | 

#### Command example
```!prisma-access-delete-address-object id="########-####-####-####-############"```
#### Context Example
```json
{
    "PrismaAccess": {
        "DeletedAddress": {
            "description": "XSOAR edited object",
            "folder": "Shared",
            "id": "########-####-####-####-############",
            "ip_netmask": "1.1.1.11/32",
            "name": "XSOAR Test Object B"
        }
    }
}
```

#### Human Readable Output

>### Address Object Deleted
>|Description|Folder|Id|Ip Netmask|Name|
>|---|---|---|---|---|
>| XSOAR edited object | Shared | ########-####-####-####-############ | 1.1.1.11/32 | XSOAR Test Object B |


### prisma-access-list-address-objects
***
List address objects.


#### Base Command

`prisma-access-list-address-objects`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| folder | Prisma access folder location for the object. | Required | 
| name | Name of the security object. | Optional | 
| limit | The maximum number of results to return. Default is 10. | Optional | 
| offset | Results paging offset. | Optional | 
| tsg_id | Tenant services group ID. If not provided, the tsg_id integration parameter will be used as the default. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAccess.FoundSecurityRule | unknown | Found security rule. | 
| PrismaAccess.FoundAddressObjects.description | String | Address description. | 
| PrismaAccess.FoundAddressObjects.folder | String | Address folder. | 
| PrismaAccess.FoundAddressObjects.fqdn | String | Address FQDN. | 
| PrismaAccess.FoundAddressObjects.id | String | Address ID. | 
| PrismaAccess.FoundAddressObjects.name | String | Address name. | 
| PrismaAccess.FoundAddressObjects.ip_netmask | String | Address IP netmask. | 

#### Command example
```!prisma-access-list-address-objects folder="Shared"```
#### Context Example
```json
{
    "PrismaAccess": {
        "FoundAddressObjects": [
            {
                "description": "Palo Alto Networks sinkhole",
                "folder": "Shared",
                "fqdn": "sinkhole.paloaltonetworks.com",
                "id": "########-####-####-####-############",
                "name": "Palo Alto Networks Sinkhole"
            },
            {
                "folder": "Shared",
                "id": "########-####-####-####-############",
                "ip_netmask": "1.1.1.1/16",
                "name": "GP-Users"
            },
            {
                "description": "Test Object Creation from XSOAR",
                "folder": "Shared",
                "id": "########-####-####-####-############",
                "ip_netmask": "1.1.1.1/32",
                "name": "XSOAR Test Object B"
            }
        ]
    }
}
```

#### Human Readable Output

>### Address Objects
>|Name|Description|Ip Netmask|Fqdn|
>|---|---|---|---|
>| Palo Alto Networks Sinkhole | Palo Alto Networks sinkhole |  | sinkhole.paloaltonetworks.com |
>| GP-Users |  | 1.1.1.1/16 |  |
>| XSOAR Test Object B | Test Object Creation from XSOAR | 1.1.1.1/32 |  |

