Beta integration that provides commands for interaction with Prisma SASE API.
This integration was integrated and tested with version 1.0 of Prisma SASE API.

## Configure Prisma SASE (Beta) on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Prisma SASE (Beta).
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | API Gateway URL |  | True |
    | API Client ID |  | True |
    | API Client Secret |  | True |
    | Use system proxy settings |  | False |
    | Default Tenant Services Group ID to use for API calls. |  | False |
    | Prisma API OAUTH URL | URL that will be used to obtain OAUTH2 access token. | False |
    | Trust any certificate (not secure) |  | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### prisma-access-create-security-rule
***
Create a new security rule


#### Base Command

`prisma-access-create-security-rule`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| folder | Prisma Access Folder Location for the Rule. | Required | 
| position | Rule position (pre or post). Possible values are: pre, post. | Required | 
| tsg_id | Tenant services group ID. | Optional | 
| name | Friendly Name of the Rule. | Required | 
| action | Rule action. | Required | 
| description | Rule description. | Optional | 
| log_setting | Rule log setting. | Optional | 
| application | Application(s).  Use , as a delimiter for multiple applications. | Required | 
| category | Category(s).  Use , as a delimiter for multiple categories. | Required | 
| destination | Destination network(s).  Use , as a delimiter for multiple networks. | Required | 
| destination_hip | Destination HIP(s).  Use , as a delimiter for multiple HIPs. | Optional | 
| profile_setting | Security profiles to apply to traffic. | Optional | 
| service | Services the rule applies to. | Required | 
| source | Source network(s).  Use , as a delimiter for multiple networks. | Required | 
| source_hip | Source HIP(s).  Use , as a delimiter for multiple HIPs. | Optional | 
| source_user | Source user(s).  Use ; as a delimeter for multiple users or groups. | Required | 
| tag | Rule tag(s).  Use , as a delimiter for multiple tags. | Optional | 
| from | Source zone(s).  Use , as a delimiter for multiple zones. | Required | 
| to | Destination zone(s).  Use , as a delimiter for multiple zones. | Required | 
| disabled | Rule disabled?. | Optional | 
| negate_source | Negate source. | Optional | 
| negate_destination | Negate destination. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAccess.CreatedSecurityRule | unknown | Created security rule | 
| PrismaAccess.CreatedSecurityRule.action | String |  | 
| PrismaAccess.CreatedSecurityRule.application | String |  | 
| PrismaAccess.CreatedSecurityRule.category | String |  | 
| PrismaAccess.CreatedSecurityRule.description | String |  | 
| PrismaAccess.CreatedSecurityRule.destination | String |  | 
| PrismaAccess.CreatedSecurityRule.folder | String |  | 
| PrismaAccess.CreatedSecurityRule.from | String |  | 
| PrismaAccess.CreatedSecurityRule.id | String |  | 
| PrismaAccess.CreatedSecurityRule.name | String |  | 
| PrismaAccess.CreatedSecurityRule.position | String |  | 
| PrismaAccess.CreatedSecurityRule.profile_setting.group | String |  | 
| PrismaAccess.CreatedSecurityRule.service | String |  | 
| PrismaAccess.CreatedSecurityRule.source | String |  | 
| PrismaAccess.CreatedSecurityRule.source_user | String |  | 
| PrismaAccess.CreatedSecurityRule.to | String |  | 

#### Command example
```!prisma-access-create-security-rule name="new-test-ruleB" action="deny" description="Test Rule Created by XSOAR" application="any" category="any" destination="XSOAR Test Object B" profile_setting="best-practice" service="application-default" source="XSOAR Test Object B" source_user="any" from="trust" to="any" folder="Shared" position="pre"```
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
                "XSOAR Test Object B"
            ],
            "folder": "Shared",
            "from": [
                "trust"
            ],
            "id": "c680####-7d34-4c##-8b##-375baade####",
            "name": "new-test-ruleB",
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
                "XSOAR Test Object B"
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
>|action|application|category|description|destination|folder|from|id|name|position|profile_setting|service|source|source_user|to|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| deny | any | any | Test Rule Created by XSOAR | XSOAR Test Object B | Shared | trust | c680####-7d34-4c##-8b##-375baade#### | new-test-ruleB | pre | group: best-practice | application-default | XSOAR Test Object B | any | any |


### prisma-access-list-security-rules
***
List security rules


#### Base Command

`prisma-access-list-security-rules`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| folder | Prisma Access Folder Location for the Rule. | Required | 
| position | Security rule position (pre, post). Possible values are: pre, post. | Required | 
| name | name of the security rule. | Optional | 
| limit | Results paging limit. Default is 10. | Optional | 
| offset | Results paging offset. | Optional | 
| tsg_id | Tenant services group ID. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAccess.FoundSecurityRule | unknown | Found security rule | 
| PrismaAccess.FoundSecurityRule.action | String |  | 
| PrismaAccess.FoundSecurityRule.application | String |  | 
| PrismaAccess.FoundSecurityRule.category | String |  | 
| PrismaAccess.FoundSecurityRule.description | String |  | 
| PrismaAccess.FoundSecurityRule.destination | String |  | 
| PrismaAccess.FoundSecurityRule.folder | String |  | 
| PrismaAccess.FoundSecurityRule.from | String |  | 
| PrismaAccess.FoundSecurityRule.id | String |  | 
| PrismaAccess.FoundSecurityRule.log_setting | String |  | 
| PrismaAccess.FoundSecurityRule.name | String |  | 
| PrismaAccess.FoundSecurityRule.position | String |  | 
| PrismaAccess.FoundSecurityRule.service | String |  | 
| PrismaAccess.FoundSecurityRule.source | String |  | 
| PrismaAccess.FoundSecurityRule.source_user | String |  | 
| PrismaAccess.FoundSecurityRule.tag | String |  | 
| PrismaAccess.FoundSecurityRule.to | String |  | 
| PrismaAccess.FoundSecurityRule.negate_destination | Boolean |  | 

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
                "id": "c680####-7d34-4c##-8b##-375baade####",
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
                "id": "c680####-7d34-4c##-8b##-375baade####",
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
                "id": "c680####-7d34-4c##-8b##-375baade####",
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
                "id": "c680####-7d34-4c##-8b##-375baade####",
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
                "id": "c680####-7d34-4c##-8b##-375baade####",
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
>|id|name|description|action|destination|folder|
>|---|---|---|---|---|---|
>| 5a5b3aff-8aec-4a90-9d77-a7a85d1681e8 | Drop Traffic to Known Malicious IP Addresses | Rule to block traffic to well known malicious IP addresses, as provided by dynamic feeds from Palo Alto Networks threat intel | drop | panw-known-ip-list | Shared |
>| 22b18d2f-a6cc-45de-a15a-978df14dc2a5 | Drop Traffic to Potential High Risk IP Addresses | Rule to block traffic to IP addresses that have recently been featured in threat activity advisories distributed by high-trust organizations | drop | panw-highrisk-ip-list | Shared |
>| 94487223-d185-424f-8a3d-31a9f8bc92af | Drop Traffic to Bulletproof hosting providers | Rule to block traffic to bulletproof IP addresses as bulletproof hosting providers place few, if any, restrictions on content and attackers can use these services to host and distribute malicious, illegal, and unethical material | drop | panw-bulletproof-ip-list | Shared |
>| 55eefe85-ccca-4341-a77d-d5083dd88987 | Drop Traffic from Known Malicious IP Addresses | Rule to block traffic from well known malicious IP addresses, as provided by dynamic feeds from Palo Alto Networks threat intel | drop | any | Shared |
>| 9aa5d7be-4823-40bc-9b3f-0e857f3c0261 | Drop Traffic from Potential High Risk IP Addresses | Rule to block traffic from IP addresses that have recently been featured in threat activity advisories distributed by high-trust organizations | drop | any | Shared |


### prisma-access-push-candidate-config
***
Push the candidate configuration


#### Base Command

`prisma-access-push-candidate-config`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| folders | Comma separated list of targets (Remote Networks, Mobile Users, Service Connections). | Required | 
| description | Config Push Job Description. | Optional | 
| tsg_id | Tenant services group ID. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAccess.ConfigPush | unknown | Config Job info | 
| PrismaAccess.ConfigPush.job_id | String |  | 
| PrismaAccess.ConfigPush.message | String |  | 
| PrismaAccess.ConfigPush.success | Boolean |  | 

#### Command example
```!prisma-access-push-candidate-config folders="Mobile Users"```
#### Context Example
```json
{
    "PrismaAccess": {
        "ConfigPush": {
            "job_id": "29",
            "message": "CommitAndPush job enqueued with jobid 29",
            "success": true
        }
    }
}
```

#### Human Readable Output

>### Configuration Push Requested
>|job_id|message|success|
>|---|---|---|
>| 29 | CommitAndPush job enqueued with jobid 29 | true |


### prisma-access-edit-security-rule
***
Edit or edit existing security rule


#### Base Command

`prisma-access-edit-security-rule`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID of the rule to be changed. | Required | 
| tsg_id | Tenant services group ID. | Optional | 
| name | Friendly Name of the Rule. | Required | 
| action | Rule action. | Required | 
| description | Rule description. | Optional | 
| log_setting | Rule log setting. | Optional | 
| application | Application(s).  Use , as a delimiter for multiple applications. | Required | 
| category | Category(s).  Use , as a delimiter for multiple categories. | Required | 
| destination | Destination network(s).  Use , as a delimiter for multiple networks. | Required | 
| destination_hip | Destination HIP(s).  Use , as a delimiter for multiple HIPs. | Optional | 
| profile_setting | Security profiles to apply to traffic. | Optional | 
| service | Services the rule applies to. | Required | 
| source | Source network(s).  Use , as a delimiter for multiple networks. | Required | 
| source_hip | Source HIP(s).  Use , as a delimiter for multiple HIPs. | Optional | 
| source_user | Source user(s).  Use ; as a delimeter for multiple users or groups. | Required | 
| tag | Rule tag(s).  Use , as a delimiter for multiple tags. | Optional | 
| from | Source zone(s).  Use , as a delimiter for multiple zones. | Required | 
| to | Destination zone(s).  Use , as a delimiter for multiple zones. | Required | 
| disabled | Rule disabled?. | Optional | 
| negate_source | Negate source. | Optional | 
| negate_destination | Negate destination. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAccess.EditedSecurityRule | unknown | Edited security rule | 
| PrismaAccess.UpdatedSecurityRule.action | String |  | 
| PrismaAccess.UpdatedSecurityRule.application | String |  | 
| PrismaAccess.UpdatedSecurityRule.category | String |  | 
| PrismaAccess.UpdatedSecurityRule.description | String |  | 
| PrismaAccess.UpdatedSecurityRule.destination | String |  | 
| PrismaAccess.UpdatedSecurityRule.folder | String |  | 
| PrismaAccess.UpdatedSecurityRule.from | String |  | 
| PrismaAccess.UpdatedSecurityRule.id | String |  | 
| PrismaAccess.UpdatedSecurityRule.name | String |  | 
| PrismaAccess.UpdatedSecurityRule.profile_setting.group | String |  | 
| PrismaAccess.UpdatedSecurityRule.service | String |  | 
| PrismaAccess.UpdatedSecurityRule.source | String |  | 
| PrismaAccess.UpdatedSecurityRule.source_user | String |  | 
| PrismaAccess.UpdatedSecurityRule.to | String |  | 

#### Command example
```!prisma-access-edit-security-rule id="c680####-7d34-4c##-8b##-375baade####" name="new-test-rule" action="deny" description="Rule Edited by XSOAR" application="any" category="any" destination="XSOAR Test Object B" profile_setting="best-practice" service="application-default" source="XSOAR Test Object B" source_user="any" from="trust" to="any"```
#### Context Example
```json
{
    "PrismaAccess": {
        "UpdatedSecurityRule": {
            "action": "deny",
            "application": [
                "any"
            ],
            "category": [
                "any"
            ],
            "description": "Rule Edited by XSOAR",
            "destination": [
                "XSOAR Test Object B"
            ],
            "folder": "Shared",
            "from": [
                "trust"
            ],
            "id": "c680####-7d34-4c##-8b##-375baade####",
            "name": "new-test-rule",
            "profile_setting": {
                "group": [
                    "best-practice"
                ]
            },
            "service": [
                "application-default"
            ],
            "source": [
                "XSOAR Test Object B"
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
>|action|application|category|description|destination|folder|from|id|name|profile_setting|service|source|source_user|to|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| deny | any | any | Rule Edited by XSOAR | XSOAR Test Object B | Shared | trust | c680####-7d34-4c##-8b##-375baade#### | new-test-rule | group: best-practice | application-default | XSOAR Test Object B | any | any |


### prisma-sase-query-agg-monitor-api
***
Query the aggregate monitor API


#### Base Command

`prisma-sase-query-agg-monitor-api`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| tsg_id | Tenant services group ID. | Optional | 
| query_data | Query data. | Optional | 
| uri | Aggregate Monitor URI to query (for example: mt/monitor/v1/agg/threats). | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaSASE.AggregateQueryResponse | unknown | Aggregate Query Response | 
| PrismaSASE.AggregateQueryResponse.header.dataCount | Number |  | 

### prisma-access-get-security-rule-by-name
***
Get a security rule using the name


#### Base Command

`prisma-access-get-security-rule-by-name`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of security rule to search . | Required | 
| folder | Prisma Access Folder Location for the Rule. | Required | 
| position | Rule position (pre, post). Possible values are: pre, post. | Required | 
| tsg_id | Tenant services group ID. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAccess.FoundSecurityRule | unknown | Found security rule | 
| PrismaAccess.FoundSecurityRule.action | String |  | 
| PrismaAccess.FoundSecurityRule.application | String |  | 
| PrismaAccess.FoundSecurityRule.category | String |  | 
| PrismaAccess.FoundSecurityRule.description | String |  | 
| PrismaAccess.FoundSecurityRule.destination | String |  | 
| PrismaAccess.FoundSecurityRule.folder | String |  | 
| PrismaAccess.FoundSecurityRule.from | String |  | 
| PrismaAccess.FoundSecurityRule.id | String |  | 
| PrismaAccess.FoundSecurityRule.name | String |  | 
| PrismaAccess.FoundSecurityRule.position | String |  | 
| PrismaAccess.FoundSecurityRule.profile_setting.group | String |  | 
| PrismaAccess.FoundSecurityRule.service | String |  | 
| PrismaAccess.FoundSecurityRule.source | String |  | 
| PrismaAccess.FoundSecurityRule.source_user | String |  | 
| PrismaAccess.FoundSecurityRule.to | String |  | 

#### Command example
```!prisma-access-get-security-rule-by-name folder="Shared" name="new-test-ruleB" position="pre"```
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
                "XSOAR Test Object B"
            ],
            "folder": "Shared",
            "from": [
                "trust"
            ],
            "id": "c680####-7d34-4c##-8b##-375baade####",
            "name": "new-test-ruleB",
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
                "XSOAR Test Object B"
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
>| deny | any | any | Test Rule Created by XSOAR | XSOAR Test Object B | Shared | trust | c680####-7d34-4c##-8b##-375baade#### | new-test-ruleB | pre | group: best-practice | application-default | XSOAR Test Object B | any | any |


### prisma-access-get-config-jobs-by-id
***
Get specific config job by the jobid


#### Base Command

`prisma-access-get-config-jobs-by-id`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Comma separated list of Job IDs. | Required | 
| tsg_id | Tenant services group ID. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAccess.ConfigJob | unknown | Config job details | 
| PrismaAccess.ConfigJob.details | String |  | 
| PrismaAccess.ConfigJob.end_ts | Date |  | 
| PrismaAccess.ConfigJob.id | String |  | 
| PrismaAccess.ConfigJob.insert_ts | Date |  | 
| PrismaAccess.ConfigJob.job_result | String |  | 
| PrismaAccess.ConfigJob.job_status | String |  | 
| PrismaAccess.ConfigJob.job_type | String |  | 
| PrismaAccess.ConfigJob.last_update | Date |  | 
| PrismaAccess.ConfigJob.opaque_int | String |  | 
| PrismaAccess.ConfigJob.opaque_str | String |  | 
| PrismaAccess.ConfigJob.owner | String |  | 
| PrismaAccess.ConfigJob.parent_id | String |  | 
| PrismaAccess.ConfigJob.percent | String |  | 
| PrismaAccess.ConfigJob.result_i | String |  | 
| PrismaAccess.ConfigJob.result_str | String |  | 
| PrismaAccess.ConfigJob.session_id | String |  | 
| PrismaAccess.ConfigJob.start_ts | Date |  | 
| PrismaAccess.ConfigJob.status_i | String |  | 
| PrismaAccess.ConfigJob.status_str | String |  | 
| PrismaAccess.ConfigJob.summary | String |  | 
| PrismaAccess.ConfigJob.type_i | String |  | 
| PrismaAccess.ConfigJob.type_str | String |  | 
| PrismaAccess.ConfigJob.uname | String |  | 

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
>|id|type_str|
>|---|---|
>| 21 | CommitAndPush |


### prisma-access-list-config-jobs
***
List config jobs


#### Base Command

`prisma-access-list-config-jobs`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| tsg_id | Tenant services group ID. | Optional | 
| limit | Query limit. Default is 200. | Optional | 
| offset | Query offset. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAccess.ConfigJob | unknown | Config job details | 
| PrismaAccess.ConfigJob.description | String |  | 
| PrismaAccess.ConfigJob.end_ts | Date |  | 
| PrismaAccess.ConfigJob.id | String |  | 
| PrismaAccess.ConfigJob.job_result | String |  | 
| PrismaAccess.ConfigJob.job_status | String |  | 
| PrismaAccess.ConfigJob.job_type | String |  | 
| PrismaAccess.ConfigJob.parent_id | String |  | 
| PrismaAccess.ConfigJob.percent | String |  | 
| PrismaAccess.ConfigJob.result_str | String |  | 
| PrismaAccess.ConfigJob.start_ts | Date |  | 
| PrismaAccess.ConfigJob.status_str | String |  | 
| PrismaAccess.ConfigJob.summary | String |  | 
| PrismaAccess.ConfigJob.type_str | String |  | 
| PrismaAccess.ConfigJob.uname | String |  | 

#### Command example
```!prisma-access-list-config-jobs limit=5```
#### Context Example
```json
{
    "PrismaAccess": {
        "ConfigJob": [
            {
                "description": "Mobile Users Global Protect configuration pushed to cloud",
                "end_ts": "2022-10-20 18:02:00",
                "id": "28",
                "job_result": "1",
                "job_status": "2",
                "job_type": "22",
                "parent_id": "27",
                "percent": "100",
                "result_str": "FAIL",
                "start_ts": "2022-10-20 18:00:24",
                "status_str": "FIN",
                "summary": "Configuration push failed",
                "type_str": "CommitAll",
                "uname": "user@example.com"
            },
            {
                "description": "",
                "end_ts": "2022-10-20 18:00:19",
                "id": "27",
                "job_result": "2",
                "job_status": "2",
                "job_type": "53",
                "parent_id": "0",
                "percent": "100",
                "result_str": "OK",
                "start_ts": "2022-10-20 17:57:06",
                "status_str": "FIN",
                "summary": "",
                "type_str": "CommitAndPush",
                "uname": "user@example.com"
            },
            {
                "description": "Mobile Users Global Protect configuration pushed to cloud",
                "end_ts": "2022-10-19 20:09:38",
                "id": "26",
                "job_result": "1",
                "job_status": "2",
                "job_type": "22",
                "parent_id": "25",
                "percent": "100",
                "result_str": "FAIL",
                "start_ts": "2022-10-19 20:08:02",
                "status_str": "FIN",
                "summary": "Configuration push failed",
                "type_str": "CommitAll",
                "uname": "user@example.com"
            },
            {
                "description": "",
                "end_ts": "2022-10-19 20:08:01",
                "id": "25",
                "job_result": "2",
                "job_status": "2",
                "job_type": "53",
                "parent_id": "0",
                "percent": "100",
                "result_str": "OK",
                "start_ts": "2022-10-19 20:06:41",
                "status_str": "FIN",
                "summary": "",
                "type_str": "CommitAndPush",
                "uname": "user@example.com"
            },
            {
                "description": "Mobile Users Global Protect configuration pushed to cloud",
                "end_ts": "2022-09-30 05:20:34",
                "id": "24",
                "job_result": "2",
                "job_status": "2",
                "job_type": "22",
                "parent_id": "23",
                "percent": "100",
                "result_str": "OK",
                "start_ts": "2022-09-30 05:16:40",
                "status_str": "FIN",
                "summary": "Configuration push finished",
                "type_str": "CommitAll",
                "uname": "user@example.com"
            }
        ]
    }
}
```

#### Human Readable Output

>### Config Job
>|id|type_str|description|summary|
>|---|---|---|---|
>| 28 | CommitAll | Mobile Users Global Protect configuration pushed to cloud | Configuration push failed |
>| 27 | CommitAndPush |  |  |
>| 26 | CommitAll | Mobile Users Global Protect configuration pushed to cloud | Configuration push failed |
>| 25 | CommitAndPush |  |  |
>| 24 | CommitAll | Mobile Users Global Protect configuration pushed to cloud | Configuration push finished |


### prisma-access-delete-security-rule
***
Delete security rule


#### Base Command

`prisma-access-delete-security-rule`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_id | Rule ID of the rule to be deleted. | Required | 
| tsg_id | Tenant services group ID. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAccess.DeletedSecurityRule | unknown | Deleted security rule info | 
| PrismaAccess.DeletedSecurityRule.action | String |  | 
| PrismaAccess.DeletedSecurityRule.application | String |  | 
| PrismaAccess.DeletedSecurityRule.category | String |  | 
| PrismaAccess.DeletedSecurityRule.description | String |  | 
| PrismaAccess.DeletedSecurityRule.destination | String |  | 
| PrismaAccess.DeletedSecurityRule.folder | String |  | 
| PrismaAccess.DeletedSecurityRule.from | String |  | 
| PrismaAccess.DeletedSecurityRule.id | String |  | 
| PrismaAccess.DeletedSecurityRule.name | String |  | 
| PrismaAccess.DeletedSecurityRule.profile_setting.group | String |  | 
| PrismaAccess.DeletedSecurityRule.service | String |  | 
| PrismaAccess.DeletedSecurityRule.source | String |  | 
| PrismaAccess.DeletedSecurityRule.source_user | String |  | 
| PrismaAccess.DeletedSecurityRule.to | String |  | 

#### Command example
```!prisma-access-delete-security-rule rule_id="c680####-7d34-4c##-8b##-375baade####"```
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
                "XSOAR Test Object B"
            ],
            "folder": "Shared",
            "from": [
                "trust"
            ],
            "id": "c680####-7d34-4c##-8b##-375baade####",
            "name": "new-test-rule",
            "profile_setting": {
                "group": [
                    "best-practice"
                ]
            },
            "service": [
                "application-default"
            ],
            "source": [
                "XSOAR Test Object B"
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
>|action|application|category|description|destination|folder|from|id|name|profile_setting|service|source|source_user|to|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| deny | any | any | Rule Edited by XSOAR | XSOAR Test Object B | Shared | trust | c680####-7d34-4c##-8b##-375baade#### | new-test-rule | group: best-practice | application-default | XSOAR Test Object B | any | any |


### prisma-access-create-address-object
***
Create a new address object


#### Base Command

`prisma-access-create-address-object`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| folder | Prisma Access Folder Location for the Object. | Required | 
| tsg_id | Tenant services group ID. | Optional | 
| name | Friendly Name of the Address Object. | Required | 
| description | Address Object description. | Optional | 
| ip_netmask | IP/Netmask of the Object using the slash notation. | Required | 
| tag | Address Object tag(s).  Use , as a delimiter for multiple tags. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAccess.CreatedAddressObject | unknown | Created Address Object | 
| PrismaAccess.CreatedAddress.description | String |  | 
| PrismaAccess.CreatedAddress.folder | String |  | 
| PrismaAccess.CreatedAddress.id | String |  | 
| PrismaAccess.CreatedAddress.ip_netmask | String |  | 
| PrismaAccess.CreatedAddress.name | String |  | 

#### Command example
```!prisma-access-create-address-object folder="Shared" ip_netmask="10.10.10.10/32" name="XSOAR Test Object B" description="Test Object Creation from XSOAR"```
#### Context Example
```json
{
    "PrismaAccess": {
        "CreatedAddress": {
            "description": "Test Object Creation from XSOAR",
            "folder": "Shared",
            "id": "c680####-7d34-4c##-8b##-375baade####",
            "ip_netmask": "10.10.10.10/32",
            "name": "XSOAR Test Object B"
        }
    }
}
```

#### Human Readable Output

>### Address Object Created
>|description|folder|id|ip_netmask|name|
>|---|---|---|---|---|
>| Test Object Creation from XSOAR | Shared | c680####-7d34-4c##-8b##-375baade#### | 10.10.10.10/32 | XSOAR Test Object B |


### prisma-access-edit-address-object
***
Edit address object


#### Base Command

`prisma-access-edit-address-object`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID of the Address Object to edit. | Required | 
| tsg_id | Tenant services group ID. | Optional | 
| name | Friendly Name of the Address Object. | Required | 
| description | Address Object description. | Optional | 
| ip_netmask | IP/Netmask of the Object using the slash notation. | Required | 
| tag | Address Object tag(s).  Use , as a delimiter for multiple tags. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAccess.EditedAddressObject | unknown | Edited Address Object | 
| PrismaAccess.EditedAddress.description | String |  | 
| PrismaAccess.EditedAddress.folder | String |  | 
| PrismaAccess.EditedAddress.id | String |  | 
| PrismaAccess.EditedAddress.ip_netmask | String |  | 
| PrismaAccess.EditedAddress.name | String |  | 

#### Command example
```!prisma-access-edit-address-object id="c680####-7d34-4c##-8b##-375baade####" ip_netmask="10.10.10.11/32" name="XSOAR Test Object" description="XSOAR edited object"```
#### Context Example
```json
{
    "PrismaAccess": {
        "EditedAddress": {
            "description": "XSOAR edited object",
            "folder": "Shared",
            "id": "c680####-7d34-4c##-8b##-375baade####",
            "ip_netmask": "10.10.10.11/32",
            "name": "XSOAR Test Object"
        }
    }
}
```

#### Human Readable Output

>### Address Object Edited
>|description|folder|id|ip_netmask|name|
>|---|---|---|---|---|
>| XSOAR edited object | Shared | c680####-7d34-4c##-8b##-375baade#### | 10.10.10.11/32 | XSOAR Test Object |


### prisma-access-delete-address-object
***
Delete address object


#### Base Command

`prisma-access-delete-address-object`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID of the Address Object to delete. | Required | 
| tsg_id | Tenant services group ID. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAccess.DeletedAddressObject | unknown | Deleted Address Object | 
| PrismaAccess.DeletedAddress.description | String |  | 
| PrismaAccess.DeletedAddress.folder | String |  | 
| PrismaAccess.DeletedAddress.id | String |  | 
| PrismaAccess.DeletedAddress.ip_netmask | String |  | 
| PrismaAccess.DeletedAddress.name | String |  | 

#### Command example
```!prisma-access-delete-address-object id="c680####-7d34-4c##-8b##-375baade####"```
#### Context Example
```json
{
    "PrismaAccess": {
        "DeletedAddress": {
            "description": "XSOAR edited object",
            "folder": "Shared",
            "id": "c680####-7d34-4c##-8b##-375baade####",
            "ip_netmask": "10.10.10.11/32",
            "name": "XSOAR Test Object"
        }
    }
}
```

#### Human Readable Output

>### Address Object Deleted
>|description|folder|id|ip_netmask|name|
>|---|---|---|---|---|
>| XSOAR edited object | Shared | c680####-7d34-4c##-8b##-375baade#### | 10.10.10.11/32 | XSOAR Test Object |


### prisma-access-list-address-objects
***
List Address Objects


#### Base Command

`prisma-access-list-address-objects`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| folder | Prisma Access Folder Location for the Object. | Required | 
| name | name of the security object. | Optional | 
| limit | Results paging limit. Default is 10. | Optional | 
| offset | Results paging offset. | Optional | 
| tsg_id | Tenant services group ID. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAccess.FoundSecurityRule | unknown | Found security rule | 
| PrismaAccess.FoundAddressObjects.description | String |  | 
| PrismaAccess.FoundAddressObjects.folder | String |  | 
| PrismaAccess.FoundAddressObjects.fqdn | String |  | 
| PrismaAccess.FoundAddressObjects.id | String |  | 
| PrismaAccess.FoundAddressObjects.name | String |  | 
| PrismaAccess.FoundAddressObjects.ip_netmask | String |  | 

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
                "id": "c680####-7d34-4c##-8b##-375baade####",
                "name": "Palo Alto Networks Sinkhole"
            },
            {
                "folder": "Shared",
                "id": "c680####-7d34-4c##-8b##-375baade####",
                "ip_netmask": "10.0.0.0/16",
                "name": "GP-Users"
            },
            {
                "description": "Test Object Creation from XSOAR",
                "folder": "Shared",
                "id": "c680####-7d34-4c##-8b##-375baade####",
                "ip_netmask": "10.10.10.10/32",
                "name": "XSOAR Test Object"
            }
        ]
    }
}
```

#### Human Readable Output

>### Address Objects
>|name|description|ip_netmask|fqdn|
>|---|---|---|---|
>| Palo Alto Networks Sinkhole | Palo Alto Networks sinkhole |  | sinkhole.paloaltonetworks.com |
>| GP-Users |  | 10.0.0.0/16 |  |
>| XSOAR Test Object | Test Object Creation from XSOAR | 10.10.10.10/32 |  |

