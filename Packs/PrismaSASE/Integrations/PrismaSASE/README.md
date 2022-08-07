Integrate Prisma SASE API
This integration was integrated and tested with version 1.0 of Prisma SASE

## Configure Prisma SASE on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Prisma SASE.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | API Gateway URL (https://api.sase.paloaltonetworks.com) | URL for Prisma SASE API Gateway | True |
    | API Client ID | Client ID for API Gateway | True |
    | API Client Secret | Client Secret for API Gateway | True |
    | Use system proxy settings | | False |
    | Prisma API OAUTH URL | | False |
    | Trust any certificate (not secure) | | False |

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
| application | Application(s). | Required | 
| category | Category. | Required | 
| destination | Destination network. | Required | 
| destination_hip | Destination HIP. | Optional | 
| profile_setting | Security profiles to apply to traffic. | Optional | 
| service | Services the rule applies to. | Required | 
| source | Source network. | Required | 
| source_hip | Source HIP. | Optional | 
| source_user | Source user(s). | Required | 
| tag | Rule tag(s). | Optional | 
| from | Source zone. | Required | 
| to | Destination zone. | Required | 
| disabled | Rule disabled?. | Optional | 
| negate_source | Negate source . | Optional | 
| negate_destination | Negate destination. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAccess.CreatedSecurityRule | unknown | Created security rule | 


#### Command Example
```!prisma-access-create-security-rule folder="Shared" position="pre" tsg_id="123456" name="XSOAR Test Rule" ```
```action="allow" description="Test Rule from XSOAR" log_setting="Cortex Data Lake" application="any" ```
```category="any" destination="any" destination_hip="any" profile_setting="best-practice" service="application-default" ```
```source="any" source_hip="any" source_user="cn=cid-23444,dc=example,dc=domain,dc=com" from="trust" to="any" disabled="false" ```
```negate_source="false" negate_destination="false" extend-context="CustomerAdd.SecurityRuleID=PrismaAccess.SecurityRule.ID"```

#### Context Example
```json
{
    "id": "b71e385c-1c8a-42fc-9444-54bccbd148b9",
    "name": "Outbound Security Rule",
    "folder": "Shared",
    "position": "pre",
    "action": "allow",
    "source_hip": [
        "any"
    ],
    "destination_hip": [
        "any"
    ],
    "from": [
        "trust"
    ],
    "to": [
        "trust"
    ],
    "source": [
        "PA-GP-Mobile-User-Pool"
    ],
    "destination": [
        "PA-GP-Mobile-User-Pool"
    ],
    "source_user": [
        "any"
    ],
    "category": [
        "any"
    ],
    "application": [
        "any"
    ],
    "service": [
        "application-default"
    ],
    "log_setting": "Cortex Data Lake",
    "profile_setting": {
        "group": [
            "best-practice"
        ]
    }
}
```


### prisma-access-list-security-rules
***
List security rules


#### Base Command

`prisma-access-list-security-rules`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| folder | "Shared" "Mobile Users" "Remote Networks" "Service Connections" "Mobile Users Container" "Mobile Users Explicit Proxy". | Required | 
| position | Security rule position (pre, post). Possible values are: pre, post. | Required | 
| name | name of the security rule. | Optional | 
| limit | Results paging limit. Default is 10. | Optional | 
| offset | Results paging offset. | Optional | 
| tsg_id | Tenant services group ID. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAccess.FoundSecurityRule | unknown | Found security rule | 


#### Command Example
```!prisma-access-list-security-rules```

#### Context Example
```json
{
    "id": "b71e385c-1c8a-42fc-9444-54bccbd148b9",
    "name": "Outbound Security Rule",
    "folder": "Shared",
    "position": "pre",
    "action": "allow",
    "source_hip": [
        "any"
    ],
    "destination_hip": [
        "any"
    ],
    "from": [
        "trust"
    ],
    "to": [
        "trust"
    ],
    "source": [
        "PA-GP-Mobile-User-Pool"
    ],
    "destination": [
        "PA-GP-Mobile-User-Pool"
    ],
    "source_user": [
        "any"
    ],
    "category": [
        "any"
    ],
    "application": [
        "any"
    ],
    "service": [
        "application-default"
    ],
    "log_setting": "Cortex Data Lake",
    "profile_setting": {
        "group": [
            "best-practice"
        ]
    }
}
```

### prisma-access-push-candidate-config
***
Push the candidate configuration


#### Base Command

`prisma-access-push-candidate-config`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| devices | Comma separated list of targets (Remote Networks, Mobile Users, Service Connections). | Optional | 
| description | Config Push Job Description. | Optional | 
| tsg_id | Tenant services group ID. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAccess.ConfigPush | unknown | Config Job info | 

#### Command Example
```!prisma-access-push-candidate-config```

#### Context Example
```json
{}
```


### prisma-access-update-security-rule
***
Edit or update existing security rule


#### Base Command

`prisma-access-update-security-rule`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID of the rule to be changed. | Required | 
| folder | Prisma Access Folder Location for the Rule. | Required | 
| name | Rule name. | Required | 
| action | Rule action (allow, deny). | Required | 
| description | Rule description. | Optional | 
| log_setting | Rule log setting. | Optional | 
| application | Application(s). | Required | 
| category | Rule category. | Required | 
| destination | Destination networks. | Required | 
| destination_hip | Destination HIP. | Optional | 
| profile_setting | Security profiles to apply to rule. | Optional | 
| service | Services which the rule applies to. | Required | 
| source | Source networks. | Required | 
| source_hip | Source HIP. | Optional | 
| source_user | Source user(s). | Required | 
| tag | Rule tag(s). | Optional | 
| from | Source zone. | Required | 
| to | Destination zone. | Required | 
| disabled | Rule disabled?. | Optional | 
| negate_source | Negate source. | Optional | 
| negate_destination | Negate destination. | Optional | 
| tsg_id | Tenant services group ID. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAccess.UpdatedSecurityRule | unknown | Updated security rule | 

#### Command Example
```!prisma-access-update-security-rule id="53cd1c5e-a3c2-4c31-b975-56b48588736c" name="customer-b" ```
```action="allow" description="Customer B Secure Access" application="any" category="any" destination="any" ```
```profile_setting="url_dns_bp" service="application-default" source="any" source_user="CN=customergroup,DC=domain,DC=com" from="trust" to="any"```

#### Context Example
```json
{
    "action": "allow",
    "application": [
        "any"
    ],
    "category": [
        "any"
    ],
    "description": "Customer B Secure Access",
    "destination": [
        "any"
    ],
    "folder": "Shared",
    "from": [
        "trust"
    ],
    "id": "53cd1c5e-a3c2-4c31-b975-56b48588736c",
    "name": "customer-b",
    "profile_setting": {
        "group": [
            "url_dns_bp"
        ]
    },
    "service": [
        "application-default"
    ],
    "source": [
        "any"
    ],
    "source_user": [
        "CN=customer-group,DC=domain,DC=com"
    ],
    "to": [
        "any"
    ]
}
```

### prisma-access-query-agg-monitor-api
***
Query the aggregate monitor API


#### Base Command

`prisma-access-query-agg-monitor-api`
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

#### Command Example
```!prisma-access-query-agg-monitor uri="/mt/monitor/v1/agg/alerts/list" query=$query_data tsg_id=1234567```

#### Context Example
```json
{
    "header": {
        "createdAt": "2022-07-13T20:54:57Z",
        "dataCount": 1,
        "requestId": "3abf8489-3816-479e-8237-8125fd987fa2",
        "clientRequestId": "8e1b66e1-6542-4bc2-b348-4455d8e3e2b4",
        "status": {
            "subCode": 200
        }
    },
    "data": [
        {
            "total_count": 69,
            "mu_count": 0,
            "rn_count": 69,
            "sc_count": 0
        }
    ]
}
```

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

#### Command Example
```!prisma-access-get-security-rule-by-name name=cid-1252366 tsg_id=123456 folder=Shared position=pre```

#### Context Example
```json
{
    "data": [
        {
            "id": "b71e385c-1c8a-42fc-94e4-54bccbd148b9",
            "name": "cid-1252366",
            "folder": "Shared",
            "position": "pre",
            "action": "allow",
            "source_hip": [
                "any"
            ],
            "destination_hip": [
                "any"
            ],
            "from": [
                "trust"
            ],
            "to": [
                "trust"
            ],
            "source": [
                "PA-GP-Mobile-User-Pool"
            ],
            "destination": [
                "PA-GP-Mobile-User-Pool"
            ],
            "source_user": [
                "any"
            ],
            "category": [
                "any"
            ],
            "application": [
                "any"
            ],
            "service": [
                "application-default"
            ],
            "log_setting": "Cortex Data Lake",
            "profile_setting": {
                "group": [
                    "best-practice"
                ]
            }
        }
    ],
    "offset": 0,
    "total": 1,
    "limit": 1
}
```

### prisma-access-get-config-jobs-by-id
***
Get specific config job by the jobid


#### Base Command

`prisma-access-get-config-jobs-by-id`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Config Job ID. | Required | 
| tsg_id | Tenant services group ID. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAccess.ConfigJob | unknown | Config job details | 

#### Command Example
```!prisma-access-get-config-jobs-by-id id=294 tsg_id=123456```

#### Context Example
```json
{
    "data": [
        {
            "details": "{\"info\":[],\"errors\":[],\"warnings\":[]}",
            "end_ts": "2022-07-13 20:44:44",
            "id": "294",
            "insert_ts": "2022-07-13 20:43:08",
            "job_result": "0",
            "job_status": "1",
            "job_type": "53",
            "last_update": "2022-07-13 20:44:44",
            "opaque_int": "0",
            "opaque_str": "",
            "owner": "cfgserv",
            "parent_id": "0",
            "percent": "99",
            "result_i": "0",
            "result_str": "PEND",
            "session_id": "",
            "start_ts": "2022-07-13 20:43:08",
            "status_i": "1",
            "status_str": "ACT",
            "summary": "",
            "type_i": "53",
            "type_str": "CommitAndPush",
            "uname": "APIGateway@ProdInternal.com"
        }
    ]
}
```

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

#### Command Example
```!prisma-access-list-config-jobs limit=2 tsg_id=1234567```

#### Context Example
```json
{
    "data": [
        {
            "end_ts": "2022-07-21 17:40:57",
            "id": "300",
            "job_result": "2",
            "job_status": "2",
            "job_type": "22",
            "parent_id": "299",
            "percent": "100",
            "result_str": "OK",
            "start_ts": "2022-07-21 17:14:38",
            "status_str": "FIN",
            "summary": "Configuration push finished",
            "type_str": "CommitAll",
            "uname": "Some User",
            "description": "Remote Networks configuration pushed to cloud"
        },
        {
            "end_ts": "2022-07-21 17:14:35",
            "id": "299",
            "job_result": "2",
            "job_status": "2",
            "job_type": "53",
            "parent_id": "0",
            "percent": "100",
            "result_str": "OK",
            "start_ts": "2022-07-21 17:13:48",
            "status_str": "FIN",
            "summary": "",
            "type_str": "CommitAndPush",
            "uname": "Some User",
            "description": ""
        }
    ],
    "total": 300,
    "limit": 2,
    "offset": 0
}
```

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

#### Command Example
```!prisma-access-delete-security-rule rule_id=b71e385c-1c8a-499c-94e4-54bccbd148b9 tsg_id=1234567```

#### Context Example
```json
{
    "id": "b71e385c-1c8a-499c-94e4-54bccbd148b9",
    "name": "Outbound Security Rule",
    "folder": "Shared",
    "position": "pre",
    "action": "allow",
    "source_hip": [
        "any"
    ],
    "destination_hip": [
        "any"
    ],
    "from": [
        "trust"
    ],
    "to": [
        "trust"
    ],
    "source": [
        "PA-GP-Mobile-User-Pool"
    ],
    "destination": [
        "PA-GP-Mobile-User-Pool"
    ],
    "source_user": [
        "any"
    ],
    "category": [
        "any"
    ],
    "application": [
        "any"
    ],
    "service": [
        "application-default"
    ],
    "log_setting": "Cortex Data Lake",
    "profile_setting": {
        "group": [
            "best-practice"
        ]
    }
}
```
