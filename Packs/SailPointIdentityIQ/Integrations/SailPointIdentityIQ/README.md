SailPoint IdentityIQ context pack enables XSOAR customers to utilize the deep, enriched contextual data in the SailPoint predictive identity platform to better drive identity-aware security practices.
This integration was integrated and tested with version 8.1 of SailPoint IdentityIQ.
Supported Cortex XSOAR versions: 6.0.0 and later.

## Configure SailPointIdentityIQ in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| identityiq_url | IdentityIQ Server URL \(e.g. https://identityiq-server.com/identityiq) | True |
| client_id | Client Id \(for OAuth 2.0\) | True |
| client_secret | Client Secret \(for OAuth 2.0\) | True |
| isFetch | Fetch incidents | False |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |
| incidentType | Incident type | False |
| max_fetch | Maximum number of incidents per fetch | False |
| first_fetch | First fetch time | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### identityiq-search-identities
***
Search identities by search/filter parameters (id, email, risk & active) using IdentityIQ SCIM API's.


#### Base Command

`identityiq-search-identities`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Internal id of the identity being requested. | Optional | 
| email | Email address of the identity being requested. | Optional | 
| active | Determines whether search will return only active identities. Default is true. | Optional | 
| risk | Numeric value of baseline risk score, users above this will be returned. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IdentityIQ.Identity.userName | String | The IdentityIQ username \(primary id\). | 
| IdentityIQ.Identity.id | String | The IdentityIQ internal id \(uuid\). | 
| IdentityIQ.Identity.name.formatted | String | The display name of the identity. | 
| IdentityIQ.Identity.name.familyName | String | The last name of the identity. | 
| IdentityIQ.Identity.name.givenName | String | The first name of the identity. | 
| IdentityIQ.Identity.active | Boolean | Indicates whether the id is active or inactive in IdentityIQ. | 
| IdentityIQ.Identity.manager.userName | String | The IdentityIQ username \(primary id\) of the identities manager. | 
| IdentityIQ.Identity.lastModified | Date | Timestamp of when the identity was last modified. | 
| IdentityIQ.Identity.displayName | String | The display name of the identity. | 
| IdentityIQ.Identity.emails | Unknown | Array of email objects. | 
| IdentityIQ.Identity.emails.type | String | Type of the email being returned. | 
| IdentityIQ.Identity.emails.value | String | The email address of the identity. | 
| IdentityIQ.Identity.emails.primary | Boolean | Indicates if this email address is the identities primary email. | 
| IdentityIQ.Identity.entitlements | Unknown | Array of entitlements objects that the identity has. | 
| IdentityIQ.Identity.roles | Unknown | Array of role objects that the identity has. | 
| IdentityIQ.Identity.capabilities | Unknown | Array of string representations of the IdentityIQ capabilities assigned to this identity. | 


#### Command Examples
```
!identityiq-search-identities
!identityiq-search-identities id=8a8080824df45873014df45bd97400c9
!identityiq-search-identities email=jerry.bennett@sailpointdemo.com
!identityiq-search-identities active=False
!identityiq-search-identities risk=500
!identityiq-search-identities active=False risk=500
```

#### Human Readable Output

### Results:
### Identity
|id|userName|displayName|name|emails|sailpointUser|extendedUser|entitlements|roles|capabilities|active|
|---|---|---|---|---|---|---|---|---|---|---|
| 8a8080824df45873014df45bd97400c9 | Adam.Kennedy | Adam Kennedy | formatted: Adam Kennedy<br/>familyName: Kennedy<br/>givenName: Adam | {'type': 'work', 'value': 'Adam.Kennedy@sailpointdemo.com', 'primary': True} | capabilities: <br/>lastRefresh: 2020-10-08T15:45:47.034-05:00<br/>jobTitle: Payroll Analyst II<br/>employeeId: 1b2c3a4e<br/>administrator: {}<br/>employeeType: Employee<br/>phone: 5124152339<br/>isManager: false<br/>location: London<br/>accounts: {'displayName': '1b2c3a4e', 'value': '8a8080824df45873014df45bd97500ca', '$ref': 'http://localhost:8088/iiq/scim/v2/Accounts/8a8080824df45873014df45bd97500ca'},<br/>{'displayName': 'Adam.Kennedy', 'value': '8a8080824df45873014df45c164601d8', '$ref': 'http://localhost:8088/iiq/scim/v2/Accounts/8a8080824df45873014df45c164601d8'},<br/>{'displayName': 'AKENNE', 'value': '8a8080824df45873014df45d012705ae', '$ref': 'http://localhost:8088/iiq/scim/v2/Accounts/8a8080824df45873014df45d012705ae'},<br/>{'displayName': 'Adam.Kennedy', 'value': '8a8080824df45873014df45da06308b0', '$ref': 'http://localhost:8088/iiq/scim/v2/Accounts/8a8080824df45873014df45da06308b0'}<br/>riskScore: 82<br/>department: Accounting<br/>region: GB | manager: {"displayName": "Douglas Flores", "value": "8a8080824df45873014df45bcfab008d", "$ref": "http://localhost:8088/iiq/scim/v2/Users/8a8080824df45873014df45bcfab008d"} |  |  |  | true |



### identityiq-get-policyviolations
***
Fetch policy violation by id or all policy violations using IdentityIQ SCIM API's.


#### Base Command

`identityiq-get-policyviolations`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Internal id of the policy violation being requested. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IdentityIQ.PolicyViolation.policyName | String | Name of the policy that was violated. | 
| IdentityIQ.PolicyViolation.constraintName | String | Name of the constraint being violated. | 
| IdentityIQ.PolicyViolation.status | String | Status of the violation \(open/closed\). | 
| IdentityIQ.PolicyViolation.description | String | Description of the policy/conflict. | 
| IdentityIQ.PolicyViolation.identity.value | Unknown | Internal id of the IdentityIQ identity in violation. | 
| IdentityIQ.PolicyViolation.identity.displayName | String | Display name of the IdentityIQ identity in violation. | 
| IdentityIQ.PolicyViolation.id | String | Internal id of the task result. | 


#### Command Example
```
!identityiq-get-policyviolations
!identityiq-get-policyviolations id=8a8080824df45873014df46036521328
```

#### Human Readable Output

### Results:
### PolicyViolation
|id|policyName|constraintName|status|description|identity|owner|
|---|---|---|---|---|---|---|
| 8a8080824df45873014df46036521328 | SOD Policy Accounts Payable Access-Accounts Receivable Access | Accounts Payable Access - Accounts Receivable Access constraint | Open |  | displayName: Frank Rivera<br/>value: 8a8080824df45873014df45bc8480065<br/>$ref: http://localhost:8088/iiq/scim/v2/Users/8a8080824df45873014df45bc8480065 | displayName: Richard Jackson<br/>value: 8a8080824df45873014df45bbbb9002b<br/>$ref: http://localhost:8088/iiq/scim/v2/Users/8a8080824df45873014df45bbbb9002b |



### identityiq-get-taskresults
***
Fetch task result by id or all task results using IdentityIQ SCIM API's.


#### Base Command

`identityiq-get-taskresults`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Internal id of the task result being requested. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IdentityIQ.TaskResult.id | String | Internal id of the task result. | 
| IdentityIQ.TaskResult.progress | String | String representation of the status of the task. | 
| IdentityIQ.TaskResult.launched | Date | Date representation of when the task was launched in IdentityIQ. | 
| IdentityIQ.TaskResult.taskDefinition | String | Name of the task template that this task result is an instantiation of. | 
| IdentityIQ.TaskResult.host | String | Host name of the IdentityIQ application server that is executing this task. | 
| IdentityIQ.TaskResult.type | String | Type of the task being executed. | 
| IdentityIQ.TaskResult.pendingSignoffs | Number | Number of signoffs on the task result that have not been done. | 
| IdentityIQ.TaskResult.completionStatus | String | Status of task 'success', 'termianted', 'failure', etc. | 
| IdentityIQ.TaskResult.launcher | String | Name of the IdentityIQ identity who launched the task. | 
| IdentityIQ.TaskResult.name | String | Unique name of the task that was launched. | 
| IdentityIQ.TaskResult.completed | Date | Timestamp of when the task was completed \(if not currently executed\). | 


#### Command Example
```
!identityiq-get-taskresults
!identityiq-get-taskresults id=0a0000016b951ded816bb41351e901b3
```

#### Human Readable Output

### Results:
### TaskResult
|id|name|type|host|progress|completionStatus|launched|taskDefinition|pendingSignoffs|launcher|completed|taskSchedule|partitioned|terminated|messages|attributes|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 0a0000016b951ded816bb41351e901b3 | Joiner: DannyFieldsPS | Workflow |  |  | Success | 2019-07-02T14:04:53.471-05:00 | Workflow Launcher | 0 | Scheduler | 2019-07-02T14:04:53.480-05:00 |  | false | false |  | {'value': '<WorkflowSummary step="Stop"/>\n', 'key': 'workflowSummary'} |



### identityiq-get-accounts
***
Fetch accounts by search/filter parameters (id, display_name, last_refresh, native_identity, last_target_agg, identity_name & application_name) using IdentityIQ SCIM API's.


#### Base Command

`identityiq-get-accounts`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Internal id of the account to be returned. | Optional | 
| display_name | displayName of the account to be returned. | Optional | 
| last_refresh | Timestamp of the last time the account(s) were refreshed from the target system.<br/>[format : yyyy-MM-dd'T'HH:mm:ss or yyyy-MM-dd]. | Optional | 
| native_identity | Unique identifier of the account on the target system. | Optional | 
| last_target_agg | Timestamp of the last targeted aggregation of the account from the target system.<br/>[format : yyyy-MM-dd'T'HH:mm:ss or yyyy-MM-dd]. | Optional | 
| identity_name | Unique name of the identity for which all accounts will be returned. | Optional | 
| application_name | Unique name of the application for which all accounts will be returned. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IdentityIQ.Account.id | String | Internal id of the account. | 
| IdentityIQ.Account.identity.value | String | Internal id of the identity that this account belongs to. | 
| IdentityIQ.Account.identity.displayName | String | Display name of the identity that this account belongs to. | 
| IdentityIQ.Account.hasEntitlements | Boolean | True if the account has access entitlements assigned to it, else false. | 
| IdentityIQ.Account.application.value | Unknown | Internal id of the application that this account is on. | 
| IdentityIQ.Account.application.displayName | String | Display name of the application that this account is on. | 
| IdentityIQ.Account.nativeIdentity | String | The name of the account as it exists on the application. | 
| IdentityIQ.Account.lastRefreshed | Date | Timestamp of when this account was last refreshed in IdentityIQ. | 


#### Command Example
```
!identityiq-get-accounts
!identityiq-get-accounts id=8a8080824df45873014df45bb504000e
!identityiq-get-accounts last_refresh=2020-10-05T15:53:46
!identityiq-get-accounts native_identity=1b2c
!identityiq-get-accounts last_target_agg=2020-10-05T15:53:46
!identityiq-get-accounts identity_name=Amanda.Ross
!identityiq-get-accounts application_name=TRAKK
!identityiq-get-accounts identity_name=Amanda.Ross application_name=TRAKK
```

#### Human Readable Output

### Results:
### Account
|id|displayName|identity|hasEntitlements|application|nativeIdentity|active|lastRefresh|manuallyCorrelated|application|locked|
|---|---|---|---|---|---|---|---|---|---|---|
| 8a8080824df45873014df45bb504000e | 1b | displayName: Jerry Bennett<br/>userName: Jerry.Bennett<br/>value: 8a8080824df45873014df45bb503000d<br/>$ref: http://localhost:8088/iiq/scim/v2/Users/8a8080824df45873014df45bb503000d | false | displayName: Human Resources<br/>value: 8a8080824df44d48014df4542d7402aa<br/>$ref: http://localhost:8088/iiq/scim/v2/Applications/8a8080824df44d48014df4542d7402aa | 1b | true | 2015-06-14T18:16:00.389-05:00 | false | displayName: Human Resources<br/>value: 8a8080824df44d48014df4542d7402aa<br/>$ref: http://localhost:8088/iiq/scim/v2/Applications/8a8080824df44d48014df4542d7402aa | false |



### identityiq-disable-account
***
Disable account's active status by id using IdentityIQ SCIM API's.


#### Base Command

`identityiq-disable-account`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Internal id of the specific account to be disabled. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IdentityIQ.AccountDisable.active | Boolean | Indicates the status of account \(should be false after request is successfully completed\). | 


#### Command Example
```
!identityiq-disable-account id=8a8080824df45873014df45c719f038c
```

#### Human Readable Output

### Results:
### Account
|id|displayName|identity|hasEntitlements|application|nativeIdentity|active|lastRefresh|manuallyCorrelated|application|locked|
|---|---|---|---|---|---|---|---|---|---|---|
| 8a8080824df45873014df45c719f038c | Jerry.Bennett | displayName: Jerry Bennett<br/>userName: Jerry.Bennett<br/>value: 8a8080824df45873014df45bb503000d<br/>$ref: http://localhost:8088/iiq/scim/v2/Users/8a8080824df45873014df45bb503000d | true | displayName: Active Directory<br/>value: 8a8080824df44d48014df45440d502cf<br/>$ref: http://localhost:8088/iiq/scim/v2/Applications/8a8080824df44d48014df45440d502cf | CN=Jerry Bennett,OU=Brussels,OU=Europe,OU=Demo,DC=seri,DC=sailpointdemo,DC=com | false | 2020-12-16T16:39:56.638-06:00 | false | displayName: Active Directory<br/>value: 8a8080824df44d48014df45440d502cf<br/>$ref: http://localhost:8088/iiq/scim/v2/Applications/8a8080824df44d48014df45440d502cf | false |



### identityiq-enable-account
***
Enable account's active status by id using IdentityIQ SCIM API's.


#### Base Command

`identityiq-enable-account`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Internal id of the specific account to be enabled. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IdentityIQ.AccountDisable.active | Boolean | Indicates the status of account \(should be true after request is successfully completed\). | 


#### Command Example
```
!identityiq-enable-account id=8a8080824df45873014df45c719f038c
```

#### Human Readable Output

### Results:
### Account
|id|displayName|identity|hasEntitlements|application|nativeIdentity|active|lastRefresh|manuallyCorrelated|application|locked|
|---|---|---|---|---|---|---|---|---|---|---|
| 8a8080824df45873014df45c719f038c | Jerry.Bennett | displayName: Jerry Bennett<br/>userName: Jerry.Bennett<br/>value: 8a8080824df45873014df45bb503000d<br/>$ref: http://localhost:8088/iiq/scim/v2/Users/8a8080824df45873014df45bb503000d | true | displayName: Active Directory<br/>value: 8a8080824df44d48014df45440d502cf<br/>$ref: http://localhost:8088/iiq/scim/v2/Applications/8a8080824df44d48014df45440d502cf | CN=Jerry Bennett,OU=Brussels,OU=Europe,OU=Demo,DC=seri,DC=sailpointdemo,DC=com | true | 2020-12-16T16:39:56.638-06:00 | false | displayName: Active Directory<br/>value: 8a8080824df44d48014df45440d502cf<br/>$ref: http://localhost:8088/iiq/scim/v2/Applications/8a8080824df44d48014df45440d502cf | false |



### identityiq-delete-account
***
Delete account by id using IdentityIQ SCIM API's.


#### Base Command

`identityiq-delete-account`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Internal id of the specific account to be deleted. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```
!identityiq-delete-account id=8a8080824df45873014df45bb335000c
```

#### Human Readable Output
Account deleted successfully!



### identitytiq-get-launched-workflows
***
Fetch launched workflow by id or all launched workflows using IdentityIQ SCIM API's.


#### Base Command

`identitytiq-get-launched-workflows`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Internal id of the specific launched workflow being requested. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IdentityIQ.Workflow.workflowName | String | Name of the workflow that was launched. | 
| IdentityIQ.Workflow.identityRequestId | String | Unique id of the identity request that launched this workflow \(if exists\). | 
| IdentityIQ.Workflow.workflowCaseId | String | Internal id of the workflowcase for this workflow. | 
| IdentityIQ.Workflow.launched | Date | Timestamp of when this workflow was launched. | 
| IdentityIQ.Workflow.targetClass | String | Type of object targeted by the workflow, usually identity. | 
| IdentityIQ.Workflow.targetName | String | Unique name of the object \(username in the case of identity\). | 
| IdentityIQ.Workflow.type | String | The type of workflow. | 
| IdentityIQ.Workflow.id | String | Internal id of the workflow. | 
| IdentityIQ.Workflow.completionStatus | String | Status of workflow – 'success', 'failure', 'pending' etc. | 
| IdentityIQ.Workflow.launcher | String | Name of the identity that launched the workflow. | 
| IdentityIQ.Workflow.terminated | Boolean | Indicates whether this workflow was terminated due to error or intentionally stopped. | 
| IdentityIQ.Workflow.name | String | Name of the workflow that was launched. | 
| IdentityIQ.Workflow.attributes | Unknown | Array of key/value pairs that are the inputs and their values to the workflow. | 
| IdentityIQ.Workflow.output | Unknown | Array of key/type/value objects that list the output of the workflow. | 


#### Command Example
```
!identitytiq-get-launched-workflows
!identitytiq-get-launched-workflows id=0a0000016b951ded816bb41348e20197
```

#### Human Readable Output

### Results:
### Workflow
|id|name|workflowName|identityRequestId|workflowCaseId|launched|targetClass|targetName|type|completionStatus|launcher|terminated|attributes|partitioned|completed|pendingSignoffs|taskDefinition|launchedWorkflow|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 0a0000016b951ded816bb41348e20197 | Joiner: Nick |  |  |  | 2019-07-02T14:04:51.148-05:00 |  |  | Workflow | Success | Scheduler | false | {'value': '<WorkflowSummary step="Stop"/>\n', 'key': 'workflowSummary'} | false | 2019-07-02T14:04:51.169-05:00 | 0 | Workflow Launcher | output: {'type': 'application/xml', 'value': '<WorkflowSummary step="Stop"/>\n', 'key': 'workflowSummary'}<br/>input: {}<br/>workflowSummary: <WorkflowSummary step="Stop"/><br/><br/>workflowName: Joiner: Nick |



### identityiq-get-roles
***
Fetch role by id or all roles using IdentityIQ SCIM API's.


#### Base Command

`identityiq-get-roles`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Internal id of the specific role being requested. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IdentityIQ.Role.name | String | Unique name of the role object in IdentityIQ. | 
| IdentityIQ.Role.owner.value | String | Internal id of the role owner identity. | 
| IdentityIQ.Role.owner.displayName | String | Displayname of the owner of the role. | 
| IdentityIQ.Role.active | Boolean | Indicates whether the role is active in IdentityIQ. | 
| IdentityIQ.Role.displayableName | String | Display name of the role in IdentityIQ. | 
| IdentityIQ.Role.permits | Unknown | Array of roles that this role permits in IdentityIQ. | 
| IdentityIQ.Role.type.name | String | Template role on which this role is based. | 
| IdentityIQ.Role.type.autoAssignment | Boolean | Indicates whether this type of role can be auto-assigned to identities. | 
| IdentityIQ.Role.type.displayName | String | Display name of the template role on which this role was based. | 
| IdentityIQ.Role.type.manualAssignment | String | Indicates whether this role type can be manually assigned. | 
| IdentityIQ.Role.descriptions.value | String | Description of the role shown in the UI. | 


#### Command Example
```
!identityiq-get-roles
!identityiq-get-roles id=8a8080824df45873014df45f8b6810e9
```

#### Human Readable Output

### Results:
### Role
|id|name|owner|active|displayableName|permits|type|descriptions|requirements|
|---|---|---|---|---|---|---|---|---|
| 8a8080824df45873014df45f8b6810e9 | All Users | displayName: The Administrator<br/>value: 8a8080824df44d48014df44def7100dd<br/>$ref: http://localhost:8088/iiq/scim/v2/Users/8a8080824df44d48014df44def7100dd | true | All Users |  | iiq: false<br/>requirements: true<br/>permits: true<br/>displayName: Business<br/>manualAssignment: true<br/>name: business<br/>autoAssignment: true<br/>assignmentSelector: true | {'locale': 'en_US', 'value': 'Role that grants access all users should have'} | {'displayName': 'User Basic', 'value': '8a8080824df45873014df45f8b1810e6', '$ref': 'http://localhost:8088/iiq/scim/v2/Roles/8a8080824df45873014df45f8b1810e6'} |



### identityiq-get-entitlements
***
Fetch entitlement by id or all entitlements using IdentityIQ SCIM API's.


#### Base Command

`identityiq-get-entitlements`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Internal id of the specific entitlement being requested. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IdentityIQ.Entitlement.application.value | String | Internal id of the application that this entitlement resides on. | 
| IdentityIQ.Entitlement.application.displayName | String | Display name of the application that this entitlement resides on. | 
| IdentityIQ.Entitlement.attribute | String | String representing the attribute on the application that this entitlement represents. | 
| IdentityIQ.Entitlement.type | String | String representing the type of attribute on the application that this entitlement represents. | 
| IdentityIQ.Entitlement.descriptions | Unknown | Array of description objects that contain a locale, and a value. | 
| IdentityIQ.Entitlement.id | String | Internal id of the entitlement object in IdentityIQ. | 
| IdentityIQ.Entitlement.requestable | Boolean | Boolean indicates whether this entitlement is directly requestable in the IdentityIQ UI. | 
| IdentityIQ.Entitlement.owner.value | String | Internal id of the owner of the entitlement in IdentityIQ. | 
| IdentityIQ.Entitlement.owner.displayName | String | Display name of the owner of the entitlement in IdentityIQ. | 
| IdentityIQ.Entitlement.aggregated | String | Indicates whether this entitlement was aggregated from the source system or not. | 
| IdentityIQ.Entitlement.created | Date | Timestamp indicates when the entitlement was created in IdentityIQ. | 


#### Command Example
```
!identityiq-get-entitlements
!identityiq-get-entitlements id=8a8080824df45873014df45d9f9008a8
```

#### Human Readable Output

### Results:
### Entitlement
|id|displayableName|type|attribute|value|owner|application|descriptions|requestable|aggregated|created|
|---|---|---|---|---|---|---|---|---|---|---|
| 8a8080824df45873014df45d9f9008a8 | input | Entitlement | capability | input |  | displayName: TRAKK<br/>value: 8a8080824df44d48014df45444c002da<br/>$ref: http://localhost:8088/iiq/scim/v2/Applications/8a8080824df44d48014df45444c002da |  | true | false |  |



### identityiq-get-alerts
***
Fetch alert by id or all alerts using IdentityIQ SCIM API's.


#### Base Command

`identityiq-get-alerts`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Internal id of the specific alert being requested. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IdentityIQ.Alert.id | String | Internal id of the Alert in IdentityIQ. | 
| IdentityIQ.Alert.lastProcessed | Date | Timestamp of when this alert was processed by IdentityIQ for match. | 
| IdentityIQ.Alert.displayName | String | Display name of the alert in IdentityIQ. | 
| IdentityIQ.Alert.meta.created | Date | Timestamp of when this alert was created in IdentityIQ | 
| IdentityIQ.Alert.name | String | Name of the alert in IdentityIQ | 
| IdentityIQ.Alert.attributes | Unknown | Array of attributes associated with this alert. | 
| IdentityIQ.Alert.actions | Unknown | Array of actions taken on this alert after processing. | 
| IdentityIQ.Alert.application | String | List of applications that are related to this alert. | 


#### Command Example
```
!identityiq-get-alerts
!identityiq-get-alerts id=0a000001764519c981766dbd2bd518ad
```

#### Human Readable Output

### Results:
### Alert
|id|name|displayName|type|targetId|targetDisplayName|targetType|alertInput|actions|application|attributes|lastProcessed|
|---|---|---|---|---|---|---|---|---|---|---|---|
| 0a000001764519c981766dbd2bd518ad | 0000000015 | Test Alert | PAN XSOAR |  |  |  | input: <br/>processorTaskInput: <br/>aggregationTaskInput:  |  |  |  | 2020-12-16T16:48:02.773-06:00 |



### identityiq-create-alert
***
Create an alert using IdentityIQ SCIM API's.


#### Base Command

`identityiq-create-alert`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| display_name | Display name of the alert. | Required | 
| attributes | List of JSON objects with the following structure.<br/>{<br/>    'key': '',<br/>    'value': '',<br/>    'type': ''<br/>}. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IdentityIQ.Alert.id | String | Internal id of the Alert in IdentityIQ. | 
| IdentityIQ.Alert.lastProcessed | Date | Timestamp of when this alert was processed by IdentityIQ for match. | 
| IdentityIQ.Alert.displayName | String | Display name of the alert in IdentityIQ. | 
| IdentityIQ.Alert.meta.created | Date | Timestamp of when this alert. | 
| IdentityIQ.Alert.name | String | Unique name of the alert in IdentityIQ. | 
| IdentityIQ.Alert.attributes | Unknown | Array of attributes associated with this alert. | 
| IdentityIQ.Alert.actions | Unknown | Array of actions taken on this alert after processing. | 
| IdentityIQ.Alert.application | String | List of applications that are related to this alert. | 


#### Command Example
```
!identityiq-create-alert display_name=Testing-Via-XSOAR
```

#### Human Readable Output

### Results:
### Alert
|id|name|displayName|type|targetId|targetDisplayName|targetType|alertInput|actions|application|attributes|lastProcessed|
|---|---|---|---|---|---|---|---|---|---|---|---|
| 0a000001764519c981767209e7491c04 | 0000000016 | XSOAR-Alert | PAN XSOAR |  |  |  | input: <br/>processorTaskInput: <br/>aggregationTaskInput:  |  |  |  | 2020-12-17T12:50:20.369-06:00 |
