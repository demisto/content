SailPoint IdentityNow
This integration was integrated and tested with SailPoint IdentityNow.
## Configure SailPointIdentityNow in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| identitynow_url | IdentityNow Server URL \(e.g. https://org.api.identitynow.com\) | True |
| client_id | Client Id \(for OAuth 2.0\) | True |
| client_secret | Client Secret \(for OAuth 2.0\) | True |
| isFetch | Fetch incidents | False |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |
| incidentType | Incident type | False |
| max_fetch | Maximum number of incidents per fetch | False |
| first_fetch | First fetch time | False |


## Important Note
This integration pack does not fetch incidents from IdentityNow. It rather utilizes "Generic Webhook" to create incidents on event triggers published by IdentityNow. One can achieve this by following the steps below:

1. Configure Cortex XSOAR Platform - Use the following link to configure Cortex XSOAR platform to initiate receiving of Event Triggers from IdentityNow platform.
- https://xsoar.pan.dev/docs/reference/integrations/generic-webhook
- Select "SailPoint IdentityNow Trigger" as the "Incident Type" in the "Generic Webhook" configuration.

2. Enable & Configure the Event Handler - IdentityNow Event Trigger can forward the events occurring within the platform to any external services/platform that have subscribed to the list of triggers available in IdentityNow. Request the IdentityNow team to enable/provide you with the 'identitynow-events-pan-xsoar' event handler designed for Cortex XSOAR. This is a standalone .nodejs microservice that assists with event trigger transform and relaying to Cortex XSOAR.
Following is a list of environment variables (added to the app.config.js) needed to configure this microservice:

| **Environment Variable** | **Description** |
| --- | --- |
| XSOAR_WEBHOOK_URL | This is the webhook URL that will be available once you configure the "Generic Webhook" in step 1. | 
| XSOAR_USERNAME | Username to connect to the "Generic Webhook". | 
| XSOAR_PASSWORD | Password to connect to the "Generic Webhook". |

3. Configure IdentityNow Platform - Use the following link to configure IdentityNow platform to subscribe to event triggers.
- https://community.sailpoint.com/t5/Admin-Help/Event-Triggers-in-SailPoint-s-Cloud-Services/ta-p/178285

Once you have configured all the above steps, whenever an event trigger will occur in IdentityNow, it will notify Cortex XSOAR (as Incidents) using the above setup.


## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### identitynow-search-identities
***
Search for identity(identities) using elastic search query used by IdentityNow Search Engine.


#### Base Command

`identitynow-search-identities`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | Elastic search query for retrieving identities. | Required | 
| offset | Offset into the full result set. Usually specified with limit to paginate through the results. | Optional | 
| limit | Max number of results to return. Maximum of 250. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SailPointIdentityNow.Identity.id | String | The IdentityNow internal Id \(uuid\). | 
| SailPointIdentityNow.Identity.name | String | Name of the identity. | 
| SailPointIdentityNow.Identity.displayName | String | The display name of the identity. | 
| SailPointIdentityNow.Identity.firstName | String | The first name of the identity. | 
| SailPointIdentityNow.Identity.lastName | String | The last name of the identity. | 
| SailPointIdentityNow.Identity.email | String | Email address of the Identity. | 
| SailPointIdentityNow.Identity.created | Date | Timestamp when the identity was created. | 
| SailPointIdentityNow.Identity.modified | Date | Timestamp when the identity was last modified. | 
| SailPointIdentityNow.Identity.inactive | Boolean | Indicates whether the identity is active. | 
| SailPointIdentityNow.Identity.protected | Boolean | Indicates whether this identity is protected. | 
| SailPointIdentityNow.Identity.status | String | Status of this Identity. | 
| SailPointIdentityNow.Identity.isManager | Boolean | Indicates whether this identity is a manager. | 
| SailPointIdentityNow.Identity.identityProfile | String | Identity profile that maps this identity. | 
| SailPointIdentityNow.Identity.source | String | Source that maps this identity. | 
| SailPointIdentityNow.Identity.attributes | String | Map of variable number of attributes unique to this identity. | 
| SailPointIdentityNow.Identity.accounts | String | Array of objects representing the accounts belonging to this identity. | 
| SailPointIdentityNow.Identity.accountCount | Number | Number of accounts belonging to this identity. | 
| SailPointIdentityNow.Identity.appCount | Number | Number of applications belonging to this identity. | 
| SailPointIdentityNow.Identity.accessCount | Number | Number of access objects belonging to this identity. | 
| SailPointIdentityNow.Identity.entitlementCount | Number | Number of entitlements assigned to this identity. | 
| SailPointIdentityNow.Identity.roleCount | Number | Number of roles assigned to this identity. | 
| SailPointIdentityNow.Identity.accessProfileCount | Number | Number of access profiles assigned to this identity. | 
| SailPointIdentityNow.Identity.pod | String | Pod on which the organization that this identity belongs to resides on. | 
| SailPointIdentityNow.Identity.org | String | The organization that this identity belongs to. | 
| SailPointIdentityNow.Identity.type | String | Type of object, will be "identity". | 


#### Command Example
```
!identitynow-search-identities query=id:2c918084740346d5017408d79229489e
```

#### Human Readable Output
### Results:
Total: 1
### Identity(Identities)
|id|name|displayName|firstName|lastName|email|created|modified|inactive|protected|status|isManager|identityProfile|source|attributes|accounts|accountCount|appCount|accessCount|entitlementCount|roleCount|accessProfileCount|pod|org|type|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 2c918084740346d5017408d79229489e | testy.testerson@sailpoint.com | testy.testerson@sailpoint.com | testy.testerson@sailpoint.com | testy.testerson@sailpoint.com | testy.testerson@sailpoint.com | 2020-08-19T22:29:39.498Z | 2021-02-04T02:03:11.294Z | false | false | UNREGISTERED | false | id: 2c9180887372d217017408d3c85d0b20<br/>name: ZIA Users | id: 2c91808a737cf404017408d28c1e77a2<br/>name: ZIA | uid: 7a736361-6c65-7200-7363-696d005d7d1a<br/>firstname: testy.testerson@sailpoint.com<br/>cloudAuthoritativeSource: 2c91808a737cf404017408d28c1e77a2<br/>cloudStatus: UNREGISTERED<br/>iplanet-am-user-alias-list: <br/>displayName: testy.testerson@sailpoint.com<br/>internalCloudStatus: UNREGISTERED<br/>identificationNumber: 7a736361-6c65-7200-7363-696d005d7d1a<br/>email: testy.testerson@sailpoint.com<br/>lastname: testy.testerson@sailpoint.com | {'id': '2c918084740346d5017408d7922a489f', 'name': 'testy.testerson@sailpoint.com', 'accountId': '7a736361-6c65-7200-7363-696d005d7d1a', 'source': {'id': '2c91808a737cf404017408d28c1e77a2', 'name': 'ZIA', 'type': 'SCIM 2.0'}, 'disabled': False, 'locked': False, 'privileged': False, 'manuallyCorrelated': False, 'entitlementAttributes': {}, 'created': '2020-08-19T22:29:39.498Z'},<br/>{'id': '2c918084740346d601740c98765a306e', 'name': 'testy.testerson@sailpoint.com', 'accountId': 'testy.testerson@sailpoint.com', 'source': {'id': '2c91808563f9f8b40163fa9734d3029f', 'name': 'IdentityNow', 'type': 'IdentityNowConnector'}, 'disabled': False, 'locked': False, 'privileged': False, 'manuallyCorrelated': False, 'entitlementAttributes': {}, 'created': '2020-08-20T15:59:12.475Z'} | 2 | 0 | 0 | 0 | 0 | 0 | stg-uswest | sailpoint-idn | identity |



### identitynow-get-accounts
***
Get accounts by search/filter parameters (id, name, native_identity).


#### Base Command

`identitynow-get-accounts`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Account Id of the user/identity. | Optional | 
| name | Name of the user/identity on the account. | Optional | 
| native_identity | Native identity for the user account. | Optional | 
| offset | Offset into the full result set. Usually specified with limit to paginate through the results. | Optional | 
| limit | Max number of results to return. Maximum of 250. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SailPointIdentityNow.Account.id | String | The IdentityNow internal id \(uuid\). | 
| SailPointIdentityNow.Account.name | String | Name of the identity on this account. | 
| SailPointIdentityNow.Account.identityId | String | The IdentityNow internal identity id. | 
| SailPointIdentityNow.Account.nativeIdentity | String | The IdentityNow internal native identity id. | 
| SailPointIdentityNow.Account.sourceId | String | Source id that maps this account. | 
| SailPointIdentityNow.Account.created | Date | Timestamp when the account was created. | 
| SailPointIdentityNow.Account.modified | Date | Timestamp when the account was last modified. | 
| SailPointIdentityNow.Account.attributes | String | Map of variable number of attributes unique to this account. | 
| SailPointIdentityNow.Account.authoritative | Boolean | Indicates whether the account is the true source for this identity. | 
| SailPointIdentityNow.Account.disabled | Boolean | Indicates whether the account is disabled. | 
| SailPointIdentityNow.Account.locked | Boolean | Indicates whether the account is locked. | 
| SailPointIdentityNow.Account.systemAccount | Boolean | Indicates whether the account is a system account. | 
| SailPointIdentityNow.Account.uncorrelated | Boolean | Indicates whether the account is uncorrelated. | 
| SailPointIdentityNow.Account.manuallyCorrelated | Boolean | Indicates whether the account was manually correlated. | 
| SailPointIdentityNow.Account.hasEntitlements | Boolean | Indicates whether the account has entitlement. | 


#### Command Example
```
!identitynow-get-accounts id=2c918084740346d30174088afa6d625e
```

#### Human Readable Output
### Results:
### Account(s)
|id|name|identityId|nativeIdentity|sourceId|created|modified|attributes|authoritative|disabled|locked|systemAccount|uncorrelated|manuallyCorrelated|hasEntitlements|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 2c918084740346d30174088afa6d625e | Testy.Testerson |  | 41263 | 2c918084737cf3fe01740875ebac75cd | 2020-08-19T21:05:59.917Z | 2020-08-19T21:06:01.269Z | externalId: null<br/>IIQDisabled: true<br/>id: 41263<br/>userName: Testy.Testerson<br/>idNowDescription: f74806c7011b760457c914ef5ea254b8752496a441a92475b910ded9eb5ec487 | false | true | false | false | true | false | false |



### identitynow-get-accountactivities
***
Get account activities by search/filter parameters (requested_for, requested_by, regarding_identity, type).


#### Base Command

`identitynow-get-accountactivities`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Account activity Id. | Optional | 
| requested_for | The identity that the activity was requested for (me indicates current user). | Optional | 
| requested_by | The identity that requested the activity (me indicates current user). | Optional | 
| regarding_identity | The specified identity will be either requester or target of account activity (me indicates current user). | Optional | 
| type | Type of account activity. | Optional | 
| offset | Offset into the full result set. Usually specified with limit to paginate through the results. | Optional | 
| limit | Max number of results to return. Maximum of 250. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SailPointIdentityNow.AccountActivity.id | String | The IdentityNow internal id \(uuid\). | 
| SailPointIdentityNow.AccountActivity.name | String | Name of the account activity. | 
| SailPointIdentityNow.AccountActivity.created | Date | Timestamp when the account activity was created. | 
| SailPointIdentityNow.AccountActivity.modified | Date | Timestamp when the account activity was last modified. | 
| SailPointIdentityNow.AccountActivity.completed | Date | Timestamp when the account activity was completed. | 
| SailPointIdentityNow.AccountActivity.completionStatus | String | Completion status of the activity. | 
| SailPointIdentityNow.AccountActivity.type | String | Type of account activity. | 
| SailPointIdentityNow.AccountActivity.requesterIdentitySummary | String | Information of the requester identity. | 
| SailPointIdentityNow.AccountActivity.targetIdentitySummary | String | Information of the target identity. | 
| SailPointIdentityNow.AccountActivity.items | String | List of items that were requested as part of the account activity. | 
| SailPointIdentityNow.AccountActivity.executionStatus | String | Execution status of the account activity. | 
| SailPointIdentityNow.AccountActivity.cancelable | Boolean | Indicates whether the account activity is cancelable. | 
| SailPointIdentityNow.AccountActivity.cancelComment | String | Comments added while canceling the account activity. | 


#### Command Example
```
!identitynow-get-accountactivities id=c8f2907b336043be8570676b270965a9
```

#### Human Readable Output
### Results:
### Account Activity(Account Activities)
|id|name|created|modified|completed|completionStatus|type|requesterIdentitySummary|targetIdentitySummary|items|executionStatus|cancelable|cancelComment|
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| c8f2907b336043be8570676b270965a9 | c8f2907b336043be8570676b270965a9 | 2020-02-20T15:28:47.051Z | 2020-02-20T15:29:10.735Z | 2020-02-20T15:29:10.735Z | INCOMPLETE | appRequest | id: 2c91808363f06ad80163fb690fae55b8<br/>name: adam.kennedy | id: 2c91808a6fca28a6016fd7f5ec3f5228<br/>name: jack.brown | {} | VERIFYING | false |  |



### identitynow-search-accessprofiles
***
Search for access profile(s) using elastic search query used by IdentityNow Search Engine.


#### Base Command

`identitynow-search-accessprofiles`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | Elastic search query for retrieving identities. | Required | 
| offset | Offset into the full result set. Usually specified with limit to paginate through the results. | Optional | 
| limit | Max number of results to return. Maximum of 250. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SailPointIdentityNow.AccessProfile.id | String | The IdentityNow internal id of the access profile object. | 
| SailPointIdentityNow.AccessProfile.name | String | Name of the access profile object. | 
| SailPointIdentityNow.AccessProfile.description | String | User friendly description of the access profile. | 
| SailPointIdentityNow.AccessProfile.source | String | Source of the access profile. | 
| SailPointIdentityNow.AccessProfile.entitlements | String | Entitlements included in the access profile. | 
| SailPointIdentityNow.AccessProfile.entitlementCount | Number | Number of entitlements included in the access profile. | 
| SailPointIdentityNow.AccessProfile.created | Date | Date when the access profile was created. | 
| SailPointIdentityNow.AccessProfile.modified | Date | Date when the access profile was last modified. | 
| SailPointIdentityNow.AccessProfile.synced | Date | Date when the access profile was last synced. | 
| SailPointIdentityNow.AccessProfile.enabled | Boolean | Indicates whether the access profile is active \(true/false\). | 
| SailPointIdentityNow.AccessProfile.requestable | Boolean | Indicates whether the access profile is requestable in IdentityNow. | 
| SailPointIdentityNow.AccessProfile.requestCommentsRequired | Boolean | Indicates whether any request for this profile must contain comments. | 
| SailPointIdentityNow.AccessProfile.owner | String | Owner of the access profile. | 
| SailPointIdentityNow.AccessProfile.pod | String | Pod that the organization containing the access profile belongs to. | 
| SailPointIdentityNow.AccessProfile.org | String | Name of the org on which the access profile exists. | 
| SailPointIdentityNow.AccessProfile.type | String | Type of access profile, will be "accessprofile". | 


#### Command Example
```
!identitynow-search-accessprofiles query=id:2c91808874feffbc01750a4d06560370
```

#### Human Readable Output
### Results:
Total: 1
### Access Profile(s)
|id|name|description|source|entitlements|entitlementCount|created|modified|synced|enabled|requestable|requestCommentsRequired|owner|pod|org|type|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 2c91808874feffbc01750a4d06560370 | Basic Users | Basic Users | id: 2c9180876ff2de9601700b99e5fb51c6<br/>name: Direct Access Profile | {'hasPermissions': False, 'description': None, 'attribute': 'Roles', 'value': 'Basic Users', 'schema': 'group', 'privileged': False, 'id': '2c91808a6fede9c401700ba9c4d43ef9', 'name': 'Basic Users'} | 1 | 2020-10-08T22:20:21Z | 2020-11-17T15:12:41Z | 2021-03-01T06:30:18.772Z | true | true | false | email: adam.kennedy@sailpoint.com<br/>type: IDENTITY<br/>id: 2c91808363f06ad80163fb690fae55b8<br/>name: adam.kennedy | stg-uswest | sailpoint-idn | accessprofile |



### identitynow-search-roles
***
Search for role(s) using elastic search query used by IdentityNow Search Engine.


#### Base Command

`identitynow-search-roles`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | Elastic search query for retrieving roles. | Required | 
| offset | Offset into the full result set. Usually specified with limit to paginate through the results. | Optional | 
| limit | Max number of results to return. Maximum of 250. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SailPointIdentityNow.Role.id | String | The IdentityNow internal id of the role object. | 
| SailPointIdentityNow.Role.name | String | Name of the role. | 
| SailPointIdentityNow.Role.description | String | Description of this role. | 
| SailPointIdentityNow.Role.accessProfiles | Unknown | Array of objects representing the access profiles that belong to this role. | 
| SailPointIdentityNow.Role.accessProfileCount | Number | Number indicated how many access profiles are attached to this role. | 
| SailPointIdentityNow.Role.created | Date | Timestamp when this role was created. | 
| SailPointIdentityNow.Role.modified | Date | Timestamp when this role was last modified. | 
| SailPointIdentityNow.Role.synced | Date | Timestamp when this role was last synced. | 
| SailPointIdentityNow.Role.enabled | Boolean | Indicates whether this role is enabled. | 
| SailPointIdentityNow.Role.requestable | Boolean | Indicates whether this role is requestable. | 
| SailPointIdentityNow.Role.requestCommentsRequired | Boolean | Indicates whether comments are required when requesting this role. | 
| SailPointIdentityNow.Role.owner | String | Owner of the role. | 
| SailPointIdentityNow.Role.pod | String | Pod on which the organization responsible for this role belongs. | 
| SailPointIdentityNow.Role.org | String | Organization on which this role exists. | 
| SailPointIdentityNow.Role.type | String | Type of object, will be "role". | 


#### Command Example
```
!identitynow-search-roles query=id:2c9180846ff9c50201700beb2e9000da
```

#### Human Readable Output
### Results:
Total: 1
### Role(s)
|id|name|description|accessProfiles|accessProfileCount|created|modified|synced|enabled|requestable|requestCommentsRequired|owner|pod|org|type|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 2c9180846ff9c50201700beb2e9000da | Basic | Basic Users | {'id': '2c9180846ff9c50201700becb01e00db', 'name': 'Basic'} | 1 | 2020-02-03T16:38:47Z | 2020-02-03T16:40:42Z | 2021-03-01T05:30:09.434Z | true | true | false | email: adam.kennedy@sailpoint.com<br/>type: IDENTITY<br/>id: 2c91808363f06ad80163fb690fae55b8<br/>name: adam.kennedy | stg-uswest | sailpoint-idn | role |



### identitynow-search-entitlements
***
Search for entitlement(s) using elastic search query used by IdentityNow Search Engine.


#### Base Command

`identitynow-search-entitlements`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | Elastic search query for retrieving entitlements. | Required | 
| offset | Offset into the full result set. Usually specified with limit to paginate through the results. | Optional | 
| limit | Max number of results to return. Maximum of 250. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SailPointIdentityNow.Entitlement.id | String | The IdentityNow internal id of the entitlement object. | 
| SailPointIdentityNow.Entitlement.name | String | Name of the entitlement object. | 
| SailPointIdentityNow.Entitlement.displayName | String | Displayname of the entitlement object. | 
| SailPointIdentityNow.Entitlement.description | String | Description of the entitlement. | 
| SailPointIdentityNow.Entitlement.modified | Date | Timestamp when the entitlement was last modified. | 
| SailPointIdentityNow.Entitlement.synced | Date | Timestamp when the entitlement was last synced. | 
| SailPointIdentityNow.Entitlement.source | String | Source from which this entitlement was aggregated. | 
| SailPointIdentityNow.Entitlement.privileged | Boolean | Indicates this is a privileged entitlement. | 
| SailPointIdentityNow.Entitlement.identityCount | Number | Indicates how many identities have this entitlement. | 
| SailPointIdentityNow.Entitlement.attribute | String | Name of the attribute type on the source. | 
| SailPointIdentityNow.Entitlement.value | String | Value of the entitlement \(its native identifier\). | 
| SailPointIdentityNow.Entitlement.schema | String | The source schema that this entitlement utilizes. | 
| SailPointIdentityNow.Entitlement.pod | String | Pod on which the organization this entitlement belongs to is located. | 
| SailPointIdentityNow.Entitlement.org | String | Organization on which the source of this entitlement resides. | 
| SailPointIdentityNow.Entitlement.type | String | Type of object, will be "entitlement". | 


#### Command Example
```
!identitynow-search-entitlements query=id:2c9180846ff7e56b01700bb399f60eaa
```

#### Human Readable Output
### Results:
Total: 1
### Entitlement(s)
|id|name|displayName|description|modified|synced|source|privileged|identityCount|attribute|value|schema|pod|org|type|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 2c9180846ff7e56b01700bb399f60eaa | BASIC_DIRECT | BASIC_DIRECT |  | 2020-10-21T19:58:39Z | 2021-03-01T04:30:40.632Z | id: 2c9180876ff2de9601700b99e5fb51c6<br/>name: Basic Direct | false |  | Roles | BASIC_DIRECT | group | stg-uswest | sailpoint-idn | entitlement |



### identitynow-search-events
***
Search for event(s) using elastic search query used by IdentityNow Search Engine.


#### Base Command

`identitynow-search-events`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | Elastic search query for retrieving events. | Required | 
| offset | Offset into the full result set. Usually specified with limit to paginate through the results. | Optional | 
| limit | Max number of results to return. Maximum of 250. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SailPointIdentityNow.Event.id | String | The IdentityNow internal id of the event object. | 
| SailPointIdentityNow.Event.name | String | Name of the event. | 
| SailPointIdentityNow.Event.stack | String | Component that triggered the event. | 
| SailPointIdentityNow.Event.created | Date | Timestamp when the event was created. | 
| SailPointIdentityNow.Event.synced | String | Timestamp when the event was last synced. | 
| SailPointIdentityNow.Event.objects | Unknown | Array of object types that were the target of this event. | 
| SailPointIdentityNow.Event.ipAddress | String | IP address that triggered this event. | 
| SailPointIdentityNow.Event.technicalName | String | System name for the event. | 
| SailPointIdentityNow.Event.target | String | Target of this event action. | 
| SailPointIdentityNow.Event.actor | String | Entity that initiated the action that caused this event. | 
| SailPointIdentityNow.Event.action | String | Action type of the event. | 
| SailPointIdentityNow.Event.attributes | String | Attributes of other interesting information about this event, contextual to the type. | 
| SailPointIdentityNow.Event.operation | String | Operation performed that triggered event. | 
| SailPointIdentityNow.Event.status | String | Status of the event. | 
| SailPointIdentityNow.Event.pod | String | Pod on which the organization that the event exists. | 
| SailPointIdentityNow.Event.org | String | Organization that initiated the event. | 
| SailPointIdentityNow.Event.type | String | Type of event. | 


#### Command Example
```
!identitynow-search-events query=id:2bd61299-d986-4c27-bd37-408b9c9ba118
```

#### Human Readable Output
### Results:
Total: 1
### Event(s)
|id|name|stack|created|synced|objects|ipAddress|technicalName|target|actor|action|attributes|operation|status|pod|org|type|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 2bd61299-d986-4c27-bd37-408b9c9ba118 | Delete Task Result Passed | sweep | 2020-02-24T22:07:03.793Z | 2020-02-24T22:07:03.831Z | TASK,<br/>RESULT |  | TASK_RESULT_DELETE_PASSED |  | name: unknown | taskResultsPruned | hostName: 24<br/>sourceName: null | DELETE | PASSED | stg-uswest | sailpoint-idn | SYSTEM_CONFIG |



### identitynow-request-grant
***
Grant access request for a single object(access profile or role) for a single user.


#### Base Command

`identitynow-request-grant`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| requested_for | Identity Id for whom the access request is being made. | Required | 
| requested_item | Id of the object(access profile or role). | Required | 
| requested_item_type | Type of object(ACCESS_PROFILE or ROLE). | Required | 
| comment | Comments to attach to the item request. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```
!identitynow-request-grant requested_for=2c9180886ccef167016cdb658fb6547a requested_item=2c918086775e1f5d01776530eb67037b requested_item_type=ACCESS_PROFILE comment=PAN_XSOAR_TEST
```

#### Human Readable Output
Access request was successful!


### identitynow-request-revoke
***
Revoke access request for a single object(access profile or role) for a single user.


#### Base Command

`identitynow-request-revoke`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| requested_for | Identity Id for whom the access request is being made. | Required | 
| requested_item | Id of the object(access profile or role). | Required | 
| requested_item_type | Type of object(ACCESS_PROFILE or ROLE). | Required | 
| comment | Comments to attach to the item request. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```
!identitynow-request-revoke requested_for=2c9180886ccef167016cdb658fb6547a requested_item=2c918086775e1f5d01776530eb67037b requested_item_type=ACCESS_PROFILE comment=PAN_XSOAR_TEST
```

#### Human Readable Output
Access request was successful!
