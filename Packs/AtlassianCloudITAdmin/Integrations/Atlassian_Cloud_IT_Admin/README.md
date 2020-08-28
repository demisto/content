1.	Get / Retrieve user information from Atlassian Cloud
2.	Create a user in Atlassian Cloud
3.	Update a user in Atlassian Cloud 
4.	Disable a user in Atlassian Cloud
5.	Enable a user in Atlassian Cloud
This integration was integrated and tested with version xx of Atlassian Cloud IT Admin
## Configure Atlassian Cloud IT Admin on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Atlassian Cloud IT Admin.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | Atlassian URL \(e.g. https://example.net\) | True |
| token | token | True |
| directoryId | Directory Id | True |
| customMappingCreateUser | Custom Mapping For Create User | False |
| customMappingUpdateUser | Custom Mapping For Update User | False |
| proxy | Use system proxy settings | False |
| insecure | Trust any certificate \(not secure\) | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### get-user
***
Retrieve the user details based on id or username.


#### Base Command

`get-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scim | SCIM User JSON with id or email populated. User?s id or userName will be used for lookup. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GetUser | unknown | Command context path | 
| GetUser.status | boolean | User status, set to one of the following values:  trueor false | 
| GetUser.brand | string | User's brand name. | 
| GetUser.details | string | Gives the user information if the API is success else error information | 
| GetUser.email  | string | User'3s email address.  | 
| GetUser.errorCode  | number | Error code in the case of exception.  Example: 404 | 
| GetUser.errorMessage  | string | Error message in the case of exception. Example: ?User not Found? | 
| GetUser.id  | string | User's id  | 
| GetUser.instanceName | string | Instance name for the Integration. | 
| GetUser.success | boolean | Success status. Can be True or False | 


#### Command Example
```!get-user scim="{\"userName\":\"testxsoar@paloaltonetworks.com\"}" using=Atlassian```

#### Context Example
```
{
    "GetUser": {
        "active": null,
        "brand": "Atlassian Cloud Admin",
        "details": {
            "code": 401,
            "message": "Unauthorized"
        },
        "email": null,
        "errorCode": 401,
        "errorMessage": null,
        "id": null,
        "instanceName": "Atlassian",
        "success": false,
        "username": "testxsoar@paloaltonetworks.com"
    }
}
```

#### Human Readable Output

>### Get Atlassian User:
>|brand|instanceName|success|username|errorCode|details|
>|---|---|---|---|---|---|
>| Atlassian Cloud Admin | Atlassian | false | testxsoar@paloaltonetworks.com | 401 | code: 401<br/>message: Unauthorized |


### create-user
***
This command creates the user based on the scim and custom map passed in argument.


#### Base Command

`create-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scim | SCIM content in JSON format | Required | 
| customMapping | An optional custom mapping that takes custom values in the SCIM data into the integration. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CreateUser | Unknown | Command context path | 
| CreateUser.brand | string | Name of the Integration | 
| CreateUser.instanceName | string | Name of the instance used for testing | 
| CreateUser.success | boolean | Status of the result. Can be true or false. | 
| CreateUser.active | boolean | Gives the active status of user. Can be true of false.  | 
| CreateUser.id | number | Value of id passed as argument | 
| CreateUser.email | string | Value of email ID passed as argument | 
| CreateUser.errorCode | number | HTTP error response code  | 
| CreateUser.errorMessage | string | Reason why the API is failed | 
| CreateUser.details | string | Gives the user information if the API is success else error information | 


#### Command Example
```!create-user scim="{\"userName\":\"testxsoar1@paloaltonetworks.com\",\"emails\":[{\"value\":\"testxsoar1@paloaltonetworks.com\",\"type\":\"work\",\"primary\":true}],\"name\":{\"familyName\":\"test\",\"givenName\":\"xsoar\"},\"displayName\": \"xsoar test\",\"title\": \"Staff IT Systems Engineer\",\"active\":true}" using=Atlassian```

#### Context Example
```
{
    "CreateUser": {
        "active": null,
        "brand": "Atlassian Cloud Admin",
        "details": {
            "code": 401,
            "message": "Unauthorized"
        },
        "email": "testxsoar1@paloaltonetworks.com",
        "errorCode": 401,
        "errorMessage": null,
        "id": null,
        "instanceName": "Atlassian",
        "success": false,
        "username": "testxsoar1@paloaltonetworks.com"
    }
}
```

#### Human Readable Output

>### Create Atlassian User:
>|brand|instanceName|success|username|email|errorCode|details|
>|---|---|---|---|---|---|---|
>| Atlassian Cloud Admin | Atlassian | false | testxsoar1@paloaltonetworks.com | testxsoar1@paloaltonetworks.com | 401 | code: 401<br/>message: Unauthorized |


### update-user
***
Update a user


#### Base Command

`update-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| oldScim | Old SCIM content in JSON format | Required | 
| newScim | New SCIM content in JSON format | Required | 
| customMapping | An optional custom mapping that takes custom values in the SCIM data into the integration. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| UpdateUser | Unknown | Command context path | 
| UpdateUser.brand | string | Name of the Integration | 
| UpdateUser.instanceName | string | Name of the instance used for testing | 
| UpdateUser.success | boolean | Status of the result. Can be true or false. | 
| UpdateUser.active | boolean | Gives the active status of user. Can be true of false.  | 
| UpdateUser.id | string | Value of id passed as argument | 
| UpdateUser.email | string | Value of email ID passed as argument | 
| UpdateUser.errorCode | number | HTTP error response code | 
| UpdateUser.errorMessage | string |  Reason why the API is failed | 
| UpdateUser.details | string | Gives the user information if the API is success else error information | 


#### Command Example
```!update-user oldScim="{\"id\":\"14f7379a-bc91-4b03-90c7-5c4fac68fc4e\"}" newScim="{\"active\":true,\"addresses\":[{\"country\":\"US\",\"locality\":\"Santa Clara\",\"postalCode\":\"950541\",\"primary\":true,\"region\":\"California\",\"streetAddress\":\"3000 Tannery Way\"}],\"displayName\":\"R B\",\"emails\":[{\"type\":\"home\",\"value\":\"test34Aug@paloaltonetworks.com\"}],\"externalId\":\"rbilgundi11@paloaltonetworks.com\",\"name\":{\"familyName\":\"B1199\",\"givenName\":\"R1199\"},\"phoneNumbers\":[{\"type\":\"work\",\"value\":\"+1 (480) 249245911\"},{\"type\":\"mobile\",\"value\":\"+1 (480) 249245911\"}],\"title\":\"Staff IT Systems Engineer\",\"urn:scim:schemas:extension:custom:1.0:user\":{\"active\":\"true\",\"adpassociateid\":\"N1XLLDZQD\",\"city\":\"Santa Clara\",\"costcenter\":\"IT Infrastructure\",\"costcentercode\":\"419100\",\"country\":\"US\",\"countrycodenumber\":\"840\",\"countryname\":\"United States Of America\",\"department\":\"IT:IT Excluding Info Security\",\"directorflag\":\"N\",\"directorflagnumber\":\"0\",\"displayname\":\"Rashmi Bilgundi\",\"email\":\"rbilgundi111@paloaltonetworks.com\",\"employeeid\":\"107602\",\"employeetype\":\"Regular\",\"employmentstatus\":\"Active\",\"exceedlmscode\":\"107602\",\"exceedlmsorganizationid\":2702,\"execadminflag\":\"N\",\"externalid\":\"adeb05c1cac7019a4fc25f573f708321111\",\"firstname\":\"Rashmi11\",\"hiredate\":\"11/29/2017\",\"jobcode\":\"640411\",\"jobfamily\":\"It Systems Engineer\",\"jobfunction\":\"Information Technology Function\",\"lastname\":\"Bilgundi\",\"leadership\":\"No\",\"location\":\"Office - USA - CA - Headquarters\",\"locationregion\":\"Americas\",\"managementlevel1\":\"Nikesh Arora\",\"managementlevel2\":\"Naveen Zutshi\",\"managementlevel3\":\"Pradeep Singh\",\"managementlevel4\":\"Bibu Mohapatra\",\"manageremail\":\"bmohapatra@paloaltonetworks.com\",\"managername\":\"Bibu Mohapatra\",\"mobilephone\":\"+1 (480) 2492459\",\"orglevel1\":\"G\\u0026A\",\"orglevel2\":\"IT\",\"orglevel3\":\"IT Excluding Info Security\",\"peoplemanagerflag\":\"N\",\"prehireflag\":\"False\",\"prismaclouddemo1roleid\":\"e1b37eda-49e1-4513-babe-7f066ac5db40\",\"prismaclouddemo2roleid\":\"25296d45-c7d5-4434-8a7b-14b31f3d0b8d\",\"prismacloudtimezone\":\"America/Los_Angeles\",\"regularemployeeflag\":\"Y\",\"samaccountname\":\"rbilgundi\",\"snowlocationregion\":\"Americas\",\"snowpeoplemanagerflag\":\"false\",\"sourceoftruth\":\"Workday\",\"state\":\"California\",\"streetaddress\":\"3000 Tannery Way\",\"suporglevel1\":\"Nikesh Arora\",\"suporglevel2\":\"Naveen Zutshi\",\"suporglevel3\":\"Pradeep Singh\",\"suporglevel4\":\"Bibu Mohapatra\",\"title\":\"Staff IT Systems Engineer\",\"trafficlightprotocol\":\"RED\",\"userName\":\"testAug62020@paloaltonetworks.com\",\"usertype\":\"EMPLOYEE\",\"vpflag\":\"N\",\"workcountrycode\":\"US\",\"workcountrycodenumber\":\"840\",\"workphone\":\"+1 (480) 2492459\",\"zipcode\":\"95054\"},\"userName\":\"qwerty@paloaltonetworks.com\",\"userType\":\"EMPLOYEE\"}" using=Atlassian```

#### Context Example
```
{
    "UpdateUser": {
        "active": null,
        "brand": "Atlassian Cloud Admin",
        "details": {
            "code": 401,
            "message": "Unauthorized"
        },
        "email": null,
        "errorCode": 401,
        "errorMessage": null,
        "id": "14f7379a-bc91-4b03-90c7-5c4fac68fc4e",
        "instanceName": "Atlassian",
        "success": false,
        "username": null
    }
}
```

#### Human Readable Output

>### Updated Atlassian User:
>|brand|instanceName|success|id|errorCode|details|
>|---|---|---|---|---|---|
>| Atlassian Cloud Admin | Atlassian | false | 14f7379a-bc91-4b03-90c7-5c4fac68fc4e | 401 | code: 401<br/>message: Unauthorized |


### disable-user
***
This command disables the user.


#### Base Command

`disable-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scim | SCIM User JSON with user_id whose user details needs to be removed. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DisableUser | Unknown | Command context path | 
| DisableUser.status | boolean | User status, set to one of the following values:  | 
| DisableUser.brand | string | User's brand name. | 
| DisableUser.details | string | User?s details including id, email, firtsName, lastName, groupAdmin etc. | 
| DisableUser.email  | string | User's email address.  | 
| DisableUser.errorCode  | number | Error code in the case of exception.  Example: 404 | 
| DisableUser.errorMessage  | string | Error message in the case of exception. Example: ?User not Found? | 
| DisableUser.Users.id  | string | User's id  | 
| DisableUser.instanceName | string | Instance name for the Integration. | 
| DisableUser.success | boolean | Success status. Can be True or False | 


#### Command Example
```!disable-user scim="{\"id\":\"253bcde1-6269-4b33-ade9-ec49e26f6ecd\"}" using=Atlassian```

#### Context Example
```
{
    "DisableUser": {
        "active": null,
        "brand": "Atlassian Cloud Admin",
        "details": {
            "code": 401,
            "message": "Unauthorized"
        },
        "email": null,
        "errorCode": 401,
        "errorMessage": null,
        "id": "253bcde1-6269-4b33-ade9-ec49e26f6ecd",
        "instanceName": "Atlassian",
        "success": false,
        "username": null
    }
}
```

#### Human Readable Output

>### Delete Atlassian User
>|brand|instanceName|success|id|errorCode|details|
>|---|---|---|---|---|---|
>| Atlassian Cloud Admin | Atlassian | false | 253bcde1-6269-4b33-ade9-ec49e26f6ecd | 401 | code: 401<br/>message: Unauthorized |


### enable-user
***
This command enables the user.


#### Base Command

`enable-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scim | SCIM content in JSON format | Required | 
| customMapping | An optional custom mapping that takes custom values in the SCIM data into the integration. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| EnableUser | Unknown | Command context path | 
| EnableUser.brand | string | Name of the Integration | 
| EnableUser.instanceName | string | Name of the instance used for testing | 
| EnableUser.success | boolean | Status of the result. Can be true or false. | 
| EnableUser.active | boolean | Gives the active status of user. Can be true of false.  | 
| EnableUser.id | string | Value of id passed as argument | 
| EnableUser.email | string | Value of email ID passed as argument | 
| EnableUser.errorCode | number | HTTP error response code  | 
| EnableUser.errorMessage | string | Reason why the API is failed | 
| EnableUser.details | string | Gives the user information if the API is success else error information | 


#### Command Example
```!enable-user scim="{\"id\":\"253bcde1-6269-4b33-ade9-ec49e26f6ecd\"}" using=Atlassian```

#### Context Example
```
{
    "EnableUser": {
        "active": null,
        "brand": "Atlassian Cloud Admin",
        "details": {
            "code": 401,
            "message": "Unauthorized"
        },
        "email": null,
        "errorCode": 401,
        "errorMessage": null,
        "id": "253bcde1-6269-4b33-ade9-ec49e26f6ecd",
        "instanceName": "Atlassian",
        "success": false,
        "username": null
    }
}
```

#### Human Readable Output

>### Enable Atlassian User
>|brand|instanceName|success|id|errorCode|details|
>|---|---|---|---|---|---|
>| Atlassian Cloud Admin | Atlassian | false | 253bcde1-6269-4b33-ade9-ec49e26f6ecd | 401 | code: 401<br/>message: Unauthorized |

