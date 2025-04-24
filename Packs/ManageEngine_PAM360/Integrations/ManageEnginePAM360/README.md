Use ManageEngine PAM360, a privileged access management solution to manage critical enterprise data such as privileged resources and accounts and secure credentials from Cortex XSOAR.

## Configure ManageEngine PAM360 in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | Server URL \(e.g., https://localhost:8282\) | True |
| APP_TOKEN | Token to access PAM360 vault | True |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### pam360-create-resource
***
Creates a new resource.


#### Base Command

`pam360-create-resource`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_name | Denotes the name of the resource. | Required | 
| resource_type | Denotes the type of the resource. | Required | 
| resource_url | Denotes the URL of the resource. | Optional | 
| domain_name | Denotes the domain name of the resource.| Optional |
| resourcegroup_name | Name of the resource group to which this resource belongs. | Optional |
| owner_name | Denotes the name of the resource owner. | Optional |
| location | Denotes the location of the resource. | Optional |
| dnsname | Denotes either the DNS Name or the IP address. | Optional |
| department | The department to which the account belongs. | Optional | 
| resource_descritpion | Description of the resource. | Optional |
| notes | Optional additional notes added about the resource.| Optional |
| account_name | Denotes the name of the account. | Required |
| password | Denotes the password of the account.| Required |
| resource_password_policy | The type of password policy set for the resource. | Optional |
| account_password_policy | The type of password policy set for the account. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PAM360.Resource.operation.result.status | String | Status of the operation. |
| PAM360.Resource.operation.result.message | String | Command execution status. |


#### Command Example
```!pam360-create-resource resource_name="SOUTH-FIN-WINSERQA-09" resource_type="Windows" resource_url="https://remote-win-serv:8285/adminhome" domain_name="SOUTH-FIN-WINSERQA-09" resourcegroup_name="Remote Windows Servers" owner_name="admin" location="Plaza - South Wing" dnsname="SOUTH-FIN-WINSERQA-09" department="Finance" resource_description="Windows server resources reserved for testing API" notes="Windows server resources reserved for testing API" account_name="administrator" password="QA!K>35Hgg(x" resource_password_policy="Strong" account_password_policy="Strong"```

#### Context Example
```
{
   "operation":{
      "result":{
         "message":"Resource SOUTH-FIN-WINSERQA-09 has been added successfully",
         "status":"Success"
      },
      "name":"CREATE RESOURCE"
   }
}
```
### pam360-create-account
***
Creates a new account under a specified resource.


#### Base Command

`pam360-create-account`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_id | Denotes the ID of the resource. | Required | 
| account_name | Name of the account. | Required | 
| password | Account password. | Required | 
| notes | Account description. | Optional |
| account_password_policy | The type of password policy set for the account.  | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PAM360.Account.operation.result.status | String | Status of the operation. |
| PAM360.Account.operation.result.message | String | Command execution status. |


#### Command Example
```!pam360-create-account resource_id=1 account_name="admin" password="t8BRq)<6h9g1" notes="Windows server resources reserved for testing API" account_password_policy="Strong"```

#### Context Example
```
{
   "operation":{
      "result":{
         "message":"Account(s) added successfully",
         "status":"Success"
      },
      "Details":[
         {
            "admin":{
               "STATUS":"Account added successfully"
            }
         }
      ],
      "name":"ADD ACCOUNTS"
   }
```
### pam360-update-resource
***
Updates the attributes of a resource such as name, type, URL, and description.


#### Base Command

`pam360-update-resource`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_id | Denotes the ID of the resource. | Required | 
| resource_name | Name of the resource. | Required | 
| resource_type | Type of the resource. | Optional | 
| resource_url | URL of the resource. | Optional |
| resource_description | Description of the resource. | Optional |
| resource_password_policy | The type of password policy set for the resource. | Optional |
| location | Location of the resource. | Optional |
| dnsname | Denotes either the DNS Name or the IP address. | Optional |
| department | The department to which the account belongs. | Optional | 
| owner_name | Name of the resource owner. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PAM360.Resource.operation.result.status | String | Status of the operation. |
| PAM360.Resource.operation.result.message | String | Command execution status. |


#### Command Example
```!pam360-update-resource resource_id=1 resource_name="SOUTH-FIN-WINSERQA-09" resource_type="Windows" resource_url="https://remote-win-serv:8285/adminhome" resource_description="Windows server resources reserved for testing API" resource_password_policy="Strong" location="Plaza - South Wing" department="Finance" dnsname="SOUTH-FIN-WINSERQA-09" owner_name="admin"```

#### Context Example
```
{
   "operation":{
      "result":{
         "message":"Resource  modified successfully.",
         "status":"Success"
      },
      "name":"EDIT RESOURCE"
   }
}
```
### pam360-update-account
***
Updates the attributes an account such as name, password policy, and notes if applicable.


#### Base Command

`pam360-update-account`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_id | Denotes the ID of the resource. | Required | 
| account_id | Denotes the ID of the account. | Required | 
| account_name | Name of the account. | Required | 
| owner_name | Name of the account owner. | Optional |
| notes | Optional additional notes added about the account. | Optional |
| account_password_policy | The type of password policy set for the account. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PAM360.Account.operation.result.status | String | Status of the operation. |
| PAM360.Account.operation.result.message | String | Command execution status. |


#### Command Example
```!pam360-update-account resource_id=1 account_id=1 account_name="admin" owner_name="admin" notes="Windows server resources reserved for testing API" account_password_policy="Strong"```

#### Context Example
```
{
   "operation":{
      "result":{
         "message":"Account admin modified successfully",
         "status":"Success"
      },
      "name":"EDIT ACCOUNT"
   }
}
```
### pam360-list-all-resources
***
Lists all resources owned by you and shared to you by other users.


#### Base Command

`pam360-list-all-resources`


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PAM360.Resource.operation.result.status | String | Status of the operation. |
| PAM360.Resource.operation.result.message | String | Command execution status. |
| PAM360.Resource.operation.Details.RESOURCE DESCRIPTION | String | Description of the resource. |
| PAM360.Resource.operation.Details.RESOURCE TYPE | String | Denotes the type of the resource. |
| PAM360.Resource.operation.Details.RESOURCE ID | String | Denotes the ID of the resource. |
| PAM360.Resource.operation.Details.RESOURCE NAME | String | Name of the resource. |
| PAM360.Resource.operation.Details.NOOFACCOUNTS | String | The number of accounts associated with the resource. |


#### Command Example
```!pam360-list-all-resources```

#### Context Example
```
{
   "operation":{
      "result":{
         "message":"Resources fetched successfully",
         "status":"Success"
      },
      "Details":[
         {
            "RESOURCE DESCRIPTION":"Windows server resources reserved for testing API",
            "RESOURCE TYPE":"Fortigate Firewall",
            "RESOURCE ID":"1",
            "RESOURCE NAME":"SOUTH-FIN-WINSERQA-09",
            "NOOFACCOUNTS":"1"
         }
      ],
      "name":"GET RESOURCES",
      "totalRows":1
   }
}
```
### pam360-list-all-accounts
***
Lists all accounts belonging to the resource.


#### Base Command

`pam360-list-all-accounts`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_id | ID of the resource. | Required |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PAM360.Account.operation.result.status | String | Status of the operation. |
| PAM360.Account.operation.result.message | String | Command execution status. |
| PAM360.Account.operation.Details.LOCATION | String | Location of the account. |
| PAM360.Account.operation.Details.RESOURCE DESCRIPTION | String | Description of the resource. |
| PAM360.Account.operation.Details.RESOURCE TYPE | String | Refers to the resource type assigned to the account. |
| PAM360.Account.operation.Details.RESOURCE ID | String | Denotes the ID of the resource. |
| PAM360.Account.operation.Details.DEPARTMENT | String | The department to which the account belongs. |
| PAM360.Account.operation.Details.RESOURCE OWNER | String | Refers to the name of the resource owner. |
| PAM360.Account.operation.Details.RESOURCE PASSWORD POLICY | String | The password policy of the resource to which the account belongs. |
| PAM360.Account.operation.Details.RESOURCE URL | String | The URL of the resource. |
| PAM360.Account.operation.Details.DOMAIN NAME | String | The domain name of the resource. |
| PAM360.Account.operation.Details.RESOURCE NAME | String | The name of the resource to which the account belongs. |
| PAM360.Account.operation.Details.DNS NAME | String | The DNS name of the resource. |
| PAM360.Account.operation.Details.ACCOUNT LIST.ACCOUNT ID | String | Denotes the ID of the account. |
| PAM360.Account.operation.Details.ACCOUNT LIST.ACCOUNT NAME | String | Denotes the name of the account. |
| PAM360.Account.operation.Details.ACCOUNT LIST.PASSWORD STATUS | String | Refers to the availability status of the password. Denotes whether the password is available for check-out or in use by another user. |
| PAM360.Account.operation.Details.ACCOUNT LIST.ACCOUNT PASSWORD POLICY | String | The type of password policy set for the account. |
| PAM360.Account.operation.Details.ACCOUNT LIST.PASSWDID | String | Refers to the Account ID required to perform password-based operations. |
| PAM360.Account.operation.Details.ACCOUNT LIST.ISREASONREQUIRED | String | Refers to the reason provided to access the password. |


#### Command Example
```!pam360-list-all-accounts resource_id=1```

#### Context Example
```
{
   "operation":{
      "result":{
         "message":"Resource details with account list fetched successfully",
         "status":"Success"
      },
      "Details":{
         "LOCATION":"Plaza - South Wing",
         "RESOURCE DESCRIPTION":"Windows server resources reserved for testing API",
         "RESOURCE TYPE":"Fortigate Firewall",
         "RESOURCE ID":"1",
         "ACCOUNT LIST":[
            {
               "ISFAVPASS":"false",
               "ACCOUNT ID":"1",
               "AUTOLOGONLIST":[
                  "SSH",
                  "Telnet"
               ],
               "ACCOUNT NAME":"administrator",
               "PASSWORD STATUS":"****",
               "ISREMOTEAPPONLY":"false",
               "ACCOUNT PASSWORD POLICY":"Strong",
               "AUTOLOGONSTATUS":"One of the resources or landing servers is configured to be connected repeatedly. Check your landing server configuration or contact your administrator.",
               "IS_TICKETID_REQD_ACW":"false",
               "PASSWDID":"1",
               "IS_TICKETID_REQD_MANDATORY":"false",
               "IS_TICKETID_REQD":"false",
               "ISREASONREQUIRED":"false"
            }
         ],
         "DEPARTMENT":"Finance",
         "RESOURCE OWNER":"admin",
         "RESOURCE PASSWORD POLICY":"Strong",
         "RESOURCE URL":"https://pam360:8282",
         "NEWSSHTERMINAL":"false",
         "DOMAIN NAME":"SOUTH-FIN-WINSERQA-09",
         "ALLOWOPENURLINBROWSER":"true",
         "RESOURCE NAME":"SOUTH-FIN-WINSERQA-09",
         "DNS NAME":"SOUTH-FIN-WINSERQA-09"
      },
      "name":"GET RESOURCE ACCOUNTLIST"
   }
}
```
### pam360-fetch-account-details
***
Fetches the details of an account using the corresponding account ID.


#### Base Command

`pam360-fetch-account-details`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_id | Denotes the ID of the resource. | Required | 
| account_id | Denotes the ID of the account. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PAM360.Account.operation.result.status | String | Status of the operation. |
| PAM360.Account.operation.result.message | String | Command execution status.|
| PAM360.Account.operation.Details.DESCRIPTION | String | Description of the account. |
| PAM360.Account.operation.Details.PASSWDID | String | Account ID that is used to perform password-related operations. |
| PAM360.Account.operation.Details.LAST MODIFIED TIME | String | The time at which the account was last modified. |
| PAM360.Account.operation.Details.EXPIRY STATUS | String | Denotes the expiry status of the account password. |
| PAM360.Account.operation.Details.COMPLIANT REASON | String | Reason for the password not being compliant with the password policy. |
| PAM360.Account.operation.Details.PASSWORD STATUS | String | Refers to the availability status of the password. Denotes whether the password is available for check-out or in use by another user. |
| PAM360.Account.operation.Details.PASSWORD POLICY | String | The type of password policy set for the account. |
| PAM360.Account.operation.Details.COMPLIANT STATUS | String | Status of whether the account password is compliant with the password policy for it. |
| PAM360.Account.operation.Details.LAST ACCESSED TIME | String | The time at which the account was last accessed. |


#### Command Example
```!pam360-fetch-account-details resource_id=1 account_id=1```

#### Context Example
```
{
   "operation":{
      "result":{
         "message":"Account details fetched successfully",
         "status":"Success"
      },
      "Details":{
         "DESCRIPTION":"N/A",
         "PASSWDID":"1",
         "LAST MODIFIED TIME":"N/A",
         "EXPIRY STATUS":"Valid",
         "COMPLIANT REASON":"-",
         "PASSWORD STATUS":"****",
         "PASSWORD POLICY":"Strong",
         "COMPLIANT STATUS":"Compliant",
         "LAST ACCESSED TIME":"Dec 1, 2021 09:00 PM"
      },
      "name":"GET RESOURCE ACCOUNT DETAILS"
   }
}
```
### pam360-fetch-resource-account-id
***
Fetches the IDs of the resources and accounts.


#### Base Command

`pam360-fetch-resource-account-id`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_name | Denotes the name of the resource. | Required |
| account_name | Denotes the name of the account. | Required |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PAM360.Resource.operation.result.status | String | Status of the operation. |
| PAM360.Resource.operation.result.message | String | Command execution status.|
| PAM360.Resource.operation.Details.RESOURCEID | String | Denotes the ID of a resource. |
| PAM360.Resource.operation.Details.ACCOUNTID | String | Denotes the ID of an account. |


#### Command Example
```!pam360-fetch-resource-account-id resource_name=SOUTH-FIN-WINSERQA-09 account_name=admin```

#### Context Example
```
{
   "operation":{
      "result":{
         "message":"Resource ID and account ID fetched successfully for the given resource name and account name.",
         "status":"Success"
      },
      "Details":{
         "ACCOUNTID":"1",
         "RESOURCEID":"1"
      },
      "name":"GET_RESOURCEACCOUNTID"
   }
}
```
### pam360-fetch-password
***
Fetches the account password using the Resource and Account IDs.


#### Base Command

`pam360-fetch-password`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_id | Denotes the ID of a resource. | Required | 
| account_id | Denotes the ID of an account. | Required | 
| reason | The reason provided to request for the password of an account. | Optional | 
| ticket_id | Valid ticket ID required when the ticketing system integration is enabled. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PAM360.Account.operation.Details.PASSWORD | String | Account password. |
| PAM360.Account.operation.result.status | String | Status of the operation. |
| PAM360.Account.operation.result.message | String | Command execution status. |


#### Command Example
```!pam360-fetch-password resource_id=1 account_id=1 reason="Need the password to log in to the Windows Server for testing purposes." ticket_id=7```

#### Context Example
```
{
   "operation":{
      "result":{
         "message":"Password fetched successfully",
         "status":"Success"
      },
      "Details":{
         "PASSWORD":"A1@8ZnQx)mh&="
      },
      "name":"GET PASSWORD"
   }
}
```
### pam360-update-account-password
***
Updates the account password.


#### Base Command

`pam360-update-account-password`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_id | Denotes the ID of the resource. | Required |
| account_id | Denotes the ID of the account. | Required |
| new_password | Password to be updated. | Required |
| reset_type | Refers to the type of password reset to be done - LOCAL or REMOTE. | Required |
| reason | Refers to the reason provided to update the password of an account. | Optional |
| ticket_id | Valid ticket ID required when the ticketing system integration is enabled.| Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PAM360.Account.operation.result.status | String | Status of the operation. |
| PAM360.Account.operation.result.message | String | Command execution status. |


#### Command Example
```!pam360-update-account-password resource_id=1 account_id=1 new_password="A8>ne3J&0Z" reset_type="local" reason="Password Expired" ticket_id=7```

#### Context Example
```
{
   "operation":{
      "result":{
         "message":"Password changed successfully",
         "status":"Success"
      },
      "name":"CHANGE PASSWORD"
   }
}
```