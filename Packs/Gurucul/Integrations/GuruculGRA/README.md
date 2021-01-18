This is the Gurucul GRA integration for getting started and learn how to build an integration with Cortex XSOAR.
You can check the Design Document of this integration [here](https://docs.google.com/document/d/1wETtBEKg37PHNU8tYeB56M1LE314ux086z3HFeF_cX0).

Please make sure you look at the integration source code and comments.

This integration was built to interact with the sample SOAR Gurucul API To check the API source code go to [GitHub](https://github.com/fvigo/soarGurucul).

## Configure Gurucul on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Gurucul.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | Server URL \(e.g. https://soar.monstersofhack.com\) | True |
| isFetch | Fetch incidents | False |
| incidentType | Incident type | False |
| max_fetch | Maximum number of incidents per fetch | False |
| apikey | API Key | True |
| threshold_ip | Score threshold for ip reputation command \(0\-100\) | False |
| threshold_domain | Score threshold for domain reputation command \(0\-100\) | False |
| alert_status | Fetch alerts with status \(ACTIVE, CLOSED\) | False |
| alert_type | Fetch alerts with type | False |
| min_severity | Minimum severity of alerts to fetch | True |
| first_fetch | First fetch time | False |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### gra-fetch-users
***
Retrieve List of All Users (Identities)


#### Base Command

`gra-fetch-users`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | Page no. | Optional | 
| max | Per page record count | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Gra.Users.firstName | String | First Name. | 
| Gra.Users.middleName | String | Middle Name. | 
| Gra.Users.lastName | String | Last Name. | 
| Gra.Users.employeeId | String | Employee Name. | 
| Gra.Users.riskScore | String | Risk Name. | 
| Gra.Users.department | String | Department. | 
| Gra.Users.email | String | Users email. | 
| Gra.Users.phone | String | Users Phone no. | 
| Gra.Users.location | String | Location. | 
| Gra.Users.manager | String | Users Manager. | 
| Gra.Users.title | String | Users title. | 
| Gra.Users.joiningDate | String | Joining Date. | 
| Gra.Users.exitDate | String | Exit Date. | 



#### Command Example
```!gra-fetch-users page=1 max=25```

#### Context Example
```
[{
  "firstName":"Evan",
  "middleName":null,
  "lastName":"Todd",
  "employeeId":"Galvin.Chavez",
  "riskScore":0,
  "userRisk":0,
  "department":"Legal Department",
  "email":"non.magna@gurucul.corp",
  "phone":"(598) 457-3271",
  "location":"AK",
  "manager":"Asher.Byers",
  "title":"QA",
  "joiningDate":"11/05/2018 05:27:51",
  "exitDate":"08/25/2018 14:58:25",
  "profilePicturePath":null
}]
```

#### Base Command

`gra-fetch-accounts`
***
Retrieve all Accounts Information

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | Page no. | Optional | 
| max | Per page record count | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Gra.Accounts.id | Number | Account Id. | 
| Gra.Accounts.name | String | Account Name. | 
| Gra.Accounts.type | String | Account type. | 
| Gra.Accounts.created_on | Date | Created On. | 
| Gra.Accounts.department | String | Department. | 
| Gra.Accounts.description | String | Description. | 
| Gra.Accounts.resource | String | Resource Name. | 
| Gra.Accounts.domain | String | Domain. | 
| Gra.Accounts.high_risk | String | High Risk. | 
| Gra.Accounts.is_orphan | String | Is Orphan. | 
| Gra.Accounts.is_reassigned | String | Is Reassigned. | 
| Gra.Accounts.risk_score | Number | Risk Score. | 
| Gra.Accounts.updated_on | Date | Updated on. |

#### Command Example
```!gra-fetch-accounts page=1 max=25```

#### Context Example
```
[
    {
      "id":93,
      "name":"Asher.Guthrie",
      "type":null,
      "created_on":"05/16/2019 06:49:18",
      "department":null,
      "description":null,
      "resource":"Windows Security",
      "domain":"in",
      "high_risk":null,
      "is_orphan":"No",
      "is_reassigned":null,
      "risk_score":0,
      "updated_on":null
    }
]
```

#### Human Readable Output

>### Results


### gra-fetch-active-resource-accounts
***
Retrieve List of All Active Accounts for a Given Resource.


#### Base Command

`!gra-fetch-active-resource-accounts`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_name | Resource Name. | Required | 
| page | Page no. | Optional | 
| max | Per page record count | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Gra.Active.Resource.Accounts.id | Number | Account Id. | 
| Gra.Active.Resource.Accounts.name | String | Account Name. | 
| Gra.Active.Resource.Accounts.type | String | Account type. | 
| Gra.Active.Resource.Accounts.created_on | Date | Created On. | 
| Gra.Active.Resource.Accounts.department | String | Department. | 
| Gra.Active.Resource.Accounts.description | String | Description. | 
| Gra.Active.Resource.Accounts.resource | String | Resource Name. | 
| Gra.Active.Resource.Accounts.domain | String | Domain. | 
| Gra.Active.Resource.Accounts.high_risk | String | High Risk. | 
| Gra.Active.Resource.Accounts.is_orphan | String | Is Orphan. | 
| Gra.Active.Resource.Accounts.is_reassigned | String | Is Reassigned. | 
| Gra.Active.Resource.Accounts.risk_score | Number | Risk Score. | 
| Gra.Active.Resource.Accounts.updated_on | Date | Updated on. |

#### Command Example
```!gra-fetch-active-resource-accounts resource_name="Linux"  page=1 max=25```

#### Context Example
```
[
    {
      "id":93,
      "name":"Asher.Guthrie",
      "type":null,
      "created_on":"05/16/2019 06:49:18",
      "department":null,
      "description":null,
      "resource":"Windows Security",
      "domain":"in",
      "high_risk":null,
      "is_orphan":"No",
      "is_reassigned":null,
      "risk_score":0,
      "updated_on":null
    }
]
```

#### Human Readable Output


### gra-fetch-user-accounts
***
 Retrieve List of All Active Accounts and Details for a Given User.


#### Base Command

`gra-fetch-user-accounts`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| employee_id | Employee ID. | Required | 
| page | Page no. | Optional | 
| max | Per page record count | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Gra.User.Accounts.id | Number | User Account Relation Id . | 
| Gra.User.Accounts.name | String | Account Name. | 
| Gra.User.Accounts.type | String | Account Type. | 
| Gra.User.Accounts.created_on | Date | Created On. | 
| Gra.User.Accounts.department | String | Department. | 
| Gra.User.Accounts.description | String | Description. | 
| Gra.User.Accounts.resource | String | Resource Name. | 
| Gra.User.Accounts.domain | String | Domain Name. | 
| Gra.User.Accounts.high_risk | String | High Risk. | 
| Gra.User.Accounts.is_orphan | String | Is Account Orphan. | 
| Gra.User.Accounts.is_reassigned | String | Is account Reassigned. | 
| Gra.User.Accounts.risk_score | String | Account Risk Score. | 
| Gra.User.Accounts.updated_on | Date | Updated On. | 



#### Command Example
```!gra-fetch-user-accounts employee_id="Alec.Holland01_NN"  page=1 max=25```

#### Context Example
```
[{
      "id":35,
      "name":"Alec.Holland01_NN",
      "type":null,
      "created_on":"02/09/2018 10:00:00",
      "department":null,
      "description":null,
      "resource":"IPS",
      "domain":"com",
      "high_risk":null,
      "is_orphan":"No",
      "is_reassigned":null,
      "risk_score":69,
      "updated_on":null
   }]
```

#### Human Readable Output


### gra-fetch-resource-highrisk-accounts
***
Retrieve High Risk Accounts for a Given Resource


#### Base Command

`gra-fetch-resource-highrisk-accounts`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_name | Resource Name. | Required | 
| page | Page no. | Optional | 
| max | Per page record count | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Gra.Resource.Highrisk.Accounts.id | Number | User Account Relation Id . | 
| Gra.Resource.Highrisk.Accounts.name | String | Account Name. | 
| Gra.Resource.Highrisk.Accounts.type | String | Account Type. | 
| Gra.Resource.Highrisk.Accounts.created_on | Date | Created On. | 
| Gra.Resource.Highrisk.Accounts.department | String | Department. | 
| Gra.Resource.Highrisk.Accounts.description | String | Description. | 
| Gra.Resource.Highrisk.Accounts.resource | String | Resource Name. | 
| Gra.Resource.Highrisk.Accounts.domain | String | Domain Name. | 
| Gra.Resource.Highrisk.Accounts.high_risk | String | High Risk. | 
| Gra.Resource.Highrisk.Accounts.is_orphan | String | Is Account Orphan. | 
| Gra.Resource.Highrisk.Accounts.is_reassigned | String | Is account Reassigned. | 
| Gra.Resource.Highrisk.Accounts.risk_score | String | Account Risk Score. | 
| Gra.Resource.Highrisk.Accounts.updated_on | Date | Updated On. | 


#### Command Example
```!gra-fetch-resource-highrisk-accounts resource_name="Windows Security"  page=1 max=25```

#### Context Example
```
[{
      "id":35,
      "name":"Alec.Holland01_NN",
      "type":null,
      "created_on":"02/09/2018 10:00:00",
      "department":null,
      "description":null,
      "resource":"Windows Security",
      "domain":"com",
      "high_risk":null,
      "is_orphan":"No",
      "is_reassigned":null,
      "risk_score":69,
      "updated_on":null
   }]
```

#### Human Readable Output

>### 

### gra-fetch-hpa
***
Retrieve List of All High Risk Privileged Accounts.


#### Base Command

`!gra-fetch-hpa`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | Page no. | Optional | 
| max | Per page record count | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Gra.Hpa.id | Number | User Account Relation Id . | 
| Gra.Hpa.name | String | Account Name. | 
| Gra.Hpa.type | String | Account Type. | 
| Gra.Hpa.created_on | Date | Created On. | 
| Gra.Hpa.department | String | Department. | 
| Gra.Hpa.description | String | Description. | 
| Gra.Hpa.resource | String | Resource Name. | 
| Gra.Hpa.domain | String | Domain Name. | 
| Gra.Hpa.high_risk | String | High Risk. | 
| Gra.Hpa.is_orphan | String | Is Account Orphan. | 
| Gra.Hpa.is_reassigned | String | Is account Reassigned. | 
| Gra.Hpa.risk_score | String | Account Risk Score. | 
| Gra.Hpa.updated_on | Date | Updated On. | 


#### Command Example
```!gra-fetch-hpa  page=1 max=25```

#### Context Example
```
{
      "id":35,
      "name":"Alec.Holland01_NN",
      "type":null,
      "created_on":"02/09/2018 10:00:00",
      "department":null,
      "description":null,
      "resource":"IPS",
      "domain":"com",
      "high_risk":null,
      "is_orphan":"No",
      "is_reassigned":null,
      "risk_score":69,
      "updated_on":null
   }
```

#### Human Readable Output

>### 


### gra-fetch-resource-hpa
***
Retrieve all High Privileged Accounts for a Given Resource.


#### Base Command

`gra-fetch-resource-hpa`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_name | Resource Name. | Required | 
| page | Page no. | Optional | 
| max | Per page record count | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Gra.Resource.Hpa.id | Number | User Account Relation Id . | 
| Gra.Resource.Hpa.name | String | Account Name. | 
| Gra.Resource.Hpa.type | String | Account Type. | 
| Gra.Resource.Hpa.created_on | Date | Created On. | 
| Gra.Resource.Hpa.department | String | Department. | 
| Gra.Resource.Hpa.description | String | Description. | 
| Gra.Resource.Hpa.resource | String | Resource Name. | 
| Gra.Resource.Hpa.domain | String | Domain Name. | 
| Gra.Resource.Hpa.high_risk | String | High Risk. | 
| Gra.Resource.Hpa.is_orphan | String | Is Account Orphan. | 
| Gra.Resource.Hpa.is_reassigned | String | Is account Reassigned. | 
| Gra.Resource.Hpa.risk_score | String | Account Risk Score. | 
| Gra.Resource.Hpa.updated_on | Date | Updated On. | 

#### Command Example
```!gra-fetch-resource-hpa resource_name="Linux"  page=1 max=25```

#### Context Example
```
[{
      "id":2,
      "name":"Jonathan.Osterman01_NN",
      "type":null,
      "created_on":"02/09/2017 10:00:00",
      "department":null,
      "description":null,
      "resource":"Linux",
      "domain":"com",
      "high_risk":null,
      "is_orphan":"No",
      "is_reassigned":null,
      "risk_score":0,
      "updated_on":null
   }]
```

#### Human Readable Output



### gra-fetch-orphan-accounts
***
Retrieve List of All Orphan / Rogue Accounts.


#### Base Command

`gra-fetch-orphan-accounts`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | Page no. | Optional | 
| max | Per page record count | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Gra.Orphan.Accounts.id | Number | User Account Relation Id . | 
| Gra.Orphan.Accounts.name | String | Account Name. | 
| Gra.Orphan.Accounts.type | String | Account Type. | 
| Gra.Orphan.Accounts.created_on | Date | Created On. | 
| Gra.Orphan.Accounts.department | String | Department. | 
| Gra.Orphan.Accounts.description | String | Description. | 
| Gra.Orphan.Accounts.resource | String | Resource Name. | 
| Gra.Orphan.Accounts.domain | String | Domain Name. | 
| Gra.Orphan.Accounts.high_risk | String | High Risk. | 
| Gra.Orphan.Accounts.is_orphan | String | Is Account Orphan. | 
| Gra.Orphan.Accounts.is_reassigned | String | Is account Reassigned. | 
| Gra.Orphan.Accounts.risk_score | String | Account Risk Score. | 
| Gra.Orphan.Accounts.updated_on | Date | Updated On. | 

#### Command Example
```!gra-fetch-orphan-accounts  page=1 max=25```

#### Context Example
```
[{
      "id":2,
      "name":"Jonathan.Osterman01_NN",
      "type":null,
      "created_on":"02/09/2017 10:00:00",
      "department":null,
      "description":null,
      "resource":"Linux",
      "domain":"com",
      "high_risk":null,
      "is_orphan":"No",
      "is_reassigned":null,
      "risk_score":0,
      "updated_on":null
   }]
```

#### Human Readable Output

### gra-fetch-resource-orphan-accounts
***
Retrieve All Orphan / Rogue Accounts for a Given Resource.


#### Base Command

`gra-fetch-resource-orphan-accounts`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_name | Resource Name. | Required | 
| page | Page no. | Optional | 
| max | Per page record count | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Gra.Resource.Orphan.Accounts.id | Number | User Account Relation Id . | 
| Gra.Resource.Orphan.Accounts.name | String | Account Name. | 
| Gra.Resource.Orphan.Accounts.type | String | Account Type. | 
| Gra.Resource.Orphan.Accounts.created_on | Date | Created On. | 
| Gra.Resource.Orphan.Accounts.department | String | Department. | 
| Gra.Resource.Orphan.Accounts.description | String | Description. | 
| Gra.Resource.Orphan.Accounts.resource | String | Resource Name. | 
| Gra.Resource.Orphan.Accounts.domain | String | Domain Name. | 
| Gra.Resource.Orphan.Accounts.high_risk | String | High Risk. | 
| Gra.Resource.Orphan.Accounts.is_orphan | String | Is Account Orphan. | 
| Gra.Resource.Orphan.Accounts.is_reassigned | String | Is account Reassigned. | 
| Gra.Resource.Orphan.Accounts.risk_score | String | Account Risk Score. | 
| Gra.Resource.Orphan.Accounts.updated_on | Date | Updated On. | 


#### Command Example
```!gra-fetch-resource-orphan-accounts resource_name="Windows Security"  page=1 max=25```

#### Context Example
```
[{
      "id":2,
      "name":"Jonathan.Osterman01_NN",
      "type":null,
      "created_on":"02/09/2017 10:00:00",
      "department":null,
      "description":null,
      "resource":"Windows Security",
      "domain":"com",
      "high_risk":null,
      "is_orphan":"No",
      "is_reassigned":null,
      "risk_score":0,
      "updated_on":null
   }]
```

#### Human Readable Output

>### 



### gra-fetch-orphan-accounts
***
Retrieve List of All Orphan / Rogue Accounts.


#### Base Command

`gra-user-activities`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| employee_id | Employee Id. | Required | 
| page | Page no. | Optional | 
| max | Per page record count | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Gra.User.Activity.employee_id | String | Employee Id . | 
| Gra.User.Activity.account_name | String | Account Name . | 
| Gra.User.Activity.resource_name | String | Resource Name . |
| Gra.User.Activity.event_desc | String | Event Description . |
| Gra.User.Activity.event_date | String | Event Date . |
| Gra.User.Activity.risk_score | Number | Risk Score . |

#### Command Example
```!gra-user-activities employee_id="aa17600"  page=1 max=25```

#### Context Example
```
{
"employee_id":"aa17600",
"account_name":null,
"resource_name":"Print",
"event_desc":"Print",
"event_date":"09/02/2019 11:51:14",
"risk_score":0.0
}
```

#### Human Readable Output



### gra-fetch-users-details
***
get details of the user.


#### Base Command

`gra-fetch-users-details`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| employee_id | Employee Id. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Gra.User.firstName | String |  First Name. | 
| Gra.User.middleName | String |  Middle Name. | 
| Gra.User.lastName | String |  Last Name. | 
| Gra.User.employeeId | String |  Employee Id. | 
| Gra.User.riskScore | String |  Risk Score. | 
| Gra.User.userRisk | String |  User Risk. | 
| Gra.User.department | String |  Department. | 
| Gra.User.email | String |  Email. | 
| Gra.User.phone | String | Phone. | 
| Gra.User.location | String | Location . | 
| Gra.User.manager | String |  Manager. | 
| Gra.User.title | String |  Title. | 
| Gra.User.joiningDate | String |  Joining Date. | 
| Gra.User.profilePicturePath | String |  Profile Picture Path. | 


#### Command Example
```!gra-user-activities employee_id="aa17600"  page=1 max=25```

#### Context Example
```
[
  {
    "firstName":"Jonathan",
    "middleName":null,
    "lastName":"Osterman01_NN",
    "employeeId":"Jonathan.Osterman01_NN",
    "riskScore":88,
    "userRisk":88,
    "department":"IT",
    "email":"Jonathan.Osterman@abc.com",
    "phone":"(91)-123-4567-890",
    "location":"USA",
    "manager":"Thor.Odinson01_NN",
    "title":"Sr.Developer",
    "joiningDate":"01/01/2017 12:47:00",
    "exitDate":"12/31/2019 23:47:00",
    "profilePicturePath":null
  }
]
```

#### Human Readable Output



### gra-fetch-users-details
***
get details of the user.


#### Base Command

`gra-highRisk-users`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | Page no. | Optional | 
| max | Per page record count | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Gra.Highrisk.Users.id | Number | User Id . | 
| Gra.Highrisk.Users.name | String |  User Name. | 
| Gra.Highrisk.Users.type | String |  Type. | 
| Gra.Highrisk.Users.created_on | Date | Created On . | 
| Gra.Highrisk.Users.department | String |  Department. | 
| Gra.Highrisk.Users.description | String |  Description. | 
| Gra.Highrisk.Users.resource | String | Resource Name. | 
| Gra.Highrisk.Users.domain | String | Domain. | 
| Gra.Highrisk.Users.high_risk | String | High Risk. | 
| Gra.Highrisk.Users.is_orphan | String | Is Orphan Account . | 
| Gra.Highrisk.Users.is_reassigned | String | Is Reassigned . | 
| Gra.Highrisk.Users.risk_score | String | Risk Score . | 
| Gra.Highrisk.Users.updated_on | Date | Updated On . | 


#### Command Example
```!gra-highRisk-users  page=1 max=25```

#### Context Example
```
[
  {
      "id":188,
      "name":"Vitoria Inger",
      "type":null,
      "created_on":"02/02/2020 10:00:00",
      "department":null,
      "description":"Mozilla/5.0 (Windows NT) AppleWebKit/534.20 (KHTML, like Gecko) Chrome/11.0.672.2 Safari/534.20",
      "resource":"AIX",
      "domain":"163.com",
      "high_risk":null,
      "is_orphan":"No",
      "is_reassigned":null,
      "risk_score":88,
      "updated_on":null
   }
]
```

#### Human Readable Output


### gra-cases
***
get details of the user.


#### Base Command

`gra-cases`
#### Input


| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| status | Case Status. | Required | 
| page | Page no. | Optional | 
| max | Per page record count | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Gra.Cases.entityId | Number | Entity Id . | 
| Gra.Cases.entityTypeId | Number |  Entity Type Id. | 
| Gra.Cases.entity | String |  Entity Name. | 
| Gra.Cases.caseId | Number | Case Id . | 
| Gra.Cases.openDate | Date |  Case Open Date. | 
| Gra.Cases.ownerId | Number |  Owner Id. | 
| Gra.Cases.ownerType | String | Owner Type. | 
| Gra.Cases.ownerName | String | Owner Name. | 
| Gra.Cases.riskDate | Date | Risk Risk. | 
| Gra.Cases.status | String | Case Status . | 


#### Command Example
```!gra-cases status="OPEN" page=1 max=25```

#### Context Example
```
[
 {
      "entityId":366,
      "entityTypeId":2,
      "entity":"Ulises Ellerby",
      "caseId":58,
      "openDate":"10/13/2020 18:44:06",
      "ownerId":1,
      "ownerType":"User",
      "ownerName":"graadmin",
      "riskDate":"10/12/2020 00:00:00",
      "status":"Open"
   }
]
```

#### Human Readable Output

### gra-user-anomalies
***
get details of the user.


#### Base Command

`gra-user-anomalies`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| employee_id | Employee Id. | Required | 
| page | Page no. | Optional | 
| max | Per page record count | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Gra.Anomalies.anomaly_name | String | Anomaly Name . | 


#### Command Example
```!gra-user-anomalies employeeId="AB1234"  page=1 max=25```

#### Context Example
```
[
   {
      "anomaly_name":"SOD_role_13oct"
   }
]
```

#### Human Readable Output

