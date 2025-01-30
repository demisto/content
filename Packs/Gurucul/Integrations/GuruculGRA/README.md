[Gurucul Risk Analytics (GRA)](https://gurucul.com/gurucul-risk-analytics-gra) is a data science backed cloud native platform that predicts, detects and prevents breaches. It ingests and analyzes massive amounts of data from the network, IT systems, cloud platforms, EDR, applications, IoT, HR and much more to give you a comprehensive contextual view of user and entity behaviors This Integration facilitates retrieval of High Risk Entities identified by GRA by creating a case for each entity within GRA. These high risk entities are fetched in Cortex XSOAR and a corresponding incident is created for each entity in Cortex XSOAR. As a part of this integration, workflows can be configured at Cortex XSOAR based on different commands provided by GRA. These will define the actions to be taken on a particular high risk entity based on the Risk Score.

Please make sure you look at the integration source code and comments.

## Configure Gurucul in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | Server URL \(e.g. `https://soar.monstersofhack.com`\) | True |
| apikey | API Key | True |
| isFetch | Fetch incidents | False |
| Classifier| Classifier for incident|False|
| IncidentType | Incident type | False |
| Mapper | Mapping incoming data|False|
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |
| first_fetch | First fetch time | False |
| max_fetch | Maximum number of incidents per fetch | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
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
| Gra.Users.userRisk | String | User Risk. | 



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
      "name":"user1",
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
      "name":"user1",
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
      "name":"user1",
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
| Gra.User.exitDate | Date |  Exit Date. | 


#### Command Example
```!gra-user-activities employee_id="aa17600"  page=1 max=25```

#### Context Example
```
[
  {
    "firstName":"Jonathan",
    "middleName":null,
    "lastName":"Osterman01_NN",
    "employeeId":"user1",
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
| Gra.Highrisk.Users.updated_on | Date | Updated On . | 
| Gra.Highrisk.Users.exitDate | Date | Exit Date . | 
| Gra.Highrisk.Users.created_on | Date | Created On . | 
| Gra.Highrisk.Users.joiningDate | Date | Joining Date . | 
| Gra.Highrisk.Users.manager | String | Manager . | 
| Gra.Highrisk.Users.employeeId | String | Employee Id . | 
| Gra.Highrisk.Users.firstName | String | First Name . | 
| Gra.Highrisk.Users.middleName | String | Middle Name . | 
| Gra.Highrisk.Users.lastName | String | Last Name . | 
| Gra.Highrisk.Users.location | String | Location . | 
| Gra.Highrisk.Users.title | String | Title . | 
| Gra.Highrisk.Users.userRisk | Number | User Risk . | 
| Gra.Highrisk.Users.riskScore | Number | Risk Score . | 
| Gra.Highrisk.Users.description | String | Description . | 
| Gra.Highrisk.Users.is_orphan | String | Is Orphan . | 
| Gra.Highrisk.Users.phone | String | Phone . | 
| Gra.Highrisk.Users.email | String | Email . | 


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
| Gra.Cases.anomalies | String | Anomalies . | 

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
| Gra.User.Anomalies.anomaly_name | String | Anomaly Name . | 


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


### gra-case-action
***
Closing a case and updating the anomaly status as Closed / Risk Managed / Model Reviewed.

#### Base Command

`gra-case-action`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| action | Action | Required | 
| caseId | Case ID | Required | 
| subOption | Sub Option | Required | 
| caseComment | Case Comment | Required | 
| riskAcceptDate | Risk Accept Date (applicable only in case of closing a case as Risk Managed) | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Gra.Case.Action.Message | String | Message  | 


#### Command Example
```!gra-case-action action=modelReviewCase caseId=5 subOption="Tuning Required" caseComment="This is Completed"```

#### Context Example
```
[
  {
    "Message": "1 Anomalies in this case closed successfully."
  }
]
```

#### Human Readable Output

### gra-case-action-anomaly
***
Closing an anomaly or anomalies within a case and updating the anomaly status as Closed / Risk Managed / Model Reviewed.

#### Base Command

`gra-case-action-anomaly`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| action | Action | Required | 
| caseId | Case ID | Required | 
| anomalyNames | Anomaly Names | Required | 
| subOption | Sub Option | Required | 
| caseComment | Case Comment | Required | 
| riskAcceptDate | Risk Accept Date (applicable only in case of closing a case as Risk Managed) | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Gra.Case.Action.Anomaly.Message | String | Message  | 
| Gra.Case.Action.Anomaly.anomalyName | String | Anomaly Name | 


#### Command Example
```!gra-case-action-anomaly action=modelReviewCaseAnomaly caseId=5 anomalyNames=anomalyName1 subOption="Tuning Required" caseComment="This is Completed"```

#### Context Example
```
[
  {
    "Message": {
      "anomalyName1": "Anomaly risk accepted successfully."
    }
  }
]
```

#### Human Readable Output


### gra-investigate-anomaly-summary
***
Retrieve detailed anomaly summary of specified anomaly name.

#### Base Command

`gra-investigate-anomaly-summary`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| modelName | Model Name | Required | 
| fromDate | From Date ( yyyy-MM-dd ) | Optional | 
| toDate | To Date ( yyyy-MM-dd ) | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Gra.Investigate.Anomaly.Summary.analyticalFeatures | String | Analytical Features  | 
| Gra.Investigate.Anomaly.Summary.entityCount | String | Entity Count | 
| Gra.Investigate.Anomaly.Summary.resourceCount | String | Resource Count | 
| Gra.Investigate.Anomaly.Summary.records | String | Records | 
| Gra.Investigate.Anomaly.Summary.anomalyBaseline | String | Anomaly Baseline | 
| Gra.Investigate.Anomaly.Summary.anomalyLastCatch | String | Anomaly Last Catch | 
| Gra.Investigate.Anomaly.Summary.executionDays | String | Execution Days | 
| Gra.Investigate.Anomaly.Summary.chainDetails | String | Chain Details | 
| Gra.Investigate.Anomaly.Summary.resourceName | String | resourceName | 
| Gra.Investigate.Anomaly.Summary.type | String | type | 
| Gra.Investigate.Anomaly.Summary.value | String | value | 
| Gra.Investigate.Anomaly.Summary.anomalousActivity | Number | anomalousActivity | 
| Gra.Investigate.Anomaly.Summary.anomalyName | String | anomalyName | 
| Gra.Investigate.Anomaly.Summary.classifier | String | classifier | 
| Gra.Investigate.Anomaly.Summary.anomalyFirstCatch | String | anomalyFirstCatch | 
| Gra.Investigate.Anomaly.Summary.anomalyDescription | String | anomalyDescription | 
| Gra.Investigate.Anomaly.Summary.similarTemplateAnomalies | String | Similar Template Anomalies | 
| Gra.Investigate.Anomaly.Summary.entitiesFlagged | Number | Entities Flagged |  


#### Command Example
```!gra-investigate-anomaly-summary modelName=ModelName```

#### Context Example
```
{
  "analyticalFeatures": {
    "eventdesc": 8
  },
  "entityCount": "466",
  "resourceCount": "4",
  "records": {
    "anomalyBaseline": "Baseline period is not configured.",
    "anomalyLastCatch": "2020-12-06 10:00:59",
    "executionDays": "null",
    "chainDetails": [
      {
        "resourceName": "resourceName",
        "type": "model",
        "value": "modelName"
      }
    ],
    "anomalousActivity": 0,
    "anomalyName": "modelName",
    "classifier": "Categories -> Categories Name, Categories -> Default, Resources -> resourceName",
    "anomalyFirstCatch": "2020-11-08 12:15:00",
    "anomalyDescription": "This template can be used to create models using the saved search query."
  },
  "similarTemplateAnomalies": {
    "anomaly1": 442,
    "anomaly2": 4,
    "anomaly3": 4,
    "anomaly4": 21,
    "anomaly5": 8,
    "anomaly6": 1
  },
  "entitiesFlagged": 0
}
```

#### Human Readable Output


### gra-analytical-features-entity-value
***
Retrieve analytical features for specified entity value and model name.

#### Base Command

`gra-analytical-features-entity-value`

#### Input

| **Argument Name** | **Description**                 | **Required** |
|-------------------|---------------------------------| --- |
| entityValue       | Entity Value                    | Required | 
| modelName         | Model Name                      | Required | 
| fromDate          | From Date ( yyyy-MM-dd )        | Optional | 
| toDate            | To Date ( yyyy-MM-dd )          | Optional | 
| entityTypeId      | Entity Type Id (defaulted to 1) | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Gra.Analytical.Features.Entity.Value.analyticalFeatures | String | Analytical Features  | 
| Gra.Analytical.Features.Entity.Value.analyticalFeatureValues | String | Analytical Feature Values | 


#### Command Example
```!gra-analytical-features-entity-value entityValue=EntityValue```

#### Context Example
```
{
    "analyticalFeatures": {
        "analyticalFeature1": 7,
        "analyticalFeature2": 1,
        "analyticalFeature3": 0
    },
    "analyticalFeatureValues": {
        "analyticalFeature1": {
            "analyticalFeature1a": 2,
            "analyticalFeature1b": 1,
            "analyticalFeature1c": 1
        },
        "analyticalFeature2": {
            "analyticalFeature2a": 6
        },
        "analyticalFeature3": {
            "analyticalFeature3a": 13,
            "analyticalFeature3b": 6
        }
    }
}
```

#### Human Readable Output
 
### gra-cases-anomaly
***
Retrieve anomalies for specified case id from GRA and update in XSOAR.

#### Base Command

`gra-cases-anomaly`

#### Input

| **Argument Name** | **Description** | **Required** |
|-------------------|-----------------| --- |
| caseId            | GRA Case Id     | Required | 

#### Context Output

| **Path**                             | **Type** | **Description**    |
|--------------------------------------|----------|--------------------|
| Gra.Cases.anomalies.anomalyName      | String   | Cases Anomaly name | 
| Gra.Cases.anomalies.riskAcceptedDate | date     |Risk accepted date of anomaly|
| Gra.Cases.anomalies.resourceName     | String   |Resource Name|
|Gra.Cases.anomalies.riskScore| String|Risk score for anomaly|
|Gra.Cases.anomalies.assignee| String |Assignee name|
|Gra.Cases.anomalies.assigneeType| String |Assignee type (User/Role)|
|Gra.Cases.anomalies.status| String |Current status of anomaly|


#### Command Example
```!gra-cases-anomaly caseId=10```

#### Context Example
```
[
    {
        "anomalyName": "Anomaly Name 1",
        "riskAcceptedDate": "2023-02-01T18:30:00Z",
        "resourceName": "Resource Name 1",
        "riskScore": 0,
        "assignee": "Assignee 1",
        "assigneeType": "User",
        "status": "Open"
    },
    {
        "anomalyName": "Anomaly Name 2",
        "riskAcceptedDate": null,
        "resourceName": "Resource Name 2",
        "riskScore": 0,
        "assignee": "Assignee 2",
        "assigneeType": "User",
        "status": "Closed"
    }
]
```

#### Human Readable Output
### gra-validate-api
***
Verifies the Gurucul platform's operational status by assessing system health, reviewing logs, and checking key performance indicators for any errors.

#### Base Command

`gra-validate-api`

#### Command Example
```!gra-validate-api```

#### Context Example
```
ok
```

#### Human Readable Output

