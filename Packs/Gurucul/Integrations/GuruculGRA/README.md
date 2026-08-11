[Gurucul Risk Analytics (GRA)](https://gurucul.com/gurucul-risk-analytics-gra) is a data science backed cloud native platform that predicts, detects and prevents breaches. It ingests and analyzes massive amounts of data from the network, IT systems, cloud platforms, EDR, applications, IoT, HR and much more to give you a comprehensive contextual view of user and entity behaviors. This integration fetches GRA Incidents or Alerts into Cortex XSOAR and exposes War Room commands for investigation and actions.  Workflows can be configured in Cortex XSOAR based on the commands provided by GRA.

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
| fetch_type | What to import from GRA (`Incidents` or `Alerts`). Cases are no longer fetched. Use a separate instance for Alerts. | False |

### Fetch setup (Incidents vs Alerts)

Use two integration instances when you need both types:

| Instance | Fetch type | Classifier | Mapper (incoming) | Incident type |
| --- | --- | --- | --- | --- |
| Incidents | Incidents | GRAIncident-Classifier | GRAIncident-Mapper | GRAIncident |
| Alerts | Alerts | GRAAlert-Classifier | GRAAlert-Mapper | GRAAlert |

The integration defaults are the Incident classifier and mapper. On an Alerts instance, change Classifier, Mapper, and Incident type to the Alert values above so fields and layouts map correctly.

## Upgrading from Case fetch (2.1.0)

If you already run a Gurucul instance that fetched **Cases**, update carefully so fetch does not run with the wrong type/classifier mid-upgrade:

1. **Disable** **Fetches incidents** on the existing Cases instance (or disable the instance).
2. **Update** the Gurucul pack to **2.1.0** (Marketplace or demisto-sdk upload).
3. Open the same instance and set:
   - **Fetch type** = `Incidents`
   - **Classifier** = `GRAIncident-Classifier`
   - **Mapper (incoming)** = `GRAIncident-Mapper`
   - **Incident type** = `GRAIncident`
4. Save, then **re-enable** fetch.

Notes:

- Existing **GRACase** incidents in XSOAR remain; use `gra-case-*` commands for actions on them. Cases are no longer fetched.
- If the instance last-run still has `maxCaseId` and no `maxIncidentId`, that Case cursor is reused as `maxIncidentId` so the first Incident fetch does not date-bootstrap from **First fetch time**.
- For Alerts, create a **separate** instance using the Alerts row in the table above.

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

### gra-incidents

***
Retrieve list of GRA incidents for a specified status.

#### Base Command

`gra-incidents`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| status | Incident Status. | Required |
| page | Page no. | Optional |
| max | Per page record count | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Gra.Incidents.incidentId | Number | Incident Id. |
| Gra.Incidents.entity | String | Entity Name. |
| Gra.Incidents.status | String | Status. |
| Gra.Incidents.openDate | Date | Open Date. |
| Gra.Incidents.anomalies | String | Anomalies. |

#### Command Example

```!gra-incidents status="OPEN" page=1 max=25```

#### Human Readable Output

### gra-incident-action

***
Close a GRA incident and update anomaly status as Closed / Risk Managed / Model Reviewed.

#### Base Command

`gra-incident-action`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| action | Action (closeIncident, modelReviewIncident, riskManageIncident). | Required |
| incidentId | Incident Id. | Required |
| subOption | Sub Option. | Required |
| incidentComment | Incident Comment. | Required |
| riskAcceptDate | Risk Accept Date in yyyy-MM-dd format (riskManageIncident only). | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Gra.Incident.Action.Message | String | Message. |

#### Command Example

```!gra-incident-action action=closeIncident incidentId=5 subOption="True Incident" incidentComment="Closed from XSOAR"```

#### Human Readable Output

### gra-incident-action-anomaly

***
Close anomalies within a GRA incident.

#### Base Command

`gra-incident-action-anomaly`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| action | Action (closeIncidentAnomaly, modelReviewIncidentAnomaly, riskAcceptIncidentAnomaly). | Required |
| incidentId | Incident Id. | Required |
| anomalyNames | Anomaly Names. | Required |
| subOption | Sub Option. | Required |
| incidentComment | Incident Comment. | Required |
| riskAcceptDate | Risk Accept Date in yyyy-MM-dd format (riskAcceptIncidentAnomaly only). | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Gra.Incident.Action.Anomaly.Message | String | Message. |

#### Command Example

```!gra-incident-action-anomaly action=closeIncidentAnomaly incidentId=5 anomalyNames=anomalyName1 subOption="True Incident" incidentComment="Done"```

#### Human Readable Output

### gra-incidents-anomaly

***
Retrieve anomalies for a specified GRA incident id.

#### Base Command

`gra-incidents-anomaly`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incidentId | GRA Incident Id. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Gra.Incidents.anomalies.anomalyName | String | Incident Anomaly name. |
| Gra.Incidents.anomalies.status | String | Current status of anomaly. |
| Gra.Incidents.anomalies.resourceName | String | Resource Name. |
| Gra.Incidents.anomalies.assignee | String | Assignee name. |
| Gra.Incidents.anomalies.assigneeType | String | Assignee type (User/Role). |
| Gra.Incidents.anomalies.riskScore | Number | Risk score for anomaly. |
| Gra.Incidents.anomalies.riskAcceptedDate | Date | Risk accepted date of anomaly. |

#### Command Example

```!gra-incidents-anomaly incidentId=10```

#### Human Readable Output

### gra-alerts

***
Retrieve list of GRA alerts for a specified status and date range.

#### Base Command

`gra-alerts`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| status | Status (OPEN, CLOSED, IN PROGRESS, ALL). | Required |
| startDate | Start Date (yyyy-MM-dd HH:mm:ss). | Required |
| endDate | End Date (yyyy-MM-dd HH:mm:ss). | Required |
| page | Page no. | Optional |
| max | Per page record count | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Gra.Alerts.alertId | Number | Alert Id. |
| Gra.Alerts.anomalyName | String | Anomaly Name. |
| Gra.Alerts.entity | String | Entity. |
| Gra.Alerts.statusName | String | Status. |
| Gra.Alerts.detectionTimestamp | Date | Detection Timestamp. |
| Gra.Alerts.severity | Number | Severity. |
| Gra.Alerts.riskScore | Number | Risk Score. |
| Gra.Alerts.resourceName | String | Resource Name. |
| Gra.Alerts.graweblink | String | GRA Weblink. |

#### Command Example

```!gra-alerts status="OPEN" startDate="2026-01-01 00:00:00" endDate="2026-12-31 23:59:59" page=1 max=25```

#### Human Readable Output

### gra-alert-get

***
Retrieve a single GRA alert by id.

#### Base Command

`gra-alert-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Alert Id. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Gra.Alert.alertId | Number | Alert Id. |
| Gra.Alert.anomalyName | String | Anomaly Name. |
| Gra.Alert.entity | String | Entity. |
| Gra.Alert.statusName | String | Status. |
| Gra.Alert.analyticalFeatures | String | Analytical Features. |
| Gra.Alert.graweblink | String | GRA Weblink. |

#### Command Example

```!gra-alert-get id=101```

#### Human Readable Output

### gra-alert-action

***
Perform an action on a GRA alert (close, assign, in progress, comment).

#### Base Command

`gra-alert-action`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| action | Action (closeAlert, inProgressAlert, assignAlert, addCommentOnAlert). | Required |
| alertId | Alert Id. | Required |
| alertComment | Alert Comment. | Required |
| incidentType | Incident or Not An Incident (closeAlert). | Optional |
| subStatus | Close sub-status (closeAlert). | Optional |
| assigneeType | Assignee type (assignAlert). | Optional |
| assigneeName | Assignee name (assignAlert). | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Gra.Alert.Action.Message | String | Message. |

#### Command Example

```!gra-alert-action action=closeAlert alertId=101 alertComment="Closed" incidentType="Incident" subStatus="True Positive"```

#### Human Readable Output

### gra-alert-comment

***
Add a comment on a GRA alert (thin wrapper for addCommentOnAlert).

#### Base Command

`gra-alert-comment`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alertId | Alert Id. | Required |
| alertComment | Alert Comment. | Required |

#### Command Example

```!gra-alert-comment alertId=101 alertComment="Investigating"```

#### Human Readable Output

### gra-alert-assign

***
Assign a GRA alert (thin wrapper for assignAlert).

#### Base Command

`gra-alert-assign`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alertId | Alert Id. | Required |
| assigneeType | Assignee type. | Required |
| assigneeName | Assignee name. | Required |
| alertComment | Alert Comment. | Optional |

#### Command Example

```!gra-alert-assign alertId=101 assigneeType=GRA_USER assigneeName="Yuki.Jacob" alertComment="Assigning via XSOAR"```

#### Human Readable Output

### gra-alert-in-progress

***
Mark a GRA alert in progress (thin wrapper for inProgressAlert).

#### Base Command

`gra-alert-in-progress`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alertId | Alert Id. | Required |
| alertComment | Alert Comment. | Optional |

#### Command Example

```!gra-alert-in-progress alertId=101 alertComment="Working this alert"```

#### Human Readable Output

### gra-alert-update-history

***
Retrieve update history for a GRA alert.

#### Base Command

`gra-alert-update-history`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alertId | Alert Id. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Gra.Alert.History.alertDetails | String | Alert history details. |

#### Command Example

```!gra-alert-update-history alertId=101```

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
