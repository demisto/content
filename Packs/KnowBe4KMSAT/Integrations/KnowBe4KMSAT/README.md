**KnowBe4's Security Awareness Training and Simulated Phishing Platform** helps you manage the ongoing problem of social engineering. Find out where your users are in both security knowledge and security culture to help establish baseline security metrics. Regular testing and training helps to mobilize your end users as a last line of defense against threat actors. Pull testing and training results as well as risky users identified by the innovative Virtual Risk Officer, using machine learning to help you predict and identify user, group, and organizational level risks.

| What does this pack do?                                                 |
| ----------------------------------------------------------------------- |
| 1. Gets account-level risk score history                                |
| 2. Gets group-level risk score history                                  |
| 3. Gets user-level risk score history                                   |
| 4. Pulls all phishing test results                                      |
| 5. Pulls phishing test results for a specific campaign                  |
| 6. Pulls training campaign statuses                                     |
| 7. Displays a list of training campaign enrollments                     |
| 8. Allows adding an external event to a user's timeline inside of KMSAT |

## Commands

| Commands                                        | Description                                                            |
| ----------------------------------------------- | ---------------------------------------------------------------------- |
| kmsat-account-info-list                         | Command displays the account information.                              |
| kmsat-account-risk-score-history                | Command lists the accounts risk score history.                         |
| kmsat-groups-risk-score-history                 | Command lists the groups risk score history.                           |
| kmsat-groups-members                            | Command lists the groups members.                                      |
| kmsat-users-risk-score-history                  | Command lists the risk score history for user.                         |
| kmsat-phishing-security-tests                   | Command lists the phishing security tests.                             |
| kmsat-phishing-security-tests-recipients        | Command lists the phishing security tests with recipients data.        |
| kmsat-phishing-security-tests-failed-recipients | Command lists the phishing security tests with failed recipients data. |
| kmsat-phishing-campaign-security-tests          | Command lists campaigns security tests.                                |
| kmsat-training-campaigns                        | Command lists training campaigns.                                      |
| kmsat-training-enrollments                      | Command lists training enrollments.                                    |
| kmsat-user-events-list                          | Command lists the user events.                                         |
| kmsat-user-event-types-list                     | Command lists the user event types.                                    |
| kmsat-user-event-create                         | Command creates a user event.                                          |
| kmsat-user-event-delete                         | Command deletes a user event.                                          |


### kmsat-account-info-list

#### Context Output

| **Path**                                | **Type** | **Description**               |
| --------------------------------------- | -------- | ----------------------------- |
| KMSAT.AccountInfo.name                  | String   | Account Name                  |
| KMSAT.AccountInfo.type                  | String   | Account Type                  |
| KMSAT.AccountInfo.domains               | String   | Account Domains               |
| KMSAT.AccountInfo.admins.id             | Number   | Account Admin ID              |
| KMSAT.AccountInfo.admins.first_name     | String   | Account Admin First Name      |
| KMSAT.AccountInfo.admins.last_name      | String   | Account Admin Last Name       |
| KMSAT.AccountInfo.admins.email          | String   | Account Admin Email           |
| KMSAT.AccountInfo.subscription_email    | String   | Account Subscription Level    |
| KMSAT.AccountInfo.subscription_end_date | Date     | Account Subscription End Date |
| KMSAT.AccountInfo.number_of_seats       | Number   | Number of Seats               |
| KMSAT.AccountInfo.current_risk_score    | Number   | Account Risk Score            |

#### Command Example
```!kmsat-account-info-list```

#### Context Example
```json

{
  "name": "KB4-Demo",
  "type": "paid",
  "domains": [
    "kb4-demo.com"
  ],
  "admins": [
    {
      "id": 974278,
      "first_name": "Grace",
      "last_name": "O'Malley",
      "email": "grace.o@kb4-demo.com"
    }
  ],
  "subscription_level": "Diamond",
  "subscription_end_date": "2021-03-06",
  "number_of_seats": 25,
  "current_risk_score": 45.742
}

```


### kmsat-account-risk-score-history

| **Argument Name** | **Description** | **Required** |
| ----------------- | --------------- | ------------ |
| page              | Page Number     | No           |
| per_page          | Per Page Amount | No           |

#### Context Output

| **Path**                                 | **Type** | **Description**                        |
| ---------------------------------------- | -------- | -------------------------------------- |
| KMSAT.AccountRiskScoreHistory.risk_score | String   | Account Risk Score And Associated Date |
| KMSAT.AccountRiskScoreHistory.date       | Date     | Account Risk Score History Date        |

#### Command Example
```!kmsat-account-risk-score-history page=1 per_page=25```

#### Context Example
```json

{
  "risk_score": 37.3,
  "date": "2021-02-07"
}

```

### kmsat-groups-risk-score-history

| **Argument Name** | **Description** | **Required** |
| ----------------- | --------------- | ------------ |
| group_id          | Group ID        | No           |
| page              | Page Number     | No           |
| per_page          | Per Page Amount | No           |

#### Context Output

| **Path**                               | **Type** | **Description**                       |
| -------------------------------------- | -------- | ------------------------------------- |
| KMSAT.GroupRiskScoreHistory.risk_score | String   | Groups Risk Score And Associated Date |
| KMSAT.GroupRiskHistory.date            | Date     | Groups Risk Score History Date        |

#### Command Example
```!kmsat-groups-risk-score-history page=1 per_page=25```

#### Context Example
```json

{
  "risk_score": 37.3,
  "date": "2021-02-07"
}

```

### kmsat-groups-members

| **Argument Name** | **Description** | **Required** |
| ----------------- | --------------- | ------------ |
| group_id          | Group ID        | No           |
| page              | Page Number     | No           |
| per_page          | Per Page Amount | No           |

#### Context Output

| **Path**                                   | **Type** | **Description**                      |
| ------------------------------------------ | -------- | ------------------------------------ |
| KMSAT.GroupsMembers.id                     | Number   | Groups Member ID                     |
| KMSAT.GroupsMembers.employee_number        | String   | Groups Member Employee Number        |
| KMSAT.GroupsMembers.first_name             | String   | Groups Member First Name             |
| KMSAT.GroupsMembers.last_name              | String   | Groups Member Last Name              |
| KMSAT.GroupsMembers.job_title              | String   | Groups Member Job title              |
| KMSAT.GroupsMembers.email                  | String   | Groups Member Email                  |
| KMSAT.GroupsMembers.phish_prone_percentage | Number   | Groups Member Phish Prone Percentage |
| KMSAT.GroupsMembers.phone_number           | String   | Groups Member Phone Number           |
| KMSAT.GroupsMembers.extension              | String   | Groups Member Extension              |
| KMSAT.GroupsMembers.mobile_phone_number    | String   | Groups Member Phone Number           |
| KMSAT.GroupsMembers.location               | String   | Groups Member Location               |
| KMSAT.GroupsMembers.division               | String   | Groups Member Division               |
| KMSAT.GroupsMembers.manager_name           | String   | Groups Member Manager Name           |
| KMSAT.GroupsMembers.provisioning_managed   | Boolean  | Groups Member Manager Email          |
| KMSAT.GroupsMembers.provisioning_guid      | Unknown  | Groups Member Provisioning GUID      |
| KMSAT.GroupsMembers.groups                 | Number   | Groups Member Groups                 |
| KMSAT.GroupsMembers.current_risk_score     | Number   | Groups Member Current Risk Score     |
| KMSAT.GroupsMembers.aliases                | String   | Groups Member Aliases                |
| KMSAT.GroupsMembers.joined_on              | Date     | Groups Member Joined On              |
| KMSAT.GroupsMembers.last_sign_in           | Date     | Groups Member Last Sign In           |
| KMSAT.GroupsMembers.status                 | String   | Groups Member Status                 |
| KMSAT.GroupsMembers.organization           | String   | Groups Member Organization           |
| KMSAT.GroupsMembers.department             | String   | Groups Member Department             |
| KMSAT.GroupsMembers.language               | String   | Groups Member Language               |
| KMSAT.GroupsMembers.comment                | String   | Groups Member Comment                |
| KMSAT.GroupsMembers.employee_start_date    | Date     | Groups Member Employee Start Date    |
| KMSAT.GroupsMembers.archived_at            | Date     | Groups Member Archived At            |
| KMSAT.GroupsMembers.custom_field_1         | String   | Groups Member Custom Field 1         |
| KMSAT.GroupsMembers.custom_field_2         | String   | Groups Member Custom Field 2         |
| KMSAT.GroupsMembers.custom_field_3         | String   | Groups Member Custom Field 3         |
| KMSAT.GroupsMembers.custom_date_1          | Date     | Groups Member Custom Date 1          |
| KMSAT.GroupsMembers.custom_date_2          | Date     | Groups Member Custom Date 2          |

#### Command Example
```!kmsat-groups-members group_id=1 page=1 per_page=25```

#### Context Example
```json

{
  "id": 667542,
  "employee_number": "19425",
  "first_name": "William",
  "last_name": "Marcoux",
  "job_title": "VP of Sales",
  "email": "wmarcoux@kb4-demo.com",
  "phish_prone_percentage": 14.235,
  "phone_number": "555-554-2222",
  "extension": "42",
  "mobile_phone_number": "555-553-4422",
  "location": "Office A",
  "division": "Sales",
  "manager_name": "Michael Scott",
  "manager_email": "mscott@kb4-demo.com",
  "provisioning_managed": false,
  "provisioning_guid": null,
  "groups": [
    3264
  ],
  "current_risk_score": 45.742,
  "aliases": [
    "alias_email@kb4-demo.com"
  ],
  "joined_on": "2019-04-02T15:02:38.000Z",
  "last_sign_in": "2019-04-02T15:02:38.000Z",
  "status": "active",
  "organization": "KB4-Demo",
  "department": "Sales",
  "language": "English - United States",
  "comment": "Low PPP",
  "employee_start_date": "2019-04-02T15:02:38.000Z",
  "archived_at": null,
  "custom_field_1": "Building C, 4th Floor",
  "custom_field_2": null,
  "custom_field_3": null,
  "custom_field_4": null,
  "custom_date_1": "1986-11-26",
  "custom_date_2": null
}

```

### kmsat-users-risk-score-history

| **Argument Name** | **Description** | **Required** |
| ----------------- | --------------- | ------------ |

### kmsat-phishing-security-tests

| **Argument Name** | **Description** | **Required** |
| ----------------- | --------------- | ------------ |

### kmsat-phishing-security-tests-recipients

| **Argument Name** | **Description** | **Required** |
| ----------------- | --------------- | ------------ |

### kmsat-phishing-security-tests-failed-recipients

| **Argument Name** | **Description** | **Required** |
| ----------------- | --------------- | ------------ |

### kmsat-phishing-campaign-security-tests

| **Argument Name** | **Description** | **Required** |
| ----------------- | --------------- | ------------ |

### kmsat-training-campaigns

| **Argument Name** | **Description** | **Required** |
| ----------------- | --------------- | ------------ |

### kmsat-training-enrollments

| **Argument Name** | **Description** | **Required** |
| ----------------- | --------------- | ------------ |

### kmsat-user-events-list

| **Argument Name** | **Description** | **Required** |
| ----------------- | --------------- | ------------ |

### kmsat-user-event-types-list

| **Argument Name** | **Description** | **Required** |
| ----------------- | --------------- | ------------ |

### kmsat-user-event-create

| **Argument Name** | **Description** | **Required** |
| ----------------- | --------------- | ------------ |

### kmsat-user-event-delete

| **Argument Name** | **Description** | **Required** |
| ----------------- | --------------- | ------------ |