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
| group_id          | Group ID        | Yes          |
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
| user_id           | User ID         | Yes          |
| page              | Page Number     | No           |
| per_page          | Per Page Amount | No           |

#### Context Output

| **Path**                          | **Type** | **Description**                      |
| --------------------------------- | -------- | ------------------------------------ |
| KMSAT.UsersRiskHistory.risk_score | Number   | Users Risk Score and Associated Date |
| KMSAT.UsersRiskHistory.date       | Date     | Users Risk Score History Date        |

#### Command Example
```!kmsat-users-risk-score-history user_id=1 page=1 per_page=25```

#### Context Example
```json

{
  "risk_score": 37.3,
  "date": "2021-02-07"
}

```

### kmsat-phishing-security-tests

| **Argument Name** | **Description** | **Required** |
| ----------------- | --------------- | ------------ |
| page              | Page Number     | No           |
| per_page          | Per Page Amount | No           |

#### Context Output

| **Path**                                      | **Type** | **Description**                             |
| --------------------------------------------- | -------- | ------------------------------------------- |
| KMSAT.PhishingSecurity.campaign_id            | Number   | Phishing Security Campaign ID               |
| KMSAT.PhishingSecurity.pst_id                 | Number   | Phishing Security PST ID                    |
| KMSAT.PhishingSecurity.status                 | String   | Phishing Security Status                    |
| KMSAT.PhishingSecurity.name                   | String   | Phishing Security Name                      |
| KMSAT.PhishingSecurity.groups.group_id        | Number   | Phishing Security Group ID                  |
| KMSAT.PhishingSecurity.groups.name            | String   | Phishing Security Group Name                |
| KMSAT.PhishingSecurity.phish_prone_percentage | Number   | Phishing Security Phishing Prone Percentage |
| KMSAT.PhishingSecurity.started_at             | Date     | Phishing Security Started at Date           |
| KMSAT.PhishingSecurity.duration               | Number   | Phishing Security Duration                  |
| KMSAT.PhishingSecurity.categories.category_id | Number   | Phishing Security Category ID               |
| KMSAT.PhishingSecurity.categories.name        | String   | Phishing Security Category Name             |
| KMSAT.PhishingSecurity.template.id            | Number   | Phishing Security Template ID               |
| KMSAT.PhishingSecurity.template.name          | String   | Phishing Security Template Name             |
| KMSAT.PhishingSecurity.lading-page.id         | Number   | Phishing Security Landing Page ID           |
| KMSAT.PhishingSecurity.landing-page.name      | String   | Phishing Security Landing Page Name         |
| KMSAT.PhishingSecurity.scheduled_count        | Number   | Phishing Security Scheduled Count           |
| KMSAT.PhishingSecurity.delivered_count        | Number   | Phishing Security Delivered Count           |
| KMSAT.PhishingSecurity.opened_count           | Number   | Phishing Security Opened Count              |
| KMSAT.PhishingSecurity.clicked_count          | Number   | Phishing Security Clicked Count             |
| KMSAT.PhishingSecurity.replied_count          | Number   | Phishing Security Replied Count             |
| KMSAT.PhishingSecurity.attachment_open_count  | Number   | Phishing Security Attachment Open Count     |
| KMSAT.PhishingSecurity.macro_enabled_count    | Number   | Phishing Security Macro Enabled Count       |
| KMSAT.PhishingSecurity.data_entered_count     | Number   | Phishing Security Data Entered Count        |
| KMSAT.PhishingSecurity.qr_code_scanned_count  | Number   | Phishing Security QR Code Scanned Count     |
| KMSAT.PhishingSecurity.reported_count         | Number   | Phishing Security Reported Count            |
| KMSAT.PhishingSecurity.bounced_count          | Number   | Phishing Security Bounced Count             |


#### Command Example
```!kmsat-phishing-security-tests page=1 per_page=25```

#### Context Example
```json

[
  {
    "campaign_id": 3423,
    "pst_id": 16142,
    "status": "Closed",
    "name": "Corporate Test",
    "groups": [
      {
        "group_id": 16342,
        "name": "Corporate Employees"
      }
    ],
    "phish_prone_percentage": 0.5,
    "started_at": "2019-04-02T15:02:38.000Z",
    "duration": 1,
    "categories": [
      {
        "category_id": 4237,
        "name": "Current Events"
      }
    ],
    "template": {
      "id": 11428,
      "name": "CNN Breaking News"
    },
    "landing-page": {
      "id": 1842,
      "name": "SEI Landing Page"
    },
    "scheduled_count": 42,
    "delivered_count": 4,
    "opened_count": 24,
    "clicked_count": 20,
    "replied_count": 0,
    "attachment_open_count": 3,
    "macro_enabled_count": 0,
    "data_entered_count": 0,
    "qr_code_scanned_count": 0,
    "reported_count": 0,
    "bounced_count": 0
  }
]

```

### kmsat-phishing-security-tests-recipients

| **Argument Name** | **Description** | **Required** |
| ----------------- | --------------- | ------------ |
| pst_id            | PST ID          | Yes          |
| page              | Page Number     | No           |
| per_page          | Per Page Amount | No           |

#### Context Output

| **Path**                                       | **Type** | **Description**                        |
| ---------------------------------------------- | -------- | -------------------------------------- |
| KMSAT.PhishingSecurityPST.recipient_id         | Number   | Phishing Security Recipient ID         |
| KMSAT.PhishingSecurityPST.pst_id               | Number   | Phishing Security PST ID               |
| KMSAT.PhishingSecurityPST.user                 | String   | Phishing Security User                 |
| KMSAT.PhishingSecurityPST.template             | String   | Phishing Security Template             |
| KMSAT.PhishingSecurityPST.scheduled_at         | Date     | Phishing Security Scheduled At         |
| KMSAT.PhishingSecurityPST.delivered_at         | Date     | Phishing Security Delivered At         |
| KMSAT.PhishingSecurityPST.opened_at            | Date     | Phishing Security Opened At            |
| KMSAT.PhishingSecurityPST.clicked_at           | Date     | Phishing Security Clicked At           |
| KMSAT.PhishingSecurityPST.replied_at           | Date     | Phishing Security Replied At           |
| KMSAT.PhishingSecurityPST.attachment_opened_at | Date     | Phishing Security Attachment Opened At |
| KMSAT.PhishingSecurityPST.macro_enabled_at     | Date     | Phishing Security Macro Enabled At     |
| KMSAT.PhishingSecurityPST.data_entered_at      | Date     | Phishing Security Data Entered At      |
| KMSAT.PhishingSecurityPST.qr_code_scanned      | Date     | Phishing Security QR Code Scanned      |
| KMSAT.PhishingSecurityPST.reported_at          | Date     | Phishing Security Reported At          |
| KMSAT.PhishingSecurityPST.bounced_at           | Date     | Phishing Security Bounced At           |
| KMSAT.PhishingSecurityPST.ip                   | String   | Phishing Security IP                   |
| KMSAT.PhishingSecurityPST.up_location          | String   | Phishing Security IP Location          |
| KMSAT.PhishingSecurityPST.browser              | String   | Phishing Security Browser              |
| KMSAT.PhishingSecurityPST.browser_version      | String   | Phishing Security Browser Version      |
| KMSAT.PhishingSecurityPST.os                   | String   | Phishing Security OS                   |

#### Command Example
```!kmsat-phishing-security-tests-recipients pst_id=1 page=1 per_page=25```

#### Context Example
```json

[
  {
    "recipient_id": 3077742,
    "pst_id": 14240,
    "user": {
      "id": 264215,
      "provisioning_guid": null,
      "first_name": "Bob",
      "last_name": "Ross",
      "email": "bob.r@kb4-demo.com"
    },
    "template": {
      "id": 2,
      "name": "Your Amazon Order"
    },
    "scheduled_at": "2019-04-02T15:02:38.000Z",
    "delivered_at": "2019-04-02T15:02:38.000Z",
    "opened_at": "2019-04-02T15:02:38.000Z",
    "clicked_at": "2019-04-02T15:02:38.000Z",
    "replied_at": null,
    "attachment_opened_at": null,
    "macro_enabled_at": null,
    "data_entered_at": "2019-04-02T15:02:38.000Z",
    "qr_code_scanned": "2022-05-12T15:29:54.000Z",
    "reported_at": null,
    "bounced_at": null,
    "ip": "XX.XX.XXX.XXX",
    "ip_location": "St.Petersburg, FL",
    "browser": "Chrome",
    "browser_version": "48.0",
    "os": "MacOSX"
  }
]

```

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