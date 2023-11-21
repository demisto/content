**KnowBe4's KMSAT Console** is a security awareness training and simulated phishing console that you can use to improve your organization's overall security. This integration pack allows you to push and pull your external data to and from your KMSAT console.

| What Does This Pack Do?                                                 |
| ----------------------------------------------------------------------- |
| 1. Pull Risk Score history for your account                             |
| 2. Pull Risk Score history for your groups                              |
| 3. Pull Risk Score history for your users                               |
| 4. Pull all Phishing Security Test (PST) results for your account       |
| 5. Pull Phishing Security Test (PST) results for a specific campaign    |
| 6. Pull statuses of your training campaigns                             |
| 7. Pull a list of your users’ training campaign enrollments             |
| 8. Pull your users’ event data                                          |
| 9. Add events to User Timelines in KMSAT                                |
| 10. Delete events from User Timelines in KMSAT                          |

## Configuration

| Parameter                   | Description | Requirement  |
| --------------------------- | ----------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Instance Name               | Enter a name for your KMSAT instance.                                                                                                                                                              | Required    |
| Your Reporting  Server URL  | Enter the Reporting Server URL for your KMSAT instance, which you can find in KnowBe4’s [Reporting API](https://developer.knowbe4.com/rest/reporting#tag/Base-URL) documentation.                  | Required    |
| Reporting API Key           | Enter the Reporting API key to use for the connection. To generate this key, see KnowBe4’s [Account Settings: API](https://support.knowbe4.com/hc/en-us/articles/12769050560403#API) documentation.| Required    |
| Your User Events Server URL | Enter the User Event URL for your KMSAT instance, which you can find in KnowBe4’s [User Event API](https://developer.knowbe4.com/rest/userEvents#tag/Base-URL) documentation.                      | Required    |
| User Events API Key         | Enter the User Event API key to use for the connection. To generate this key, see KnowBe4’s [User Event API](https://support.knowbe4.com/hc/en-us/articles/360024863474) documentation.            | Required    |

## Commands

| Commands                                             | Description                                                            |
| ---------------------------------------------------- | ---------------------------------------------------------------------- |
| kmsat-account-info-list                              | Displays account information                                           |
| kmsat-account-risk-score-history-list                | Displays your organization’s Risk Score history                        |
| kmsat-groups-list                                    | Displays all groups                                                    |
| kmsat-groups-risk-score-history-list                 | Displays Risk Score history for groups                                 |
| kmsat-groups-members-list                            | Displays members of groups                                             |
| kmsat-users-risk-score-history-list                  | Displays Risk Score history for users                                  |
| kmsat-phishing-security-tests-list                   | Displays all PSTs                                                      |
| kmsat-phishing-security-tests-recipients-list        | Displays PSTs and user data for enrolled users                         |
| kmsat-phishing-security-tests-failed-recipients-list | Displays failed PSTs and user data for enrolled users                  |
| kmsat-phishing-campaign-security-tests-list          | Displays PSTs for a phishing campaign                                  |
| kmsat-training-campaigns-list                        | Displays all training campaigns                                        |
| kmsat-training-enrollments-list                      | Displays all training enrollments                                      |
| kmsat-user-event-list                                | Displays a user event by id                                            |
| kmsat-user-events-list                               | Displays all user events                                               |
| kmsat-user-event-types-list                          | Displays types of user events                                          |
| kmsat-user-event-create                              | Creates an event on the User Timeline                                  |
| kmsat-user-event-delete                              | Deletes an event from the User Timeline                                |
| kmsat-user-event-status-list                         | Lists the status of user event request by request id                   |
| kmsat-user-event-statuses-list                       | Lists the statuses of user event requests                              |


### kmsat-account-info-list

#### Context Output

| **Path**                                | **Type** | **Description**               |
| --------------------------------------- | -------- | ----------------------------- |
| KMSAT.AccountInfo.name                  | String   | Account name                  |
| KMSAT.AccountInfo.type                  | String   | Account type                  |
| KMSAT.AccountInfo.domains               | String   | Account domains               |
| KMSAT.AccountInfo.admins.id             | Number   | Account admin ID              |
| KMSAT.AccountInfo.admins.first_name     | String   | Account admin first name      |
| KMSAT.AccountInfo.admins.last_name      | String   | Account admin last name       |
| KMSAT.AccountInfo.admins.email          | String   | Account admin email address   |
| KMSAT.AccountInfo.subscription_email    | String   | Account subscription level    |
| KMSAT.AccountInfo.subscription_end_date | Date     | Account subscription end date |
| KMSAT.AccountInfo.number_of_seats       | Number   | Number of account seats       |
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
      "email": "example5@kb4-demo.com"
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
| KMSAT.AccountRiskScoreHistory.risk_score | String   | Account Risk Score and associated date |
| KMSAT.AccountRiskScoreHistory.date       | Date     | Account Risk Score history date        |

#### Command Example
```!kmsat-account-risk-score-history-list  page=1 per_page=25```

#### Context Example
```json

{
  "risk_score": 37.3,
  "date": "2021-02-07"
}

```

### kmsat-groups-list

### kmsat-account-risk-score-history

| **Argument Name** | **Description** | **Requirement** |
| ----------------- | --------------- | --------------- |
| page              | Page Number     | Optional        |
| per_page          | Per Page Amount | Optional        |


#### Context Output

| **Path**                        | **Type** | **Description**            |
| ------------------------------- | -------- | -------------------------- |
| KMSAT.Groups.id                 | Number   | Group ID                   |
| KMSAT.Groups.name               | String   | Group name                 |
| KMSAT.Groups.group_type         | String   | Group type                 |
| KMSAT.Groups.provisioning_guid  | String   | Group provisioning GUID    |
| KMSAT.Groups.member_count       | Number   | Group member count         |
| KMSAT.Groups.current_risk_score | Number   | Group's current Risk Score |
| KMSAT.Groups.status             | String   | Groups status              |


#### Command Example
```!kmsat-groups-list page=1 per_page=25```

#### Context Example
```json

{
  "id": 3142,
  "name": "Customer Service",
  "group_type": "console_group",
  "provisioning_guid": "abc12345-6789-abc-1234-456789abc123",
  "member_count": 42,
  "current_risk_score": 45.742,
  "status": "active"
}

```


### kmsat-groups-risk-score-history

| **Argument Name** | **Description** | **Requirement** |
| ----------------- | --------------- | --------------- |
| group_id          | Group ID        | Optional        |
| page              | Page number     | Optional        |
| per_page          | Amount per page | Optional        |

#### Context Output

| **Path**                               | **Type** | **Description**                       |
| -------------------------------------- | -------- | ------------------------------------- |
| KMSAT.GroupRiskScoreHistory.risk_score | String   | Group Risk Score And associated date  |
| KMSAT.GroupRiskHistory.date            | Date     | Group Risk Score history date         |

#### Command Example
```!kmsat-groups-risk-score-history-list page=1 per_page=25```

#### Context Example
```json

{
  "risk_score": 37.3,
  "date": "2021-02-07"
}

```

### kmsat-groups-members

| **Argument Name** | **Description** | **Requirement** |
| ----------------- | --------------- | ------------ |
| group_id          | Group ID        | Required          |
| page              | Page Number     | Optional          |
| per_page          | Per Page Amount | Optional          |

#### Context Output

| **Path**                                   | **Type** | **Description**                      |
| ------------------------------------------ | -------- | ------------------------------------ |
| KMSAT.GroupsMembers.id                     | Number   | User's ID                            |
| KMSAT.GroupsMembers.employee_number        | String   | User's employee number               |
| KMSAT.GroupsMembers.first_name             | String   | User's first name                    |
| KMSAT.GroupsMembers.last_name              | String   | User's last name                     |
| KMSAT.GroupsMembers.job_title              | String   | User's job title                     |
| KMSAT.GroupsMembers.email                  | String   | User's email address                 |
| KMSAT.GroupsMembers.phish_prone_percentage | Number   | User's Phish-prone Percentage        |
| KMSAT.GroupsMembers.phone_number           | String   | User's phone number                  |
| KMSAT.GroupsMembers.extension              | String   | User's extension                     |
| KMSAT.GroupsMembers.mobile_phone_number    | String   | User's phone number                  |
| KMSAT.GroupsMembers.location               | String   | User's location                      |
| KMSAT.GroupsMembers.division               | String   | User's division                      |
| KMSAT.GroupsMembers.manager_name           | String   | Name of user's manager               |
| KMSAT.GroupsMembers.provisioning_managed   | Boolean  | Email address of user's manager      |
| KMSAT.GroupsMembers.provisioning_guid      | Unknown  | User’s provisioning GUID             |
| KMSAT.GroupsMembers.groups                 | Number   | User's groups                        |
| KMSAT.GroupsMembers.current_risk_score     | Number   | User’s current Risk Score            |
| KMSAT.GroupsMembers.aliases                | String   | User's aliases                       |
| KMSAT.GroupsMembers.joined_on              | Date     | User created at                      |
| KMSAT.GroupsMembers.last_sign_in           | Date     | User's last login                    |
| KMSAT.GroupsMembers.status                 | String   | User's status                        |
| KMSAT.GroupsMembers.organization           | String   | User's organization                  |
| KMSAT.GroupsMembers.department             | String   | User's department                    |
| KMSAT.GroupsMembers.language               | String   | User's language                      |
| KMSAT.GroupsMembers.comment                | String   | User comment                         |
| KMSAT.GroupsMembers.employee_start_date    | Date     | User's employee start date           |
| KMSAT.GroupsMembers.archived_at            | Date     | User archived at                     |
| KMSAT.GroupsMembers.custom_field_1         | String   | User custom field 1                  |
| KMSAT.GroupsMembers.custom_field_2         | String   | User custom field 2                  |
| KMSAT.GroupsMembers.custom_field_3         | String   | User custom field 3                  |
| KMSAT.GroupsMembers.custom_date_1          | Date     | User custom date 1                   |
| KMSAT.GroupsMembers.custom_date_2          | Date     | User custom date 2                   |

#### Command Example
```!kmsat-groups-members-list  group_id=1 page=1 per_page=25```

#### Context Example
```json

{
  "id": 667542,
  "employee_number": "19425",
  "first_name": "William",
  "last_name": "Marcoux",
  "job_title": "VP of Sales",
  "email": "example2@kb4-demo.com",
  "phish_prone_percentage": 14.235,
  "phone_number": "555-554-2222",
  "extension": "42",
  "mobile_phone_number": "555-553-4422",
  "location": "Office A",
  "division": "Sales",
  "manager_name": "Michael Scott",
  "manager_email": "example3@kb4-demo.com",
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

| **Argument Name** | **Description** | **Requirement** |
| ----------------- | --------------- | --------------- |
| user_id           | User ID         | Required        |
| page              | Page number     | Optional        |
| per_page          | Amount per page | Optional        |

#### Context Output

| **Path**                          | **Type** | **Description**                       |
| --------------------------------- | -------- | ------------------------------------- |
| KMSAT.UsersRiskHistory.risk_score | Number   | User's Risk Score and associated date |
| KMSAT.UsersRiskHistory.date       | Date     | User's Risk Score history date        |

#### Command Example
```!kmsat-users-risk-score-history-list  user_id=1 page=1 per_page=25```

#### Context Example
```json

{
  "risk_score": 37.3,
  "date": "2021-02-07"
}

```

### kmsat-phishing-security-tests

| **Argument Name** | **Description** | **Requirement** |
| ----------------- | --------------- | --------------- |
| page              | Page number     | Optional        |
| per_page          | Amount per page | Optional        |

#### Context Output

| **Path**                                      | **Type** | **Description**                             |
| --------------------------------------------- | -------- | ------------------------------------------- |
| KMSAT.PhishingSecurity.campaign_id            | Number   | Phishing campaign ID                        |
| KMSAT.PhishingSecurity.pst_id                 | Number   | PST ID                                      |
| KMSAT.PhishingSecurity.status                 | String   | PST status                                  |
| KMSAT.PhishingSecurity.name                   | String   | PST name                                    |
| KMSAT.PhishingSecurity.groups.group_id        | Number   | PST group ID                                |
| KMSAT.PhishingSecurity.groups.name            | String   | PST group name                              |
| KMSAT.PhishingSecurity.phish_prone_percentage | Number   | PST Phish-prone Percentage                  |
| KMSAT.PhishingSecurity.started_at             | Date     | PST started date                            |
| KMSAT.PhishingSecurity.duration               | Number   | PST duration                                |
| KMSAT.PhishingSecurity.categories.category_id | Number   | PST category ID                             |
| KMSAT.PhishingSecurity.categories.name        | String   | PST category name                           |
| KMSAT.PhishingSecurity.template.id            | Number   | PST template ID                             |
| KMSAT.PhishingSecurity.template.name          | String   | PST template Name                           |
| KMSAT.PhishingSecurity.lading_page.id         | Number   | PST landing page ID                         |
| KMSAT.PhishingSecurity.landing_page.name      | String   | PST landing page name                       |
| KMSAT.PhishingSecurity.scheduled_count        | Number   | PST scheduled count                         |
| KMSAT.PhishingSecurity.delivered_count        | Number   | PST delivered count                         |
| KMSAT.PhishingSecurity.opened_count           | Number   | PST opened count                            |
| KMSAT.PhishingSecurity.clicked_count          | Number   | PST clicked count                           |
| KMSAT.PhishingSecurity.replied_count          | Number   | PST replied count                           |
| KMSAT.PhishingSecurity.attachment_open_count  | Number   | PST attachment opened count                 |
| KMSAT.PhishingSecurity.macro_enabled_count    | Number   | PST macro enabled count                     |
| KMSAT.PhishingSecurity.data_entered_count     | Number   | PST data entered count                      |
| KMSAT.PhishingSecurity.qr_code_scanned_count  | Number   | PST QR Code scanned count                   |
| KMSAT.PhishingSecurity.reported_count         | Number   | PST reported count                          |
| KMSAT.PhishingSecurity.bounced_count          | Number   | PST bounced count                           |


#### Command Example
```!kmsat-phishing-security-tests-list  page=1 per_page=25```

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
    "landing_page": {
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

| **Argument Name** | **Description** | **Requirement** |
| ----------------- | --------------- | --------------- |
| pst_id            | PST ID          | Required        |
| page              | Page number     | Optional        |
| per_page          | Amount per page | Optional        |

#### Context Output

| **Path**                                       | **Type** | **Description**                        |
| ---------------------------------------------- | -------- | -------------------------------------- |
| KMSAT.PhishingSecurityPST.recipient_id         | Number   | PST recipient ID                       |
| KMSAT.PhishingSecurityPST.pst_id               | Number   | PST ID                                 |
| KMSAT.PhishingSecurityPST.user                 | String   | PST user                               |
| KMSAT.PhishingSecurityPST.template             | String   | PST template                           |
| KMSAT.PhishingSecurityPST.scheduled_at         | Date     | PST scheduled at                       |
| KMSAT.PhishingSecurityPST.delivered_at         | Date     | PST delivered at                       |
| KMSAT.PhishingSecurityPST.opened_at            | Date     | PST opened at                          |
| KMSAT.PhishingSecurityPST.clicked_at           | Date     | PST clicked at                         |
| KMSAT.PhishingSecurityPST.replied_at           | Date     | PST replied at                         |
| KMSAT.PhishingSecurityPST.attachment_opened_at | Date     | PST attachment opened at               |
| KMSAT.PhishingSecurityPST.macro_enabled_at     | Date     | PST macro enabled at                   |
| KMSAT.PhishingSecurityPST.data_entered_at      | Date     | PST data entered at                    |
| KMSAT.PhishingSecurityPST.qr_code_scanned      | Date     | PST QR code scanned at                 |
| KMSAT.PhishingSecurityPST.reported_at          | Date     | PST reported at                        |
| KMSAT.PhishingSecurityPST.bounced_at           | Date     | PST bounced at                         |
| KMSAT.PhishingSecurityPST.ip                   | String   | PST IP address                         |
| KMSAT.PhishingSecurityPST.up_location          | String   | PST IP address location                |
| KMSAT.PhishingSecurityPST.browser              | String   | PST browser                            |
| KMSAT.PhishingSecurityPST.browser_version      | String   | PST browser version                    |
| KMSAT.PhishingSecurityPST.os                   | String   | PST operating system                   |

#### Command Example
```!kmsat-phishing-security-tests-recipients-list  pst_id=1 page=1 per_page=25```

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
      "email": "example4@kb4-demo.com"
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

| **Argument Name** | **Description** | **Requirement** |
| ----------------- | --------------- | --------------- |
| pst_id            | PST ID          | Required        |

#### Context Output

| **Path**                                       | **Type** | **Description**                        |
| ---------------------------------------------- | -------- | -------------------------------------- |
| KMSAT.PhishingSecurityPST.recipient_id         | Number   | PST recipient ID                       |
| KMSAT.PhishingSecurityPST.pst_id               | Number   | PST ID                                 |
| KMSAT.PhishingSecurityPST.user                 | String   | PST user                               |
| KMSAT.PhishingSecurityPST.template             | String   | PST template                           |
| KMSAT.PhishingSecurityPST.scheduled_at         | Date     | PST scheduled at                       |
| KMSAT.PhishingSecurityPST.delivered_at         | Date     | PST delivered at                       |
| KMSAT.PhishingSecurityPST.opened_at            | Date     | PST opened at                          |
| KMSAT.PhishingSecurityPST.clicked_at           | Date     | PST clicked at                         |
| KMSAT.PhishingSecurityPST.replied_at           | Date     | PST replied at                         |
| KMSAT.PhishingSecurityPST.attachment_opened_at | Date     | PST attachment opened at               |
| KMSAT.PhishingSecurityPST.macro_enabled_at     | Date     | PST macro enabled at                   |
| KMSAT.PhishingSecurityPST.data_entered_at      | Date     | PST data entered at                    |
| KMSAT.PhishingSecurityPST.qr_code_scanned      | Date     | PST QR code scanned at                 |
| KMSAT.PhishingSecurityPST.reported_at          | Date     | PST reported at                        |
| KMSAT.PhishingSecurityPST.bounced_at           | Date     | PST bounced at                         |
| KMSAT.PhishingSecurityPST.ip                   | String   | PST IP address                         |
| KMSAT.PhishingSecurityPST.up_location          | String   | PST IP address location                |
| KMSAT.PhishingSecurityPST.browser              | String   | PST browser                            |
| KMSAT.PhishingSecurityPST.browser_version      | String   | PST browser version                    |
| KMSAT.PhishingSecurityPST.os                   | String   | PST operating system                   |

#### Command Example
```!kmsat-phishing-security-tests-failed-recipients-list  pst_id=1```

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
      "email": "example4@kb4-demo.com"
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

### kmsat-phishing-campaign-security-tests

| **Argument Name** | **Description** | **Requirement** |
| ----------------- | --------------- | --------------- |
| campaign_id       | Campaign ID     | Required        |
| page              | Page number     | Optional        |
| per_page          | Amount per page | Optional        |

#### Context Output

| **Path**                                 | **Type** | **Description**                 |
| ---------------------------------------- | -------- | --------------------------------|
| KMSAT.CampaignPST.campaign_id            | Number   | Phishing campaign ID            |
| KMSAT.CampaignPST.pst_id                 | Number   | PST ID                          |
| KMSAT.CampaignPST.status                 | String   | PST status                      |
| KMSAT.CampaignPST.name                   | String   | PST name                        |
| KMSAT.CampaignPST.groups.group_id        | Number   | PST group ID                    |
| KMSAT.CampaignPST.groups.name            | String   | PST group name                  |
| KMSAT.CampaignPST.phish_prone_percentage | Number   | PST Phish-prone Percentage      |
| KMSAT.CampaignPST.started_at             | Date     | PST started at                  |
| KMSAT.CampaignPST.duration               | Number   | PST duration                    |
| KMSAT.CampaignPST.categories.category_id | Number   | PST category ID                 |
| KMSAT.CampaignPST.categories.name        | String   | PST category name               |
| KMSAT.CampaignPST.template.id            | Number   | PST template ID                 |
| KMSAT.CampaignPST.template.name          | String   | PST template name               |
| KMSAT.CampaignPST.landing_page.id        | Number   | PST landing page ID             |
| KMSAT.CampaignPST.landing_page.name      | String   | PST landing page name           |
| KMSAT.CampaignPST.scheduled_count        | Number   | PST scheduled count             |
| KMSAT.CampaignPST.delivered_count        | Number   | PST delivered count             |
| KMSAT.CampaignPST.opened_count           | Number   | PST opened count                |
| KMSAT.CampaignPST.clicked_count          | Number   | PST clicked count               |
| KMSAT.CampaignPST.replied_count          | Number   | PST replied count               |
| KMSAT.CampaignPST.attachment_open_count  | Number   | PST attachment opened count     |
| KMSAT.CampaignPST.macro_enabled_count    | Number   | PST macro enabled count         |
| KMSAT.CampaignPST.data_entered_count     | Number   | PST data entered count          |
| KMSAT.CampaignPST.qr_code_scanned_count  | Number   | PST QR code scanned count       |
| KMSAT.CampaignPST.reported_count         | Number   | PST reported count              |
| KMSAT.CampaignPST.bounced_count          | Number   | PST bounced count               |



#### Command Example
```!kmsat-phishing-campaign-security-tests-list  campaign_id=1 page=1 per_page=25```

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
    "landing_page": {
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

### kmsat-training-campaigns

| **Argument Name** | **Description** | **Requireent** |
| ----------------- | --------------- | -------------- |
| page              | Page Number     | Optional       |
| per_page          | Per Page Amount | Optional       |

#### Context Output

| **Path**                                           | **Type** | **Description**                               |
| -------------------------------------------------- | -------- | --------------------------------------------- |
| KMSAT.TrainingCampaigns.campaign_id                | Number   | Training campaign ID                          |
| KMSAT.TrainingCampaigns.name                       | String   | Training campaign name                        |
| KMSAT.TrainingCampaigns.groups.group_id            | Number   | Training campaign group ID                    |
| KMSAT.TrainingCampaigns.groups.name                | String   | Training campaign group name                  |
| KMSAT.TrainingCampaigns.status                     | String   | Training campaign Status                      |
| KMSAT.TrainingCampaigns.content.store_purchase_id  | Number   | Training campaign content store purchase ID   |
| KMSAT.TrainingCampaigns.content.content_type       | String   | Training campaign content type                |
| KMSAT.TrainingCampaigns.content.name               | String   | Training campaign content name                |
| KMSAT.TrainingCampaigns.content.description        | String   | Training campaign content description         |
| KMSAT.TrainingCampaigns.content.type               | String   | Training campaign content type                |
| KMSAT.TrainingCampaigns.content.duration           | Number   | Training campaign content duration            |
| KMSAT.TrainingCampaigns.content.retired            | Boolean  | Training campaign content retired             |
| KMSAT.TrainingCampaigns.content.retirement_date    | Date     | Training campaign content retirement date     |
| KMSAT.TrainingCampaigns.content.publish_date       | Date     | Training campaign content publish date        |
| KMSAT.TrainingCampaigns.content.publisher          | String   | Training campaign content publisher           |
| KMSAT.TrainingCampaigns.content.purchase_date      | Date     | Training campaign content purchase date       |
| KMSAT.TrainingCampaigns.content.policy_url         | String   | Training campaign content policy URL          |
| KMSAT.TrainingCampaigns.content.policy_id          | Number   | Training campaign content policy ID           |
| KMSAT.TrainingCampaigns.content.minimum_time       | Number   | Training campaign content minimum time        |
| KMSAT.TrainingCampaigns.content.default_language   | String   | Training campaign content default language    |
| KMSAT.TrainingCampaigns.content.published          | Boolean  | Training campaign content published           |
| KMSAT.TrainingCampaigns.duration_type              | String   | Training campaign duration type               |
| KMSAT.TrainingCampaigns.start_date                 | Date     | Training campaign start date                  |
| KMSAT.TrainingCampaigns.end_date                   | Date     | Training campaign end date                    |
| KMSAT.TrainingCampaigns.relative_duration          | String   | Training campaign relative duration           |
| KMSAT.TrainingCampaigns.auto_enroll                | Boolean  | Training campaign auto enrolls                |
| KMSAT.TrainingCampaigns.allow_multiple_enrollments | Boolean  | Training campaign allows multiple enrollments |
| KMSAT.TrainingCampaigns.completion_percentage      | Number   | Training campaign completion percentage       |


#### Command Example
```!kmsat-training-campaigns-list  campaign_id=1 page=1 per_page=25```

#### Context Example
```json

{
  "campaign_id": 4261,
  "name": "Annual Training",
  "groups": [
    {
      "group_id": 0,
      "name": "All Users"
    }
  ],
  "status": "Completed",
  "content": [
    [
      {
        "store_purchase_id": 7,
        "content_type": "Store Purchase",
        "name": "2019 Security Awareness Training",
        "description": "A comprehensive overview of best practices...",
        "type": "Training Module",
        "duration": 42,
        "retired": false,
        "retirement_date": null,
        "publish_date": "2019-04-02T15:02:38.000Z",
        "publisher": "KnowBe4",
        "purchase_date": "2019-04-02T15:02:38.000Z",
        "policy_url": "https://www.yourcompany.com/employees/acceptableusepolicy.html"
      },
      {
        "policy_id": 142,
        "content_type": "Uploaded Policy",
        "name": "Security Awareness Policy",
        "minimum_time": 3,
        "default_language": "en-us",
        "published": true
      }
    ]
  ],
  "duration_type": "Specific End Date",
  "start_date": "2019-04-02T15:02:38.000Z",
  "end_date": "2019-04-02T15:02:38.000Z",
  "relative_duration": "string",
  "auto_enroll": true,
  "allow_multiple_enrollments": false,
  "completion_percentage": 0
}

```

### kmsat-training-enrollments

| **Argument Name** | **Description** | **Requirement** |
| ----------------- | --------------- | --------------- |
| status            | Status          | Optional        |
| page              | Page number     | Optional        |
| per_page          | Amount per page | Optional        |

#### Context Output

| **Path**                                      | **Type** | **Description**                          |
| --------------------------------------------- | -------- | ---------------------------------------- |
| KMSAT.TrainingEnrollments.enrollment_id       | Number   | Training enrollment ID                   |
| KMSAT.TrainingEnrollments.content_type        | String   | Training enrollment content type         |
| KMSAT.TrainingEnrollments.module_name         | String   | Training enrollment module name          |
| KMSAT.TrainingEnrollments.user.id             | Number   | Training enrollment user ID              |
| KMSAT.TrainingEnrollments.user.first_name     | String   | Training enrollment user’s first name    |
| KMSAT.TrainingEnrollments.user.last_name      | String   | Training enrollment user’s last name     |
| KMSAT.TrainingEnrollments.user.email          | String   | Training enrollment user’s email address |
| KMSAT.TrainingEnrollments.campaign_name       | String   | Training enrollment campaign name        |
| KMSAT.TrainingEnrollments.enrollment_date     | Date     | Training enrollment date                 |
| KMSAT.TrainingEnrollments.start_date          | Date     | Training enrollment start date           |
| KMSAT.TrainingEnrollments.completion_date     | Date     | Training enrollment completion date      |
| KMSAT.TrainingEnrollments.status              | String   | Training enrollment status               |
| KMSAT.TrainingEnrollments.time_spent          | Number   | Training enrollment time spent           |
| KMSAT.TrainingEnrollments.policy_acknowledged | Boolean  | Training enrollment policy acknowledged  |



#### Command Example
```!kmsat-training-enrollments-list  status="Completed" page=1 per_page=25```

#### Context Example
```json

{
  "enrollment_id": 1425526,
  "content_type": "Uploaded Policy",
  "module_name": "Acceptable Use Policy",
  "user": {
    "id": 796742,
    "first_name": "Sarah",
    "last_name": "Thomas",
    "email": "example1@kb4-demo.com"
  },
  "campaign_name": "New Employee Policies",
  "enrollment_date": "2019-04-02T15:02:38.000Z",
  "start_date": "2019-04-02T15:02:38.000Z",
  "completion_date": "2019-04-02T15:02:38.000Z",
  "status": "Passed",
  "time_spent": 2340,
  "policy_acknowledged": false
}

```
### kmsat-user-event-list


| **Argument Name** | **Type**        | **Requirement** |
| ----------------- | --------------- | --------------- |
| event_type        | String          | Optional        |
| target_user       | String          | Optional        |
| external_id       | String          | Optional        |
| source            | string          | Optional        |
| occurred_date     | String          | Optional        |
| risk_level        | Number          | Optional        |
| risk_decay_mode   | Number          | Optional        |
| risk_expired_date | String          | Optional        |
| page              | Number          | Optional        |
| per_page          | Number          | Optional        |
| order_by          | String          | Optional        |
| order_direction   | String          | Optional        |

#### Context Output

| **Path**                          | **Type** | **Description**              |
| --------------------------------- | -------- | ---------------------------- |
| KMSAT.UserEvents.id               | Number   | Event ID                     |
| KMSAT.UserEvents.user.email       | String   | User email address           |
| KMSAT.UserEvents.user.id          | Number   | User ID                      |
| KMSAT.UserEvents.user.archived    | Boolean  | User archived                |
| KMSAT.UserEvents.external_id      | String   | External ID of the event     |
| KMSAT.UserEvents.source           | String   | Source of the event          |
| KMSAT.UserEvents.description      | String   | Description of the event     |
| KMSAT.UserEvents.occurred_date    | Date     | Date the event occurred      |
| KMSAT.UserEvents.risk.level       | Number   | Risk level of the event      |
| KMSAT.UserEvents.risk.factor      | Number   | Risk factor of the event     |
| KMSAT.UserEvents.risk.decay_mode  | String   | Decay Mode of the risk level |
| KMSAT.UserEvents.risk.expire_date | String   | Risk expiration date         |
| KMSAT.UserEvents.event_type.id    | Number   | ID of event type             |
| KMSAT.UserEvents.event_type.name  | String   | Name of event type           |
#### Command Example
```!kmsat-user-event-list id=xyz```
### kmsat-user-events-list


| **Argument Name** | **Type**        | **Requirement** |
| ----------------- | --------------- | --------------- |
| event_type        | String          | Optional        |
| target_user       | String          | Optional        |
| external_id       | String          | Optional        |
| source            | string          | Optional        |
| occurred_date     | String          | Optional        |
| risk_level        | Number          | Optional        |
| risk_decay_mode   | Number          | Optional        |
| risk_expired_date | String          | Optional        |
| page              | Number          | Optional        |
| per_page          | Number          | Optional        |
| order_by          | String          | Optional        |
| order_direction   | String          | Optional        |

#### Context Output

| **Path**                          | **Type** | **Description**              |
| --------------------------------- | -------- | ---------------------------- |
| KMSAT.UserEvents.id               | Number   | Event ID                     |
| KMSAT.UserEvents.user.email       | String   | User email address           |
| KMSAT.UserEvents.user.id          | Number   | User ID                      |
| KMSAT.UserEvents.user.archived    | Boolean  | User archived                |
| KMSAT.UserEvents.external_id      | String   | External ID of the event     |
| KMSAT.UserEvents.source           | String   | Source of the event          |
| KMSAT.UserEvents.description      | String   | Description of the event     |
| KMSAT.UserEvents.occurred_date    | Date     | Date the event occurred      |
| KMSAT.UserEvents.risk.level       | Number   | Risk level of the event      |
| KMSAT.UserEvents.risk.factor      | Number   | Risk factor of the event     |
| KMSAT.UserEvents.risk.decay_mode  | String   | Decay Mode of the risk level |
| KMSAT.UserEvents.risk.expire_date | String   | Risk expiration date         |
| KMSAT.UserEvents.event_type.id    | Number   | ID of event type             |
| KMSAT.UserEvents.event_type.name  | String   | Name of event type           |

#### Command Example
```!kmsat-user-events-list target_user=1 risk_level=1 page=1 per_page=25```

#### Context Example
```json

{
  "data": [
    {
      "id": 0,
      "user": {
        "email": "string",
        "id": 0,
        "archived": true
      },
      "external_id": "string",
      "source": "string",
      "description": "string",
      "occurred_date": "2019-08-24",
      "risk": {
        "level": 0,
        "factor": 0,
        "decay_mode": "string",
        "expire_date": "string"
      },
      "event_type": {
        "id": 0,
        "name": "string"
      }
    }
  ]
}

```

### kmsat-user-event-types-list

| **Argument Name** | **Description**                  | **Requirement** |
| ----------------- | -------------------------------- | --------------- |
| name              | Filter by name of the event type | Optional        |

#### Context Output

| **Path**                         | **Type** | **Description**           |
| -------------------------------- | -------- | ------------------------- |
| KMSAT.UserEventTypes.id          | Number   | ID of the event type      |
| KMSAT.UserEventTypes.account_id  | Number   | Account ID                |
| KMSAT.UserEventTypes.name        | String   | Name of the event type    |
| KMSAT.UserEventTypes.description | String   | Description of event type |

#### Command Example
```!kmsat-user-event-types-list name="John"```

#### Context Example
```json

{
  "data": [
    {
      "id": 0,
      "name": "string",
      "description": "string"
    }
  ]
}

```

### kmsat-user-event-create

| **Argument Name** | **Description** | **Requirement** |
| ----------------- | --------------- | ------------    |
| target_user       | String          | Required        |
| event_type        | String          | Required        |
| external_id       | String          | Optional        |
| source            | string          | Optional        |
| description       | String          | Optional        |
| occurred_date     | String          | Optional        |
| risk_level        | Number          | Optional        |
| risk_decay_mode   | Number          | Optional        |
| risk_expired_date | String          | Optional        |

#### Context Output

| **Path**                 | **Type** | **Description**        |
| ------------------------ | -------- | ---------------------- |
| KMSAT.UserEventCreate.id | Number   | Unique ID of the event |

#### Command Example
```!kmsat-user-event-create target_user="John" event_type="New Event"```

#### Context Example
```json

{
  "data": {
    "id": "string"
  }
}

```

### kmsat-user-event-delete

| **Argument Name** | **Description** | **Requirement** |
| ----------------- | --------------- | --------------- |
| id                | Event ID        | Required        |

#### Command Example
```!kmsat-user-event-delete id=1```

### kmsat-user-event-status-list

| **Argument Name** | **Description**                  | **Requirement** |
| ----------------- | -------------------------------- | --------------- |
| id              | request id from kmsat- | Required        |

#### Context Output

| **Path**                         | **Type** | **Description**           |
| -------------------------------- | -------- | ------------------------- |
| KMSAT.UserEventStatus.id    | Number   | ID of the Event Type      |
| KMSAT.UserEventTypes.details   | Object   | Details of event request including event id and any failures      |
| KMSAT.UserEventTypes.details.events   | Array   | list of event ids   |
| KMSAT.UserEventTypes.details.failures    | Array   | reasons for failure |
| KMSAT.UserEventTypes.processed   | Date   | Date and time event was processed      |
| KMSAT.UserEventTypes.api_key   | String   | Name of api key used |

#### Command Example
```!kmsat-user-event-status-list id=xyz```

#### Context Example
```json
{
    "data": {
          "id": "abcdefgh-843c-4fc8-bb2f-decf89876f7b",
          "details": {
              "events": [
                  "123456-a083-42b9-b50a-fb69b8e2b185"
              ],
              "failures": []
          },
          "processed": "2023-04-1T14:39:40.132Z",
          "api_key": "Test integration"
      }
}
```

### kmsat-user-event-statuses-list
| **Argument Name** | **Description**                  | **Requirement** |
| ----------------- | -------------------------------- | --------------- |
| processed         | date item was processed | No        |
| page              | Page Number     | No           |
| per_page          | Per Page Amount | No           |

#### Context Output

| **Path**                         | **Type** | **Description**           |
| -------------------------------- | -------- | ------------------------- |
| KMSAT.UserEventStatus.id    | Number   | ID of the Event Type      |
| KMSAT.UserEventTypes.details   | Object   | Details of event request including event id and any failures      |
| KMSAT.UserEventTypes.details.events   | Array   | list of event ids   |
| KMSAT.UserEventTypes.details.failures    | Array   | reasons for failure |
| KMSAT.UserEventTypes.processed   | Date   | Date and time event was processed      |
| KMSAT.UserEventTypes.api_key   | String   | Name of api key used |

#### Command Example
```!kmsat-user-event-status-list id=xyz```

#### Context Example
```json
{
    "data": [
        {
            "id": "abcdefgh-843c-4fc8-bb2f-decf89876f7b",
            "details": {
                "events": [
                    "123456-a083-42b9-b50a-fb69b8e2b185"
                ],
                "failures": []
            },
            "processed": "2023-04-1T14:39:40.132Z",
            "api_key": "Test integration"
        },
        {
            "id": "qrstevei-843c-4fc8-bb2f-decf89876f7b",
            "details": {
                "events": [
                    "9876543-a083-42b9-b50a-fb69b8e2b185"
                ],
                "failures": []
            },
            "processed": "2023-04-1T00:39:40.132Z",
            "api_key": "Test integration"
        }
    ]
}
```
### kmsat-phishing-campaigns-security-tests-list

***
Returns All Campaign Phishing Security Tests (PSTs).

#### Base Command

`kmsat-phishing-campaigns-security-tests-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| campaign_id | Campaign ID. | Required | 
| page | Page Number. | Required | 
| per_page | Per Page Amount. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| KMSAT.CampaignPST.campaign_id | Number | Campaign Phishing Security Campaign ID | 
| KMSAT.CampaignPST.pst_id | Number | Campaign Phishing Security PST ID | 
| KMSAT.CampaignPST.status | String | Campaign Phishing Security Status | 
| KMSAT.CampaignPST.name | String | Campaign Phishing Security Name | 
| KMSAT.CampaignPST.groups.group_id | Number | Campaign Phishing Security Group ID | 
| KMSAT.CampaignPST.groups.name | String | Campaign Phishing Security Name | 
| KMSAT.CampaignPST.phish_prone_percentage | Number | Campaign Phishing Security Phish Prone Percentage | 
| KMSAT.CampaignPST.started_at | Date | Campaign Phishing Security Started At | 
| KMSAT.CampaignPST.duration | Number | Campaign Phishing Security Duration | 
| KMSAT.CampaignPST.categories.category_id | Number | Campaign Phishing Security Categories Category ID | 
| KMSAT.CampaignPST.categories.name | String | Campaign Phishing Security Categories Name | 
| KMSAT.CampaignPST.template.id | Number | Campaign Phishing Security Template ID | 
| KMSAT.CampaignPST.template.name | String | Campaign Phishing Security Template Name | 
| KMSAT.CampaignPST.landing_page.id | Number | Campaign Phishing Security Landing Page ID | 
| KMSAT.CampaignPST.landing_page.name | String | Campaign Phishing Security Landing Page Name | 
| KMSAT.CampaignPST.scheduled_count | Number | Campaign Phishing Security Scheduled Count | 
| KMSAT.CampaignPST.delivered_count | Number | Campaign Phishing Security Delivered Count | 
| KMSAT.CampaignPST.opened_count | Number | Campaign Phishing Security Opened Count | 
| KMSAT.CampaignPST.clicked_count | Number | Campaign Phishing Security Clicked Count | 
| KMSAT.CampaignPST.replied_count | Number | Campaign Phishing Security Replied Count | 
| KMSAT.CampaignPST.attachment_open_count | Number | Campaign Phishing Security Attachment Open Count | 
| KMSAT.CampaignPST.macro_enabled_count | Number | Campaign Phishing Security Macro Enabled Count | 
| KMSAT.CampaignPST.data_entered_count | Number | Campaign Phishing Security Data Entered Count | 
| KMSAT.CampaignPST.qr_code_scanned_count | Number | Campaign Phishing Security QR Code Scanned Count | 
| KMSAT.CampaignPST.reported_count | Number | Campaign Phishing Security Reported Count | 
| KMSAT.CampaignPST.bounced_count | Number | Campaign Phishing Security Bounced Count | 
