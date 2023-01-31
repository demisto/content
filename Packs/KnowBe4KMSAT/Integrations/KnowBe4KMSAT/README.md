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
| 8. Pulls user event data from KMSAT                                     |
| 9. Allows adding an external event to a user's timeline inside of KMSAT |
| 10. Allows deleting an event fom a user's timeline inside of KMSAT      |

## Commands

| Commands                                             | Description                                                            |
| ---------------------------------------------------- | ---------------------------------------------------------------------- |
| kmsat-account-info-list                              | Command displays the account information.                              |
| kmsat-account-risk-score-history-list                | Command lists the accounts risk score history.                         |
| kmsat-groups-list                                    | Command lists all the groups.                                          |
| kmsat-groups-risk-score-history-list                 | Command lists the groups risk score history.                           |
| kmsat-groups-members-list                            | Command lists the groups members.                                      |
| kmsat-users-risk-score-history-list                  | Command lists the risk score history for user.                         |
| kmsat-phishing-security-tests-list                   | Command lists the phishing security tests.                             |
| kmsat-phishing-security-tests-recipients-list        | Command lists the phishing security tests with recipients data.        |
| kmsat-phishing-security-tests-failed-recipients-list | Command lists the phishing security tests with failed recipients data. |
| kmsat-phishing-campaign-security-tests-list          | Command lists campaigns security tests.                                |
| kmsat-training-campaigns-list                        | Command lists training campaigns.                                      |
| kmsat-training-enrollments-list                      | Command lists training enrollments.                                    |
| kmsat-user-events-list                               | Command lists the user events.                                         |
| kmsat-user-event-types-list                          | Command lists the user event types.                                    |
| kmsat-user-event-create                              | Command creates a user event.                                          |
| kmsat-user-event-delete                              | Command deletes a user event.                                          |


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

| **Argument Name** | **Description** | **Required** |
| ----------------- | --------------- | ------------ |
| page              | Page Number     | No           |
| per_page          | Per Page Amount | No           |


#### Context Output

| **Path**                        | **Type** | **Description**           |
| ------------------------------- | -------- | ------------------------- |
| KMSAT.Groups.id                 | Number   | Groups ID                 |
| KMSAT.Groups.name               | String   | Groups Name               |
| KMSAT.Groups.group_type         | String   | Groups Type               |
| KMSAT.Groups.provisioning_guid  | String   | Groups Provisioning GUID  |
| KMSAT.Groups.member_count       | Number   | Groups Member Count       |
| KMSAT.Groups.current_risk_score | Number   | Groups Current Risk Score |
| KMSAT.Groups.status             | String   | Groups Status             |


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
```!kmsat-groups-risk-score-history-list page=1 per_page=25```

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
```!kmsat-groups-members-list  group_id=1 page=1 per_page=25```

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
```!kmsat-users-risk-score-history-list  user_id=1 page=1 per_page=25```

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
| pst_id            | PST ID          | Yes          |

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

### kmsat-phishing-campaign-security-tests

| **Argument Name** | **Description** | **Required** |
| ----------------- | --------------- | ------------ |
| campaign_id       | Campaign ID     | Yes          |
| page              | Page Number     | No           |
| per_page          | Per Page Amount | No           |

#### Context Output

| **Path**                                 | **Type** | **Description**                                   |
| ---------------------------------------- | -------- | ------------------------------------------------- |
| KMSAT.CampaignPST.campaign_id            | Number   | Campaign Phishing Security Campaign ID            |
| KMSAT.CampaignPST.pst_id                 | Number   | Campaign Phishing Security PST ID                 |
| KMSAT.CampaignPST.status                 | String   | Campaign Phishing Security Status                 |
| KMSAT.CampaignPST.name                   | String   | Campaign Phishing SecurityName                    |
| KMSAT.CampaignPST.groups.group_id        | Number   | Campaign Phishing Security Group ID               |
| KMSAT.CampaignPST.groups.name            | String   | Campaign Phishing Security Group Name             |
| KMSAT.CampaignPST.phish_prone_percentage | Number   | Campaign Phishing Security Phish Prone Percentage |
| KMSAT.CampaignPST.started_at             | Date     | Campaign Phishing Security Started At             |
| KMSAT.CampaignPST.duration               | Number   | Campaign Phishing Security Duration               |
| KMSAT.CampaignPST.categories.category_id | Number   | Campaign Phishing Security Category ID            |
| KMSAT.CampaignPST.categories.name        | String   | Campaign Phishing Security Category Name          |
| KMSAT.CampaignPST.template.id            | Number   | Campaign Phishing Security Template ID            |
| KMSAT.CampaignPST.template.name          | String   | Campaign Phishing Security Template Name          |
| KMSAT.CampaignPST.landing-page.id        | Number   | Campaign Phishing Security Landing Page ID        |
| KMSAT.CampaignPST.landing-page-name      | String   | Campaign Phishing Security Landing Page Name      |
| KMSAT.CampaignPST.scheduled_count        | Number   | Campaign Phishing Security Scheduled Count        |
| KMSAT.CampaignPST.delivered_count        | Number   | Campaign Phishing Security Delivered Count        |
| KMSAT.CampaignPST.opened_count           | Number   | Campaign Phishing Security Opened Count           |
| KMSAT.CampaignPST.clicked_count          | Number   | Campaign Phishing Security Clicked Count          |
| KMSAT.CampaignPST.replied_count          | Number   | Campaign Phishing Security Replied Count          |
| KMSAT.CampaignPST.attachment_open_count  | Number   | Campaign Phishing Security Attachment Open Count  |
| KMSAT.CampaignPST.macro_enabled_count    | Number   | Campaign Phishing Security Macro Enabled Count    |
| KMSAT.CampaignPST.data_entered_count     | Number   | Campaign Phishing Security Data Entered Count     |
| KMSAT.CampaignPST.qr_code_scanned_count  | Number   | Campaign Phishing Security QR Code Scanned Count  |
| KMSAT.CampaignPST.reported_count         | Number   | Campaign Phishing Security Reported Count         |
| KMSAT.CampaignPST.bounced_count          | Number   | Campaign Phishing Security Bounced Count          |



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

### kmsat-training-campaigns

| **Argument Name** | **Description** | **Required** |
| ----------------- | --------------- | ------------ |
| page              | Page Number     | No           |
| per_page          | Per Page Amount | No           |

#### Context Output

| **Path**                                           | **Type** | **Description**                               |
| -------------------------------------------------- | -------- | --------------------------------------------- |
| KMSAT.TrainingCampaigns.campaign_id                | Number   | Training Campaigns Campaign ID                |
| KMSAT.TrainingCampaigns.name                       | String   | Training Campaigns Name                       |
| KMSAT.TrainingCampaigns.groups.group_id            | Number   | Training Campaigns Groups ID                  |
| KMSAT.TrainingCampaigns.groups.name                | String   | Training Campaigns Groups Name                |
| KMSAT.TrainingCampaigns.status                     | String   | Training Campaigns Status                     |
| KMSAT.TrainingCampaigns.content.store_purchase_id  | Number   | Training Campaigns Content Store Purchased ID |
| KMSAT.TrainingCampaigns.content.content_type       | String   | Training Campaigns Contents Content Type      |
| KMSAT.TrainingCampaigns.content.name               | String   | Training Campaigns Content Name               |
| KMSAT.TrainingCampaigns.content.description        | String   | Training Campaigns Content Description        |
| KMSAT.TrainingCampaigns.content.type               | String   | Training Campaigns Content Type               |
| KMSAT.TrainingCampaigns.content.duration           | Number   | Training Campaigns Content Duration           |
| KMSAT.TrainingCampaigns.content.retired            | Boolean  | Training Campaigns Content Retired            |
| KMSAT.TrainingCampaigns.content.retirement_date    | Date     | Training Campaigns Content Retirement Date    |
| KMSAT.TrainingCampaigns.content.publish_date       | Date     | Training Campaigns Content Publish Date       |
| KMSAT.TrainingCampaigns.content.publisher          | String   | Training Campaigns Content Publisher          |
| KMSAT.TrainingCampaigns.content.purchase_date      | Date     | Training Campaigns Content Purchase Date      |
| KMSAT.TrainingCampaigns.content.policy_url         | String   | Training Campaigns Content Policy URL         |
| KMSAT.TrainingCampaigns.content.policy_id          | Number   | Training Campaigns Content Policy ID          |
| KMSAT.TrainingCampaigns.content.minimum_time       | Number   | Training Campaigns Content Minimum Time       |
| KMSAT.TrainingCampaigns.content.default_language   | String   | Training Campaigns Content Default Language   |
| KMSAT.TrainingCampaigns.content.published          | Boolean  | Training Campaigns Content Published          |
| KMSAT.TrainingCampaigns.duration_type              | String   | Training Campaigns Duration Type              |
| KMSAT.TrainingCampaigns.start_date                 | Date     | Training Campaigns Start Date                 |
| KMSAT.TrainingCampaigns.end_date                   | Date     | Training Campaigns End Date                   |
| KMSAT.TrainingCampaigns.relative_duration          | String   | Training Campaigns Relative Duration          |
| KMSAT.TrainingCampaigns.auto_enroll                | Boolean  | Training Campaigns Auto Enroll                |
| KMSAT.TrainingCampaigns.allow_multiple_enrollments | Boolean  | Training Campaigns Allow Multiple Enrollments |
| KMSAT.TrainingCampaigns.completion_percentage      | Number   | Training Campaigns Completion Percentage      |


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

| **Argument Name** | **Description** | **Required** |
| ----------------- | --------------- | ------------ |
| status            | Status          | No           |
| page              | Page Number     | No           |
| per_page          | Per Page Amount | No           |

#### Context Output

| **Path**                                      | **Type** | **Description**      |
| --------------------------------------------- | -------- | -------------------- |
| KMSAT.TrainingEnrollments.enrollment_id       | Number   | Training Enrollments |
| KMSAT.TrainingEnrollments.content_type        | String   | Training Enrollments |
| KMSAT.TrainingEnrollments.module_name         | String   | Training Enrollments |
| KMSAT.TrainingEnrollments.user.id             | Number   | Training Enrollments |
| KMSAT.TrainingEnrollments.user.first_name     | String   | Training Enrollments |
| KMSAT.TrainingEnrollments.user.last_name      | String   | Training Enrollments |
| KMSAT.TrainingEnrollments.user.email          | String   | Training Enrollments |
| KMSAT.TrainingEnrollments.campaign_name       | String   | Training Enrollments |
| KMSAT.TrainingEnrollments.enrollment_date     | Date     | Training Enrollments |
| KMSAT.TrainingEnrollments.start_date          | Date     | Training Enrollments |
| KMSAT.TrainingEnrollments.completion_date     | Date     | Training Enrollments |
| KMSAT.TrainingEnrollments.status              | String   | Training Enrollments |
| KMSAT.TrainingEnrollments.time_spent          | Number   | Training Enrollments |
| KMSAT.TrainingEnrollments.policy_acknowledged | Boolean  | Training Enrollments |



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
    "email": "s_thomas@kb4-demo.com"
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

### kmsat-user-events-list


| **Argument Name** | **Description** | **Required** |
| ----------------- | --------------- | ------------ |
| event_type        | String          | No           |
| target_user       | String          | No           |
| external_id       | String          | No           |
| source            | string          | No           |
| occurred_date     | String          | No           |
| risk_level        | Number          | No           |
| risk_decay_mode   | Number          | No           |
| risk_expired_date | String          | No           |
| page              | Number          | No           |
| per_page          | Number          | No           |
| order_by          | String          | No           |
| order_direction   | String          | No           |

#### Context Output

| **Path**                          | **Type** | **Description**           |
| --------------------------------- | -------- | ------------------------- |
| KMSAT.UserEvents.id               | Number   | Unique ID of the event    |
| KMSAT.UserEvents.user.email       | String   | User email address        |
| KMSAT.UserEvents.user.id          | Number   | User ID                   |
| KMSAT.UserEvents.user.archived    | Boolean  | User Archived flag        |
| KMSAT.UserEvents.external_id      | String   | External ID of the event  |
| KMSAT.UserEvents.source           | String   | Source of the event       |
| KMSAT.UserEvents.description      | String   | Description of the event  |
| KMSAT.UserEvents.occurred_date    | Date     | When the event occurred   |
| KMSAT.UserEvents.risk.level       | Number   | Risk Level of the event   |
| KMSAT.UserEvents.risk.factor      | Number   | Risk Factor of the event  |
| KMSAT.UserEvents.risk.decay_mode  | String   | The Risk Level Decay Mode |
| KMSAT.UserEvents.risk.expire_date | String   | Risk Expire Date          |
| KMSAT.UserEvents.event_type.id    | Number   | Event Type ID             |
| KMSAT.UserEvents.event_type.name  | String   | Event Type Name           |

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

| **Argument Name** | **Description**                  | **Required** |
| ----------------- | -------------------------------- | ------------ |
| name              | Filter by name of the event type | No           |

#### Context Output

| **Path**                         | **Type** | **Description**           |
| -------------------------------- | -------- | ------------------------- |
| KMSAT.UserEventTypes.id          | Number   | ID of the Event Type      |
| KMSAT.UserEventTypes.account_id  | Number   | Account ID                |
| KMSAT.UserEventTypes.name        | String   | Name of the Event Type    |
| KMSAT.UserEventTypes.description | String   | Description of Event Type |

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

| **Argument Name** | **Description** | **Required** |
| ----------------- | --------------- | ------------ |
| target_user       | String          | Yes          |
| event_type        | String          | Yes          |
| external_id       | String          | No           |
| source            | string          | No           |
| description       | String          | No           |
| occurred_date     | String          | No           |
| risk_level        | Number          | No           |
| risk_decay_mode   | Number          | No           |
| risk_expired_date | String          | No           |

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

| **Argument Name** | **Description** | **Required** |
| ----------------- | --------------- | ------------ |
| id                | Event ID        | Yes          |

#### Command Example
```!kmsat-user-event-delete id=1```