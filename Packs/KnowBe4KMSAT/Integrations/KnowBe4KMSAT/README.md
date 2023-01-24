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

### kmsat-groups-risk-score-history

| **Argument Name** | **Description** | **Required** |
| ----------------- | --------------- | ------------ |

### kmsat-groups-members

| **Argument Name** | **Description** | **Required** |
| ----------------- | --------------- | ------------ |

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