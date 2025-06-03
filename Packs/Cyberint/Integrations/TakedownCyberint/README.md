Use the Cyberint Takedowns integration to manage takedowns requests

## Configure Cyberint Takedowns on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Cyberint Takedowns.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description**                                                                                                                                                                                        | **Required** |
    | --- |--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------| --- |
    | Cyberint API URL | Example: `https://yourcompany.cyberint.io`                                                                                                                                                               | True |
    | Company Name |                                                                                                                                                                                                        | True |
    | API access token |                                                                                                                                                                                                        | True |
    | Trust any certificate (not secure) |                                                                                                                                                                                                        | False |
    | Use system proxy settings |                                                                                                                                                                                                        | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### cyberint-retrieve-takedowns

***
Retrieve takedowns requests.

#### Base Command

`cyberint-retrieve-takedowns`

#### Input

| **Argument Name**       | **Description**                  | **Required** |
|-------------------------|----------------------------------|--------------|
| customer_id             | Customer ID.                     | Optional     |
| reason                  | Reason for the takedown request. | Optional     |
| url                     | URL for the takedown request.    | Optional     |
| original_url            | Original URL.                    | Optional     |
| customer                | Customer.                        | Optional     |
| status                  | Status.                          | Optional     |
| brand                   | Brand.                           | Optional     |
| alert_ref_id            | Alert reference ID.              | Optional     |
| alert_id                | Alert ID.                        | Optional     |
| hosting_providers       | Hosting providers.               | Optional     |
| name_servers            | Name servers.                    | Optional     |
| escalation_actions      | Escalation actions.              | Optional     |
| last_escalation_date    | Last escalation date.            | Optional     |
| last_status_change_date | Last status change date.         | Optional     |
| last_seen_date          | Last seen date.                  | Optional     |
| created_date            | Created date.                    | Optional     |
| status_reason           | Status reason.                   | Optional     |
| id                      | Takedown request ID.             | Optional     |

#### Context Output

| **Path**                                         | **Type** | **Description**                     |
|--------------------------------------------------|----------|-------------------------------------|
| Cyberint.takedowns.reason                  | String   | Reason for the takedown request.    |
| Cyberint.takedowns.url                     | String   | URL for the takedown request.       |
| Cyberint.takedowns.original_url            | String   | Original URL.                       |
| Cyberint.takedowns.customer                | String   | Customer.                           |
| Cyberint.takedowns.status                  | String   | Status.                             |
| Cyberint.takedowns.brand                   | String   | Brand.                              |
| Cyberint.takedowns.alert_ref_id            | String   | Alert reference ID.                 |
| Cyberint.takedowns.alert_id                | Number   | Alert ID.                           |
| Cyberint.takedowns.hosting_providers       | Array    | List of hosting providers.          |
| Cyberint.takedowns.name_servers            | Array    | List of name servers.               |
| Cyberint.takedowns.escalation_actions      | Array    | List of escalation actions.         |
| Cyberint.takedowns.last_escalation_date    | String   | Last escalation date (ISO 8601).    |
| Cyberint.takedowns.last_status_change_date | String   | Last status change date.            |
| Cyberint.takedowns.last_seen_date          | String   | Last seen date.                     |
| Cyberint.takedowns.created_date            | String   | Created date.                       |
| Cyberint.takedowns.status_reason           | String   | Status reason.                      |
| Cyberint.takedowns.id                      | String   | Takedown request ID (UUID).         |

#### Command example

```!cyberint-retrieve-takedowns customer_id=Cyberint```

#### Context Example

```json
{
    "Cyberint.takedowns": [
        {
          "data": {
            "takedown_requests": [
              {
                "reason": "phishing",
                "url": "string",
                "original_url": "string",
                "customer": "string",
                "status": "pending",
                "brand": "string",
                "alert_ref_id": "string",
                "alert_id": 0,
                "hosting_providers": [
                  "string"
                ],
                "name_servers": [
                  "string"
                ],
                "escalation_actions": [
                  "string"
                ],
                "last_escalation_date": "2019-08-24T14:15:22Z",
                "last_status_change_date": "2019-08-24T14:15:22Z",
                "last_seen_date": "2019-08-24T14:15:22Z",
                "created_date": "2019-08-24T14:15:22Z",
                "status_reason": "string",
                "id": "497f6eca-6276-4993-bfeb-53cbbbba6f08"
              }
            ]
          }
        }
    ]
}
```

#### Human Readable Output

##### Takedowns

| **Name**          | **Type**  | **Description**                        |
|-------------------|----------|----------------------------------------|
| reason                  | String   | Reason for the takedown request.    |
| url                     | String   | URL for the takedown request.       |
| original_url            | String   | Original URL.                       |
| customer                | String   | Customer.                           |
| status                  | String   | Status.                             |
| brand                   | String   | Brand.                              |
| alert_ref_id            | String   | Alert reference ID.                 |
| alert_id                | Number   | Alert ID.                           |
| hosting_providers       | Array    | List of hosting providers.          |
| name_servers            | Array    | List of name servers.               |
| escalation_actions      | Array    | List of escalation actions.         |
| last_escalation_date    | String   | Last escalation date (ISO 8601).    |
| last_status_change_date | String   | Last status change date.            |
| last_seen_date          | String   | Last seen date.                     |
| created_date            | String   | Created date.                       |
| status_reason           | String   | Status reason.                      |
| id                      | String   | Takedown request ID (UUID).         |


### cyberint-takedown-url

***
Submit takedown request.

#### Base Command

`cyberint-takedown-url`

#### Input

| **Argument Name** | **Description**                  | **Required** |
|-------------------|----------------------------------|--------------|
| customer          | Customer.                        | Required     |
| reason            | Reason for the takedown request. | Required     |
| url               | URL for the takedown request.     | Required     |
| brand             | Brand.                           | Optional     |
| original_url      | Original URL.                    | Optional     |
| alert_id          | Alert ID.                        | Optional     |
| note              | Note.                            | Optional     |

#### Context Output

| **Path**                                              | **Type** | **Description**                     |
|-------------------------------------------------------|----------|-------------------------------------|
| Cyberint.takedown_request.reason                      | String   | Reason for the takedown request.    |
| Cyberint.takedown_request.url                         | String   | URL for the takedown request.       |
| Cyberint.takedown_request.original_url                | String   | Original URL.                       |
| Cyberint.takedown_request.customer                    | String   | Customer.                           |
| Cyberint.takedown_request.status                      | String   | Status.                             |
| Cyberint.takedown_request.brand                       | String   | Brand.                              |
| Cyberint.takedown_request.alert_ref_id                | String   | Alert reference ID.                 |
| Cyberint.takedown_request.alert_id                    | Number   | Alert ID.                           |
| Cyberint.takedown_request.hosting_providers           | Array    | List of hosting providers.          |
| Cyberint.takedown_request.name_servers                | Array    | List of name servers.               |
| Cyberint.takedown_request.escalation_actions          | Array    | List of escalation actions.         |
| Cyberint.takedown_request.last_escalation_date        | String   | Last escalation date (ISO 8601).    |
| Cyberint.takedown_request.last_status_change_date     | String   | Last status change date.            |
| Cyberint.takedown_request.last_seen_date              | String   | Last seen date.                     |
| Cyberint.takedown_request.created_date                | String   | Created date.                       |
| Cyberint.takedown_request.status_reason               | String   | Status reason.                      |
| Cyberint.takedown_request.id                          | String   | Takedown request ID (UUID).         |

#### Command example

```!cyberint-takedown-url customer=Cyberint reason=Description url=https://dummy-url-for-takedown.com```

#### Context Example

```json
{
    "Cyberint.takedowns": [
        {
          "customer": "string",
          "reason": "phishing",
          "url": "string",
          "brand": "string",
          "original_url": "string",
          "alert_id": 0,
          "note": "string"
        }
    ]
}
```

#### Human Readable Output

##### Takedown submit response

| **Name**                | **Type** | **Description**                        |
|-------------------------|----------|----------------------------------------|
| reason                  | String   | Reason for the takedown request.       |
| url                     | String   | URL for the takedown request.          |
| original_url            | String   | Original URL.                          |
| customer                | String   | Customer.                              |
| status                  | String   | Status.                                |
| brand                   | String   | Brand.                                 |
| alert_ref_id            | String   | Alert reference ID.                    |
| alert_id                | Number   | Alert ID.                              |
| hosting_providers       | Array    | List of hosting providers.             |
| name_servers            | Array    | List of name servers.                  |
| escalation_actions      | Array    | List of escalation actions.            |
| last_escalation_date    | String   | Last escalation date (ISO 8601).       |
| last_status_change_date | String   | Last status change date (ISO 8601).    |
| last_seen_date          | String   | Last seen date (ISO 8601).             |
| created_date            | String   | Created date (ISO 8601).               |
| status_reason           | String   | Status reason.                         |
| id                      | String   | Takedown request ID (UUID).            |
