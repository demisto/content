This integration allows the security operations center to create and manage incidents based on Vectra Events Detections.
This integration was integrated and tested with Vectra API v3.5.

## Configure Vectra RUX - Network Detection & Response in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL | URL of the Vectra AI platform. | True |
| Client ID | Identifies a client or application for authentication and authorization in the Vectra AI platform.  | True |
| Client Secret Key | Secret key used for secure communication with the Vectra AI platform. | True |
| Fetch incidents |  | False |
| Max Fetch | The maximum number of events detections to fetch each time. If the value is greater than 200, it will be considered as 200. The maximum is 200. | False |
| First Fetch Time | The date or relative timestamp from which to begin fetching events detections.<br/><br/>Supported formats: 2 minutes, 2 hours, 2 days, 2 weeks, 2 months, 2 years, yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ.<br/><br/>For example: 01 Oct 2025, 01 Mar 2021 04:45:33, 2025-12-17T14:05:44Z. | False |
| Entity Types | Filter by entity type. If not selected, it will fetch all events detections. | False |
| Create Incidents for Prioritized Detections | Enabling this checkbox generates incidents for prioritized events detections. If not selected, incidents are created for all events detections. | False |
| Create Incidents for Escalated Detections | Enabling this checkbox generates incidents for escalated events detections. If not selected, incidents are created for all events detections. | False |
| Mirroring Direction | The mirroring direction in which to mirror the detections. You can mirror 'Incoming' (from Vectra to XSOAR), 'Outgoing' (from XSOAR to Vectra), or in both directions. | False |
| Mirror tag for notes | The tag value should be used to mirror the detection note by adding the same tag in the notes. | False |
| Open Detection on Incident Reopen | Enabling this checkbox opens the detection in Vectra when the incident is reopened in XSOAR.<br/><br/>Note: This parameter is only used when the mirroring direction is set to 'Outgoing' or 'Incoming And Outgoing'. | False |
| Detection Status for Incident Reopen | Detection status to set in Vectra when incident is reopened in XSOAR. Default value is 'Escalated'.<br/><br/>Note: This parameter is only used when open detection on incident reopen is 'checked' and the mirroring direction is set to 'Outgoing' or 'Incoming And Outgoing'. | False |
| Close Detection on Incident Closure | Enabling this checkbox closes the detection in Vectra when the incident is closed in XSOAR.<br/><br/>Note: This parameter is only used when the mirroring direction is set to 'Outgoing' or 'Incoming And Outgoing'. | False |
| Detection Close Reason for Incident Closure | Detection close reason to set in Vectra when closing incidents in XSOAR. Default value is 'Benign'.<br/><br/>Note: This parameter is only used when close detection on incident closer is 'checked' and the mirroring direction is set to 'Outgoing' or 'Incoming And Outgoing'. | False |
| Incident type |  | False |
| Trust any certificate (not secure) | When checked, no SSL certificates check will be done when interacting with the Vectra RUX API. It's insecure. \(Default - unchecked\) | False |
| Use system proxy settings | Use the system proxy settings to reach with the Vectra RUX API. | False |

## Configuration for fetching Vectra RUX Events Detections as an XSOAR Incident

To fetch Vectra RUX Events Detections follow the next steps:

1. Select Fetches incidents.
2. Under Classifier, select "N/A".
3. Under Incident type, select "Vectra RUX Events Detection".
4. Under Mapper (incoming), select "Vectra RUX - Incoming Mapper" for default mapping.
5. Enter connection parameters. (Server URL, Client ID & Client Secret Key)
6. Update "Max Fetch" & "First Fetch Time" based on your requirements.
7. Filter the Detections by the "Entity Type"(Account and Host).
8. Filter the Detections by "Create Incidents for Prioritized Detections", "Create Incidents for Escalated Detections":
    1. **Default Behavior**: By default, the integration retrieves all event detections across all entity types (Account and Host) and all detection statuses (Open, Acknowledged, Escalated, Paused). This includes both prioritized and non-prioritized detections.
    2. **Fetch Only Prioritized Detections**: Enable "Create Incidents for Prioritized Detections" to filter out non-prioritized detections. Incidents will be created only for prioritized event detections.
    3. **Fetch Only Escalated Detections**: Enable "Create Incidents for Escalated Detections" to retrieve all escalated detections, regardless of their priority level.
    4. **Fetch Prioritized and Escalated Detections**: Enable both "Create Incidents for Prioritized Detections" and "Create Incidents for Escalated Detections". This configuration retrieves detections that are either prioritized or escalated.
9. Select the Incident Mirroring Direction:
    1. Incoming - Mirrors changes from the Vectra RUX Detection into the Cortex XSOAR incident.
    2. Outgoing - Mirrors changes from the Cortex XSOAR incident to the Vectra RUX Detection.
    3. Incoming And Outgoing - Mirrors changes both Incoming and Outgoing directions on incidents.
10. Enter the relevant tag name for mirror notes.
**Note:** This value is mapped to the dbotMirrorTags incident field in Cortex XSOAR, which defines how Cortex XSOAR handles notes when you tag them in the War Room. This is required for mirroring notes from Cortex XSOAR to Vectra RUX.
11. Uncheck the "Open Detection on Incident Reopen" option if you don't want to open the detection in Vectra when the incident is reopened in XSOAR. This option is only used when the mirroring direction is set to 'Outgoing' or 'Incoming And Outgoing'.
12. Select the "Detection Status for Incident Reopen" option if you want to set the detection status in Vectra when the incident is reopened in XSOAR. Default value is 'Escalated'. This option is only used when the "Open Detection on Incident Reopen" option is checked and the mirroring direction is set to 'Outgoing' or 'Incoming And Outgoing'.
13. Uncheck the "Close Detection on Incident Closure" option if you don't want to close the detection in Vectra when the incident is closed in XSOAR. This option is only used when the mirroring direction is set to 'Outgoing' or 'Incoming And Outgoing'.
14. Select the "Detection Close Reason for Incident Closure" option if you want to set the detection close reason in Vectra when the incident is closed in XSOAR. Default value is 'Benign'. This option is only used when the "Close Detection on Incident Closure" option is checked and the mirroring direction is set to 'Outgoing' or 'Incoming And Outgoing'.
15. Select SSL certificate validation and Proxy if required.

**Notes for mirroring:**

* This feature is compliant with XSOAR version 6.0 and above.
* When mirroring incidents, you can make changes in Vectra that will be reflected in Cortex XSOAR, or vice versa.
* Any tags removed from the Vectra entity will not be removed in the XSOAR incident, as XSOAR doesn't allow the removal of the tags field via the backend. However, tags removed from the XSOAR incident UI will be removed from the Vectra entity.
* New notes from the XSOAR incident will be created as notes in the Vectra Detection. Updates to existing notes in the XSOAR incident will not be reflected in the Vectra Detection.
* New notes from the Vectra Detection will be created as notes in the XSOAR incident. Updates to existing notes in the Vectra Detection will create new notes in the XSOAR incident.
* If the Detection Status is updated in the Vectra Detection, it will be reflected in the XSOAR incident, or vice versa.
* If you want to reopen a detection in Vectra when the incident is reopened in XSOAR, check the "Open Detection on Incident Reopen" option. This option is only used when the mirroring direction is set to 'Outgoing' or 'Incoming And Outgoing'.
* Set the "Detection Status for Incident Reopen" option to set the detection status in Vectra when the incident is reopened in XSOAR. Default value is 'Escalated'. This option is only used when the "Open Detection on Incident Reopen" option is checked and the mirroring direction is set to 'Outgoing' or 'Incoming And Outgoing'.
* If you want to close a detection in Vectra when the incident is closed in XSOAR, check the "Close Detection on Incident Closure" option. This option is only used when the mirroring direction is set to 'Outgoing' or 'Incoming And Outgoing'.
* Set the "Detection Close Reason for Incident Closure" option to set the detection close reason in Vectra when the incident is closed in XSOAR. Default value is 'Benign'. This option is only used when the "Close Detection on Incident Closure" option is checked and the mirroring direction is set to 'Outgoing' or 'Incoming And Outgoing'.
* The mirroring settings apply only for incidents that are fetched after applying the settings.
* The mirroring is strictly tied to Incident type "Vectra RUX Events Detection" & Incoming mapper "Vectra RUX  - Incoming Mapper" If you want to change or use your custom incident type/mapper then make sure changes related to these are present.
* If you want to use the mirror mechanism and you're using custom mappers, then the incoming mapper must contain the following fields: dbotMirrorDirection, dbotMirrorId, dbotMirrorInstance, and dbotMirrorTags.
* To use a custom mapper, you must first duplicate the mapper and update the fields in the copy of the mapper. (Refer to the "Create a custom mapper consisting of the default Vectra RUX mapper" section for more information.)
* Following new fields are introduced in the response of the incident to enable the mirroring:
  * **mirror_direction:** This field determines the mirroring direction for the incident. It is a required field for XSOAR to enable mirroring support.
  * **mirror_tags:** This field determines what would be the tag needed to mirror the XSOAR entry out to Vectra RUX. It is a required field for XSOAR to enable mirroring support.
  * **mirror_instance:** This field determines from which instance the XSOAR incident was created. It is a required field for XSOAR to enable mirroring support.

#### Expire Inactive Detections

* Use the **Expire Inactive Detections - Vectra RUX** playbook to expire inactive detections that are fetched in XSOAR.
* You can also schedule a job with the **Expire Inactive Detections - Vectra RUX** playbook in Cortex XSOAR to expire inactive detections periodically. Refer to [Cortex XSOAR documentation](https://xsoar.pan.dev/docs/incidents/incident-jobs) for more information. To create a job with a 24-hour recurring schedule, follow these steps:
  1. In Cortex XSOAR, navigate to **Jobs** (via the top menu or sidebar).
  2. Click **New Job**.
  3. Select **Time triggered** and enable **Recurring**.
  4. Set the schedule to **Every 24 hours** (or configure a specific daily time using a cron expression such as `0 0 * * *`).
  5. Set the **Name** for the job (e.g., `Expire Inactive Detections - Daily`).
  6. Under **Playbook**, select **Expire Inactive Detections - Vectra RUX**.
  7. Click **Create new job** to activate the job.

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### vectra-detections-mark-asclosed

***
Mark detections as closed with provided detection IDs in the argument.

#### Base Command

`vectra-detections-mark-asclosed`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| detection_ids | Provide a list of detection IDs separated by commas or a single detection ID. | Required |
| close_reason | Provide the close reason. Possible values are: benign, remediated. | Required |

#### Context Output

There is no context output for this command.

#### Command example

```!vectra-detections-mark-asclosed detection_ids=123,345 close_reason=remediated```

#### Human Readable Output

>##### The provided detection IDs have been successfully closed as remediated

### vectra-user-list

***
Returns a list of users.

#### Base Command

`vectra-user-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| email | Filter by email. | Optional |
| role | Filter users with the specified role. Use the role standardized name. Possible values are: Admin, Auditor, Global Analyst, Read-Only, Restricted Admin, Security Analyst, Setting Admin, Super Admin. | Optional |
| last_login_timestamp | Return only the users which have a last login timestamp equal to or after the given timestamp.<br/><br/>Supported formats: 2 minutes, 2 hours, 2 days, 2 weeks, 2 months, 2 years, yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ.<br/><br/>For example: 01 May 2023, 01 Mar 2021 04:45:33, 2022-04-17T14:05:44Z. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Vectra.User.id | Number | The ID of the User. |
| Vectra.User.user_id | Number | The ID of the User. |
| Vectra.User.name | String | Username of the user. |
| Vectra.User.email | String | The email associated with the user. |
| Vectra.User.role | String | The role associated with the user. |
| Vectra.User.last_login_timestamp | String | Last login timestamp in UTC format of the user. |
| Vectra.User.last_login | String | Last login timestamp of the user. |

#### Command example

```!vectra-user-list```

#### Context Example

```json
{
  "Vectra": {
    "User": [
      {
        "id": 59,
        "user_id": 59,
        "username": "user.name1",
        "email": "",
        "role": "Security Analyst",
        "last_login_timestamp": "2023-08-22T09:24:44Z",
        "last_login": "2023-08-22T09:24:44Z"
      },
      {
        "id": 32,
        "user_id": 32,
        "username": "user.name2",
        "email": "",
        "role": "Super Admin",
        "last_login_timestamp": "2023-07-02T18:41:19Z",
        "last_login": "2023-07-02T18:41:19Z"
      },
      {
        "id": 23,
        "user_id": 23,
        "username": "vectra_mdr",
        "email": "",
        "role": "Vectra MDR"
      }
    ]
  }
}
```

#### Human Readable Output

>### Users Table
>
>|User ID|User Name|Role|Last Login Timestamp|
>|---|---|---|---|
>| 59 | user.name1 | Security Analyst | 2023-08-22T09:24:44Z |
>| 32 | user.name2 | Super Admin | 2023-07-02T18:41:19Z |
>| 23 | vectra_mdr | Vectra MDR |  |

### vectra-entity-list

***
Returns a list of entities.

#### Base Command

`vectra-entity-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| prioritized | Fetch only entities whose priority score is above the configured priority threshold will be included in the response. Possible values are: true, false. | Optional |
| entity_type | Specify the type of the entity. Possible values are: account, host. | Optional |
| name | Filter by matching entity name. | Optional |
| tags | Filter by a tag or a comma-separated list of tags. | Optional |
| state | Filter on entity activation state. Possible values are: active, inactive. | Optional |
| ordering | Orders records by last timestamp or urgency score. Default sorting is by urgency score in descending order. Use the minus symbol (-) to sort scores in descending order. Multiple ordering fields can be specified with a comma-separated list (e.g., ordering=urgency_score,-name). | Optional |
| last_detection_timestamp | Return only the entities which have a last detection timestamp equal to or after the given timestamp.<br/><br/>Supported formats: 2 minutes, 2 hours, 2 days, 2 weeks, 2 months, 2 years, yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ.<br/><br/>For example: 01 May 2023, 01 Mar 2021 04:45:33, 2022-04-17T14:05:44Z. | Optional |
| page | Enables the caller to specify a particular page of results. Default is 1. | Optional |
| page_size | Specify the desired page size for the request. Maximum is 5000. Default is 50. | Optional |
| last_modified_timestamp | Return only the entities which have a last modified timestamp equal to or after the given timestamp.<br/><br/>Supported formats: 2 minutes, 2 hours, 2 days, 2 weeks, 2 months, 2 years, yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ.<br/><br/>For example: 01 May 2023, 01 Mar 2021 04:45:33, 2022-04-17T14:05:44Z. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Vectra.Entity.id | Number | ID of the entity. |
| Vectra.Entity.name | String | Name of the entity. |
| Vectra.Entity.breadth_contrib | Number | Breadth contribution of the entity. |
| Vectra.Entity.importance | Number | Entity importance. |
| Vectra.Entity.type | String | Type of the entity. |
| Vectra.Entity.is_prioritized | Boolean | Entity is prioritized or not. |
| Vectra.Entity.severity | String | Severity of the entity. |
| Vectra.Entity.urgency_score | Number | Urgency score of the entity. |
| Vectra.Entity.velocity_contrib | Number | Velocity contribution of the entity. |
| Vectra.Entity.detection_set | String | Set of detections related to entity. |
| Vectra.Entity.last_detection_timestamp | Date | Time of the last detection activity related to entity. |
| Vectra.Entity.notes.id | String | Notes of the entity. |
| Vectra.Entity.notes.dateCreated | String | Created date of the Note. |
| Vectra.Entity.notes.dateModified | String | Modified date of the Note. |
| Vectra.Entity.notes.createdBy | String | Created user of the Note. |
| Vectra.Entity.notes.ModifiedBy | String | Modified user of the Note. |
| Vectra.Entity.notes.note | String | Note of the entity. |
| Vectra.Entity.attack_rating | Number | Attack Ratting of the entity. |
| Vectra.Entity.privilege_level | String | Privilege Level of the entity. |
| Vectra.Entity.privilege_category | String | Privilege Category of the entity. |
| Vectra.Entity.attack_profile | String | Attack Profile of the entity. |
| Vectra.Entity.sensors | Unknown | Sensors of the entity. |
| Vectra.Entity.state | String | State of the entity. |
| Vectra.Entity.tags | Unknown | Tags of the entity. |
| Vectra.Entity.url | String | Url link of the entity. |
| Vectra.Entity.host_type | Unknown | Host type of the entity. |
| Vectra.Entity.account_type | String | Account type of the entity. |

#### Command example

```!vectra-entity-list entity_type=account page=1 page_size=4 tags=test,test1 prioritized=true state=active```

#### Context Example

```json
{
  [
    {
      "id": 334,
      "name": "account_name",
      "breadth_contrib": 2,
      "entity_importance": 1,
      "importance": 2,
      "entity_type": "account",
      "type": "account",
      "is_prioritized": true,
      "severity": "Critical",
      "urgency_score": 100,
      "velocity_contrib": 2,
      "detection_set": [
        "http://server_url.com/api/v3.3/detections/1933",
        "http://server_url.com/api/v3.3/detections/1934"
      ],
      "last_detection_timestamp": "2023-05-15T09:39:24Z",
      "last_modified_timestamp": "2023-07-27T08:56:09Z",
      "notes": [],
      "attack_rating": 10,
      "attack_profile": "AWS Threat Actor",
      "sensors": [
        "test"
      ],
      "state": "active",
      "tags": [
        "test"
      ],
      "url": "http://server_url.com/api/v3.3/accounts/334",
      "account_type": [
        "o365"
      ]
    },
    {
      "id": 335,
      "name": "account_name_1",
      "breadth_contrib": 2,
      "entity_importance": 1,
      "importance": 2,
      "entity_type": "account",
      "type": "account",
      "is_prioritized": true,
      "severity": "Critical",
      "urgency_score": 80,
      "velocity_contrib": 2,
      "detection_set": [
        "http://server_url.com/api/v3.3/detections/1935",
        "http://server_url.com/api/v3.3/detections/1937"
      ],
      "last_detection_timestamp": "2023-05-15T09:41:24Z",
      "last_modified_timestamp": "2023-07-27T08:56:09Z",
      "notes": [],
      "attack_rating": 6,
      "attack_profile": "attack1",
      "sensors": [],
      "state": "active",
      "tags": [
        "test",
        "test1"
      ],
      "url": "http://server_url.com/api/v3.3/accounts/335",
      "account_type": [
        "o365"
      ]
    },
    {
      "id": 337,
      "name": "account_name_2",
      "breadth_contrib": 2,
      "entity_importance": 1,
      "importance": 1,
      "entity_type": "account",
      "type": "account",
      "is_prioritized": true,
      "severity": "Critical",
      "urgency_score": 40,
      "velocity_contrib": 2,
      "detection_set": [
        "http://server_url.com/api/v3.3/detections/1835",
        "http://server_url.com/api/v3.3/detections/1837"
      ],
      "last_detection_timestamp": "2023-05-15T09:40:24Z",
      "last_modified_timestamp": "2023-07-27T08:56:09Z",
      "notes": [],
      "attack_rating": 9,
      "attack_profile": "attack2",
      "sensors": [],
      "state": "active",
      "tags": [
        "test1"
      ],
      "url": "http://server_url.com/api/v3.3/accounts/337",
      "account_type": [
        "aws"
      ]
    },
    {
      "id": 339,
      "name": "account_name_3",
      "breadth_contrib": 2,
      "entity_importance": 1,
      "importance": 2,
      "entity_type": "account",
      "type": "account",
      "is_prioritized": true,
      "severity": "Critical",
      "urgency_score": 21,
      "velocity_contrib": 2,
      "detection_set": [
        "http://server_url.com/api/v3.3/detections/1735",
        "http://server_url.com/api/v3.3/detections/1737"
      ],
      "last_detection_timestamp": "2023-05-15T09:44:24Z",
      "last_modified_timestamp": "2023-07-27T08:56:09Z",
      "notes": [],
      "attack_rating": 5,
      "attack_profile": "attack3",
      "sensors": [],
      "state": "active",
      "tags": [
        "test"
      ],
      "url": "http://server_url.com/api/v3.3/accounts/339",
      "account_type": [
        "o365"
      ]
    }
  ]
}
```

#### Human Readable Output

>### Entities Table (Showing Page 1 out of 1)
>
>|ID|Name|Entity Type|Urgency Score|Entity Importance|Last Detection Timestamp|Last Modified Timestamp|Detections IDs|Prioritize|State|Tags|
>|---|---|---|---|---|---|---|---|---|---|---|
>| [334](http://server_url.com/accounts/334) | account_name | account | 100 | High | 2023-05-15T09:39:24Z | 2023-07-18T09:44:24Z | [1933](http://server_url.com/detections/1933), [1934](http://server_url.com/detections/1934) | true | active | test |
>| [335](http://server_url.com/accounts/335) | account_name_1 | account | 80 | High | 2023-05-15T09:41:24Z | 2023-07-17T09:44:24Z | [1935](http://server_url.com/detections/1935), [1937](http://server_url.com/detections/1937) | true | active | test, test1 |
>| [337](http://server_url.com/accounts/337) | account_name_2 | account | 40 | Medium | 2023-05-15T09:40:24Z | 2023-07-16T09:44:24Z | [1835](http://server_url.com/detections/1835), [1837](http://server_url.com/detections/1837) | true | active | test1 |
>| [339](http://server_url.com/accounts/339) | account_name_3 | account | 21 | High | 2023-05-15T09:44:24Z | 2023-07-15T09:44:24Z | [1735](http://server_url.com/detections/1735), [1737](http://server_url.com/detections/1737) | true | active | test |

### vectra-entity-describe

***
Describes an entity by ID.

#### Base Command

`vectra-entity-describe`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entity_id | Specify the id of the entity. | Required |
| entity_type | Specify the type of the entity. Possible values are: host, account. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Vectra.Entity.id | Number | ID of the entity. |
| Vectra.Entity.name | String | Name of the entity. |
| Vectra.Entity.breadth_contrib | Number | Breadth contribution of the entity. |
| Vectra.Entity.importance | Number | Entity importance. |
| Vectra.Entity.type | String | Type of the entity. |
| Vectra.Entity.is_prioritized | Boolean | Entity is prioritized or not. |
| Vectra.Entity.severity | String | Severity of the entity. |
| Vectra.Entity.urgency_score | Number | Urgency score of the entity. |
| Vectra.Entity.velocity_contrib | Number | Velocity contribution of the entity. |
| Vectra.Entity.detection_set | String | Set of detections related to the entity. |
| Vectra.Entity.last_detection_timestamp | Date | Time of the last detection activity related to the entity. |
| Vectra.Entity.last_modified_timestamp | Date | Time of the last modification activity related to the entity. |
| Vectra.Entity.notes.id | String | Notes of the entity. |
| Vectra.Entity.notes.dateCreated | String | Created date of the Note. |
| Vectra.Entity.notes.dateModified | String | Modified date of the Note. |
| Vectra.Entity.notes.createdBy | String | Created user of the Note. |
| Vectra.Entity.notes.ModifiedBy | String | Modified user of the Note. |
| Vectra.Entity.notes.note | String | Note of the entity. |
| Vectra.Entity.attack_rating | Number | Attack Ratting of the entity. |
| Vectra.Entity.privilege_level | String | Privilege Level of the entity. |
| Vectra.Entity.privilege_category | String | Privilege Category of the entity. |
| Vectra.Entity.attack_profile | String | Attack Profile of the entity. |
| Vectra.Entity.sensors | Unknown | Sensors of the entity. |
| Vectra.Entity.state | String | State of the entity. |
| Vectra.Entity.tags | Unknown | Tags of the entity. |
| Vectra.Entity.url | String | Url link of the entity. |
| Vectra.Entity.host_type | Unknown | Host type of the entity. |
| Vectra.Entity.account_type | Unknown | Account type of the entity. |

#### Command example

```!vectra-entity-describe entity_type=account entity_id=334```

#### Context Example

```json
{
    "id": 334,
    "name": "account_name",
    "breadth_contrib": 2,
    "entity_importance": 1,
    "importance": 2,
    "entity_type": "account",
    "type": "account",
    "is_prioritized": true,
    "severity": "Critical",
    "urgency_score": 100,
    "velocity_contrib": 2,
    "detection_set": [
      "http://server_url.com/api/v3.3/detections/1933",
      "http://server_url.com/api/v3.3/detections/1934"
    ],
    "last_detection_timestamp": "2023-05-15T09:39:24Z",
    "last_modified_timestamp": "2023-07-28T05:25:47Z",
    "notes": [],
    "attack_rating": 10,
    "attack_profile": "test_attack",
    "sensors": [
      "test"
    ],
    "state": "active",
    "tags": [
      "test"
    ],
    "url": "http://server_url.com/api/v3.3/accounts/334",
    "account_type": [
      "o365"
    ]
  }
}
```

#### Human Readable Output

>### Entity detail
>
>#### Entity ID: [334](http://server_url.com/accounts/334)
>
>|Name|Entity Type|Urgency Score|Entity Importance|Last Detection Timestamp|Last Modified Timestamp|Detections IDs|Prioritize|State|Tags|
>|---|---|---|---|---|---|---|---|---|---|
>| account_name | account | 100 | High | 2023-05-15T09:39:24Z | 2023-07-28T05:25:47Z | [1933](http://server_url.com/detections/1933), [1934](http://server_url.com/detections/1934) | true | active | test |

### vectra-entity-detection-list

***
Returns a list of detections for a specified entity.

#### Base Command

`vectra-entity-detection-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entity_id | Specify the id of the entity. | Required |
| entity_type | Specify the type of the entity. Possible values are: account, host. | Required |
| page | Enables the caller to specify a particular page of results. Default is 1. | Optional |
| page_size | Specify the desired page size for the request. Maximum is 5000. Default is 50. | Optional |
| detection_category | The category of the detection. Possible values are: Command &amp; Control, Botnet, Reconnaissance, Lateral Movement, Exfiltration, Info. | Optional |
| detection_type | Filter by detection type. | Optional |
| last_timestamp | Return only the detections which have a last timestamp equal to or after the given timestamp. <br/>Formats: YYYY-MM-ddTHH:mm:ssZ, YYYY-MM-dd, N days, N hours.<br/>Example: 2023-04-25T00:00:00Z, 2023-04-25, 2 days, 5 hours, 01 Mar 2023, 01 Feb 2023 04:45:33, 15 Jun. | Optional |
| detection_name | Filter by detection name. | Optional |
| state | Filter by state. Default is active. | Optional |
| tags | Filter by a tag or a comma-separated list of tags. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Vectra.Entity.Detections.id | Number | Entity detection ID. |
| Vectra.Entity.Detections.assigned_date | Unknown | Date assigned to the detection. |
| Vectra.Entity.Detections.assigned_to | Unknown | User or entity assigned to the detection. |
| Vectra.Entity.Detections.category | String | Category of the detection. |
| Vectra.Entity.Detections.certainty | Number | Certainty level of the detection. |
| Vectra.Entity.Detections.c_score | Number | Confidence score of the detection. |
| Vectra.Entity.Detections.description | String | Description of the detection. |
| Vectra.Entity.Detections.detection | String | Detection information. |
| Vectra.Entity.Detections.detection_category | String | Category of the detection. |
| Vectra.Entity.Detections.detection_type | String | Type of the detection. |
| Vectra.Entity.Detections.grouped_details.external_target.ip | String | IP address of the external target in the detection group. |
| Vectra.Entity.Detections.grouped_details.external_target.name | String | Name of the external target in the detection group. |
| Vectra.Entity.Detections.grouped_details.num_sessions | Number | Number of sessions in the detection group. |
| Vectra.Entity.Detections.grouped_details.bytes_received | Number | Total bytes received in the detection group. |
| Vectra.Entity.Detections.grouped_details.bytes_sent | Number | Total bytes sent in the detection group. |
| Vectra.Entity.Detections.grouped_details.ja3_hashes | String | JA3 hashes in the detection group. |
| Vectra.Entity.Detections.grouped_details.ja3s_hashes | String | JA3S hashes in the detection group. |
| Vectra.Entity.Detections.grouped_details.sessions.tunnel_type | String | Tunnel type used in the sessions of the detection group. |
| Vectra.Entity.Detections.grouped_details.sessions.protocol | String | Protocol used in the sessions of the detection group. |
| Vectra.Entity.Detections.grouped_details.sessions.app_protocol | String | Application protocol used in the sessions of the detection group. |
| Vectra.Entity.Detections.grouped_details.sessions.dst_port | Number | Destination port in the sessions of the detection group. |
| Vectra.Entity.Detections.grouped_details.sessions.dst_ip | String | Destination IP address in the sessions of the detection group. |
| Vectra.Entity.Detections.grouped_details.sessions.bytes_received | Number | Total bytes received in the sessions of the detection group. |
| Vectra.Entity.Detections.grouped_details.sessions.bytes_sent | Number | Total bytes sent in the sessions of the detection group. |
| Vectra.Entity.Detections.grouped_details.sessions.first_timestamp | Date | First timestamp of the sessions in the detection group. |
| Vectra.Entity.Detections.grouped_details.sessions.last_timestamp | Date | Last timestamp of the sessions in the detection group. |
| Vectra.Entity.Detections.grouped_details.sessions.dst_geo | Unknown | Geolocation of the destination IP in the sessions of the detection group. |
| Vectra.Entity.Detections.grouped_details.sessions.dst_geo_lat | Unknown | Latitude of the destination IP in the sessions of the detection group. |
| Vectra.Entity.Detections.grouped_details.sessions.dst_geo_lon | Unknown | Longitude of the destination IP in the sessions of the detection group. |
| Vectra.Entity.Detections.grouped_details.first_timestamp | Date | First timestamp of the detection group. |
| Vectra.Entity.Detections.grouped_details.last_timestamp | Date | Last timestamp of the detection group. |
| Vectra.Entity.Detections.grouped_details.dst_ips | String | Destination IP addresses in the detection group. |
| Vectra.Entity.Detections.grouped_details.dst_ports | Number | Destination ports in the detection group. |
| Vectra.Entity.Detections.grouped_details.target_domains | String | Target domains in the detection group. |
| Vectra.Entity.Detections.is_targeting_key_asset | Boolean | Indicates if the detection is targeting a key asset. |
| Vectra.Entity.Detections.last_timestamp | Date | Last timestamp of the detection. |
| Vectra.Entity.Detections.note | Unknown | Note associated with the detection. |
| Vectra.Entity.Detections.note_modified_by | Unknown | User or entity who last modified the note. |
| Vectra.Entity.Detections.note_modified_timestamp | Unknown | Timestamp when the note was last modified. |
| Vectra.Entity.Detections.notes | Unknown | Additional notes related to the detection. |
| Vectra.Entity.Detections.sensor_name | String | Name of the sensor associated with the detection. |
| Vectra.Entity.Detections.src_account.id | Number | ID of the source account associated with the detection. |
| Vectra.Entity.Detections.src_account.name | String | Name of the source account associated with the detection. |
| Vectra.Entity.Detections.src_account.url | String | URL of the source account associated with the detection. |
| Vectra.Entity.Detections.src_account.threat | Number | Threat level of the source account associated with the detection. |
| Vectra.Entity.Detections.src_account.certainty | Number | Certainty level of the source account associated with the detection. |
| Vectra.Entity.Detections.src_account.privilege_level | Number | Privilege level of the source account associated with the detection. |
| Vectra.Entity.Detections.src_account.privilege_category | String | Privilege category of the source account associated with the detection. |
| Vectra.Entity.Detections.src_host.id | Number | ID of the source host in the detection. |
| Vectra.Entity.Detections.src_host.ip | String | IP address of the source host in the detection. |
| Vectra.Entity.Detections.src_host.name | String | Name of the source host in the detection. |
| Vectra.Entity.Detections.src_host.url | String | URL associated with the source host in the detection. |
| Vectra.Entity.Detections.src_host.is_key_asset | Boolean | Indicates if the source host is a key asset. |
| Vectra.Entity.Detections.src_host.groups | Unknown | Groups associated with the source host in the detection. |
| Vectra.Entity.Detections.src_host.threat | Number | Threat level associated with the source host in the detection. |
| Vectra.Entity.Detections.src_host.certainty | Number | Certainty level associated with the source host in the detection. |
| Vectra.Entity.Detections.src_ip | String | Source IP address in the detection. |
| Vectra.Entity.Detections.state | String | State of the detection. |
| Vectra.Entity.Detections.summary.bytes_received | Number | Total bytes received in the detection summary. |
| Vectra.Entity.Detections.summary.bytes_sent | Number | Total bytes sent in the detection summary. |
| Vectra.Entity.Detections.summary.cnc_server | String | CNC server associated with the detection summary. |
| Vectra.Entity.Detections.summary.num_events | Number | Total number of events related to the detection. |
| Vectra.Entity.Detections.summary.probable_owner | Unknown | Probable owner of the detection summary. |
| Vectra.Entity.Detections.summary.sessions | Number | Total sessions in the detection summary. |
| Vectra.Entity.Detections.tags | Unknown | Tags associated with the detection. |
| Vectra.Entity.Detections.threat | Number | Threat level of the detection. |
| Vectra.Entity.Detections.t_score | Number | T-score of the detection. |
| Vectra.Entity.Detections.type | String | Type of the detection. |
| Vectra.Entity.Detections.url | String | URL associated with the detection. |

#### Command example

```!vectra-entity-detection-list entity_id=1```

#### Context Example

```json
{
  [
    {
      "id": 132,
      "category": "exfiltration",
      "certainty": 70,
      "c_score": 70,
      "description": "",
      "detection": "Data Smuggler",
      "detection_category": "exfiltration",
      "detection_type": "smuggler",
      "grouped_details": [
        {
          "event_id": "ec2162c7-e526-4446-a549-71558743a1d7",
          "event_name": "UpdateAssumeRolePolicy",
          "aws_account_id": "aws_account_id",
          "src_external_host": {
            "ip": "0.0.0.0"
          },
          "aws_region": "us-east-1",
          "access_key_id": [
            "123456"
          ],
          "identity_type": "Federated Account",
          "assumed_role": "AWSReservedSSO_AdministratorAccess_a670eb90f07e2960",
          "request_parameters": [
            "{\"roleName\": \"stratus-red-team-backdoor-r-role\", \"policyDocument\": \"{\\\"Version\\\": \\\"2012-10-17\\\", \\\"Statement\\\": {\\\"Effect\\\": \\\"Allow\\\", \\\"Principal\\\": {\\\"AWS\\\": \\\"arn:aws:iam::123456789012:root\\\"}, \\\"Action\\\": \\\"sts:AssumeRole\\\"}}\"}"
          ],
          "response_elements": [],
          "role_sequence": [
            "account_id",
            "AWSReservedSSO_AdministratorAccess_a670eb90f07e2960"
          ],
          "user_agent": [
            "stratus-red-team_06e15b96-ee6b-482c-aff4-4f2f4a46a67c"
          ],
          "last_timestamp": "2023-06-06T17:01:04Z"
        },
        {
          "event_id": "89a098eb-1198-4e2a-9fa4-ef568ae39403",
          "event_name": "UpdateAssumeRolePolicy",
          "aws_account_id": "884414556547",
          "src_external_host": {
            "ip": "0.0.0.0"
          },
          "aws_region": "us-east-1",
          "access_key_id": [
            "123456"
          ],
          "identity_type": "Federated Account",
          "assumed_role": "AWSReservedSSO_AdministratorAccess_a670eb90f07e2960",
          "request_parameters": [
            "{\"policyDocument\": \"{\\\"Version\\\": \\\"2012-10-17\\\", \\\"Statement\\\": {\\\"Effect\\\": \\\"Allow\\\", \\\"Principal\\\": {\\\"AWS\\\": \\\"arn:aws:iam::123456789012:root\\\"}, \\\"Action\\\": \\\"sts:AssumeRole\\\"}}\", \"roleName\": \"stratus-red-team-backdoor-r-role\"}"
          ],
          "response_elements": [],
          "role_sequence": [
            "account_name",
            "AWSReservedSSO_AdministratorAccess_a670eb90f07e2960"
          ],
          "user_agent": [
            "stratus-red-team_a24eac3a-4fee-46ce-bc37-b4e675343fc9"
          ],
          "last_timestamp": "2023-06-06T15:40:43Z"
        }
      ],
      "is_targeting_key_asset": false,
      "last_timestamp": "2023-06-06T17:01:04Z",
      "notes": [],
      "sensor_name": "mafosb50",
      "src_account": {
        "id": 21,
        "name": "account_name",
        "url": "http://server_url.com/api/v3.3/accounts/21",
        "threat": 76,
        "certainty": 35
      },
      "src_ip": "0.0.0.0",
      "state": "active",
      "tags": [],
      "threat": 80,
      "t_score": 80,
      "type": "account",
      "url": "http://server_url.com/api/v3.3/detections/132"
    },
    {
      "id": 135,
      "category": "lateral_movement",
      "certainty": 50,
      "c_score": 50,
      "description": "",
      "detection": "AWS Suspect Admin Privilege Granting",
      "detection_category": "lateral_movement",
      "detection_type": "aws_admin_privilege_granted",
      "grouped_details": [
        {
          "event_id": "85d88db5-cf2d-4b6e-9411-d3119d9920e0",
          "event_name": "AttachRolePolicy",
          "aws_account_id": "884414556547",
          "src_external_host": {
            "ip": "0.0.0.0"
          },
          "aws_region": "us-east-1",
          "access_key_id": [
            "123456"
          ],
          "identity_type": "Federated Account",
          "assumed_role": "AWSReservedSSO_AdministratorAccess_a670eb90f07e2960",
          "request_parameters": [
            "{\"roleName\":\"stratus-red-team-backdoor-r-role\",\"policyArn\":\"arn:aws:iam::aws:policy/AdministratorAccess\"}"
          ],
          "response_elements": [],
          "role_sequence": [
            "account_name",
            "AWSReservedSSO_AdministratorAccess_a670eb90f07e2960"
          ],
          "user_agent": [
            "APN/1.0 HashiCorp/1.0 Terraform/1.1.2 (+https://www.terraform.io) terraform-provider-aws/3.76.1 (+https://registry.terraform.io/providers/hashicorp/aws) aws-sdk-go/1.44.157 (go1.19.3; linux; amd64) stratus-red-team_5077134d-32ea-4403-996b-de30d7f278d7 HashiCorp-terraform-exec/0.17.3"
          ],
          "last_timestamp": "2023-06-06T17:00:46Z"
        },
        {
          "event_id": "ca157e7c-9a53-4012-9288-e6ac1c488fbc",
          "event_name": "AttachRolePolicy",
          "aws_account_id": "884414556547",
          "src_external_host": {
            "ip": "0.0.0.0"
          },
          "aws_region": "us-east-1",
          "access_key_id": [
            "123456"
          ],
          "identity_type": "Federated Account",
          "assumed_role": "AWSReservedSSO_AdministratorAccess_a670eb90f07e2960",
          "request_parameters": [
            "{\"roleName\":\"stratus-red-team-backdoor-r-role\",\"policyArn\":\"arn:aws:iam::aws:policy/AdministratorAccess\"}"
          ],
          "response_elements": [],
          "role_sequence": [
            "account_name",
            "AWSReservedSSO_AdministratorAccess_a670eb90f07e2960"
          ],
          "user_agent": [
            "APN/1.0 HashiCorp/1.0 Terraform/1.1.2 (+https://www.terraform.io) terraform-provider-aws/3.76.1 (+https://registry.terraform.io/providers/hashicorp/aws) aws-sdk-go/1.44.157 (go1.19.3; linux; amd64) stratus-red-team_01be8427-d1b5-4c18-8edb-0301c8e66c8e HashiCorp-terraform-exec/0.17.3"
          ],
          "last_timestamp": "2023-06-06T15:40:07Z"
        }
      ],
      "is_targeting_key_asset": false,
      "last_timestamp": "2023-06-06T17:00:46Z",
      "notes": [],
      "sensor_name": "mafosb50",
      "src_account": {
        "id": 21,
        "name": "account_name",
        "url": "http://server_url.com/api/v3.3/accounts/21",
        "threat": 76,
        "certainty": 35
      },
      "src_ip": "0.0.0.0",
      "state": "fixed",
      "summary": {
      },
      "tags": [],
      "threat": 60,
      "t_score": 60,
      "type": "account",
      "url": "http://server_url.com/api/v3.3/detections/135"
    },
    {
      "id": 140,
      "category": "reconnaissance",
      "certainty": 40,
      "c_score": 40,
      "description": "",
      "detection": "RPC Targeted Recon",
      "detection_category": "reconnaissance",
      "detection_type": "rpc_recon_1to1",
      "grouped_details": [
        {
          "event_id": "cf9f469b-0a8e-47c6-85eb-5a0486292e58",
          "event_name": "ModifySnapshotAttribute",
          "aws_account_id": "884414556547",
          "src_external_host": {
            "ip": "0.0.0.0"
          },
          "aws_region": "us-west-2",
          "access_key_id": [
            "123456"
          ],
          "identity_type": "Federated Account",
          "assumed_role": "AWSReservedSSO_AdministratorAccess_a670eb90f07e2960",
          "request_parameters": [
            "{\"snapshotId\":\"snap-0f7d022a2f4f67e08\",\"createVolumePermission\":{\"add\":{\"items\":[{\"userId\":\"012345678912\"}]}},\"attributeType\":\"CREATE_VOLUME_PERMISSION\"}"
          ],
          "response_elements": [
            "{\"requestId\":\"350c1eb8-b696-4d94-88d4-a764a0eed08b\",\"_return\":true}"
          ],
          "role_sequence": [
            "account_name",
            "AWSReservedSSO_AdministratorAccess_a670eb90f07e2960"
          ],
          "user_agent": [
            "stratus-red-team_a4dd596b-7a8d-4e77-a74d-13f19adf4403"
          ],
          "last_timestamp": "2023-06-06T15:46:28Z"
        }
      ],
      "is_targeting_key_asset": false,
      "last_timestamp": "2023-06-06T15:46:28Z",
      "notes": [],
      "sensor_name": "mafosb50",
      "src_account": {
        "id": 21,
        "name": "account_name",
        "url": "http://server_url.com/api/v3.3/accounts/21",
        "threat": 76,
        "certainty": 35
      },
      "src_ip": "0.0.0.0",
      "state": "fixed",
      "summary": {
      },
      "tags": [],
      "threat": 60,
      "t_score": 60,
      "type": "account",
      "url": "http://server_url.com/api/v3.3/detections/140"
    }
  ]
}
```

#### Human Readable Output

>### Detections Table (Showing Page 1 out of 1)
>
>|ID|Detection Name|Detection Type|Category|Account Name|Src IP|Threat Score|Certainty Score|Number Of Events|State|Last Timestamp|
>|---|---|---|---|---|---|---|---|---|---|---|
>| [132](http://server_url.com/detections/132) | Data Smuggler | smuggler | exfiltration | [account_name](http://server_url.com/accounts/21) | 0.0.0.0 | 80 | 70 | 0 | active | 2023-06-06T17:01:04Z |
>| [135](http://server_url.com/detections/135) | AWS Suspect Admin Privilege Granting | aws_admin_privilege_granted | lateral_movement | [account_name](http://server_url.com/accounts/21) | 0.0.0.0 | 60 | 50 | 0 | fixed | 2023-06-06T17:00:46Z |
>| [140](http://server_url.com/detections/140) | RPC Targeted Recon | rpc_recon_1to1 | reconnaissance | [account_name](http://server_url.com/accounts/21) | 0.0.0.0 | 60 | 40 | 0 | fixed | 2023-06-06T15:46:28Z |

### vectra-detection-describe

***
Returns a list of detections for the specified detection ID(s).

#### Base Command

`vectra-detection-describe`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| detection_ids | Specify the ID(s) of the detections. | Required |
| page | Enables the caller to specify a particular page of results. Default is 1. | Optional |
| page_size | Specify the desired page size for the request. Maximum is 5000. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Vectra.Entity.Detections.id | Number | Entity detection ID. |
| Vectra.Entity.Detections.assigned_date | Unknown | Date assigned to the detection. |
| Vectra.Entity.Detections.assigned_to | Unknown | User or entity assigned to the detection. |
| Vectra.Entity.Detections.category | String | Category of the detection. |
| Vectra.Entity.Detections.certainty | Number | Certainty level of the detection. |
| Vectra.Entity.Detections.c_score | Number | Confidence score of the detection. |
| Vectra.Entity.Detections.description | String | Description of the detection. |
| Vectra.Entity.Detections.detection | String | Detection information. |
| Vectra.Entity.Detections.detection_category | String | Category of the detection. |
| Vectra.Entity.Detections.detection_type | String | Type of the detection. |
| Vectra.Entity.Detections.grouped_details.external_target.ip | String | IP address of the external target in the detection group. |
| Vectra.Entity.Detections.grouped_details.external_target.name | String | Name of the external target in the detection group. |
| Vectra.Entity.Detections.grouped_details.num_sessions | Number | Number of sessions in the detection group. |
| Vectra.Entity.Detections.grouped_details.bytes_received | Number | Total bytes received in the detection group. |
| Vectra.Entity.Detections.grouped_details.bytes_sent | Number | Total bytes sent in the detection group. |
| Vectra.Entity.Detections.grouped_details.ja3_hashes | String | JA3 hashes in the detection group. |
| Vectra.Entity.Detections.grouped_details.ja3s_hashes | String | JA3S hashes in the detection group. |
| Vectra.Entity.Detections.grouped_details.sessions.tunnel_type | String | Tunnel type used in the sessions of the detection group. |
| Vectra.Entity.Detections.grouped_details.sessions.protocol | String | Protocol used in the sessions of the detection group. |
| Vectra.Entity.Detections.grouped_details.sessions.app_protocol | String | Application protocol used in the sessions of the detection group. |
| Vectra.Entity.Detections.grouped_details.sessions.dst_port | Number | Destination port in the sessions of the detection group. |
| Vectra.Entity.Detections.grouped_details.sessions.dst_ip | String | Destination IP address in the sessions of the detection group. |
| Vectra.Entity.Detections.grouped_details.sessions.bytes_received | Number | Total bytes received in the sessions of the detection group. |
| Vectra.Entity.Detections.grouped_details.sessions.bytes_sent | Number | Total bytes sent in the sessions of the detection group. |
| Vectra.Entity.Detections.grouped_details.sessions.first_timestamp | Date | First timestamp of the sessions in the detection group. |
| Vectra.Entity.Detections.grouped_details.sessions.last_timestamp | Date | Last timestamp of the sessions in the detection group. |
| Vectra.Entity.Detections.grouped_details.sessions.dst_geo | Unknown | Geolocation of the destination IP in the sessions of the detection group. |
| Vectra.Entity.Detections.grouped_details.sessions.dst_geo_lat | Unknown | Latitude of the destination IP in the sessions of the detection group. |
| Vectra.Entity.Detections.grouped_details.sessions.dst_geo_lon | Unknown | Longitude of the destination IP in the sessions of the detection group. |
| Vectra.Entity.Detections.grouped_details.first_timestamp | Date | First timestamp of the detection group. |
| Vectra.Entity.Detections.grouped_details.last_timestamp | Date | Last timestamp of the detection group. |
| Vectra.Entity.Detections.grouped_details.dst_ips | String | Destination IP addresses in the detection group. |
| Vectra.Entity.Detections.grouped_details.dst_ports | Number | Destination ports in the detection group. |
| Vectra.Entity.Detections.grouped_details.target_domains | String | Target domains in the detection group. |
| Vectra.Entity.Detections.is_targeting_key_asset | Boolean | Indicates if the detection is targeting a key asset. |
| Vectra.Entity.Detections.last_timestamp | Date | Last timestamp of the detection. |
| Vectra.Entity.Detections.note | Unknown | Note associated with the detection. |
| Vectra.Entity.Detections.note_modified_by | Unknown | User or entity who last modified the note. |
| Vectra.Entity.Detections.note_modified_timestamp | Unknown | Timestamp when the note was last modified. |
| Vectra.Entity.Detections.notes | Unknown | Additional notes related to the detection. |
| Vectra.Entity.Detections.sensor_name | String | Name of the sensor associated with the detection. |
| Vectra.Entity.Detections.src_account.id | Number | ID of the source account associated with the detection. |
| Vectra.Entity.Detections.src_account.name | String | Name of the source account associated with the detection. |
| Vectra.Entity.Detections.src_account.url | String | URL of the source account associated with the detection. |
| Vectra.Entity.Detections.src_account.threat | Number | Threat level of the source account associated with the detection. |
| Vectra.Entity.Detections.src_account.certainty | Number | Certainty level of the source account associated with the detection. |
| Vectra.Entity.Detections.src_account.privilege_level | Number | Privilege level of the source account associated with the detection. |
| Vectra.Entity.Detections.src_account.privilege_category | String | Privilege category of the source account associated with the detection. |
| Vectra.Entity.Detections.src_host.id | Number | ID of the source host in the detection. |
| Vectra.Entity.Detections.src_host.ip | String | IP address of the source host in the detection. |
| Vectra.Entity.Detections.src_host.name | String | Name of the source host in the detection. |
| Vectra.Entity.Detections.src_host.url | String | URL associated with the source host in the detection. |
| Vectra.Entity.Detections.src_host.is_key_asset | Boolean | Indicates if the source host is a key asset. |
| Vectra.Entity.Detections.src_host.groups | Unknown | Groups associated with the source host in the detection. |
| Vectra.Entity.Detections.src_host.threat | Number | Threat level associated with the source host in the detection. |
| Vectra.Entity.Detections.src_host.certainty | Number | Certainty level associated with the source host in the detection. |
| Vectra.Entity.Detections.src_ip | String | Source IP address in the detection. |
| Vectra.Entity.Detections.state | String | State of the detection. |
| Vectra.Entity.Detections.summary.bytes_received | Number | Total bytes received in the detection summary. |
| Vectra.Entity.Detections.summary.bytes_sent | Number | Total bytes sent in the detection summary. |
| Vectra.Entity.Detections.summary.cnc_server | String | CNC server associated with the detection summary. |
| Vectra.Entity.Detections.summary.num_events | Number | Total number of events related to the detection. |
| Vectra.Entity.Detections.summary.probable_owner | Unknown | Probable owner of the detection summary. |
| Vectra.Entity.Detections.summary.sessions | Number | Total sessions in the detection summary. |
| Vectra.Entity.Detections.tags | Unknown | Tags associated with the detection. |
| Vectra.Entity.Detections.threat | Number | Threat level of the detection. |
| Vectra.Entity.Detections.t_score | Number | T-score of the detection. |
| Vectra.Entity.Detections.type | String | Type of the detection. |
| Vectra.Entity.Detections.url | String | URL associated with the detection. |

#### Command example

```!vectra-detection-describe detection_ids=132,135,140```

#### Context Example

```json
{
  [
    {
      "id": 132,
      "category": "exfiltration",
      "certainty": 70,
      "c_score": 70,
      "description": "",
      "detection": "Data Smuggler",
      "detection_category": "exfiltration",
      "detection_type": "smuggler",
      "grouped_details": [
        {
          "event_id": "ec2162c7-e526-4446-a549-71558743a1d7",
          "event_name": "UpdateAssumeRolePolicy",
          "aws_account_id": "aws_account_id",
          "src_external_host": {
            "ip": "0.0.0.0"
          },
          "aws_region": "us-east-1",
          "access_key_id": [
            "123456"
          ],
          "identity_type": "Federated Account",
          "assumed_role": "AWSReservedSSO_AdministratorAccess_a670eb90f07e2960",
          "request_parameters": [
            "{\"roleName\": \"stratus-red-team-backdoor-r-role\", \"policyDocument\": \"{\\\"Version\\\": \\\"2012-10-17\\\", \\\"Statement\\\": {\\\"Effect\\\": \\\"Allow\\\", \\\"Principal\\\": {\\\"AWS\\\": \\\"arn:aws:iam::123456789012:root\\\"}, \\\"Action\\\": \\\"sts:AssumeRole\\\"}}\"}"
          ],
          "response_elements": [],
          "role_sequence": [
            "account_id",
            "AWSReservedSSO_AdministratorAccess_a670eb90f07e2960"
          ],
          "user_agent": [
            "stratus-red-team_06e15b96-ee6b-482c-aff4-4f2f4a46a67c"
          ],
          "last_timestamp": "2023-06-06T17:01:04Z"
        },
        {
          "event_id": "89a098eb-1198-4e2a-9fa4-ef568ae39403",
          "event_name": "UpdateAssumeRolePolicy",
          "aws_account_id": "884414556547",
          "src_external_host": {
            "ip": "0.0.0.0"
          },
          "aws_region": "us-east-1",
          "access_key_id": [
            "123456"
          ],
          "identity_type": "Federated Account",
          "assumed_role": "AWSReservedSSO_AdministratorAccess_a670eb90f07e2960",
          "request_parameters": [
            "{\"policyDocument\": \"{\\\"Version\\\": \\\"2012-10-17\\\", \\\"Statement\\\": {\\\"Effect\\\": \\\"Allow\\\", \\\"Principal\\\": {\\\"AWS\\\": \\\"arn:aws:iam::123456789012:root\\\"}, \\\"Action\\\": \\\"sts:AssumeRole\\\"}}\", \"roleName\": \"stratus-red-team-backdoor-r-role\"}"
          ],
          "response_elements": [],
          "role_sequence": [
            "account_name",
            "AWSReservedSSO_AdministratorAccess_a670eb90f07e2960"
          ],
          "user_agent": [
            "stratus-red-team_a24eac3a-4fee-46ce-bc37-b4e675343fc9"
          ],
          "last_timestamp": "2023-06-06T15:40:43Z"
        }
      ],
      "is_targeting_key_asset": false,
      "last_timestamp": "2023-06-06T17:01:04Z",
      "notes": [],
      "sensor_name": "mafosb50",
      "src_account": {
        "id": 21,
        "name": "account_name",
        "url": "http://server_url.com/api/v3.3/accounts/21",
        "threat": 76,
        "certainty": 35
      },
      "src_ip": "0.0.0.0",
      "state": "active",
      "summary": {
      },
      "tags": [],
      "threat": 80,
      "t_score": 80,
      "type": "account",
      "url": "http://server_url.com/api/v3.3/detections/132"
    },
    {
      "id": 135,
      "category": "lateral_movement",
      "certainty": 50,
      "c_score": 50,
      "description": "",
      "detection": "AWS Suspect Admin Privilege Granting",
      "detection_category": "lateral_movement",
      "detection_type": "aws_admin_privilege_granted",
      "grouped_details": [
        {
          "event_id": "85d88db5-cf2d-4b6e-9411-d3119d9920e0",
          "event_name": "AttachRolePolicy",
          "aws_account_id": "884414556547",
          "src_external_host": {
            "ip": "0.0.0.0"
          },
          "aws_region": "us-east-1",
          "access_key_id": [
            "123456"
          ],
          "identity_type": "Federated Account",
          "assumed_role": "AWSReservedSSO_AdministratorAccess_a670eb90f07e2960",
          "request_parameters": [
            "{\"roleName\":\"stratus-red-team-backdoor-r-role\",\"policyArn\":\"arn:aws:iam::aws:policy/AdministratorAccess\"}"
          ],
          "response_elements": [],
          "role_sequence": [
            "account_name",
            "AWSReservedSSO_AdministratorAccess_a670eb90f07e2960"
          ],
          "user_agent": [
            "APN/1.0 HashiCorp/1.0 Terraform/1.1.2 (+https://www.terraform.io) terraform-provider-aws/3.76.1 (+https://registry.terraform.io/providers/hashicorp/aws) aws-sdk-go/1.44.157 (go1.19.3; linux; amd64) stratus-red-team_5077134d-32ea-4403-996b-de30d7f278d7 HashiCorp-terraform-exec/0.17.3"
          ],
          "last_timestamp": "2023-06-06T17:00:46Z"
        },
        {
          "event_id": "ca157e7c-9a53-4012-9288-e6ac1c488fbc",
          "event_name": "AttachRolePolicy",
          "aws_account_id": "884414556547",
          "src_external_host": {
            "ip": "0.0.0.0"
          },
          "aws_region": "us-east-1",
          "access_key_id": [
            "123456"
          ],
          "identity_type": "Federated Account",
          "assumed_role": "AWSReservedSSO_AdministratorAccess_a670eb90f07e2960",
          "request_parameters": [
            "{\"roleName\":\"stratus-red-team-backdoor-r-role\",\"policyArn\":\"arn:aws:iam::aws:policy/AdministratorAccess\"}"
          ],
          "response_elements": [],
          "role_sequence": [
            "account_name",
            "AWSReservedSSO_AdministratorAccess_a670eb90f07e2960"
          ],
          "user_agent": [
            "APN/1.0 HashiCorp/1.0 Terraform/1.1.2 (+https://www.terraform.io) terraform-provider-aws/3.76.1 (+https://registry.terraform.io/providers/hashicorp/aws) aws-sdk-go/1.44.157 (go1.19.3; linux; amd64) stratus-red-team_01be8427-d1b5-4c18-8edb-0301c8e66c8e HashiCorp-terraform-exec/0.17.3"
          ],
          "last_timestamp": "2023-06-06T15:40:07Z"
        }
      ],
      "is_targeting_key_asset": false,
      "last_timestamp": "2023-06-06T17:00:46Z",
      "notes": [],
      "sensor_name": "mafosb50",
      "src_account": {
        "id": 21,
        "name": "account_name",
        "url": "http://server_url.com/api/v3.3/accounts/21",
        "threat": 76,
        "certainty": 35
      },
      "src_ip": "0.0.0.0",
      "state": "fixed",
      "summary": {
      },
      "tags": [],
      "threat": 60,
      "t_score": 60,
      "type": "account",
      "url": "http://server_url.com/api/v3.3/detections/135"
    },
    {
      "id": 140,
      "category": "reconnaissance",
      "certainty": 40,
      "c_score": 40,
      "description": "",
      "detection": "RPC Targeted Recon",
      "detection_category": "reconnaissance",
      "detection_type": "rpc_recon_1to1",
      "grouped_details": [
        {
          "event_id": "cf9f469b-0a8e-47c6-85eb-5a0486292e58",
          "event_name": "ModifySnapshotAttribute",
          "aws_account_id": "884414556547",
          "src_external_host": {
            "ip": "0.0.0.0"
          },
          "aws_region": "us-west-2",
          "access_key_id": [
            "123456"
          ],
          "identity_type": "Federated Account",
          "assumed_role": "AWSReservedSSO_AdministratorAccess_a670eb90f07e2960",
          "request_parameters": [
            "{\"snapshotId\":\"snap-0f7d022a2f4f67e08\",\"createVolumePermission\":{\"add\":{\"items\":[{\"userId\":\"012345678912\"}]}},\"attributeType\":\"CREATE_VOLUME_PERMISSION\"}"
          ],
          "response_elements": [
            "{\"requestId\":\"350c1eb8-b696-4d94-88d4-a764a0eed08b\",\"_return\":true}"
          ],
          "role_sequence": [
            "account_name",
            "AWSReservedSSO_AdministratorAccess_a670eb90f07e2960"
          ],
          "user_agent": [
            "stratus-red-team_a4dd596b-7a8d-4e77-a74d-13f19adf4403"
          ],
          "last_timestamp": "2023-06-06T15:46:28Z"
        }
      ],
      "is_targeting_key_asset": false,
      "last_timestamp": "2023-06-06T15:46:28Z",
      "notes": [],
      "sensor_name": "mafosb50",
      "src_account": {
        "id": 21,
        "name": "account_name",
        "url": "http://server_url.com/api/v3.3/accounts/21",
        "threat": 76,
        "certainty": 35
      },
      "src_ip": "0.0.0.0",
      "state": "fixed",
      "summary": {
      },
      "tags": [],
      "threat": 60,
      "t_score": 60,
      "type": "account",
      "url": "http://server_url.com/api/v3.3/detections/140"
    }
  ]
}
```

#### Human Readable Output

>### Detections Table (Showing Page 1 out of 1)
>
>|ID|Detection Name|Detection Type|Category|Account Name|Src IP|Threat Score|Certainty Score|Number Of Events|State|Last Timestamp|
>|---|---|---|---|---|---|---|---|---|---|---|
>| [132](http://server_url.com/detections/132) | Data Smuggler | smuggler | exfiltration | [account_name](http://server_url.com/accounts/21) | 0.0.0.0 | 80 | 70 | 0 | active | 2023-06-06T17:01:04Z |
>| [135](http://server_url.com/detections/135) | AWS Suspect Admin Privilege Granting | aws_admin_privilege_granted | lateral_movement | [account_name](http://server_url.com/accounts/21) | 0.0.0.0 | 60 | 50 | 0 | fixed | 2023-06-06T17:00:46Z |
>| [140](http://server_url.com/detections/140) | RPC Targeted Recon | rpc_recon_1to1 | reconnaissance | [account_name](http://server_url.com/accounts/21) | 0.0.0.0 | 60 | 40 | 0 | fixed | 2023-06-06T15:46:28Z |

### vectra-entity-note-add

***
Add a note to the entity.

#### Base Command

`vectra-entity-note-add`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entity_id | Specify the id of the entity. | Required |
| entity_type | Specify the type of the entity. Possible values are: account, host. | Required |
| note | Note to be added in the specified entity_id. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Vectra.Entity.Notes.entity_id | String | ID of the entity associated with the note. |
| Vectra.Entity.Notes.note_id | Number | ID of the note. |
| Vectra.Entity.Notes.date_created | Date | Date when the note was created. |
| Vectra.Entity.Notes.date_modified | Unknown | Date when the note was last modified. |
| Vectra.Entity.Notes.created_by | String | User who created the note. |
| Vectra.Entity.Notes.modified_by | Unknown | User who last modified the note. |
| Vectra.Entity.Notes.note | String | Content of the note. |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Vectra.Entity.Notes.entity_id | String | The ID of the entity associated with the note. |
| Vectra.Entity.Notes.note_id | Number | The ID of the note. |
| Vectra.Entity.Notes.date_created | Date | The date when the note was created. |
| Vectra.Entity.Notes.date_modified | Unknown | The date when the note was last modified. |
| Vectra.Entity.Notes.created_by | String | The user who created the note. |
| Vectra.Entity.Notes.modified_by | Unknown | The user who last modified the note. |
| Vectra.Entity.Notes.note | String | The content of the note. |

#### Command example

```!vectra-entity-note-add entity_id=1 entity_type=account note="test note"```

#### Context Example

```json
{
  {
    "date_created": "2023-06-21T06:19:15.224449Z",
    "created_by": "test_user",
    "note": "test_note",
    "note_id": 19,
    "entity_id": 1
  }
}
```

#### Human Readable Output

>##### The note has been successfully added to the entity
>
>Returned Note ID: **19**

### vectra-entity-note-update

***
Update a note in the entity.

#### Base Command

`vectra-entity-note-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entity_id | Specify the id of the entity. | Required |
| entity_type | Specify the type of the entity. Possible values are: account, host. | Required |
| note_id | Specify the ID of the note. | Required |
| note | Note to be updated for the specified note_id. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Vectra.Entity.Notes.entity_id | String | ID of the entity associated with the note. |
| Vectra.Entity.Notes.note_id | Number | ID of the note. |
| Vectra.Entity.Notes.date_created | Date | Date when the note was created. |
| Vectra.Entity.Notes.date_modified | Unknown | Date when the note was last modified. |
| Vectra.Entity.Notes.created_by | String | User who created the note. |
| Vectra.Entity.Notes.modified_by | Unknown | User who last modified the note. |
| Vectra.Entity.Notes.note | String | Content of the note. |

#### Command example

```!vectra-entity-note-update entity_id=1 entity_type=account note_id=1 note="note modified"```

#### Context Example

```json
{
  {
    "date_created": "2023-06-16T04:55:58Z",
    "date_modified": "2023-06-22T04:57:09Z",
    "created_by": "test_user",
    "modified_by": "test_user",
    "note": "note modified",
    "note_id": 8,
    "entity_id": 1
  }
}
```

#### Human Readable Output

>##### The note has been successfully updated in the entity

### vectra-entity-note-remove

***
Remove a note from the entity.

#### Base Command

`vectra-entity-note-remove`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entity_id | Specify the ID of the entity. | Required |
| entity_type | Specify the type of the entity. Possible values are: account, host. | Required |
| note_id | Specify the ID of the note. | Required |

#### Context Output

There is no context output for this command.

#### Command Example

```!vectra-entity-note-remove entity_id=1 entity_type=account note_id=1"```

#### Context Example

```json
{}
```

#### Human Readable Output

>##### The note has been successfully removed from the entity

### vectra-entity-tag-add

***
Add tags in the entity.

#### Base Command

`vectra-entity-tag-add`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entity_id | Specify the id of the entity. | Required |
| entity_type | Specify the type of the entity. Possible values are: account, host. | Required |
| tags | Comma-separated values of tags to be included in the entity. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Vectra.Entity.Tags.tag_id | String | ID of the tag. |
| Vectra.Entity.Tags.entity_id | String | ID of the entity associated with the tag. |
| Vectra.Entity.Tags.entity_type | String | Type of the entity. |
| Vectra.Entity.Tags.tags | Unknown | A list of tags linked to an entity. |

#### Command example

```!vectra-entity-tag-add entity_id=1 entity_type=host tags="tag1, tag2"```

#### Context Example

```json
{
  {
    "tag_id": "1",
    "tags": [
        "tag1",
        "tag2"
    ],
    "entity_type": "host",
    "entity_id": 1
  }
}
```

#### Human Readable Output

>##### Tags have been successfully added to the entity
>
>Updated list of tags: **tag1**, **tag2**

### vectra-entity-tag-remove

***
Remove tags from the entity.

#### Base Command

`vectra-entity-tag-remove`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entity_id | Specify the id of the entity. | Required |
| entity_type | Specify the type of the entity. Possible values are: account, host. | Required |
| tags | Comma-separated values of tags to be removed from the entity. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Vectra.Entity.Tags.tag_id | String | ID of the tag. |
| Vectra.Entity.Tags.entity_id | String | ID of the entity associated with the tag. |
| Vectra.Entity.Tags.entity_type | String | Type of the entity. |
| Vectra.Entity.Tags.tags | Unknown | A list of tags linked to an entity. |

#### Command example

```!vectra-entity-tag-remove entity_id=1 entity_type=host tags="tag2"```

#### Context Example

```json
{
  {
    "tag_id": "1",
    "tags": ["tag1"],
    "entity_type": "host",
    "entity_id": 1
  }
}
```

#### Human Readable Output

>##### Specified tags have been successfully removed for the entity
>
>Updated list of tags: **tag1**

### vectra-entity-tag-list

***
Returns a list of tags for a specified entity.

#### Base Command

`vectra-entity-tag-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entity_id | Specify the id of the entity. | Required |
| entity_type | Specify the type of the entity. Possible values are: account, host. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Vectra.Entity.Tags.tag_id | String | ID of the tag. |
| Vectra.Entity.Tags.entity_id | String | ID of the entity associated with the tag. |
| Vectra.Entity.Tags.entity_type | String | Type of the entity. |
| Vectra.Entity.Tags.tags | Unknown | A list of tags linked to an entity. |

#### Command example

```!vectra-entity-tag-list entity_id=1 entity_type=host```

#### Context Example

```json
{
  "Vectra": {
    "Entity": {
      "Tags": {
        "tag_id": "1",
        "tags": [
            "tag1",
            "tag2"
        ],
        "entity_type": "host",
        "entity_id": 1
      }
    }
  }
}
```

#### Human Readable Output

>##### List of tags: **tag1**, **tag2**

### vectra-entity-assignment-add

***
Add an assignment for the entity.

#### Base Command

`vectra-entity-assignment-add`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entity_id | Specify the ID of the entity. | Required |
| entity_type | Specify the type of the entity. Possible values are: account, host. | Required |
| user_id | Specify the ID of the user. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Vectra.Entity.Assignments.id | Number | ID of the assignment. |
| Vectra.Entity.Assignments.assignment_id | Number | ID of the assignment. |
| Vectra.Entity.Assignments.assigned_by.id | Number | ID of the user who assigned the entity. |
| Vectra.Entity.Assignments.assigned_by.username | String | Username of the user who assigned the entity. |
| Vectra.Entity.Assignments.date_assigned | Date | Date when the entity was assigned. |
| Vectra.Entity.Assignments.date_resolved | Date | Date when the entity was resolved. |
| Vectra.Entity.Assignments.events.assignment_id | Number | ID of the assignment event. |
| Vectra.Entity.Assignments.events.actor | Number | ID of the actor who performed the assignment event. |
| Vectra.Entity.Assignments.events.event_type | String | Type of assignment event. |
| Vectra.Entity.Assignments.events.datetime | Date | Date of the assignment event. |
| Vectra.Entity.Assignments.events.context.to | Number | ID of the entity that was assigned to. |
| Vectra.Entity.Assignments.events.context.entity_t_score | Number | Threat score of the entity that was assigned to. |
| Vectra.Entity.Assignments.events.context.entity_c_score | Number | Certainty score of the entity that was assigned to. |
| Vectra.Entity.Assignments.outcome.id | String | ID of the assignment outcome. |
| Vectra.Entity.Assignments.outcome.builtin | String | Whether the assignment outcome is builtin or not. |
| Vectra.Entity.Assignments.outcome.user_selectable | String | Whether the assignment outcome is user selectable or not. |
| Vectra.Entity.Assignments.outcome.title | String | Title of the assignment outcome. |
| Vectra.Entity.Assignments.outcome.category | String | Category of the assignment outcome. |
| Vectra.Entity.Assignments.resolved_by.id | Number | ID of the user who resolved the entity. |
| Vectra.Entity.Assignments.resolved_by.username | String | Username of the user who resolved the entity. |
| Vectra.Entity.Assignments.triaged_detections | Unknown | Number of detections that have been triaged for the entity. |
| Vectra.Entity.Assignments.host_id | Number | ID of the host that the entity is associated with. |
| Vectra.Entity.Assignments.account_id | Unknown | ID of the account that the entity is associated with. |
| Vectra.Entity.Assignments.assigned_to.id | Number | ID of the user who is currently assigned to the entity. |
| Vectra.Entity.Assignments.assigned_to.username | String | Username of the user who is currently assigned to the entity. |

#### Command Example

```!vectra-entity-assignment-add entity_id=1 entity_type=account user_id=1```

#### Context Example

```json
{
  {
    "assigned_by": {
      "id": 2,
      "username": "test_user_2"
    },
    "date_assigned": "2023-07-24T08:52:59.367115Z",
    "events": [
      {
        "assignment_id": 74,
        "actor": 65,
        "event_type": "created",
        "datetime": "2023-07-24T08:52:59Z",
        "context": {
          "to": 60,
          "entity_t_score": 0,
          "entity_c_score": 0
        }
      }
    ],
    "host_id": 10,
    "assigned_to": {
      "id": 1,
      "username": "test.user@mail.com"
    },
    "assignment_id": 1,
    "id":1
  }
}
```

#### Human Readable Output

>##### The assignment has been successfully created
>
>### Assignment detail
>
>|Assignment ID|Assigned By|Assigned Date|Assigned To|Event Type|
>|---|---|---|---|---|
>| 1 | test_user_2 | 2023-07-24T08:52:59.367115Z | test.user@mail.com | created |

### vectra-entity-assignment-update

***
Update an assignment in the entity.

#### Base Command

`vectra-entity-assignment-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| assignment_id | Specify the ID of the assignment. | Required |
| user_id | Specify the ID of the user. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Vectra.Entity.Assignments.id | Number | ID of the assignment. |
| Vectra.Entity.Assignments.assignment_id | Number | ID of the assignment. |
| Vectra.Entity.Assignments.assigned_by.id | Number | ID of the user who assigned the entity. |
| Vectra.Entity.Assignments.assigned_by.username | String | Username of the user who assigned the entity. |
| Vectra.Entity.Assignments.date_assigned | Date | Date when the entity was assigned. |
| Vectra.Entity.Assignments.date_resolved | Date | Date when the entity was resolved. |
| Vectra.Entity.Assignments.events.assignment_id | Number | ID of the assignment event. |
| Vectra.Entity.Assignments.events.actor | Number | ID of the actor who performed the assignment event. |
| Vectra.Entity.Assignments.events.event_type | String | Type of assignment event. |
| Vectra.Entity.Assignments.events.datetime | Date | Date of the assignment event. |
| Vectra.Entity.Assignments.events.context.to | Number | ID of the entity that was assigned to. |
| Vectra.Entity.Assignments.events.context.from | Number | ID of the entity that was assigned. |
| Vectra.Entity.Assignments.events.context.entity_t_score | Number | Threat score of the entity that was assigned to. |
| Vectra.Entity.Assignments.events.context.entity_c_score | Number | Certainty score of the entity that was assigned to. |
| Vectra.Entity.Assignments.outcome.id | String | ID of the assignment outcome. |
| Vectra.Entity.Assignments.outcome.builtin | String | Whether the assignment outcome is builtin or not. |
| Vectra.Entity.Assignments.outcome.user_selectable | String | Whether the assignment outcome is user selectable or not. |
| Vectra.Entity.Assignments.outcome.title | String | Title of the assignment outcome. |
| Vectra.Entity.Assignments.outcome.category | String | Category of the assignment outcome. |
| Vectra.Entity.Assignments.resolved_by.id | Number | ID of the user who resolved the entity. |
| Vectra.Entity.Assignments.resolved_by.username | String | Username of the user who resolved the entity. |
| Vectra.Entity.Assignments.triaged_detections | Unknown | Number of detections that have been triaged for the entity. |
| Vectra.Entity.Assignments.host_id | Number | ID of the host that the entity is associated with. |
| Vectra.Entity.Assignments.account_id | Unknown | ID of the account that the entity is associated with. |
| Vectra.Entity.Assignments.assigned_to.id | Number | ID of the user who is currently assigned to the entity. |
| Vectra.Entity.Assignments.assigned_to.username | String | Username of the user who is currently assigned to the entity. |

#### Command Example

```!vectra-entity-assignment-update assignment_id=1 user_id=2```

#### Context Example

```json
{
  {
    "assigned_by": {
      "id": 65,
      "username": "api_client"
    },
    "date_assigned": "2023-07-21T12:44:10Z",
    "events": [
      {
        "assignment_id": 1,
        "actor": 65,
        "event_type": "reassigned",
        "datetime": "2023-07-25T06:26:10Z",
        "context": {
          "from": 1,
          "to": 2,
          "entity_t_score": 68,
          "entity_c_score": 90
        }
      },
      {
        "assignment_id": 1,
        "actor": 65,
        "event_type": "created",
        "datetime": "2023-07-21T12:44:10Z",
        "context": {
          "to": 1,
          "entity_t_score": 68,
          "entity_c_score": 90
        }
      }
    ],
    "host_id": 97,
    "assigned_to": {
      "id": 2,
      "username": "test_user_2"
    },
    "assignment_id": 1,
    "id": 1
  }
}
```

#### Human Readable Output

>##### The assignment has been successfully updated
>
>### Assignment detail
>
>|Assignment ID|Assigned By|Assigned Date|Assigned To|Event Type|
>|---|---|---|---|---|
>| 1 | api_client | 2023-07-21T12:44:10Z | test_user_2 | reassigned |

### vectra-detection-pcap-download

***
Download pcap of the detection.

#### Base Command

`vectra-detection-pcap-download`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| detection_id | Specify the ID of the detection. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.Size | Number | The size of the file. |
| File.SHA1 | String | The SHA1 hash of the file. |
| File.SHA256 | String | The SHA256 hash of the file. |
| File.SHA512 | String | The SHA512 hash of the file. |
| File.Name | String | The name of the file. |
| File.SSDeep | String | The SSDeep hash of the file. |
| File.EntryID | String | The entry ID of the file. |
| File.Info | String | File information. |
| File.Type | String | The file type. |
| File.MD5 | String | The MD5 hash of the file. |
| File.Extension | String | The file extension. |

#### Command Example

```!vectra-detection-pcap-download detection_id="116"```

#### Context Example

```json
{
    "File": {
      "EntryID": "1703@7e0f6637-f0a4-46b3-8c61-2f94b3432428",
      "Extension": "pcap",
      "Info": "pcap-ng capture file - version 1.0",
      "MD5": "709db6e1f8f5054ca57caf43ba248ed6",
      "Name": "IP-192.168.55.10_hidden_dns_tunnel_1382.pcap",
      "SHA1": "49fe55c6aef85549261b46dd2e54f8d485306ee5",
      "SHA256": "8615bde9332584b4fd4fe4dc2cc6fc4c75504f6d44667814456c089fd413aa4d",
      "SHA512": "3fa29be0e20884c850b62d2a99aa09b24488289ba0bc9aff37ebe982c21d3a78fb26d9c9ac7fbf2a0839ba649dc0a845f30e7f13de3a0c6284c3c2ac54102143",
      "SSDeep": "384:dN+Pm11R0XPmts64kZog9ZaikYngk+SnRxFyeyCEyuAOasucOcakca0/rHfcjOUI:dI+t25caEPjRSnmuNasxRana4DgOUDcX",
      "Size": 23988,
      "Type": "application/vnd.tcpdump.pcap"
  }
}
```

#### Human Readable Output

>Uploaded file: IP-192.168.55.10_hidden_dns_tunnel_1382.pcap
>
>|Property|Type|Size|Info|MD5|SHA1|SHA256|SHA512|SSDeep|
>|---|---|---|---|---|---|---|---|---|
>| Value | application/vnd.tcpdump.pcap | 23,988 bytes | pcap-ng capture file - version 1.0 | 709db6e1f8f5054ca57caf43ba248ed6 | 49fe55c6aef85549261b46dd2e54f8d485306ee5 | 8615bde9332584b4fd4fe4dc2cc6fc4c75504f6d44667814456c089fd413aa4d | 3fa29be0e20884c850b62d2a99aa09b24488289ba0bc9aff37ebe982c21d3a78fb26d9c9ac7fbf2a0839ba649dc0a845f30e7f13de3a0c6284c3c2ac54102143 |  384:dN+Pm11R0XPmts64kZog9ZaikYngk+SnRxFyeyCEyuAOasucOcakca0/rHfcjOUI:dI+t25caEPjRSnmuNasxRana4DgOUDcX |

### vectra-assignment-list

***
Returns a list of all assignments.

#### Base Command

`vectra-assignment-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entity_ids | Specify the IDs of the entities. Comma-separated values supported. | Optional |
| entity_type | Specify the type of the entity. Possible values are: account, host. | Optional |
| resolved | Filter by resolved status. Possible values are: True, False. | Optional |
| assignees | Filter by user ids of the assignment. Comma-separated values supported. | Optional |
| resolution | Filter by outcome ids of the resolution. Comma-separated values supported. | Optional |
| created_after | Filter by created after the timestamp.<br/><br/>Supported formats: 2 minutes, 2 hours, 2 days, 2 weeks, 2 months, 2 years, yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ.<br/>    <br/>For example: 01 May 2023, 01 Mar 2021 04:45:33, 2022-04-17T14:05:44Z. | Optional |
| page | Enables the caller to specify a particular page of results. Default is 1. | Optional |
| page_size | Specify the desired page size for the request. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Vectra.Entity.Assignments.id | Number | ID of the assignment. |
| Vectra.Entity.Assignments.assignment_id | Number | ID of the assignment. |
| Vectra.Entity.Assignments.assigned_by.id | Number | ID of the user who assigned the entity. |
| Vectra.Entity.Assignments.assigned_by.username | String | Username of the user who assigned the entity. |
| Vectra.Entity.Assignments.date_assigned | Date | Date when the entity was assigned. |
| Vectra.Entity.Assignments.date_resolved | Date | Date when the entity was resolved. |
| Vectra.Entity.Assignments.events.assignment_id | Number | ID of the assignment event. |
| Vectra.Entity.Assignments.events.actor | Number | ID of the actor who performed the assignment event. |
| Vectra.Entity.Assignments.events.event_type | String | Type of the assignment event. |
| Vectra.Entity.Assignments.events.datetime | Date | Date of the assignment event. |
| Vectra.Entity.Assignments.events.context.to | Number | ID of the entity that was assigned to. |
| Vectra.Entity.Assignments.events.context.entity_t_score | Number | Threat score of the entity that was assigned to. |
| Vectra.Entity.Assignments.events.context.entity_c_score | Number | Certainty score of the entity that was assigned to. |
| Vectra.Entity.Assignments.events.context.triage_as | String | Triage status of the entity. |
| Vectra.Entity.Assignments.events.context.triaged_detection_ids | Array | IDs of the detections that have been triaged for the entity. |
| Vectra.Entity.Assignments.events.context.fixed_detection_ids | Array | IDs of the detections that have been fixed. |
| Vectra.Entity.Assignments.events.context.created_rule_ids | Array | IDs of the rules that have been created for the entity. |
| Vectra.Entity.Assignments.outcome.id | Number | ID of the assignment outcome. |
| Vectra.Entity.Assignments.outcome.builtin | Boolean | Whether the assignment outcome is builtin or not. |
| Vectra.Entity.Assignments.outcome.user_selectable | Boolean | Whether the assignment outcome is user selectable or not. |
| Vectra.Entity.Assignments.outcome.title | String | Title of the assignment outcome. |
| Vectra.Entity.Assignments.outcome.category | String | Category of the assignment outcome. |
| Vectra.Entity.Assignments.resolved_by.id | Number | ID of the user who resolved the entity. |
| Vectra.Entity.Assignments.resolved_by.username | String | Username of the user who resolved the entity. |
| Vectra.Entity.Assignments.triaged_detections | Array | Number of detections that have been triaged for the entity. |
| Vectra.Entity.Assignments.host_id | Number | ID of the host that the entity is associated with. |
| Vectra.Entity.Assignments.account_id | Number | ID of the account that the entity is associated with. |
| Vectra.Entity.Assignments.assigned_to.id | Number | ID of the user who is currently assigned to the entity. |
| Vectra.Entity.Assignments.assigned_to.username | String | Username of the user who is currently assigned to the entity. |

#### Command Example

```!vectra-assignment-list```

#### Context Example

```json
{
    "Vectra": {
      "Entity": {
        "Assignments": [
          {
            "id": 214,
            "assigned_by": {
              "id": 64,
              "username": "test.user4@mail.com"
            },
            "date_assigned": "2023-08-18T10:55:29Z",
            "events": [
              {
                "assignment_id": 214,
                "actor": 64,
                "event_type": "reassigned",
                "datetime": "2023-08-18T10:56:11Z",
                "context": {
                  "from": 39,
                  "to": 59,
                  "entity_t_score": 0,
                  "entity_c_score": 0
                }
              },
              {
                "assignment_id": 214,
                "actor": 64,
                "event_type": "created",
                "datetime": "2023-08-18T10:55:29Z",
                "context": {
                  "to": 39,
                  "entity_t_score": 0,
                  "entity_c_score": 0
                }
              }
            ],
            "host_id": 220,
            "assigned_to": {
              "id": 59,
              "username": "test.user2@mail.com"
            },
            "assignment_id": 214
          },
          {
            "id": 212,
            "assigned_by": {
              "id": 65,
              "username": "test.user4@mail.com"
            },
            "date_assigned": "2023-08-18T06:29:56Z",
            "date_resolved": "2023-08-18T06:32:09Z",
            "events": [
              {
                "assignment_id": 212,
                "actor": 65,
                "event_type": "resolved",
                "datetime": "2023-08-18T06:32:09Z",
                "context": {
                  "entity_t_score": 77,
                  "entity_c_score": 53
                }
              },
              {
                "assignment_id": 212,
                "actor": 65,
                "event_type": "reassigned",
                "datetime": "2023-08-18T06:31:02Z",
                "context": {
                  "from": 59,
                  "to": 60,
                  "entity_t_score": 77,
                  "entity_c_score": 53
                }
              },
              {
                "assignment_id": 212,
                "actor": 65,
                "event_type": "created",
                "datetime": "2023-08-18T06:29:56Z",
                "context": {
                  "to": 59,
                  "entity_t_score": 77,
                  "entity_c_score": 53
                }
              }
            ],
            "outcome": {
              "id": 1,
              "builtin": true,
              "user_selectable": true,
              "title": "Benign True Positive",
              "category": "benign_true_positive"
            },
            "resolved_by": {
              "id": 65,
              "username": "test.user4@mail.com"
            },
            "account_id": 108,
            "assigned_to": {
              "id": 60,
              "username": "test.user1@mail.com"
            },
            "assignment_id": 212
          }
        ]
      }
    }
  }

```

#### Human Readable Output

>### Assignments Table (Showing Page 1 out of 1)
>
>|Account ID|Host ID|Assignment ID|Assigned By|Assigned To|Date Assigned|Resolved By|Date Resolved|Outcome ID|Outcome|
>|---|---|---|---|---|---|---|---|---|---|
>|  | 220 | 214 | test.user4@mail.com | test.user2@mail.com | 2023-08-18T10:55:29Z |  |  |  |  |
>| 108 |  | 212 | test.user4@mail.com | test.user1@mail.com | 2023-08-18T06:29:56Z | test.user4@mail.com | 2023-08-18T06:32:09Z | 1 | Benign True Positive |

### vectra-entity-note-list

***
Returns a list of notes for a specified entity.

#### Base Command

`vectra-entity-note-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entity_id | Specify the ID of the entity. | Required |
| entity_type | Specify the type of the entity. Possible values are: host, account. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Vectra.Entity.Notes.note_id | Number | ID of the note. |
| Vectra.Entity.Notes.id | Number | ID of the note. |
| Vectra.Entity.Notes.date_created | Date | Date when the note was created. |
| Vectra.Entity.Notes.date_modified | Unknown | Date when the note was last modified. |
| Vectra.Entity.Notes.created_by | String | User who created the note. |
| Vectra.Entity.Notes.modified_by | Unknown | User who last modified the note. |
| Vectra.Entity.Notes.note | String | Content of the note. |
| Vectra.Entity.Notes.entity_id | String | ID of the entity associated with the note. |
| Vectra.Entity.Notes.entity_type | String | Type of the entity associated with the note. |

#### Command Example

```!vectra-entity-note-list entity_id="107" entity_type="account"```

#### Context Example

```json
{
  "Vectra": {
    "Entity": {
      "Notes": [
        {
          "created_by": "test_user@mail.com",
          "date_created": "2023-08-25T07:09:08Z",
          "entity_id": 107,
          "entity_type": "account",
          "id": 1070,
          "modified_by": "test_user@mail.com",
          "note": "From XSOAR",
          "note_id": 1070
        },
        {
          "created_by": "test_user@mail.com",
          "date_created": "2023-08-25T07:08:58Z",
          "entity_id": 107,
          "entity_type": "account",
          "id": 1069,
          "modified_by": "test_user@mail.com",
          "note": "Test note",
          "note_id": 1069
        },
        {
          "created_by": "api_client",
          "date_created": "2023-08-16T05:23:33Z",
          "entity_id": 107,
          "entity_type": "account",
          "id": 922,
          "note": "[Mirrored From XSOAR] XSOAR Incident ID: 14228\n\nNote: **bold**\n\n_Italic_\n\n+Underline+\n\n~~strikethrough~~\n\nAdded By: admin",
          "note_id": 922
        }
      ]
    }
  }
}

```

#### Human Readable Output

>### Entity Notes Table
>
>|Note ID|Note|Created By|Created Date|Modified By|Modified Date|
>|---|---|---|---|---|---|
>| 1070 | From XSOAR | test_user@mail.com | 2023-08-25T07:09:08Z | test_user@mail.com | 2023-08-25T08:10:08Z |
>| 1069 | Test note | test_user@mail.com | 2023-08-25T07:08:58Z | test_user@mail.com | 2023-08-25T08:10:08Z |
>| 922 | [Mirrored From XSOAR] XSOAR Incident ID: 14228<br>Note:XSOAR note<br>Added By: admin | api_client | 2023-08-16T05:23:33Z |  |  |

### vectra-group-list

***
Returns a list of all groups.

#### Base Command

`vectra-group-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_type | Filter by group type. Possible values are: account, host, ip, domain. | Optional |
| account_names | Filter by Account Names. Supports comma-separated values.<br/><br/>Note: Only valid when the group_type parameter is set to "account". | Optional |
| domains | Filter by Domains. Supports comma-separated values.<br/><br/>Note: Only valid when the group_type parameter is set to "domain". | Optional |
| host_ids | Filter by Host IDs. Supports comma-separated values.<br/><br/>Note: Only valid when the group_type parameter is set to "host". | Optional |
| host_names | Filter by Host Names. Supports comma-separated values.<br/><br/>Note: Only valid when the group_type parameter is set to "host". | Optional |
| importance | Filter by group importance. Possible values are: high, medium, low, never_prioritize. | Optional |
| ips | Filter by IPs. Supports comma-separated values.<br/><br/>Note: Only valid when the group_type parameter is set to "ip". | Optional |
| description | Filter by group description. | Optional |
| last_modified_timestamp | Return only the groups which have a last modification timestamp equal to or after the given timestamp.<br/><br/>Supported formats: 2 minutes, 2 hours, 2 days, 2 weeks, 2 months, 2 years, yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ.<br/><br/>For example: 01 May 2023, 01 Mar 2023 04:45:33, 2023-04-17T14:05:44Z. | Optional |
| last_modified_by | Filters by the user id who made the most recent modification to the group. | Optional |
| group_name | Filters by group name. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Vectra.Group.group_id | Number | ID of the group. |
| Vectra.Group.id | Number | ID of the group. |
| Vectra.Group.name | String | Name of the group. |
| Vectra.Group.description | String | Description of the group. |
| Vectra.Group.last_modified | Date | Date when the group was last modified. |
| Vectra.Group.last_modified_by | String | Name of the user who last modified the group. |
| Vectra.Group.type | String | Type of the group. |
| Vectra.Group.members | Unknown | Members of the group. |
| Vectra.Group.members.id | Number | Entity ID of member. |
| Vectra.Group.members.name | String | Entity name of member. |
| Vectra.Group.members.is_key_asset | Boolean | Indicates key asset. |
| Vectra.Group.members.url | String | Entity URL of member. |
| Vectra.Group.members.uid | String | Entity UID of member. |
| Vectra.Group.rules.triage_category | String | Triage category of rule. |
| Vectra.Group.rules.id | Number | Id of the rule. |
| Vectra.Group.rules.description | String | Description of the rule. |
| Vectra.Group.importance | String | Importance level of the group. |
| Vectra.Group.cognito_managed | Boolean | Whether the group is managed by Cognito or not. |

#### Command Example

```!vectra-group-list```

#### Context Example

```json
{
  "Vectra": {
    "Group": [
      {
        "id": 1,
        "group_id": 1,
        "name": "Cognito - Box",
        "description": "Domains used by the Box service",
        "last_modified": "2023-05-31T13:57:53Z",
        "last_modified_by": "cognito",
        "type": "domain",
        "members": [
          "*.abc.com",
          "*.xyz.net"
        ],
        "rules": [
          {
            "triage_category": "Box",
            "id": 175,
            "description": "data storage to Box service"
          }
        ],
        "importance": "medium",
        "cognito_managed": true
      },
      {
        "id": 8,
        "group_id": 8,
        "name": "Cognito - IPAM",
        "description": "IPAM, created by Cognito",
        "last_modified": "2023-08-18T09:16:54Z",
        "last_modified_by": "cognito",
        "type": "host",
        "members": [
          {
            "is_key_asset": false,
            "id": 97,
            "name": "IP-0.0.0.0",
            "url": "https://server_url.com/api/v3.3/hosts/97"
          },
          {
            "is_key_asset": false,
            "id": 212,
            "name": "IP-0.0.0.1",
            "url": "https://server_url.com/api/v3.3/hosts/212"
          }
        ],
        "rules": [
          {
            "triage_category": "Expected IPAM Behavior",
            "id": 189,
            "description": "Expected behavior from these devices"
          },
          {
            "triage_category": "Expected IPAM Behavior",
            "id": 193,
            "description": "Expected behavior from these devices"
          }
        ],
        "importance": "medium"
      },
      {
        "id": 16,
        "group_id": 16,
        "name": "Cognito - Guest Wifi",
        "description": "IP space used by Guest Wifi",
        "last_modified": "2023-08-18T08:55:54Z",
        "last_modified_by": "cognito",
        "type": "ip",
        "members": [
          "0.0.0.0",
          "0.0.0.1"
        ],
        "importance": "medium",
        "cognito_managed": false
      },
      {
        "id": 22,
        "group_id": 22,
        "name": "Dev-Group-Account-High",
        "description": "",
        "last_modified": "2023-08-25T10:17:37Z",
        "last_modified_by": "cognito",
        "type": "account",
        "members": [
          {
            "uid": "O300:service-principal_00000000-0000-0000-0000-000000000001"
          },
          {
            "uid": "administrator@fictotech.com"
          }
        ],
        "importance": "high"
      }
    ]
  }
}
```

#### Human Readable Output

>### Groups Table
>
>|Group ID|Name|Group Type|Description|Importance|Members|Last Modified Timestamp|
>|---|---|---|---|---|---|---|
>| 1 | Cognito - Box | domain | Domains used by the Box service | medium | \*\.abc\.com, \*\.xyz\.net | 2023-05-31T13:57:53Z |
>| 8 | Cognito - IPAM | host | IPAM, created by Cognito | medium | [97](https://server_url.com/hosts/97?pivot=Vectra-RUX-XSOAR-1.0.0), [212](https://server_url.com/hosts/212?pivot=Vectra-RUX-XSOAR-1.0.0) | 2023-08-18T09:16:54Z |
>| 16 | Cognito - Guest Wifi | ip | IP space used by Guest Wifi | medium | 0\.0\.0\.0, 0\.0\.0\.1 | 2023-08-18T08:55:54Z |
>| 22 | Dev-Group-Account-High | account |  | high | O300:service\-principal_00000000\-0000\-0000\-0000\-000000000001, administrator@fictotech\.com | 2023-08-25T10:17:37Z |

### vectra-group-unassign

***
Unassign members from the specified group.

#### Base Command

`vectra-group-unassign`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_id | Specify Group ID to unassign members. | Required |
| members | Member values based on the group type. Supports comma-separated values.<br/><br/> Note: <br/>If the group type is host, then the "Host IDs". <br/>If the group type is account, then "Account Names".<br/>If the group type is ip, then the list of "IPs".<br/>If the group type is domain, then the list of "Domains" . | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Vectra.Group.group_id | Number | ID of the group. |
| Vectra.Group.id | Number | ID of the group. |
| Vectra.Group.name | String | Name of the group. |
| Vectra.Group.description | String | Description of the group. |
| Vectra.Group.last_modified | Date | Date when the group was last modified. |
| Vectra.Group.last_modified_by | String | Name of the user who last modified the group. |
| Vectra.Group.type | String | Type of the group. |
| Vectra.Group.members | Unknown | Members of the group. |
| Vectra.Group.members.id | Number | Entity ID of member. |
| Vectra.Group.members.name | String | Entity name of member. |
| Vectra.Group.members.is_key_asset | Boolean | Indicates key asset. |
| Vectra.Group.members.url | String | Entity URL of member. |
| Vectra.Group.members.uid | String | Entity UID of member. |
| Vectra.Group.rules.triage_category | String | Triage category of rule. |
| Vectra.Group.rules.id | Number | Id of the rule. |
| Vectra.Group.rules.description | String | Description of the rule. |

#### Command Example

```!vectra-group-unassign group_id=23 members="*.domain4.com,*.domain5.com"```

#### Context Example

```json
{
  "Vectra": {
    "Group": {
      "cognito_managed": false,
      "description": "xsoar-group-accout-test",
      "group_id": 23,
      "id": 23,
      "last_modified": "2023-09-04T12:03:02Z",
      "last_modified_by": "API Client a7f5be37",
      "members": ["*.domain1.net", "*.domain2.com", "*.domain3.com"],
      "name": "xsoar-group-accout-test",
      "type": "domain"
    }
  }
}
```

#### Human Readable Output

>### Member(s) \*.domain4.com, \*.domain5.com have been unassigned from the group
>
>### Updated group details
>
>|Group ID|Name|Group Type|Description|Members|Last Modified Timestamp|
>|---|---|---|---|---|---|
>| 1 | xsoar-group-accout-test | domain | xsoar-group-accout-test | \*\.domain1\.net, \*\.domain2\.com, \*\.domain3\.com | 2023-09-04T07:30:01Z |

### vectra-group-assign

***
Assign members to the specified group.

#### Base Command

`vectra-group-assign`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_id | Specify Group ID to assign members. | Required |
| members | Member values based on the group type. Supports comma-separated values.<br/><br/> Note: <br/>If the group type is host, then the "Host IDs". <br/>If the group type is account, then "Account Names".<br/>If the group type is ip, then the list of "IPs".<br/>If the group type is domain, then the list of "Domains" . | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Vectra.Group.group_id | Number | ID of the group. |
| Vectra.Group.id | Number | ID of the group. |
| Vectra.Group.name | String | Name of the group. |
| Vectra.Group.description | String | Description of the group. |
| Vectra.Group.last_modified | Date | Date when the group was last modified. |
| Vectra.Group.last_modified_by | String | Name of the user who last modified the group. |
| Vectra.Group.type | String | Type of the group. |
| Vectra.Group.members | Unknown | Members of the group. |
| Vectra.Group.members.id | Number | Entity ID of member. |
| Vectra.Group.members.name | String | Entity name of member. |
| Vectra.Group.members.is_key_asset | Boolean | Indicates key asset. |
| Vectra.Group.members.url | String | Entity URL of member. |
| Vectra.Group.members.uid | String | Entity UID of member. |
| Vectra.Group.rules.triage_category | String | Triage category of rule. |
| Vectra.Group.rules.id | Number | Id of the rule. |
| Vectra.Group.rules.description | String | Description of the rule. |

#### Command Example

```!vectra-group-assign group_id=23 members="*.domain4.com,*.domain5.com"```

#### Context Example

```json
{
  "Vectra": {
    "Group": {
      "cognito_managed": false,
      "description": "xsoar-group-accout-test",
      "group_id": 23,
      "id": 23,
      "last_modified": "2023-09-04T11:59:15Z",
      "last_modified_by": "API Client a7f5be37",
      "members": [
        "*.domain1.net",
        "*.domain2.com",
        "*.domain3.com",
        "*.domain4.com",
        "*.domain5.com"
      ],
      "name": "xsoar-group-accout-test",
      "type": "domain"
    }
  }
}
```

#### Human Readable Output

>### Member(s) \*.domain4.com, \*.domain5.com have been assigned to the group
>
>### Updated group details
>
>|Group ID|Name|Group Type|Description|Members|Last Modified Timestamp|
>|---|---|---|---|---|---|
>| 1 | xsoar-group-accout-test | domain | xsoar-group-accout-test | \*\.domain1\.net, \*\.domain2\.com, \*\.domain3\.com, \*\.domain4\.com, \*\.domain5\.com | 2023-09-04T06:30:01Z |

### vectra-entity-detections-mark-asclosed

***
Mark the detections of the entity as closed with the provided entity ID in the argument.

#### Base Command

`vectra-entity-detections-mark-asclosed`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entity_id | Specify the ID of the entity. | Required |
| entity_type | Specify the type of the entity. Possible values are: account, host. | Required |
| close_reason | Specify the close reason. Possible values are: benign, remediated. | Required |

#### Context Output

There is no context output for this command.

#### Command example

```!vectra-entity-detections-mark-asclosed entity_id=1 entity_type=account close_reason=benign```

#### Human Readable Output

>##### The detections (34122, 35097) of the provided entity ID have been successfully closed as benign

### vectra-detections-mark-asopen

***
Open detections with provided detection IDs in the argument.

#### Base Command

`vectra-detections-mark-asopen`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| detection_ids | Provide a list of detection IDs separated by commas or a single detection ID. | Required |

#### Context Output

There is no context output for this command.

#### Command example

```!vectra-detections-mark-asopen detection_ids=1,2,3```

#### Human Readable Output

>##### The provided detection IDs have been successfully re-opened

### vectra-detection-tag-list

***
Returns a list of tags for a specified detection.

#### Base Command

`vectra-detection-tag-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| detection_id | Specify the ID of the detection. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Vectra.Detection.Tags.tag_id | String | The ID of the tag. |
| Vectra.Detection.Tags.detection_id | String | The ID of the Detection associated with the tag. |
| Vectra.Detection.Tags.tags | Unknown | A list of tags linked to a detection. |

#### Command example

```!vectra-detection-tag-list detection_id=123```

#### Context Example

```json
{
    "Vectra": {
        "Detection": {
            "Tags": {
                "detection_id": 123,
                "tag_id": "123",
                "tags": [
                    "tag1",
                    "tag2"
                ]
            }
        }
    }
}
```

#### Human Readable Output

>##### List of tags: **tag1, tag2**

### vectra-detection-tag-add

***
Add tags to a detection.

#### Base Command

`vectra-detection-tag-add`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| detection_id | Specify the ID of the detection. | Required |
| tags | Comma-separated values of tags to be added to the detection. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Vectra.Detection.Tags.tag_id | String | The ID of the tag. |
| Vectra.Detection.Tags.detection_id | String | The ID of the detection associated with the tag. |
| Vectra.Detection.Tags.tags | Unknown | A list of tags linked to a detection. |

#### Command example

```!vectra-detection-tag-add detection_id=1 tags="tag1,tag2"```

#### Context Example

```json
{
    "Vectra": {
        "Detection": {
            "Tags": {
                "detection_id": 1,
                "tag_id": 1,
                "tags": [
                    "tag",
                    "tag1",
                    "tag2"
                ]
            }
        }
    }
}
```

#### Human Readable Output

>##### Tags have been successfully added to the detection
>
>Updated list of tags: **tag**, **tag1**, **tag2**

### vectra-detection-tag-remove

***
Remove tags from the detection.

#### Base Command

`vectra-detection-tag-remove`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| detection_id | Specify the ID of the detection. | Required |
| tags | Comma-separated values of tags to be removed from the detection. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Vectra.Detection.Tags.tag_id | String | The ID of the tag. |
| Vectra.Detection.Tags.detection_id | String | The ID of the detection associated with the tag. |
| Vectra.Detection.Tags.tags | Unknown | A list of tags linked to a detection. |

#### Command example

```!vectra-detection-tag-remove detection_id="2" tags="tag3,tag4"```

#### Context Example

```json
{
    "Vectra": {
        "Detection": {
            "Tags": {
                "detection_id": 2,
                "tag_id": "2",
                "tags": [
                    "tag",
                    "tag1",
                    "tag2"
                ]
            }
        }
    }
}
```

#### Human Readable Output

>##### Specified tags have been successfully removed for the detection
>
>Updated list of tags: **tag**, **tag1**, **tag2**

### vectra-detection-note-list

***
Returns a list of notes for a specified detection.

#### Base Command

`vectra-detection-note-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| detection_id | Specify the ID of the detection. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Vectra.Detection.Notes.note_id | Number | ID of the note. |
| Vectra.Detection.Notes.id | Number | ID of the note. |
| Vectra.Detection.Notes.date_created | Date | Date when the note was created \(ISO8601\). |
| Vectra.Detection.Notes.date_modified | Date | Date when the note was last modified \(ISO8601\). |
| Vectra.Detection.Notes.created_by | String | User who created the note. |
| Vectra.Detection.Notes.modified_by | String | User who last modified the note. |
| Vectra.Detection.Notes.note | String | Content of the note. |
| Vectra.Detection.Notes.detection_id | String | ID of the detection associated with the note. |

#### Command example

```!vectra-detection-note-list detection_id=1```

#### Context Example

```json
{
  "Vectra": {
    "Detection": {
      "Notes": [
        {
          "created_by": "test_user@mail.com",
          "date_created": "2023-08-25T07:09:08Z",
          "detection_id": 1,
          "id": 1070,
          "modified_by": "test_user@mail.com",
          "note": "From XSOAR",
          "note_id": 1070
        },
        {
          "created_by": "test_user@mail.com",
          "date_created": "2023-08-25T07:08:58Z",
          "detection_id": 1,
          "id": 1069,
          "modified_by": "test_user@mail.com",
          "note": "Test note",
          "note_id": 1069
        },
        {
          "created_by": "api_client",
          "date_created": "2023-08-16T05:23:33Z",
          "detection_id": 1,
          "id": 922,
          "note": "[Mirrored From XSOAR] XSOAR Incident ID: 14228\n\nNote: **bold**\n\n_Italic_\n\n+Underline+\n\n~~strikethrough~~\n\nAdded By: admin",
          "note_id": 922
        }
      ]
    }
  }
}
```

#### Human Readable Output

>### Detection Notes Table
>
>|Note ID|Note|Created By|Created Date|Modified By|Modified Date|
>|---|---|---|---|---|---|
>| 1070 | From XSOAR | test_user@mail.com | 2023-08-25T07:08:58Z | test_user@mail.com | 2023-08-25T07:08:58Z |
>| 1069 | Test note | test_user@mail.com | 2023-08-25T07:08:58Z | test_user@mail.com | 2023-08-25T07:08:58Z |
>| 922 | [Mirrored From XSOAR] XSOAR Incident ID: 14228\n\nNote: **bold**\n\n_Italic_\n\n+Underline+\n\n~~strikethrough~~\n\nAdded By: admin | api_client | 2023-08-16T05:23:33Z |  |  |

### vectra-detection-note-add

***
Add a note to the detection.

#### Base Command

`vectra-detection-note-add`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| detection_id | Specify the ID of the detection. | Required |
| note | Note to be added in the specified detection_id. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Vectra.Detection.Notes.detection_id | String | ID of the detection associated with the note. |
| Vectra.Detection.Notes.note_id | Number | ID of the note. |
| Vectra.Detection.Notes.id | Number | ID of the note. |
| Vectra.Detection.Notes.date_created | Date | Date when the note was created  \(ISO8601\). |
| Vectra.Detection.Notes.created_by | String | User who created the note. |
| Vectra.Detection.Notes.note | String | Content of the note. |

#### Command example

```!vectra-detection-note-add detection_id=1 note="test note"```

#### Context Example

```json
{
  {
    "date_created": "2023-06-21T06:19:15.224449Z",
    "created_by": "test_user",
    "note": "test note",
    "note_id": 19,
    "id": 19,
    "detection_id": 1
  }
}
```

#### Human Readable Output

>##### The note has been successfully added to the detection
>
>Returned Note ID: **19**

### vectra-detection-note-update

***
Update a note in the detection.

#### Base Command

`vectra-detection-note-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| detection_id | Specify the ID of the detection. | Required |
| note_id | Specify the ID of the note. | Required |
| note | Note to be updated for the specified note_id. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Vectra.Detection.Notes.detection_id | String | ID of the detection associated with the note. |
| Vectra.Detection.Notes.note_id | Number | ID of the note. |
| Vectra.Detection.Notes.id | Number | ID of the note. |
| Vectra.Detection.Notes.date_created | Date | Date when the note was created \(ISO8601\). |
| Vectra.Detection.Notes.date_modified | Date | Date when the note was last modified \(ISO8601\). |
| Vectra.Detection.Notes.created_by | String | User who created the note. |
| Vectra.Detection.Notes.modified_by | String | User who last modified the note. |
| Vectra.Detection.Notes.note | String | Content of the note. |

#### Command example

```!vectra-detection-note-update detection_id=1 note_id=1 note="note modified"```

#### Context Example

```json
{
  {
    "date_created": "2023-06-16T04:55:58Z",
    "date_modified": "2023-06-22T04:57:09Z",
    "created_by": "test_user",
    "modified_by": "test_user",
    "note": "note modified",
    "note_id": 8,
    "id": 8,
    "detection_id": 1
  }
}
```

#### Human Readable Output

>##### The note has been successfully updated in the detection

### vectra-detection-note-remove

***
Remove a note from the detection.

#### Base Command

`vectra-detection-note-remove`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| detection_id | Specify the ID of the detection. | Required |
| note_id | Specify the ID of the note. | Required |

#### Context Output

There is no context output for this command.

#### Command Example

```!vectra-detection-note-remove detection_id=1 note_id=1```

#### Context Example

```json
{}
```

#### Human Readable Output

>##### The note has been successfully removed from the detection

### vectra-entity-unresolved-priority-reset

***
Update the unresolved priority of an entity to false.

#### Base Command

`vectra-entity-unresolved-priority-reset`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entity_id | Specify the ID of the entity.<br/><br/>Note: Users can get the entity ID by executing the "vectra-entity-list" command. | Required |
| entity_type | Specify the type of the entity. Possible values are: account, host. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Vectra.Entity.id | String | An ID of the entity. |
| Vectra.Entity.type | String | The type of the entity. |
| Vectra.Entity.unresolved_priority | Boolean | An entity unresolved priority status. |

#### Command Example

```!vectra-entity-unresolved-priority-reset entity_id=1 entity_type=account```

#### Context Example

```json
{
    "Vectra": {
        "Entity": [
            {
                "id": "1",
                "type": "account",
                "unresolved_priority": false
            }
        ]
    }
}
```

#### Human Readable Output

>##### The unresolved priority of the provided entity has been successfully changed as 'false'

### vectra-detection-investigation-status-update

***
Update the investigation status of the detection by detection ID(s).

#### Base Command

`vectra-detection-investigation-status-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| detection_ids | Provide a list of detection IDs separated by comma or a single detection ID.<br/><br/>Note: Users can get the detection ID by executing the "vectra-detection-list" command. | Required |
| investigation_status | Specify the investigation status. Possible values are: open, acknowledged, escalated, paused, closed, expired. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Vectra.Detection.id | String | The detection ID. |
| Vectra.Detection.investigation_status | String | The detection investigation status. |

#### Command Example

```!vectra-detection-investigation-status-update detection_ids=1 investigation_status=escalated```

#### Context Example

```json
{
    "Vectra": {
        "Detection": [
            {
                "id": "1",
                "investigation_status": "escalated"
            }
        ]
    }
}
```

#### Human Readable Output

>##### The investigation Status for provided Detection ID(s) ['1'] have been updated as escalated

### vectra-detection-external-id-update

***
Update the external reference ID for the provided detection ID(s).

#### Base Command

`vectra-detection-external-id-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| detection_ids | Provide a list of detection IDs separated by comma or a single detection ID.<br/><br/>Note: Users can get the detection ID by executing the "vectra-detection-list" command. | Required |
| external_reference_id | Provide the external reference ID. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Vectra.Detection.id | String | The detection ID. |
| Vectra.Detection.external_reference_id | String | The external reference ID of the detection. |

#### Command Example

```!vectra-detection-external-id-update detection_ids=1 external_reference_id=12345```

#### Context Example

```json
{
    "Vectra": {
        "Detection": [
            {
                "id": "1",
                "external_reference_id": "12345"
            }
        ]
    }
}
```

#### Human Readable Output

>##### The external reference ID for provided Detection ID(s) ['1'] have been updated as 12345

### vectra-entity-external-id-update

***
Update the external reference ID for the provided entity.

#### Base Command

`vectra-entity-external-id-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entity_id | Specify the ID of the entity.<br/><br/>Note: Users can get the entity ID by executing the "vectra-entity-list" command. | Required |
| entity_type | Specify the type of the entity. Possible values are: account, host. | Required |
| external_reference_id | Provide the external reference ID. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Vectra.Entity.id | String | An ID of the entity. |
| Vectra.Entity.type | String | The type of the entity. |
| Vectra.Entity.external_reference_id | String | The external reference ID of the entity. |

#### Command Example

```!vectra-entity-external-id-update entity_id=1 entity_type=account external_reference_id=12345```

#### Context Example

```json
{
    "Vectra": {
        "Entity": [
            {
                "id": "1",
                "type": "account",
                "external_reference_id": "12345"
            }
        ]
    }
}
```

#### Human Readable Output

>##### The external reference ID for provided Entity have been updated as 12345

### vectra-detection-list

***
Returns a list of detections based on the specified filters.

#### Base Command

`vectra-detection-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| created_after | Filter the detections by created on or after the specified time.<br/><br/>Supported formats: 2 minutes, 2 hours, 2 days, 2 weeks, 2 months, 2 years, yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ.<br/><br/>For example: 01 March 2026, 01 Mar 2026 04:45:33, 2026-04-17T14:05:44Z. | Optional |
| created_before | Filter the detections by created on or before the specified time.<br/><br/>Supported formats: 2 minutes, 2 hours, 2 days, 2 weeks, 2 months, 2 years, yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ.<br/><br/>For example: 01 March 2026, 01 Mar 2026 04:45:33, 2026-04-17T14:05:44Z. | Optional |
| last_detected_after | Filter the detections by last detected on or after the specified time.<br/><br/>Supported formats: 2 minutes, 2 hours, 2 days, 2 weeks, 2 months, 2 years, yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ.<br/><br/>For example: 01 March 2026, 01 Mar 2026 04:45:33, 2026-04-17T14:05:44Z. | Optional |
| last_detected_before | Filter the detections by last detected on or before the specified time.<br/><br/>Supported formats: 2 minutes, 2 hours, 2 days, 2 weeks, 2 months, 2 years, yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ.<br/><br/>For example: 01 March 2026, 01 Mar 2026 04:45:33, 2026-04-17T14:05:44Z. | Optional |
| description | Filter by description containing specified value. | Optional |
| detection_name | Filter by detection name. | Optional |
| detection_type | Filter by detection type. | Optional |
| detection_category | Filter by detections category. Possible values are: Command & Control, Botnet, Reconnaissance, Lateral Movement, Exfiltration, Info. | Optional |
| include_info_category_detections | Include the info category detections which are excluded by default. Possible values are: true, false. Default is true. | Optional |
| close_reason | Filter by close reason of the detection. Possible values are: benign, remediated. | Optional |
| detection_state | Filter by detection state. Possible values are: active, inactive, fixed. | Optional |
| entity_type | Filter by Entity type. Possible values are: account, host. | Optional |
| tags | Filter by detection tags. Comma-separated values supported. | Optional |
| is_triaged | Filter by detection triage status. Possible values are: true, false. Default is false. | Optional |
| page | Provide page number to retrieve. Default is 1. | Optional |
| page_size | Provide a number of results per page. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Vectra.Detection.id | Number | A unique identifier for the detection. |
| Vectra.Detection.assigned_date | Date | The date when the detection was assigned. |
| Vectra.Detection.assigned_to | String | The email or user to whom the detection is assigned. |
| Vectra.Detection.certainty | Number | The certainty level associated with the detection. |
| Vectra.Detection.created_timestamp | Date | The timestamp when the detection was created. |
| Vectra.Detection.custom_detection | Unknown | The custom detection configuration or settings. |
| Vectra.Detection.data_source.type | String | The type of data source for the detection. |
| Vectra.Detection.data_source.connection_name | String | The name of the connection used for data ingestion. |
| Vectra.Detection.data_source.connection_id | String | A unique identifier for the data source connection. |
| Vectra.Detection.description | String | The description of the detection. |
| Vectra.Detection.detection | String | The name of the detection. |
| Vectra.Detection.detection_category | String | The category of the detection. |
| Vectra.Detection.detection_type | String | The type of the detection. |
| Vectra.Detection.detection_url | String | The URL to access the detection details. |
| Vectra.Detection.filtered_by_ai | Boolean | Indicates if the detection was filtered by AI. |
| Vectra.Detection.filtered_by_rule | Boolean | Indicates if the detection was filtered by a rule. |
| Vectra.Detection.filtered_by_user | Boolean | Indicates if the detection was filtered by a user. |
| Vectra.Detection.first_timestamp | Date | The first timestamp when the detection was observed. |
| Vectra.Detection.grouped_details.role | String | The role associated with the detection group. |
| Vectra.Detection.grouped_details.last_timestamp | Date | The last timestamp of the detection group. |
| Vectra.Detection.groups.id | Number | A unique identifier for the group. |
| Vectra.Detection.groups.name | String | The name of the group. |
| Vectra.Detection.groups.description | String | The description of the group. |
| Vectra.Detection.groups.type | String | The type of the group. |
| Vectra.Detection.groups.last_modified | Date | The timestamp when the group was last modified. |
| Vectra.Detection.groups.last_modified_by | String | The email or user who last modified the group. |
| Vectra.Detection.is_custom_model | Boolean | Indicates if the detection uses a custom model. |
| Vectra.Detection.is_marked_custom | Boolean | Indicates if the detection is marked as custom. |
| Vectra.Detection.is_triaged | Boolean | Indicates if the detection has been triaged. |
| Vectra.Detection.last_timestamp | Date | The last timestamp when the detection was observed. |
| Vectra.Detection.note | String | A note associated with the detection. |
| Vectra.Detection.note_modified_by | String | The email or user who modified the note. |
| Vectra.Detection.note_modified_timestamp | Date | The timestamp when the note was last modified. |
| Vectra.Detection.notes.created_by | String | The email or user who created the note. |
| Vectra.Detection.notes.date_created | Date | The date when the note was created. |
| Vectra.Detection.notes.date_modified | Date | The date when the note was modified. |
| Vectra.Detection.notes.id | Number | A unique identifier for the note. |
| Vectra.Detection.notes.modified_by | String | The email or user who modified the note. |
| Vectra.Detection.notes.note | String | The content of the note. |
| Vectra.Detection.reason | String | The reason for the detection state or triage action. |
| Vectra.Detection.sensor | String | The sensor identifier that detected the activity. |
| Vectra.Detection.sensor_name | String | The name of the sensor that detected the activity. |
| Vectra.Detection.src_account.id | Number | A unique identifier for the source account. |
| Vectra.Detection.src_account.name | String | The name of the source account. |
| Vectra.Detection.src_account.url | String | The URL to access the source account details. |
| Vectra.Detection.src_account.threat | Number | The threat level associated with the source account. |
| Vectra.Detection.src_account.certainty | Number | The certainty level associated with the source account. |
| Vectra.Detection.src_account.privilege_level | Number | The privilege level associated with the source account. |
| Vectra.Detection.src_account.privilege_category | String | The privilege category associated with the source account. |
| Vectra.Detection.src_host.id | Number | A unique identifier for the source host. |
| Vectra.Detection.src_host.name | String | The name of the source host. |
| Vectra.Detection.src_host.ip | String | The IP address of the source host. |
| Vectra.Detection.src_host.url | String | The URL to access the source host details. |
| Vectra.Detection.src_host.is_key_asset | Boolean | Indicates if the source host is a key asset. |
| Vectra.Detection.src_host.group.id | Number | A unique identifier for the source host group. |
| Vectra.Detection.src_host.group.name | String | The name of the source host group. |
| Vectra.Detection.src_host.group.description | String | The description of the source host group. |
| Vectra.Detection.src_host.group.type | String | The type of the source host group. |
| Vectra.Detection.src_host.group.last_modified | Date | The timestamp when the source host group was last modified. |
| Vectra.Detection.src_host.group.last_modified_by | String | The email or user who last modified the source host group. |
| Vectra.Detection.src_host.threat | Number | The threat level associated with the source host. |
| Vectra.Detection.src_host.certainty | Number | The certainty level associated with the source host. |
| Vectra.Detection.src_ip | String | The source IP address in the detection. |
| Vectra.Detection.src_groups.id | Number | A unique identifier for the source group. |
| Vectra.Detection.src_groups.name | String | The name of the source group. |
| Vectra.Detection.src_groups.description | String | The description of the source group. |
| Vectra.Detection.src_groups.type | String | The type of the source group. |
| Vectra.Detection.src_groups.last_modified | Date | The timestamp when the source group was last modified. |
| Vectra.Detection.src_groups.last_modified_by | String | The email or user who last modified the source group. |
| Vectra.Detection.dst_groups.id | Number | A unique identifier for the destination group. |
| Vectra.Detection.dst_groups.name | String | The name of the destination group. |
| Vectra.Detection.dst_groups.description | String | The description of the destination group. |
| Vectra.Detection.dst_groups.type | String | The type of the destination group. |
| Vectra.Detection.dst_groups.last_modified | Date | The timestamp when the destination group was last modified. |
| Vectra.Detection.dst_groups.last_modified_by | String | The email or user who last modified the destination group. |
| Vectra.Detection.state | String | The current state of the detection. |
| Vectra.Detection.summary.artifact | Array | The artifacts associated with the detection summary. |
| Vectra.Detection.summary.last_timestamp | Date | The last timestamp in the detection summary. |
| Vectra.Detection.summary.description | String | The description in the detection summary. |
| Vectra.Detection.summary.roles | Array | The roles associated with the detection summary. |
| Vectra.Detection.tags | Array | The tags associated with the detection. |
| Vectra.Detection.is_targeting_key_asset | Boolean | Indicates if the detection is targeting a key asset. |
| Vectra.Detection.threat | Number | The threat level of the detection. |
| Vectra.Detection.triage_rule_id | Unknown | A unique identifier for the triage rule applied to the detection. |
| Vectra.Detection.type | String | The type of the detection. |
| Vectra.Detection.url | String | The URL to access the detection details. |

#### Command Example

```!vectra-detection-list page=1 page_size=2```

#### Context Example

```json
{
    "Vectra": {
        "Detection": [
            {
                "summary": {
                    "app_name": "Exchange",
                    "operations": [
                        "Add-MailboxPermission"
                    ],
                    "src_ips": [
                        "10.0.0.1"
                    ],
                    "description": "This account performed Exchange operations that were unusual for the account."
                },
                "src_account": {
                    "id": 1001,
                    "name": "user@example.com",
                    "url": "https://example.vectra.ai/api/v3.5/accounts/1001",
                    "threat": 45,
                    "certainty": 60
                },
                "state": "active",
                "created_timestamp": "2026-01-15T10:30:00Z",
                "filtered_by_user": false,
                "type": "account",
                "detection_type": "M365 Risky Exchange Operation",
                "data_source": {
                    "type": "o365",
                    "connection_name": "M365-Production",
                    "connection_id": "abc123"
                },
                "filtered_by_rule": false,
                "detection": "M365 Risky Exchange Operation",
                "url": "https://example.vectra.ai/api/v3.5/detections/5001",
                "sensor": "abc123",
                "threat": 50,
                "is_custom_model": false,
                "is_triaged": false,
                "detection_category": "lateral_movement",
                "filtered_by_ai": false,
                "detection_url": "https://example.vectra.ai/api/v3.5/detections/5001",
                "last_timestamp": "2026-01-15T12:00:00Z",
                "first_timestamp": "2026-01-15T10:00:00Z",
                "certainty": 50,
                "is_marked_custom": false,
                "id": 5001,
                "sensor_name": "Vectra NDR",
                "is_targeting_key_asset": false,
                "grouped_details": [
                    {
                        "parameters": [
                            {
                                "data": [
                                    {
                                        "name": "Identity",
                                        "value": "mailbox@example.com"
                                    }
                                ],
                                "timestamp": "2026-01-15T11:30:00Z"
                            }
                        ],
                        "operation": "Add-MailboxPermission",
                        "behavior": "Mailbox management",
                        "user_type": "Admin",
                        "last_timestamp": "2026-01-15T12:00:00Z",
                        "src_ip": "10.0.0.1",
                        "app_name": "Exchange"
                    }
                ]
            },
            {
                "state": "active",
                "created_timestamp": "2026-01-15T09:00:00Z",
                "filtered_by_user": false,
                "type": "host",
                "detection_type": "Suspicious Domain",
                "groups": [
                    {
                        "id": 10,
                        "name": "Production Servers",
                        "description": "Production server subnet",
                        "type": "ip",
                        "last_modified": "2026-01-10T08:00:00Z",
                        "last_modified_by": "admin@example.com"
                    }
                ],
                "data_source": {
                    "type": "sensor",
                    "connection_name": "Network Sensor 1",
                    "connection_id": "xyz789"
                },
                "filtered_by_rule": false,
                "detection": "Suspicious Domain",
                "url": "https://example.vectra.ai/api/v3.5/detections/5002",
                "sensor": "xyz789",
                "threat": 30,
                "is_custom_model": false,
                "is_triaged": false,
                "detection_category": "command_and_control",
                "filtered_by_ai": false,
                "detection_url": "https://example.vectra.ai/api/v3.5/detections/5002",
                "src_ip": "10.0.1.50",
                "last_timestamp": "2026-01-15T09:45:00Z",
                "first_timestamp": "2026-01-15T09:00:00Z",
                "src_host": {
                    "id": 2001,
                    "ip": "10.0.1.50",
                    "name": "workstation-01",
                    "url": "https://example.vectra.ai/api/v3.5/hosts/2001",
                    "is_key_asset": false,
                    "groups": [
                        {
                            "id": 10,
                            "name": "Production Servers",
                            "description": "Production server subnet",
                            "last_modified": "2026-01-10T08:00:00Z",
                            "last_modified_by": "admin@example.com",
                            "type": "ip"
                        }
                    ],
                    "threat": 35,
                    "certainty": 40
                },
                "certainty": 25,
                "is_marked_custom": false,
                "id": 5002,
                "sensor_name": "Network Sensor 1",
                "is_targeting_key_asset": false,
                "grouped_details": [
                    {
                        "protocol": "dns",
                        "last_timestamp": "2026-01-15T09:45:00Z",
                        "grouping_field": "last_timestamp",
                        "response_code": "NXDomain",
                        "target_domains": [
                            "suspicious-domain.example"
                        ],
                        "dst_ips": [
                            "8.8.8.8"
                        ]
                    }
                ],
                "summary": {
                    "num_failures": 5,
                    "num_successes": 0,
                    "num_sessions": 10
                }
            }
        ]
    }
}
```

#### Human Readable Output

>### Detections Table (Showing Page 1 out of 100)
>
>|ID|Detection Name|Detection Type|Account Name|Host Name|Src IP|Threat Score|Certainty Score|Number Of Events|State|Last Timestamp|
>|---|---|---|---|---|---|---|---|---|---|---|
>| [5001](https://example.vectra.ai/detections/5001?pivot=Vectra-RUX-XSOAR-1.0.0) | M365 Risky Exchange Operation | M365 Risky Exchange Operation | [user@example.com](https://example.vectra.ai/accounts/1001?pivot=Vectra-RUX-XSOAR-1.0.0) |  |  | 50 | 50 | 0 | active | 2026-01-15T12:00:00Z |
>| [5002](https://example.vectra.ai/detections/5002?pivot=Vectra-RUX-XSOAR-1.0.0) | Suspicious Domain | Suspicious Domain |  | [workstation-01](https://example.vectra.ai/hosts/2001?pivot=Vectra-RUX-XSOAR-1.0.0) | 10.0.1.50 | 30 | 25 | 0 | active | 2026-01-15T09:45:00Z |

### vectra-investigation-query-send

***
Submit an investigation query and receive a request ID for retrieving results.

#### Base Command

`vectra-investigation-query-send`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | Provide an investigation query in the supported query language. | Required |
| version | Specify the version of the query language. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Vectra.Investigation.request_id | String | The unique identifier for the query request. Use this to retrieve results. |
| Vectra.Investigation.searchable_range.searchable_days_allowed | Number | A Maximum number of days of data that can be searched. |

#### Command Example

```!vectra-investigation-query-send query="SELECT * FROM detections" version=v1```

#### Context Example

```json
{
    "Vectra": {
        "Investigation": {
            "request_id": "b57d7a27-28ad-4c0c-b28a-0e7b3",
            "searchable_range": {
                "searchable_days_allowed": 14
            }
        }
    }
}
```

#### Human Readable Output

>##### The Vectra investigation has started. You can view the results by executing the below command
>
>!vectra-investigation-result-get id=b57d7a27-28ad-4c0c-b28a-0e7b3

### vectra-investigation-result-get

***
Retrieve the results of a previously submitted investigation query using the request ID.

#### Base Command

`vectra-investigation-result-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Provide the unique request ID of investigation. | Required |
| page | Provide page number to retrieve. Default is 1. | Optional |
| page_size | Provide a number of results per page to retrieve. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Vectra.Investigation.request_id | String | The unique identifier for the query request. |
| Vectra.Investigation.data | Unknown | An array of query results. |
| Vectra.Investigation.meta.query_status | String | The status of the query. |
| Vectra.Investigation.meta.num_rows_available | Number | Total rows returned by the query. |
| Vectra.Investigation.meta.page | Number | The current page number. |
| Vectra.Investigation.meta.page_size | Number | The rows returned on this page. |
| Vectra.Investigation.meta.estimated_file_size_bytes | Number | The estimated size of the full result set in bytes. |
| Vectra.Investigation.meta.columns | Unknown | An array of tuples describing the result schema. |

#### Command Example

```!vectra-investigation-result-get id=b57d7a27-28ad-4c0c-b28a-0e7b3```

#### Context Example

```json
{
    "Vectra": {
        "Investigation": {
            "request_id": "b57d7a27-28ad-4c0c-b28a-0e7b3",
            "meta": {
                "page": 1,
                "page_size": 50,
                "estimated_file_size_bytes": 0,
                "num_rows_available": 0,
                "query_status": "SUCCESS",
                "columns": [
                    [
                        "timestamp",
                        [
                            {
                                "type": "timestamp"
                            },
                            ""
                        ]
                    ],
                    [
                        "orig_h",
                        [
                            {
                                "type": "string"
                            },
                            ""
                        ]
                    ],
                    [
                        "resp_h",
                        [
                            {
                                "type": "string"
                            },
                            ""
                        ]
                    ],
                    [
                        "resp_p",
                        [
                            {
                                "type": "number"
                            },
                            ""
                        ]
                    ]
                ]
            }
        }
    }
}
```

#### Human Readable Output

>### Investigation Result for Request ID: b57d7a27-28ad-4c0c-b28a-0e7b3
>
>|Query Status|Page Number|Page size|Total Rows|File Size (bytes)|Columns|
>|---|---|---|---|---|---|
>| SUCCESS | 1 | 50 | 0 | 0 | **-** ***values***: timestamp, [{'type': 'timestamp'}, '']<br>**-** ***values***: orig_h, [{'type': 'string'}, '']<br>**-** ***values***: resp_h, [{'type': 'string'}, '']<br>**-** ***values***: resp_p, [{'type': 'number'}, ''] |

>### Investigation Results Data
>
>**No entries.**
