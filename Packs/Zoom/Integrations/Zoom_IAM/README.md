An Identity and Access Management integration template.
This integration was integrated and tested with version 2.0.0 of Zoom_IAM.

## Configure Zoom_IAM in Cortex


| **Parameter**                      | **Description**                          | **Required** |
| ---------------------------------- | ---------------------------------------- | ------------ |
| Account ID (OAuth)                 |                                          | False        |
| Client ID (OAuth)                  |                                          | False        |
| Client Secret (OAuth)              |                                          | False        |
| API Key (JWT-Deprecated)           | This authentication method is deprecated. | False        |
| API Secret (JWT-Deprecated)        | This authentication method is deprecated. | False        |
| Use system proxy settings          |                                          | False        |
| Trust any certificate (not secure) |                                          | False        |
| Allow disabling users              |                                          | False        |
| Allow enabling users               |                                          | False        |
| Incoming Mapper                    |                                          | True         |
| Outgoing Mapper                    |                                          | True         |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### iam-disable-user
***
Disable an active user.


#### Base Command

`iam-disable-user`
#### Input

| **Argument Name** | **Description**                                                                       | **Required** |
| ----------------- | ------------------------------------------------------------------------------------- | ------------ |
| user-profile      | A User Profile indicator. <br/>For example: `{"email": "john.doe@example.com"}`<br/>. | Required     |


#### Context Output

| **Path**                | **Type** | **Description**                                                                         |
| ----------------------- | -------- | --------------------------------------------------------------------------------------- |
| IAM.Vendor.active       | Boolean  | When true, indicates that the employee's status is active in the 3rd-party integration. |
| IAM.Vendor.brand        | String   | Name of the integration.                                                                |
| IAM.Vendor.details      | string   | Provides the raw data from the 3rd-party integration.                                   |
| IAM.Vendor.email        | String   | The employee's email address.                                                           |
| IAM.Vendor.errorCode    | Number   | HTTP error response code.                                                               |
| IAM.Vendor.errorMessage | String   | Reason why the API failed.                                                              |
| IAM.Vendor.id           | String   | The employee's user ID in the app.                                                      |
| IAM.Vendor.instanceName | string   | Name of the integration instance.                                                       |
| IAM.Vendor.success      | Boolean  | When true, indicates that the command was executed successfully.                        |
| IAM.Vendor.username     | String   | The employee's username in the app.                                                     |

#### Command example
```!iam-disable-user user-profile=`{"email": "example@example.com", "givenname": "Example"}````
#### Context Example
```json
{
    "IAM": {
        "UserProfile": {
            "email": "example@example.com",
            "givenname": "Example"
        },
        "Vendor": [
            {
                "action": "disable",
                "active": false,
                "brand": "Zoom_IAM",
                "details": {
                    "email": "example@example.com",
                    "givenname": "Example"
                },
                "email": "example@example.com",
                "errorCode": null,
                "errorMessage": "",
                "id": "6mIygOyeTT61Wzw_PAo5jw",
                "instanceName": "Zoom_IAM_instance_1 JWT",
                "reason": "",
                "skipped": false,
                "success": true,
                "username": ""
            },
            {
                "action": "disable",
                "active": null,
                "brand": "Zoom_IAM",
                "details": {
                    "account_id": "aeKD2BFJRASt1QVURWo9CA",
                    "account_number": 1114287,
                    "cluster": "us06",
                    "cms_user_id": "",
                    "created_at": "2020-06-16T06:57:23Z",
                    "dept": "",
                    "email": "example@example.com",
                    "first_name": "Example",
                    "group_ids": [],
                    "id": "6mIygOyeTT61Wzw_PAo5jw",
                    "im_group_ids": [],
                    "jid": "6miygoyett61wzw_pao5jw@xmpp.zoom.us",
                    "job_title": "",
                    "language": "en-US",
                    "last_client_version": "5.8.7.2058(win)",
                    "last_login_time": "2022-08-24T07:25:49Z",
                    "last_name": "Example",
                    "location": "",
                    "login_types": [
                        1
                    ],
                    "personal_meeting_url": "https://us06web.zoom.us/j/3269259758?pwd=Q2VTN1JsM2J2OCtmS1hWaHBTUmV6QT09",
                    "phone_country": "",
                    "phone_number": "",
                    "pic_url": "https://lh3.googleusercontent.com/a/AItbvmn0GJLCTIkOIatpkUy-PuEf-tFQEnBVOUxcT2oB=s96-c",
                    "pmi": 3269259758,
                    "role_id": "2",
                    "role_name": "Member",
                    "status": "inactive",
                    "timezone": "Asia/Jerusalem",
                    "type": 1,
                    "use_pmi": false,
                    "user_created_at": "2020-06-16T06:57:23Z",
                    "verified": 0
                },
                "email": "example@example.com",
                "errorCode": null,
                "errorMessage": "",
                "id": null,
                "instanceName": "Zoom_IAM_instance_2 OAuth",
                "reason": "User is already disabled.",
                "skipped": true,
                "success": true,
                "username": null
            }
        ]
    }
}
```

#### Human Readable Output

>### Disable User Results (Zoom_IAM)
>|brand|instanceName|success|active|id|email|details|
>|---|---|---|---|---|---|---|
>| Zoom_IAM | Zoom_IAM_instance_1 JWT | true | false | 6mIygOyeTT61Wzw_PAo5jw | example@example.com | email: example@example.com<br/>givenname: Example |


### iam-enable-user
***
Enable a deactivated user.


#### Base Command

`iam-enable-user`
#### Input

| **Argument Name** | **Description**           | **Required** |
| ----------------- | ------------------------- | ------------ |
| user-profile      | A User Profile indicator. | Required     |


#### Context Output

| **Path**                | **Type** | **Description**                                                                         |
| ----------------------- | -------- | --------------------------------------------------------------------------------------- |
| IAM.Vendor.active       | Boolean  | When true, indicates that the employee's status is active in the 3rd-party integration. |
| IAM.Vendor.brand        | String   | Name of the integration.                                                                |
| IAM.Vendor.details      | string   | Provides the raw data from the 3rd-party integration.                                   |
| IAM.Vendor.email        | String   | The employee's email address.                                                           |
| IAM.Vendor.errorCode    | Number   | HTTP error response code.                                                               |
| IAM.Vendor.errorMessage | String   | Reason why the API failed.                                                              |
| IAM.Vendor.id           | String   | The employee's user ID in the app.                                                      |
| IAM.Vendor.instanceName | string   | Name of the integration instance.                                                       |
| IAM.Vendor.success      | Boolean  | When true, indicates that the command was executed successfully.                        |
| IAM.Vendor.username     | String   | The employee's username in the app.                                                     |

#### Command example
```!iam-enable-user user-profile=`{"email": "example@example.com", "givenname": "Example"}````
#### Context Example
```json
{
    "IAM": {
        "UserProfile": {
            "email": "example@example.com",
            "givenname": "Example"
        },
        "Vendor": [
            {
                "action": "enable",
                "active": true,
                "brand": "Zoom_IAM",
                "details": {
                    "email": "example@example.com",
                    "givenname": "Example"
                },
                "email": "example@example.com",
                "errorCode": null,
                "errorMessage": "",
                "id": "6mIygOyeTT61Wzw_PAo5jw",
                "instanceName": "Zoom_IAM_instance_2 OAuth",
                "reason": "",
                "skipped": false,
                "success": true,
                "username": ""
            },
            {
                "action": "enable",
                "active": true,
                "brand": "Zoom_IAM",
                "details": {
                    "email": "example@example.com",
                    "givenname": "Example"
                },
                "email": "example@example.com",
                "errorCode": null,
                "errorMessage": "",
                "id": "6mIygOyeTT61Wzw_PAo5jw",
                "instanceName": "Zoom_IAM_instance_1 JWT",
                "reason": "",
                "skipped": false,
                "success": true,
                "username": ""
            }
        ]
    }
}
```

#### Human Readable Output

>### Enable User Results (Zoom_IAM)
>|brand|instanceName|success|active|id|email|details|
>|---|---|---|---|---|---|---|
>| Zoom_IAM | Zoom_IAM_instance_2 OAuth | true | true | 6mIygOyeTT61Wzw_PAo5jw | example@example.com | email: example@example.com<br/>givenname: Example |


### iam-get-user
***
Retrieves a single user resource.


#### Base Command

`iam-get-user`
#### Input

| **Argument Name** | **Description**           | **Required** |
| ----------------- | ------------------------- | ------------ |
| user-profile      | A User Profile indicator. | Required     |


#### Context Output

There is no context output for this command.
#### Command example
```!iam-get-user user-profile=`{"email": "example@example.com", "givenname": "Example"}````
#### Context Example
```json
{
    "IAM": {
        "UserProfile": {
            "account_id": "aeKD2BFJRASt1QVURWo9CA",
            "account_number": 1114287,
            "cluster": "us06",
            "cms_user_id": "",
            "created_at": "2020-06-16T06:57:23Z",
            "dept": "",
            "email": "example@example.com",
            "first_name": "Example",
            "group_ids": [],
            "id": "6mIygOyeTT61Wzw_PAo5jw",
            "im_group_ids": [],
            "jid": "6miygoyett61wzw_pao5jw@xmpp.zoom.us",
            "job_title": "",
            "language": "en-US",
            "last_client_version": "5.8.7.2058(win)",
            "last_login_time": "2022-08-24T07:25:49Z",
            "last_name": "Example",
            "location": "",
            "login_types": [
                1
            ],
            "personal_meeting_url": "https://us06web.zoom.us/j/3269259758?pwd=Q2VTN1JsM2J2OCtmS1hWaHBTUmV6QT09",
            "phone_country": "",
            "phone_number": "",
            "pic_url": "https://lh3.googleusercontent.com/a/AItbvmn0GJLCTIkOIatpkUy-PuEf-tFQEnBVOUxcT2oB=s96-c",
            "pmi": 3269259758,
            "role_id": "2",
            "role_name": "Member",
            "status": "active",
            "timezone": "Asia/Jerusalem",
            "type": 1,
            "use_pmi": false,
            "user_created_at": "2020-06-16T06:57:23Z",
            "verified": 0
        },
        "Vendor": [
            {
                "action": "get",
                "active": true,
                "brand": "Zoom_IAM",
                "details": {
                    "account_id": "aeKD2BFJRASt1QVURWo9CA",
                    "account_number": 1114287,
                    "cluster": "us06",
                    "cms_user_id": "",
                    "created_at": "2020-06-16T06:57:23Z",
                    "dept": "",
                    "email": "example@example.com",
                    "first_name": "Example",
                    "group_ids": [],
                    "id": "6mIygOyeTT61Wzw_PAo5jw",
                    "im_group_ids": [],
                    "jid": "6miygoyett61wzw_pao5jw@xmpp.zoom.us",
                    "job_title": "",
                    "language": "en-US",
                    "last_client_version": "5.8.7.2058(win)",
                    "last_login_time": "2022-08-24T07:25:49Z",
                    "last_name": "Example",
                    "location": "",
                    "login_types": [
                        1
                    ],
                    "personal_meeting_url": "https://us06web.zoom.us/j/3269259758?pwd=Q2VTN1JsM2J2OCtmS1hWaHBTUmV6QT09",
                    "phone_country": "",
                    "phone_number": "",
                    "pic_url": "https://lh3.googleusercontent.com/a/AItbvmn0GJLCTIkOIatpkUy-PuEf-tFQEnBVOUxcT2oB=s96-c",
                    "pmi": 3269259758,
                    "role_id": "2",
                    "role_name": "Member",
                    "status": "active",
                    "timezone": "Asia/Jerusalem",
                    "type": 1,
                    "use_pmi": false,
                    "user_created_at": "2020-06-16T06:57:23Z",
                    "verified": 0
                },
                "email": "example@example.com",
                "errorCode": null,
                "errorMessage": "",
                "id": "6mIygOyeTT61Wzw_PAo5jw",
                "instanceName": "Zoom_IAM_instance_2 OAuth",
                "reason": "",
                "skipped": false,
                "success": true,
                "username": ""
            },
            {
                "action": "get",
                "active": true,
                "brand": "Zoom_IAM",
                "details": {
                    "account_id": "aeKD2BFJRASt1QVURWo9CA",
                    "account_number": 1114287,
                    "cluster": "us06",
                    "cms_user_id": "",
                    "created_at": "2020-06-16T06:57:23Z",
                    "dept": "",
                    "email": "example@example.com",
                    "first_name": "Example",
                    "group_ids": [],
                    "id": "6mIygOyeTT61Wzw_PAo5jw",
                    "im_group_ids": [],
                    "jid": "6miygoyett61wzw_pao5jw@xmpp.zoom.us",
                    "job_title": "",
                    "language": "en-US",
                    "last_client_version": "5.8.7.2058(win)",
                    "last_login_time": "2022-08-24T07:25:49Z",
                    "last_name": "Example",
                    "location": "",
                    "login_types": [
                        1
                    ],
                    "personal_meeting_url": "https://us06web.zoom.us/j/3269259758?pwd=Q2VTN1JsM2J2OCtmS1hWaHBTUmV6QT09",
                    "phone_country": "",
                    "phone_number": "",
                    "pic_url": "https://lh3.googleusercontent.com/a/AItbvmn0GJLCTIkOIatpkUy-PuEf-tFQEnBVOUxcT2oB=s96-c",
                    "pmi": 3269259758,
                    "role_id": "2",
                    "role_name": "Member",
                    "status": "active",
                    "timezone": "Asia/Jerusalem",
                    "type": 1,
                    "use_pmi": false,
                    "user_created_at": "2020-06-16T06:57:23Z",
                    "verified": 0
                },
                "email": "example@example.com",
                "errorCode": null,
                "errorMessage": "",
                "id": "6mIygOyeTT61Wzw_PAo5jw",
                "instanceName": "Zoom_IAM_instance_1 JWT",
                "reason": "",
                "skipped": false,
                "success": true,
                "username": ""
            }
        ]
    }
}
```

#### Human Readable Output

>### Get User Results (Zoom_IAM)
>|brand|instanceName|success|active|id|email|details|
>|---|---|---|---|---|---|---|
>| Zoom_IAM | Zoom_IAM_instance_1 JWT | true | true | 6mIygOyeTT61Wzw_PAo5jw | example@example.com | id: 6mIygOyeTT61Wzw_PAo5jw<br/>first_name: Example<br/>last_name: Example<br/>email: example@example.com<br/>type: 1<br/>role_name: Member<br/>pmi: 3269259758<br/>use_pmi: false<br/>personal_meeting_url: https:<span>//</span>us06web.zoom.us/j/3269259758?pwd=Q2VTN1JsM2J2OCtmS1hWaHBTUmV6QT09<br/>timezone: Asia/Jerusalem<br/>verified: 0<br/>dept: <br/>created_at: 2020-06-16T06:57:23Z<br/>last_login_time: 2022-08-24T07:25:49Z<br/>last_client_version: 5.8.7.2058(win)<br/>pic_url: https:<span>//</span>lh3.googleusercontent.com/a/AItbvmn0GJLCTIkOIatpkUy-PuEf-tFQEnBVOUxcT2oB=s96-c<br/>cms_user_id: <br/>jid: 6miygoyett61wzw_pao5jw@xmpp.zoom.us<br/>group_ids: <br/>im_group_ids: <br/>account_id: aeKD2BFJRASt1QVURWo9CA<br/>language: en-US<br/>phone_country: <br/>phone_number: <br/>status: active<br/>job_title: <br/>location: <br/>login_types: 1<br/>role_id: 2<br/>account_number: 1114287<br/>cluster: us06<br/>user_created_at: 2020-06-16T06:57:23Z |


### get-mapping-fields
***
Retrieves a User Profile schema, which holds all of the user fields within the application. Used for outgoing-mapping through the Get Schema option.


#### Base Command

`get-mapping-fields`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.
## Incident Mirroring

You can enable incident mirroring between Cortex XSOAR incidents and Zoom_IAM corresponding events (available from Cortex XSOAR version 6.0.0).
To set up the mirroring:
Enable *Fetching incidents* in your instance configuration.

Newly fetched incidents will be mirrored in the chosen direction. However, this selection does not affect existing incidents.
**Important Note:** To ensure the mirroring works as expected, mappers are required, both for incoming and outgoing, to map the expected fields in Cortex XSOAR and Zoom_IAM.