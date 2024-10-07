Zimperium is a mobile security platform that generates alerts based on anomalous or unauthorized activities detected on a user's mobile device.
This integration was integrated and tested with version 4.24 of Zimperium
## Configure Zimperium in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | Server URL (e.g. `https://domain.zimperium.com`) | True |
| api_key | API Key | True |
| isFetch | Fetch incidents | False |
| fetch_query | Fetch Query. e.g, severity==CRITICAL | False |
| max_fetch | Max fetch | False |
| fetch_time | First fetch timestamp \(&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days, 3 months, 1 year\) | False |
| incidentType | Incident type | False |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### zimperium-events-search
***
Search events.


#### Base Command

`zimperium-events-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | Search events query. | Optional | 
| verbose | Retrieve event full details. | Optional | 
| size | Maximum number of events to retrieve in each page. Default is 10. | Optional | 
| page | Page number. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Zimperium.Events.appName | String | Application name. | 
| Zimperium.Events.bssid | String | Network BSSID. | 
| Zimperium.Events.bundleId | String | Bundle ID. | 
| Zimperium.Events.country | String | Event country. | 
| Zimperium.Events.customerContactName | String | Customer contact name. | 
| Zimperium.Events.customerContactPhone | String | Customer contact phone. | 
| Zimperium.Events.customerId | String | Customer ID. | 
| Zimperium.Events.deviceHash | String | Device hash. | 
| Zimperium.Events.deviceId | string | Device ID. | 
| Zimperium.Events.deviceModel | String | Device model. | 
| Zimperium.Events.deviceTime | String | Device time. | 
| Zimperium.Events.eventDetail | Unknown | Event additional details. | 
| Zimperium.Events.eventFullName | String | Event full name. | 
| Zimperium.Events.eventId | String | Event ID. | 
| Zimperium.Events.eventName | String | Event name. | 
| Zimperium.Events.eventState | String | Event state. | 
| Zimperium.Events.eventStateCode | Number | Event status code. | 
| Zimperium.Events.eventVector | String | Device or network attack vector. | 
| Zimperium.Events.firstName | String | First name of the phone owner. | 
| Zimperium.Events.lastName | String | Last name of the phone owner. | 
| Zimperium.Events.middleName | String | Middle name of the phone owner. | 
| Zimperium.Events.incidentSummary | String | Incident summary. | 
| Zimperium.Events.lastSeenTime | Date | Event last seen time. | 
| Zimperium.Events.locationDetail | String | Location details. | 
| Zimperium.Events.latitude | String | Latitude of the phone. | 
| Zimperium.Events.longitude | String | Longitude of the phone. | 
| Zimperium.Events.mdmId | String | MD ID. | 
| Zimperium.Events.mitigatedDate | Date | Mitigated date of the phone. | 
| Zimperium.Events.osType | String | OS type of the phone. | 
| Zimperium.Events.osVersion | String | OS version of the phone. | 
| Zimperium.Events.persistedTime | Date | Persisted time of the event. | 
| Zimperium.Events.queuedTime | Date | Queued time of the event. | 
| Zimperium.Events.severity | String | Severity of the event. | 
| Zimperium.Events.ssid | String | Network SSID. | 
| Zimperium.Events.tag1 | String | User pre\-defined Zimperium tag. | 
| Zimperium.Events.tag2 | String | User pre defined Zimperium tag. | 
| Zimperium.Events.typeDesc | String | Event type description. | 
| Zimperium.Events.userEmail | String | Email address of the phone user. | 
| Zimperium.Events.userPhoneNumber | String | Phone number of the phone user. | 
| Zimperium.Events.zdid | String | Zimperium device ID. | 
| Zimperium.Events.zipsVersion | String | zIPS version where the event occurred. | 


#### Command Example
```!zimperium-events-search query="severity==LOW;eventName==THREAT_DETECTED;osType==Android"```

#### Context Example
```
{
    "Zimperium": {
        "Events": {
            "appName": "zIPS",
            "bssid": null,
            "bundleId": "com.zimperium.zips",
            "country": "us",
            "customerContactName": "PAXSOAR",
            "customerContactPhone": "14151234567",
            "customerId": "paxsoar",
            "deviceHash": "d3a5f56726ea39341ca19a534b8d5bc0cac07484b3032148857118f31b72bf01",
            "deviceId": "198280699673142",
            "deviceModel": "G900H",
            "deviceTime": "2020-06-06 02:05:57 +0000",
            "eventFullName": "app.dormant",
            "eventId": "7fb73a12-4be1-4b91-be33-60f3e580c689",
            "eventName": "THREAT_DETECTED",
            "eventState": "Pending",
            "eventStateCode": 1,
            "eventVector": "2",
            "firstName": "Fname",
            "incidentSummary": "Device is dormant. It is recommended to contact the user to reactivate the app.",
            "lastName": "Lname",
            "lastSeenTime": "2020-06-03 02:05:19 +0000",
            "latitude": null,
            "locationDetail": null,
            "longitude": null,
            "mdmId": null,
            "middleName": null,
            "mitigatedDate": null,
            "osType": "Android",
            "osVersion": "4.4.2",
            "persistedTime": "2020-06-06 02:05:57 +0000",
            "queuedTime": "2020-06-06 02:05:57 +0000",
            "severity": "LOW",
            "ssid": null,
            "tag1": null,
            "tag2": null,
            "typeDesc": "ZIPS_EVENT",
            "userEmail": "test@gmail.com",
            "userPhoneNumber": "",
            "zdid": "c728a9f1-dbcc-4b0f-84b2-5dc07e80b6e5",
            "zipsVersion": "4.9.19"
        }
    }
}
```

#### Human Readable Output

>### Number of events found: 1. 
>|eventId|eventName|eventState|incidentSummary|severity|persistedTime|
>|---|---|---|---|---|---|
>| 7fb73a12-4be1-4b91-be33-60f3e580c689 | THREAT_DETECTED | Pending | Device is dormant. It is recommended to contact the user to reactivate the app. | LOW | 2020-06-06 02:05:57 +0000 |


### zimperium-users-search
***
Search users.


#### Base Command

`zimperium-users-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | The query to search for users. | Optional | 
| email | Search users by email address. | Optional | 
| size | Maximum number of users to retrieve in each page. Default is 10. | Optional | 
| page | Page number. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Zimperium.Users.activationTokenUrl | String | Activation token that is used to activate zIPS. | 
| Zimperium.Users.agreedToTerms | bool | Whether the user completed enrollment. | 
| Zimperium.Users.alias | String | User alias. | 
| Zimperium.Users.createdDate | Date | User created date. | 
| Zimperium.Users.dateJoined | Date | User joined date. | 
| Zimperium.Users.email | String | User email address. | 
| Zimperium.Users.firstName | String | User first name. | 
| Zimperium.Users.lastLogin | Date | User last login date. | 
| Zimperium.Users.lastName | String | User last name. | 
| Zimperium.Users.middleName | String | User middle name. | 
| Zimperium.Users.lastSyncFromMdm | Date | Last time the user synced from MDM, e.g., AirWatch, Mobile Iron, etc. | 
| Zimperium.Users.lastZconsoleLogin | Date | User last login to the Zimperium console. | 
| Zimperium.Users.modifiedDate | Date | User modified date. | 
| Zimperium.Users.objectId | String | User object ID. | 
| Zimperium.Users.passwordExpirationDate | Date | Use password expiration date. | 
| Zimperium.Users.phoneNumber | String | User phone number. | 
| Zimperium.Users.phoneNumberVerified | bool | Whether the user phone number is verified. | 
| Zimperium.Users.pwdRecoveryRequest | bool | Whether the user requested password recovery. | 
| Zimperium.Users.role | Number | User role. | 
| Zimperium.Users.roles.roleId | Number | User role ID. | 
| Zimperium.Users.signupSteps | Number | User sign\-up steps. | 
| Zimperium.Users.staff | bool | Whether the user is a staff member. | 
| Zimperium.Users.status | Number | User status. | 
| Zimperium.Users.superuser | bool | Whether the user is a superuser. | 
| Zimperium.Users.syncedFromMdm | bool | Whether the user is synced from MDM, e.g., AirWatch, Mobile Iron, etc. | 
| Zimperium.Users.termsVersion | String | User terms version. | 


#### Command Example
```!zimperium-users-search size=3 page=0```

#### Context Example
```
{
    "Zimperium": {
        "Users": [
            {
                "activationTokenUrl": "https://uat-device-api.zimperium.com/activation?stoken=YY4kCi4g&redirect_uri=zips",
                "agreedToTerms": false,
                "alias": "paxsoar-rbaqodbmqad6dr53qmx0jvl2ze5v02pw",
                "createdDate": "2020-06-03T01:58:58+0000",
                "dateJoined": "2020-06-03T01:58:58+0000",
                "email": "test@gmail.com",
                "firstName": "Fname",
                "lastLogin": "2020-06-12T02:16:34+0000",
                "lastName": "Lname",
                "lastSyncFromMdm": null,
                "lastZconsoleLogin": "2020-06-12T02:16:34+0000",
                "middleName": null,
                "modifiedDate": "2020-06-10T20:18:32+0000",
                "objectId": "3d588112-6467-4c2d-932a-b728f866163d",
                "passwordExpirationDate": "2020-09-08T20:18:32+0000",
                "phoneNumber": "",
                "phoneNumberVerified": false,
                "pwdRecoveryRequest": false,
                "role": 3,
                "roles": [
                    {
                        "roleId": 522488
                    }
                ],
                "signupSteps": 1,
                "staff": false,
                "status": 1,
                "superuser": false,
                "syncedFromMdm": false,
                "termsVersion": null
            },
            {
                "activationTokenUrl": "https://uat-device-api.zimperium.com/activation?stoken=VjRll23q&redirect_uri=zips",
                "agreedToTerms": false,
                "alias": "paxsoar-kz9qvdnvedqnkkkrgdvrobr3pkagmlovaoz3vo0dkp",
                "createdDate": "2020-06-02T19:49:21+0000",
                "dateJoined": "2020-06-02T19:49:21+0000",
                "email": "hhalliyal@paloaltonetworks.com",
                "firstName": "Hema",
                "lastLogin": "2020-06-02T20:21:08+0000",
                "lastName": "Halliyal",
                "lastSyncFromMdm": null,
                "lastZconsoleLogin": "2020-06-02T20:21:08+0000",
                "middleName": null,
                "modifiedDate": "2020-06-02T19:49:21+0000",
                "objectId": "437c8d9f-e9c2-44a0-bd8d-5cebd5cd8162",
                "passwordExpirationDate": "2020-08-31T19:49:21+0000",
                "phoneNumber": "",
                "phoneNumberVerified": false,
                "pwdRecoveryRequest": false,
                "role": 3,
                "roles": [
                    {
                        "roleId": 522488
                    }
                ],
                "signupSteps": 7,
                "staff": false,
                "status": 1,
                "superuser": false,
                "syncedFromMdm": false,
                "termsVersion": null
            },
            {
                "activationTokenUrl": "https://uat-device-api.zimperium.com/activation?stoken=1TKB9BKJ&redirect_uri=zips",
                "agreedToTerms": false,
                "alias": "paxsoar-9ok5bgx3o8ax6vd8xk9rrq6x25v5ml808djrvwb94e",
                "createdDate": "2020-06-02T19:48:47+0000",
                "dateJoined": "2020-06-02T19:48:47+0000",
                "email": "akrupnik@paloaltonetworks.com",
                "firstName": "A",
                "lastLogin": "2020-06-11T06:33:53+0000",
                "lastName": "Krupnik",
                "lastSyncFromMdm": null,
                "lastZconsoleLogin": "2020-06-11T06:33:53+0000",
                "middleName": null,
                "modifiedDate": "2020-06-02T19:48:47+0000",
                "objectId": "109e9873-29a4-49f3-bcf1-fd24ec634517",
                "passwordExpirationDate": "2020-08-31T19:48:47+0000",
                "phoneNumber": "",
                "phoneNumberVerified": false,
                "pwdRecoveryRequest": false,
                "role": 3,
                "roles": [
                    {
                        "roleId": 522488
                    }
                ],
                "signupSteps": 7,
                "staff": false,
                "status": 1,
                "superuser": false,
                "syncedFromMdm": false,
                "termsVersion": null
            }
        ]
    }
}
```

#### Human Readable Output

>### Number of users found: 5.  More users are available in the next page.
>|objectId|alias|firstName|lastName|email|
>|---|---|---|---|---|
>| 3d588112-6467-4c2d-932a-b728f866163d | paxsoar-rbaqodbmqad6dr53qmx0jvl2ze5v02pw | Fname | Lname | test@gmail.com |
>| 437c8d9f-e9c2-44a0-bd8d-5cebd5cd8162 | paxsoar-kz9qvdnvedqnkkkrgdvrobr3pkagmlovaoz3vo0dkp | Hema | Halliyal | hhalliyal@paloaltonetworks.com |
>| 109e9873-29a4-49f3-bcf1-fd24ec634517 | paxsoar-9ok5bgx3o8ax6vd8xk9rrq6x25v5ml808djrvwb94e | A | Krupnik | akrupnik@paloaltonetworks.com |


### zimperium-user-get-by-id
***
Retrieves details for a single user by object ID.


#### Base Command

`zimperium-user-get-by-id`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| object_id | Object ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Zimperium.Users.activationTokenUrl | String | Activation token that is used to activate zIPS. | 
| Zimperium.Users.agreedToTerms | Number | Whether the user completed enrollment. | 
| Zimperium.Users.alias | String | User alias. | 
| Zimperium.Users.createdDate | Date | User created date. | 
| Zimperium.Users.dateJoined | Date | User joined date. | 
| Zimperium.Users.email | String | User email address. | 
| Zimperium.Users.firstName | String | User first name. | 
| Zimperium.Users.lastName | String | User last name. | 
| Zimperium.Users.middleName | String | User middle name. | 
| Zimperium.Users.lastLogin | Date | User last login date. | 
| Zimperium.Users.lastSyncFromMdm | Unknown | Last time the user synced from MDM, e.g., AirWatch, Mobile Iron, etc. | 
| Zimperium.Users.lastZconsoleLogin | Date | User last login to the Zimperium console. | 
| Zimperium.Users.modifiedDate | Date | User last modified date. | 
| Zimperium.Users.objectId | String | User object ID. | 
| Zimperium.Users.passwordExpirationDate | Date | Use password expiration date. | 
| Zimperium.Users.phoneNumber | String | User phone number. | 
| Zimperium.Users.phoneNumberVerified | bool | Whether the user phone number is verified. | 
| Zimperium.Users.pwdRecoveryRequest | bool | Whether the user requested password recovery. | 
| Zimperium.Users.role | Number | User role. | 
| Zimperium.Users.roles.roleId | Number | User role ID. | 
| Zimperium.Users.signupSteps | Number | User sign\-up steps. | 
| Zimperium.Users.staff | bool | Whether the user is a staff member. | 
| Zimperium.Users.status | Number | User status. | 
| Zimperium.Users.superuser | bool | Whether the user is a superuser. | 
| Zimperium.Users.syncedFromMdm | bool | Whether the user is synced from MDM, e.g., AirWatch, Mobile Iron, etc. | 
| Zimperium.Users.termsVersion | String | User terms version. | 


#### Command Example
```!zimperium-user-get-by-id object_id=a045723f-5d3b-46f6-915a-fcbd42752aa0```

#### Context Example
```
{
    "Zimperium": {
        "Users": {
            "activationTokenUrl": "https://uat-device-api.zimperium.com/activation?stoken=Cu5MB9NB&redirect_uri=zips",
            "agreedToTerms": false,
            "alias": "paxsoar-mb11mz8o7mgne39eybezl8qngzen7bbg3ywld0lxqa",
            "createdDate": "2020-06-02T19:46:54+0000",
            "dateJoined": "2020-06-02T19:46:54+0000",
            "email": "paxsoar.support@zimperium.com",
            "firstName": "Z",
            "lastLogin": "2020-06-03T01:57:49+0000",
            "lastName": "Support",
            "lastSyncFromMdm": null,
            "lastZconsoleLogin": "2020-06-03T01:57:49+0000",
            "middleName": null,
            "modifiedDate": "2020-06-02T19:46:54+0000",
            "objectId": "a045723f-5d3b-46f6-915a-fcbd42752aa0",
            "passwordExpirationDate": "2020-08-31T19:46:54+0000",
            "phoneNumber": "",
            "phoneNumberVerified": false,
            "pwdRecoveryRequest": false,
            "role": 4,
            "roles": [
                {
                    "roleId": 522489
                }
            ],
            "signupSteps": 1,
            "staff": false,
            "status": 1,
            "superuser": false,
            "syncedFromMdm": false,
            "termsVersion": null
        }
    }
}
```

#### Human Readable Output

>### User:
>|objectId|alias|firstName|lastName|email|
>|---|---|---|---|---|
>| a045723f-5d3b-46f6-915a-fcbd42752aa0 | paxsoar-mb11mz8o7mgne39eybezl8qngzen7bbg3ywld0lxqa | Z | Support | paxsoar.support@zimperium.com |


### zimperium-devices-search
***
Search devices.


#### Base Command

`zimperium-devices-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | Search devices query. | Optional | 
| size | Maximum number of users to retrieve in each page. Default is 10. | Optional | 
| page | Page number. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Zimperium.Devices.appName | String | Application name. | 
| Zimperium.Devices.bundleId | String | Bundle ID. | 
| Zimperium.Devices.country | String | Device country. | 
| Zimperium.Devices.countryCode | String | Device country code. | 
| Zimperium.Devices.createdAt | Date | Created time of the device. | 
| Zimperium.Devices.deviceGroupName | String | Device group name. | 
| Zimperium.Devices.deviceHash | String | Device hash. | 
| Zimperium.Devices.deviceId | String | Device ID. | 
| Zimperium.Devices.email | String | Email address associated to the device. | 
| Zimperium.Devices.externalTrackingId1 | String | User pre\-defined Zimperium tag. | 
| Zimperium.Devices.externalTrackingId2 | String | User pre\-defined Zimperium tag. | 
| Zimperium.Devices.firstName | String | Device owner first name. | 
| Zimperium.Devices.lastName | String | Device owner last name. | 
| Zimperium.Devices.middleName | String | Device owner middle name. | 
| Zimperium.Devices.lastSeen | Date | Device last seen. | 
| Zimperium.Devices.mdmId | String | MDM ID, e.g., AirWatch, Mobile Iron. | 
| Zimperium.Devices.model | String | Device model. | 
| Zimperium.Devices.operatorAlpha | String | Name of the mobile operator. | 
| Zimperium.Devices.osBuild | String | OS build. | 
| Zimperium.Devices.osSecurityPatch | String | OS security patch. | 
| Zimperium.Devices.osType | String | OS type of the phone. | 
| Zimperium.Devices.osUpgradeable | bool | Whether the OS is upgradable. | 
| Zimperium.Devices.osVersion | String | OS version. | 
| Zimperium.Devices.osVulnerable | bool | Whether the OS is vulnerable. | 
| Zimperium.Devices.phoneNumber | String | Device phone number. | 
| Zimperium.Devices.processor | String | Device processor. | 
| Zimperium.Devices.riskPosture | String | Device risk. | 
| Zimperium.Devices.riskPostureCode | Number | Device risk code. | 
| Zimperium.Devices.status | String | Device status. | 
| Zimperium.Devices.statusCode | Number | Device status code. | 
| Zimperium.Devices.systemToken | String | Device system token. | 
| Zimperium.Devices.type | String | Device type. | 
| Zimperium.Devices.updatedDate | Date | Device updated date. | 
| Zimperium.Devices.userId | String | User ID of the device owner. | 
| Zimperium.Devices.version | String | Device version. | 
| Zimperium.Devices.vulnerabilities | String | Device vulnerabilities. | 
| Zimperium.Devices.zdid | String | Device ZD ID. | 
| Zimperium.Devices.zipsDistributionVersion | String | zIPS distribution version. | 
| Zimperium.Devices.zipsVersion | String | zIPS version. | 


#### Command Example
```!zimperium-devices-search query="osType==Android"```

#### Context Example
```
{
    "Zimperium": {
        "Devices": {
            "appName": "zIPS",
            "bundleId": "com.zimperium.zips",
            "country": "us",
            "countryCode": "us",
            "createdAt": "2020-06-03 02:04:25 UTC",
            "deviceGroupName": null,
            "deviceHash": "d3a5f56726ea39341ca19a534b8d5bc0cac07484b3032148857118f31b72bf01",
            "deviceId": "198280699673142",
            "email": "test@gmail.com",
            "externalTrackingId1": null,
            "externalTrackingId2": null,
            "firstName": "Fname",
            "lastName": "Lname",
            "lastSeen": "2020-06-03 02:05:19 UTC",
            "mdmId": null,
            "middleName": null,
            "model": "SM-G900H",
            "operatorAlpha": "AT&T",
            "osBuild": "LRX21T.G900HXXS1BPC8",
            "osSecurityPatch": "2016-03-01",
            "osType": "Android",
            "osUpgradeable": false,
            "osVersion": "4.4.2",
            "osVulnerable": false,
            "phoneNumber": "",
            "processor": "armeabi-v7a",
            "riskPosture": "Low",
            "riskPostureCode": 1,
            "status": "Inactive",
            "statusCode": 2,
            "systemToken": "paxsoar",
            "type": "k3gxx",
            "updatedDate": "2020-07-07 02:28:47 UTC",
            "userId": "3d588112-6467-4c2d-932a-b728f866163d",
            "version": "4.9.19",
            "vulnerabilities": [
                "Jailbroken/Rooted",
                "USB Debug Mode",
                "Stagefright",
                "Device Encryption Disabled",
                "Developer Mode",
                "Screen Lock Disabled",
                "3rd Party App Store"
            ],
            "zdid": "c728a9f1-dbcc-4b0f-84b2-5dc07e80b6e5",
            "zipsDistributionVersion": "n/a",
            "zipsVersion": "4.9.19"
        }
    }
}
```

#### Human Readable Output

>### Number of devices found: 1. 
>|deviceId|zdid|deviceHash|model|osType|osVersion|updatedDate|
>|---|---|---|---|---|---|---|
>| 198280699673142 | c728a9f1-dbcc-4b0f-84b2-5dc07e80b6e5 | d3a5f56726ea39341ca19a534b8d5bc0cac07484b3032148857118f31b72bf01 | SM-G900H | Android | 4.4.2 | 2020-07-07 02:28:47 UTC |


### zimperium-device-get-by-id
***
Retrieves details for a single device.


#### Base Command

`zimperium-device-get-by-id`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | Device ID. | Optional | 
| zdid | Zimperium ID. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Zimperium.Devices.appName | String | Application name. | 
| Zimperium.Devices.bundleId | String | Bundle ID. | 
| Zimperium.Devices.country | String | Device country. | 
| Zimperium.Devices.countryCode | String | Device country code. | 
| Zimperium.Devices.createdAt | Date | Created time of the device. | 
| Zimperium.Devices.deviceGroupName | String | Device group name. | 
| Zimperium.Devices.deviceHash | String | Device hash. | 
| Zimperium.Devices.deviceId | String | Device ID. | 
| Zimperium.Devices.email | String | Email address associated to the device. | 
| Zimperium.Devices.externalTrackingId1 | String | User pre\-defined Zimperium tag. | 
| Zimperium.Devices.externalTrackingId2 | String | User pre\-defined Zimperium tag. | 
| Zimperium.Devices.firstName | String | Device owner first name. | 
| Zimperium.Devices.lastName | String | Device owner last name. | 
| Zimperium.Devices.middleName | String | Device owner middle name. | 
| Zimperium.Devices.lastSeen | Date | Device last seen time. | 
| Zimperium.Devices.mdmId | String | MDM ID. e.g: AirWatch, Iron Mobile. | 
| Zimperium.Devices.model | String | Device model. | 
| Zimperium.Devices.operatorAlpha | String | Name of the mobile operator. | 
| Zimperium.Devices.osBuild | String | OS build. | 
| Zimperium.Devices.osSecurityPatch | String | OS security patch. | 
| Zimperium.Devices.osType | String | OS type of the phone. | 
| Zimperium.Devices.osUpgradeable | bool | Whether the OS is upgradable. | 
| Zimperium.Devices.osVersion | String | OS version. | 
| Zimperium.Devices.osVulnerable | bool | Whether the OS is vulnerable. | 
| Zimperium.Devices.phoneNumber | String | Phone number. | 
| Zimperium.Devices.processor | String | Device processor. | 
| Zimperium.Devices.riskPosture | String | Device risk. | 
| Zimperium.Devices.riskPostureCode | Number | Device risk code. | 
| Zimperium.Devices.status | String | Device status. | 
| Zimperium.Devices.statusCode | Number | Device status code. | 
| Zimperium.Devices.systemToken | String | Device system token. | 
| Zimperium.Devices.type | String | Device type. | 
| Zimperium.Devices.updatedDate | Date | Device updated date. | 
| Zimperium.Devices.userId | String | Device owner user ID. | 
| Zimperium.Devices.version | String | Device version. | 
| Zimperium.Devices.vulnerabilities | String | Device vulnerabilities. | 
| Zimperium.Devices.zdid | String | Device ZD ID. | 
| Zimperium.Devices.zipsDistributionVersion | String | zIPS distribution version. | 
| Zimperium.Devices.zipsVersion | String | zIPS version. | 


#### Command Example
```!zimperium-device-get-by-id zdid=2a086e00-32f3-4c03-90b2-b9fd4ea836e5```

#### Context Example
```
{
    "Zimperium": {
        "Devices": {
            "appName": "zIPS",
            "bundleId": "com.zimperium.zips",
            "country": null,
            "countryCode": null,
            "createdAt": "2020-06-10 08:50:32 UTC",
            "deviceGroupName": null,
            "deviceHash": "f5b42533a5cd2e4452a954b62a5bbab7ac2147d5bf1ade726a48f1f1d111c9",
            "deviceId": "c3e39cf6-97aa-38df-86eb-60a8a2cafbc1",
            "email": "test@gmail.com",
            "externalTrackingId1": "",
            "externalTrackingId2": "",
            "firstName": "Fname",
            "lastName": "Lname",
            "lastSeen": "2020-07-10 12:20:03 UTC",
            "mdmId": null,
            "middleName": null,
            "model": null,
            "operatorAlpha": null,
            "osBuild": null,
            "osSecurityPatch": null,
            "osType": null,
            "osUpgradeable": false,
            "osVersion": null,
            "osVulnerable": false,
            "phoneNumber": "",
            "processor": null,
            "riskPosture": "Critical",
            "riskPostureCode": 3,
            "status": "Inactive",
            "statusCode": 2,
            "systemToken": "paxsoar",
            "type": null,
            "updatedDate": "2020-07-13 12:20:52 UTC",
            "userId": "3d588112-6467-4c2d-932a-b728f866163d",
            "version": "4.13.3",
            "vulnerabilities": [
                "USB Debug Mode",
                "Developer Mode",
                "Screen Lock Disabled"
            ],
            "zdid": "2a086e00-32f3-4c03-90b2-b9fd4ea836e5",
            "zipsDistributionVersion": "n/a",
            "zipsVersion": "4.13.3"
        }
    }
}
```

#### Human Readable Output

>### Device :
>|deviceId|zdid|updatedDate|deviceHash|
>|---|---|---|---|
>| c3e39cf6-97aa-38df-86eb-60a8a2cafbc1 | 2a086e00-32f3-4c03-90b2-b9fd4ea836e5 | 2020-07-13 12:20:52 UTC | f5b42533a5cd2e4452a954b62a5bbab7ac2147d5bf1ade726a48f1f1d111c9 |


### zimperium-devices-get-last-updated
***
Retrieves devices from Greater than Last Updated.


#### Base Command

`zimperium-devices-get-last-updated`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| from_last_update | &lt;number&gt; &lt;time unit&gt;, e.g., 7 days, 3 months, 1 year | Optional | 
| exclude_deleted | Whether to exclude deleted devices. Default is True. | Optional | 
| size | Number of devices to retrieve in each page. | Optional | 
| page | Page number. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Zimperium.Devices.appName | String | Application name. | 
| Zimperium.Devices.bundleId | String | Bundle ID. | 
| Zimperium.Devices.country | String | Device country. | 
| Zimperium.Devices.countryCode | String | Device country code. | 
| Zimperium.Devices.createdAt | Date | Created time of the device. | 
| Zimperium.Devices.deviceGroupName | String | Device group name. | 
| Zimperium.Devices.deviceHash | String | Device hash. | 
| Zimperium.Devices.deviceId | String | Device ID. | 
| Zimperium.Devices.email | String | Email associated to the device. | 
| Zimperium.Devices.externalTrackingId1 | String | User pre defined Zimperium Tag. | 
| Zimperium.Devices.externalTrackingId2 | String | User pre defined Zimperium Tag. | 
| Zimperium.Devices.firstName | String | Device owner first name. | 
| Zimperium.Devices.lastName | String | Device owner last name. | 
| Zimperium.Devices.middleName | String | Device owner middle name. | 
| Zimperium.Devices.lastSeen | Date | Device last seen time. | 
| Zimperium.Devices.mdmId | String | MDM ID, e.g., AirWatch, Mobile Iron. | 
| Zimperium.Devices.model | String | Device model. | 
| Zimperium.Devices.operatorAlpha | String | Name of the mobile operator. | 
| Zimperium.Devices.osBuild | String | OS build. | 
| Zimperium.Devices.osSecurityPatch | String | OS security patch. | 
| Zimperium.Devices.osType | String | OS type of the phone. | 
| Zimperium.Devices.osUpgradeable | bool | Whether the OS is upgradable. | 
| Zimperium.Devices.osVersion | String | OS version. | 
| Zimperium.Devices.osVulnerable | bool | Whether the OS is vulnerable. | 
| Zimperium.Devices.phoneNumber | String | Phone number. | 
| Zimperium.Devices.processor | String | Device processor. | 
| Zimperium.Devices.riskPosture | String | Device risk. | 
| Zimperium.Devices.riskPostureCode | Number | Device risk code. | 
| Zimperium.Devices.status | String | Device status. | 
| Zimperium.Devices.statusCode | Number | Device status code. | 
| Zimperium.Devices.systemToken | String | Device system token. | 
| Zimperium.Devices.type | String | Device type. | 
| Zimperium.Devices.updatedDate | Date | Device updated date. | 
| Zimperium.Devices.userId | String | Device owner user ID. | 
| Zimperium.Devices.version | String | Device version. | 
| Zimperium.Devices.vulnerabilities | String | Device vulnerabilities. | 
| Zimperium.Devices.zdid | String | Device ZD ID. | 
| Zimperium.Devices.zipsDistributionVersion | String | zIPS distribution version. | 
| Zimperium.Devices.zipsVersion | String | zIPS version. | 


#### Command Example
```!zimperium-devices-get-last-updated from_last_update="1 month"```

#### Context Example
```
{
    "Zimperium": {
        "Devices": [
            {
                "appName": "zIPS",
                "bundleId": "com.zimperium.zips",
                "country": "us",
                "countryCode": "us",
                "createdAt": "2020-06-03 02:04:25 UTC",
                "deviceGroupName": null,
                "deviceHash": "d3a5f56726ea39341ca19a534b8d5bc0cac07484b3032148857118f31b72bf01",
                "deviceId": "198280699673142",
                "email": "test@gmail.com",
                "externalTrackingId1": null,
                "externalTrackingId2": null,
                "firstName": "Fname",
                "lastName": "Lname",
                "lastSeen": "2020-06-03 02:05:19 UTC",
                "mdmId": null,
                "middleName": null,
                "model": "SM-G900H",
                "operatorAlpha": "AT&T",
                "osBuild": "LRX21T.G900HXXS1BPC8",
                "osSecurityPatch": "2016-03-01",
                "osType": "Android",
                "osUpgradeable": false,
                "osVersion": "4.4.2",
                "osVulnerable": false,
                "phoneNumber": "",
                "processor": "armeabi-v7a",
                "riskPosture": "Low",
                "riskPostureCode": 1,
                "status": "Inactive",
                "statusCode": 2,
                "systemToken": "paxsoar",
                "type": "k3gxx",
                "updatedDate": "2020-07-07 02:28:47 UTC",
                "userId": "3d588112-6467-4c2d-932a-b728f866163d",
                "version": "4.9.19",
                "vulnerabilities": [
                    "Jailbroken/Rooted",
                    "USB Debug Mode",
                    "Stagefright",
                    "Device Encryption Disabled",
                    "Developer Mode",
                    "Screen Lock Disabled",
                    "3rd Party App Store"
                ],
                "zdid": "c728a9f1-dbcc-4b0f-84b2-5dc07e80b6e5",
                "zipsDistributionVersion": "n/a",
                "zipsVersion": "4.9.19"
            },
            {
                "appName": "zIPS",
                "bundleId": "com.zimperium.zips",
                "country": null,
                "countryCode": null,
                "createdAt": "2020-06-10 08:50:32 UTC",
                "deviceGroupName": null,
                "deviceHash": "f5b42533a5cd2e4452a954b62a5bbab7ac2147d5bf1ade726a48f1f1d111c9",
                "deviceId": "c3e39cf6-97aa-38df-86eb-60a8a2cafbc1",
                "email": "test@gmail.com",
                "externalTrackingId1": "",
                "externalTrackingId2": "",
                "firstName": "Fname",
                "lastName": "Lname",
                "lastSeen": "2020-07-10 12:20:03 UTC",
                "mdmId": null,
                "middleName": null,
                "model": null,
                "operatorAlpha": null,
                "osBuild": null,
                "osSecurityPatch": null,
                "osType": null,
                "osUpgradeable": false,
                "osVersion": null,
                "osVulnerable": false,
                "phoneNumber": "",
                "processor": null,
                "riskPosture": "Critical",
                "riskPostureCode": 3,
                "status": "Inactive",
                "statusCode": 2,
                "systemToken": "paxsoar",
                "type": null,
                "updatedDate": "2020-07-13 12:20:52 UTC",
                "userId": "3d588112-6467-4c2d-932a-b728f866163d",
                "version": "4.13.3",
                "vulnerabilities": [
                    "USB Debug Mode",
                    "Developer Mode",
                    "Screen Lock Disabled"
                ],
                "zdid": "2a086e00-32f3-4c03-90b2-b9fd4ea836e5",
                "zipsDistributionVersion": "n/a",
                "zipsVersion": "4.13.3"
            }
        ]
    }
}
```

#### Human Readable Output

>### Number of devices found: 2. 
>|deviceId|zdid|model|osType|osVersion|updatedDate|deviceHash|
>|---|---|---|---|---|---|---|
>| 198280699673142 | c728a9f1-dbcc-4b0f-84b2-5dc07e80b6e5 | SM-G900H | Android | 4.4.2 | 2020-07-07 02:28:47 UTC | d3a5f56726ea39341ca19a534b8d5bc0cac07484b3032148857118f31b72bf01 |
>| c3e39cf6-97aa-38df-86eb-60a8a2cafbc1 | 2a086e00-32f3-4c03-90b2-b9fd4ea836e5 |  |  |  | 2020-07-13 12:20:52 UTC | f5b42533a5cd2e4452a954b62a5bbab7ac2147d5bf1ade726a48f1f1d111c9 |


### zimperium-app-classification-get
***
Retrieves application classification.


#### Base Command

`zimperium-app-classification-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| app_name | Application name. | Optional | 
| app_hash | Application hash. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Zimperium.Application.classification | String | Application classification. | 
| Zimperium.Application.deviceCount | Number | Application device count. | 
| Zimperium.Application.hash | String | Application hash. | 
| Zimperium.Application.metadata | Unknown | Application metadata. | 
| Zimperium.Application.modifiedDate | Date | Application modified date. | 
| Zimperium.Application.name | String | Application name. | 
| Zimperium.Application.namespace | String | Application name space. | 
| Zimperium.Application.objectId | String | Application object ID. | 
| Zimperium.Application.privacyEnum | Number | Application privacy enum. | 
| Zimperium.Application.privacyRisk | String | Application privacy risk. | 
| Zimperium.Application.processState | String | Application process state. | 
| Zimperium.Application.score | Number | Application score \(0 to 100\). 0 is the best, 100 is the worst. | 
| Zimperium.Application.securityEnum | Number | Application security enum. | 
| Zimperium.Application.securityRisk | String | Application security risk. | 
| Zimperium.Application.systemToken | String | System token. | 
| Zimperium.Application.type | Number | Application type. | 
| Zimperium.Application.version | String | Application version. | 


#### Command Example
```!zimperium-app-classification-get app_name=Duo```

#### Context Example
```
{
    "Zimperium": {
        "Application": [
            {
                "classification": "Legitimate",
                "deviceCount": 1,
                "hash": "85525e9c1fd30a20848812e417f3bb1a",
                "metadata": {
                    "activities": [
                        "com.google.android.apps.tachyon.appupdate.HardBlockActivity",
                        "com.google.android.apps.tachyon.call.feedback.BadCallRatingActivity",
                        "com.google.android.apps.tachyon.call.history.ExportHistoryActivity",
                        "com.google.android.apps.tachyon.call.oneonone.ui.OneOnOneCallActivity",
                        "com.google.android.apps.tachyon.call.postcall.ui.PostCallActivity",
                        "com.google.android.apps.tachyon.call.precall.OneOnOnePrecallActivity",
                        "com.google.android.apps.tachyon.call.precall.fullhistory.FullHistoryActivity",
                        "com.google.android.apps.tachyon.clips.share.ReceiveShareIntentActivity",
                        "com.google.android.apps.tachyon.clips.ui.ClipsComposerActivity",
                        "com.google.android.apps.tachyon.clips.ui.gallerypicker.GalleryPickerActivity",
                        "com.google.android.apps.tachyon.clips.ui.viewclips.ViewClipsActivity",
                        "com.google.android.apps.tachyon.externalcallactivity.ExternalCallActivity",
                        "com.google.android.apps.tachyon.groupcalling.creategroup.EditGroupActivity",
                        "com.google.android.apps.tachyon.groupcalling.creategroup.GroupCreationActivity",
                        "com.google.android.apps.tachyon.groupcalling.incall.InGroupCallActivity",
                        "com.google.android.apps.tachyon.groupcalling.incoming.IncomingGroupCallActivity",
                        "com.google.android.apps.tachyon.groupcalling.precall.PrecallScreenGroupActivity",
                        "com.google.android.apps.tachyon.groupcalling.precall.PrecallScreenGroupInviteActivity",
                        "com.google.android.apps.tachyon.invites.externalinvite.ExternalInviteActivity",
                        "com.google.android.apps.tachyon.invites.invitescreen.InviteScreenActivity",
                        "com.google.android.apps.tachyon.registration.countrycode.CountryCodeActivity",
                        "com.google.android.apps.tachyon.registration.enterphonenumber.PhoneRegistrationActivity",
                        "com.google.android.apps.tachyon.registration.onboarding.OnboardingActivity",
                        "com.google.android.apps.tachyon.settings.blockedusers.BlockedUsersActivity",
                        "com.google.android.apps.tachyon.settings.knockknock.KnockKnockSettingActivity",
                        "com.google.android.apps.tachyon.settings.notifications.NotificationSettingsActivity",
                        "com.google.android.apps.tachyon.settings.v2.AccountSettingsActivity",
                        "com.google.android.apps.tachyon.settings.v2.ApplicationSettingsActivity",
                        "com.google.android.apps.tachyon.settings.v2.CallSettingsActivity",
                        "com.google.android.apps.tachyon.settings.v2.MessageSettingsActivity",
                        "com.google.android.apps.tachyon.ui.blockusers.BlockUsersActivity",
                        "com.google.android.apps.tachyon.ui.duoprivacy.DuoPrivacyActivity",
                        "com.google.android.apps.tachyon.ui.launcher.LauncherActivity",
                        "com.google.android.apps.tachyon.ui.lockscreen.LockscreenTrampolineActivity",
                        "com.google.android.apps.tachyon.ui.main.MainActivity",
                        "com.google.android.apps.tachyon.ui.warningdialog.WarningDialogActivity",
                        "com.google.android.gms.common.api.GoogleApiActivity",
                        "com.google.android.libraries.social.licenses.LicenseActivity",
                        "com.google.android.libraries.social.licenses.LicenseMenuActivity",
                        "com.google.android.libraries.surveys.internal.view.SurveyActivity",
                        "com.google.android.play.core.common.PlayCoreDialogWrapperActivity",
                        "com.google.android.play.core.missingsplits.PlayCoreMissingSplitsActivity",
                        "com.google.research.ink.annotate.AnnotateActivity"
                    ],
                    "filename": "/data/app/com.google.android.apps.tachyon-5hQwDR1DIKxnBrAIkdNlmg==/base.apk",
                    "package": "com.google.android.apps.tachyon",
                    "permissions": [
                        "android.permission.ACCESS_NETWORK_STATE",
                        "android.permission.ACCESS_WIFI_STATE",
                        "android.permission.AUTHENTICATE_ACCOUNTS",
                        "android.permission.BLUETOOTH",
                        "android.permission.BROADCAST_STICKY",
                        "android.permission.CAMERA",
                        "android.permission.CHANGE_NETWORK_STATE",
                        "android.permission.FOREGROUND_SERVICE",
                        "android.permission.GET_ACCOUNTS",
                        "android.permission.GET_PACKAGE_SIZE",
                        "android.permission.INTERNET",
                        "android.permission.MANAGE_ACCOUNTS",
                        "android.permission.MODIFY_AUDIO_SETTINGS",
                        "android.permission.READ_APP_BADGE",
                        "android.permission.READ_CONTACTS",
                        "android.permission.READ_PHONE_STATE",
                        "android.permission.READ_PROFILE",
                        "android.permission.READ_SYNC_STATS",
                        "android.permission.RECEIVE_BOOT_COMPLETED",
                        "android.permission.RECORD_AUDIO",
                        "android.permission.VIBRATE",
                        "android.permission.WAKE_LOCK",
                        "android.permission.WRITE_CALL_LOG",
                        "android.permission.WRITE_CONTACTS",
                        "android.permission.WRITE_SYNC_SETTINGS",
                        "com.anddoes.launcher.permission.UPDATE_COUNT",
                        "com.android.launcher.permission.INSTALL_SHORTCUT",
                        "com.google.android.c2dm.permission.RECEIVE",
                        "com.google.android.providers.gsf.permission.READ_GSERVICES",
                        "com.htc.launcher.permission.READ_SETTINGS",
                        "com.htc.launcher.permission.UPDATE_SHORTCUT",
                        "com.huawei.android.launcher.permission.CHANGE_BADGE",
                        "com.huawei.android.launcher.permission.READ_SETTINGS",
                        "com.huawei.android.launcher.permission.WRITE_SETTINGS",
                        "com.majeur.launcher.permission.UPDATE_BADGE",
                        "com.oppo.launcher.permission.READ_SETTINGS",
                        "com.oppo.launcher.permission.WRITE_SETTINGS",
                        "com.samsung.android.app.telephonyui.permission.READ_SETTINGS_PROVIDER",
                        "com.samsung.android.app.telephonyui.permission.WRITE_SETTINGS_PROVIDER",
                        "com.samsung.android.aremoji.provider.permission.READ_STICKER_PROVIDER",
                        "com.samsung.android.livestickers.provider.permission.READ_STICKER_PROVIDER",
                        "com.samsung.android.provider.filterprovider.permission.READ_FILTER",
                        "com.samsung.android.provider.stickerprovider.permission.READ_STICKER_PROVIDER",
                        "com.sec.android.provider.badge.permission.READ",
                        "com.sec.android.provider.badge.permission.WRITE",
                        "com.sonyericsson.home.permission.BROADCAST_BADGE",
                        "com.sonymobile.home.permission.PROVIDER_INSERT_BADGE"
                    ],
                    "receivers": [
                        "androidx.work.impl.background.systemalarm.ConstraintProxy$BatteryChargingProxy",
                        "androidx.work.impl.background.systemalarm.ConstraintProxy$BatteryNotLowProxy",
                        "androidx.work.impl.background.systemalarm.ConstraintProxy$NetworkStateProxy",
                        "androidx.work.impl.background.systemalarm.ConstraintProxy$StorageNotLowProxy",
                        "androidx.work.impl.background.systemalarm.ConstraintProxyUpdateReceiver",
                        "androidx.work.impl.background.systemalarm.RescheduleReceiver",
                        "androidx.work.impl.diagnostics.DiagnosticsReceiver",
                        "androidx.work.impl.utils.ForceStopRunnable$BroadcastReceiver",
                        "com.google.android.apps.tachyon.call.notification.CallRetryNotifierReceiver",
                        "com.google.android.apps.tachyon.call.notification.InCallNotificationIntentReceiver",
                        "com.google.android.apps.tachyon.call.notification.MissedCallNotificationIntentReceiver",
                        "com.google.android.apps.tachyon.clips.notification.MessagesNotificationIntentReceiver",
                        "com.google.android.apps.tachyon.common.applifecycle.AppInstallReceiver",
                        "com.google.android.apps.tachyon.common.applifecycle.AppUpdateReceiver",
                        "com.google.android.apps.tachyon.common.applifecycle.BootReceiver",
                        "com.google.android.apps.tachyon.common.applifecycle.LocaleChangeReceiver",
                        "com.google.android.apps.tachyon.groupcalling.incall.InGroupCallNotificationIntentReceiver",
                        "com.google.android.apps.tachyon.groupcalling.incoming.IncomingGroupCallIntentReceiver",
                        "com.google.android.apps.tachyon.groupcalling.incoming.IncomingGroupCallNotificationIntentReceiver",
                        "com.google.android.apps.tachyon.groupcalling.notification.GroupUpdateNotificationReceiver",
                        "com.google.android.apps.tachyon.invites.invitehelper.IntentChooserCallbackReceiver",
                        "com.google.android.apps.tachyon.net.fcm.CjnNotificationIntentReceiver",
                        "com.google.android.apps.tachyon.net.fcm.GenericFcmEventHandlerNotificationIntentReceiver",
                        "com.google.android.apps.tachyon.notifications.engagement.EngagementNotificationIntentReceiver",
                        "com.google.android.apps.tachyon.notifications.receiver.BasicNotificationIntentReceiver",
                        "com.google.android.apps.tachyon.phenotype.PhenotypeBroadcastReceiver",
                        "com.google.android.apps.tachyon.ping.notification.PingNotificationIntentReceiver",
                        "com.google.android.apps.tachyon.registration.SystemAccountChangedReceiver",
                        "com.google.android.apps.tachyon.registration.notification.RegistrationNotificationIntentReceiver",
                        "com.google.android.apps.tachyon.simdetection.SimStateBroadcastReceiver",
                        "com.google.android.libraries.internal.growth.growthkit.inject.GrowthKitBootCompletedBroadcastReceiver",
                        "com.google.android.libraries.internal.growth.growthkit.internal.debug.TestingToolsBroadcastReceiver",
                        "com.google.android.libraries.internal.growth.growthkit.internal.experiments.impl.PhenotypeBroadcastReceiver",
                        "com.google.android.libraries.phenotype.client.stable.PhenotypeStickyAccount$AccountRemovedBroadcastReceiver",
                        "com.google.firebase.iid.FirebaseInstanceIdReceiver"
                    ],
                    "services": [
                        "androidx.work.impl.background.systemalarm.SystemAlarmService",
                        "androidx.work.impl.background.systemjob.SystemJobService",
                        "androidx.work.impl.foreground.SystemForegroundService",
                        "com.google.android.apps.tachyon.call.service.CallService",
                        "com.google.android.apps.tachyon.clientapi.ClientApiService",
                        "com.google.android.apps.tachyon.contacts.reachability.ReachabilityService",
                        "com.google.android.apps.tachyon.contacts.sync.DuoAccountService",
                        "com.google.android.apps.tachyon.contacts.sync.SyncService",
                        "com.google.android.apps.tachyon.net.fcm.CallConnectingForegroundService",
                        "com.google.android.apps.tachyon.net.fcm.FcmReceivingService",
                        "com.google.android.apps.tachyon.telecom.TachyonTelecomConnectionService",
                        "com.google.android.apps.tachyon.telecom.TelecomFallbackService",
                        "com.google.android.libraries.internal.growth.growthkit.internal.jobs.impl.GrowthKitBelowLollipopJobService",
                        "com.google.android.libraries.internal.growth.growthkit.internal.jobs.impl.GrowthKitJobService",
                        "com.google.apps.tiktok.concurrent.InternalForegroundService",
                        "com.google.firebase.components.ComponentDiscoveryService",
                        "com.google.firebase.messaging.FirebaseMessagingService"
                    ],
                    "signature": "6c22867349d7e4b05b7ebb333056236f",
                    "subject": {
                        "commonName": "corp_tachyon",
                        "countryName": "US",
                        "localityName": "Mountain View",
                        "organizationName": "Google Inc.",
                        "organizationalUnitName": "Android",
                        "stateOrProvinceName": "California"
                    }
                },
                "modifiedDate": "2020-06-10 10:07:22 UTC",
                "name": "Duo",
                "namespace": "com.google.android.apps.tachyon",
                "objectId": "ebdfed24-951e-45f5-845a-2c163c53fc47",
                "privacyEnum": 1,
                "privacyRisk": "Medium",
                "processState": "AVAILABLE",
                "score": 0,
                "securityEnum": 1,
                "securityRisk": "Medium",
                "systemToken": "paxsoar",
                "type": 0,
                "version": "91.0.315322534.DR91_RC03"
            },
            {
                "classification": "Legitimate",
                "deviceCount": 1,
                "hash": "f26cf1135f9d2ea60532a5a13c6fbed5",
                "metadata": {
                    "activities": [
                        "com.google.android.apps.tachyon.appupdate.HardBlockActivity",
                        "com.google.android.apps.tachyon.call.feedback.BadCallRatingActivity",
                        "com.google.android.apps.tachyon.call.history.ExportHistoryActivity",
                        "com.google.android.apps.tachyon.call.oneonone.ui.OneOnOneCallActivity",
                        "com.google.android.apps.tachyon.call.postcall.ui.PostCallActivity",
                        "com.google.android.apps.tachyon.call.precall.OneOnOnePrecallActivity",
                        "com.google.android.apps.tachyon.call.precall.fullhistory.FullHistoryActivity",
                        "com.google.android.apps.tachyon.clips.share.ReceiveShareIntentActivity",
                        "com.google.android.apps.tachyon.clips.ui.ClipsComposerActivity",
                        "com.google.android.apps.tachyon.clips.ui.gallerypicker.GalleryPickerActivity",
                        "com.google.android.apps.tachyon.clips.ui.viewclips.ViewClipsActivity",
                        "com.google.android.apps.tachyon.externalcallactivity.ExternalCallActivity",
                        "com.google.android.apps.tachyon.groupcalling.creategroup.EditGroupActivity",
                        "com.google.android.apps.tachyon.groupcalling.creategroup.GroupCreationActivity",
                        "com.google.android.apps.tachyon.groupcalling.incall.InGroupCallActivity",
                        "com.google.android.apps.tachyon.groupcalling.incoming.IncomingGroupCallActivity",
                        "com.google.android.apps.tachyon.groupcalling.precall.PrecallScreenGroupActivity",
                        "com.google.android.apps.tachyon.groupcalling.precall.PrecallScreenGroupInviteActivity",
                        "com.google.android.apps.tachyon.invites.externalinvite.ExternalInviteActivity",
                        "com.google.android.apps.tachyon.invites.invitescreen.InviteScreenActivity",
                        "com.google.android.apps.tachyon.registration.countrycode.CountryCodeActivity",
                        "com.google.android.apps.tachyon.registration.enterphonenumber.PhoneRegistrationActivity",
                        "com.google.android.apps.tachyon.registration.onboarding.OnboardingActivity",
                        "com.google.android.apps.tachyon.settings.blockedusers.BlockedUsersActivity",
                        "com.google.android.apps.tachyon.settings.knockknock.KnockKnockSettingActivity",
                        "com.google.android.apps.tachyon.settings.notifications.NotificationSettingsActivity",
                        "com.google.android.apps.tachyon.settings.v2.AccountSettingsActivity",
                        "com.google.android.apps.tachyon.settings.v2.ApplicationSettingsActivity",
                        "com.google.android.apps.tachyon.settings.v2.CallSettingsActivity",
                        "com.google.android.apps.tachyon.settings.v2.MessageSettingsActivity",
                        "com.google.android.apps.tachyon.ui.blockusers.BlockUsersActivity",
                        "com.google.android.apps.tachyon.ui.duoprivacy.DuoPrivacyActivity",
                        "com.google.android.apps.tachyon.ui.launcher.LauncherActivity",
                        "com.google.android.apps.tachyon.ui.lockscreen.LockscreenTrampolineActivity",
                        "com.google.android.apps.tachyon.ui.main.MainActivity",
                        "com.google.android.apps.tachyon.ui.warningdialog.WarningDialogActivity",
                        "com.google.android.gms.common.api.GoogleApiActivity",
                        "com.google.android.libraries.social.licenses.LicenseActivity",
                        "com.google.android.libraries.social.licenses.LicenseMenuActivity",
                        "com.google.android.libraries.surveys.internal.view.SurveyActivity",
                        "com.google.android.play.core.common.PlayCoreDialogWrapperActivity",
                        "com.google.android.play.core.missingsplits.PlayCoreMissingSplitsActivity",
                        "com.google.research.ink.annotate.AnnotateActivity"
                    ],
                    "filename": "/data/app/com.google.android.apps.tachyon-tPZVegxYyWlY3qYsaqXeUQ==/base.apk",
                    "package": "com.google.android.apps.tachyon",
                    "permissions": [
                        "android.permission.ACCESS_NETWORK_STATE",
                        "android.permission.ACCESS_WIFI_STATE",
                        "android.permission.AUTHENTICATE_ACCOUNTS",
                        "android.permission.BLUETOOTH",
                        "android.permission.BROADCAST_STICKY",
                        "android.permission.CAMERA",
                        "android.permission.CHANGE_NETWORK_STATE",
                        "android.permission.FOREGROUND_SERVICE",
                        "android.permission.GET_ACCOUNTS",
                        "android.permission.GET_PACKAGE_SIZE",
                        "android.permission.INTERNET",
                        "android.permission.MANAGE_ACCOUNTS",
                        "android.permission.MODIFY_AUDIO_SETTINGS",
                        "android.permission.READ_APP_BADGE",
                        "android.permission.READ_CONTACTS",
                        "android.permission.READ_PHONE_STATE",
                        "android.permission.READ_PROFILE",
                        "android.permission.READ_SYNC_STATS",
                        "android.permission.RECEIVE_BOOT_COMPLETED",
                        "android.permission.RECORD_AUDIO",
                        "android.permission.VIBRATE",
                        "android.permission.WAKE_LOCK",
                        "android.permission.WRITE_CALL_LOG",
                        "android.permission.WRITE_CONTACTS",
                        "android.permission.WRITE_SYNC_SETTINGS",
                        "com.anddoes.launcher.permission.UPDATE_COUNT",
                        "com.android.launcher.permission.INSTALL_SHORTCUT",
                        "com.google.android.c2dm.permission.RECEIVE",
                        "com.google.android.providers.gsf.permission.READ_GSERVICES",
                        "com.htc.launcher.permission.READ_SETTINGS",
                        "com.htc.launcher.permission.UPDATE_SHORTCUT",
                        "com.huawei.android.launcher.permission.CHANGE_BADGE",
                        "com.huawei.android.launcher.permission.READ_SETTINGS",
                        "com.huawei.android.launcher.permission.WRITE_SETTINGS",
                        "com.majeur.launcher.permission.UPDATE_BADGE",
                        "com.oppo.launcher.permission.READ_SETTINGS",
                        "com.oppo.launcher.permission.WRITE_SETTINGS",
                        "com.samsung.android.app.telephonyui.permission.READ_SETTINGS_PROVIDER",
                        "com.samsung.android.app.telephonyui.permission.WRITE_SETTINGS_PROVIDER",
                        "com.samsung.android.aremoji.provider.permission.READ_STICKER_PROVIDER",
                        "com.samsung.android.livestickers.provider.permission.READ_STICKER_PROVIDER",
                        "com.samsung.android.provider.filterprovider.permission.READ_FILTER",
                        "com.samsung.android.provider.stickerprovider.permission.READ_STICKER_PROVIDER",
                        "com.sec.android.provider.badge.permission.READ",
                        "com.sec.android.provider.badge.permission.WRITE",
                        "com.sonyericsson.home.permission.BROADCAST_BADGE",
                        "com.sonymobile.home.permission.PROVIDER_INSERT_BADGE"
                    ],
                    "receivers": [
                        "androidx.work.impl.background.systemalarm.ConstraintProxy$BatteryChargingProxy",
                        "androidx.work.impl.background.systemalarm.ConstraintProxy$BatteryNotLowProxy",
                        "androidx.work.impl.background.systemalarm.ConstraintProxy$NetworkStateProxy",
                        "androidx.work.impl.background.systemalarm.ConstraintProxy$StorageNotLowProxy",
                        "androidx.work.impl.background.systemalarm.ConstraintProxyUpdateReceiver",
                        "androidx.work.impl.background.systemalarm.RescheduleReceiver",
                        "androidx.work.impl.diagnostics.DiagnosticsReceiver",
                        "androidx.work.impl.utils.ForceStopRunnable$BroadcastReceiver",
                        "com.google.android.apps.tachyon.call.notification.CallRetryNotifierReceiver",
                        "com.google.android.apps.tachyon.call.notification.InCallNotificationIntentReceiver",
                        "com.google.android.apps.tachyon.call.notification.MissedCallNotificationIntentReceiver",
                        "com.google.android.apps.tachyon.clips.notification.MessagesNotificationIntentReceiver",
                        "com.google.android.apps.tachyon.common.applifecycle.AppInstallReceiver",
                        "com.google.android.apps.tachyon.common.applifecycle.AppUpdateReceiver",
                        "com.google.android.apps.tachyon.common.applifecycle.BootReceiver",
                        "com.google.android.apps.tachyon.common.applifecycle.LocaleChangeReceiver",
                        "com.google.android.apps.tachyon.groupcalling.incall.InGroupCallNotificationIntentReceiver",
                        "com.google.android.apps.tachyon.groupcalling.incoming.IncomingGroupCallIntentReceiver",
                        "com.google.android.apps.tachyon.groupcalling.incoming.IncomingGroupCallNotificationIntentReceiver",
                        "com.google.android.apps.tachyon.groupcalling.notification.GroupUpdateNotificationReceiver",
                        "com.google.android.apps.tachyon.invites.invitehelper.IntentChooserCallbackReceiver",
                        "com.google.android.apps.tachyon.net.fcm.CjnNotificationIntentReceiver",
                        "com.google.android.apps.tachyon.net.fcm.GenericFcmEventHandlerNotificationIntentReceiver",
                        "com.google.android.apps.tachyon.notifications.engagement.EngagementNotificationIntentReceiver",
                        "com.google.android.apps.tachyon.notifications.receiver.BasicNotificationIntentReceiver",
                        "com.google.android.apps.tachyon.phenotype.PhenotypeBroadcastReceiver",
                        "com.google.android.apps.tachyon.ping.notification.PingNotificationIntentReceiver",
                        "com.google.android.apps.tachyon.registration.SystemAccountChangedReceiver",
                        "com.google.android.apps.tachyon.registration.notification.RegistrationNotificationIntentReceiver",
                        "com.google.android.apps.tachyon.simdetection.SimStateBroadcastReceiver",
                        "com.google.android.libraries.internal.growth.growthkit.inject.GrowthKitBootCompletedBroadcastReceiver",
                        "com.google.android.libraries.internal.growth.growthkit.internal.debug.TestingToolsBroadcastReceiver",
                        "com.google.android.libraries.internal.growth.growthkit.internal.experiments.impl.PhenotypeBroadcastReceiver",
                        "com.google.android.libraries.phenotype.client.stable.PhenotypeStickyAccount$AccountRemovedBroadcastReceiver",
                        "com.google.firebase.iid.FirebaseInstanceIdReceiver"
                    ],
                    "services": [
                        "androidx.work.impl.background.systemalarm.SystemAlarmService",
                        "androidx.work.impl.background.systemjob.SystemJobService",
                        "androidx.work.impl.foreground.SystemForegroundService",
                        "com.google.android.apps.tachyon.call.service.CallService",
                        "com.google.android.apps.tachyon.clientapi.ClientApiService",
                        "com.google.android.apps.tachyon.contacts.reachability.ReachabilityService",
                        "com.google.android.apps.tachyon.contacts.sync.DuoAccountService",
                        "com.google.android.apps.tachyon.contacts.sync.SyncService",
                        "com.google.android.apps.tachyon.net.fcm.CallConnectingForegroundService",
                        "com.google.android.apps.tachyon.net.fcm.FcmReceivingService",
                        "com.google.android.apps.tachyon.telecom.TachyonTelecomConnectionService",
                        "com.google.android.apps.tachyon.telecom.TelecomFallbackService",
                        "com.google.android.libraries.internal.growth.growthkit.internal.jobs.impl.GrowthKitBelowLollipopJobService",
                        "com.google.android.libraries.internal.growth.growthkit.internal.jobs.impl.GrowthKitJobService",
                        "com.google.apps.tiktok.concurrent.InternalForegroundService",
                        "com.google.firebase.components.ComponentDiscoveryService",
                        "com.google.firebase.messaging.FirebaseMessagingService"
                    ],
                    "signature": "6c22867349d7e4b05b7ebb333056236f",
                    "subject": {
                        "commonName": "corp_tachyon",
                        "countryName": "US",
                        "localityName": "Mountain View",
                        "organizationName": "Google Inc.",
                        "organizationalUnitName": "Android",
                        "stateOrProvinceName": "California"
                    }
                },
                "modifiedDate": "2020-06-10 09:37:22 UTC",
                "name": "Duo",
                "namespace": "com.google.android.apps.tachyon",
                "objectId": "02a0ed2d-b22f-4b25-834f-232c7e1b4914",
                "privacyEnum": 1,
                "privacyRisk": "Medium",
                "processState": "AVAILABLE",
                "score": 0,
                "securityEnum": 1,
                "securityRisk": "Medium",
                "systemToken": "paxsoar",
                "type": 0,
                "version": "91.0.314224792.DR91_RC01"
            }
        ]
    }
}
```

#### Human Readable Output

>### Application:
>|objectId|hash|name|version|classification|score|privacyEnum|securityEnum|
>|---|---|---|---|---|---|---|---|
>| ebdfed24-951e-45f5-845a-2c163c53fc47 | 85525e9c1fd30a20848812e417f3bb1a | Duo | 91.0.315322534.DR91_RC03 | Legitimate | 0.0 | 1 | 1 |
>| 02a0ed2d-b22f-4b25-834f-232c7e1b4914 | f26cf1135f9d2ea60532a5a13c6fbed5 | Duo | 91.0.314224792.DR91_RC01 | Legitimate | 0.0 | 1 | 1 |


### zimperium-report-get
***
Gets a report.


#### Base Command

`zimperium-report-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| bundle_id | Bundle ID. | Optional | 
| itunes_id | iTunes ID. | Optional | 
| app_hash | Application hash. | Optional | 
| platform | Application platform. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Zimperium.Reports.app_analysis.analysis | Unknown | Application analysis data. | 
| Zimperium.Reports.behavior.count_sms | Number | The number of SMS messages. | 
| Zimperium.Reports.behavior.network.http_requests | Unknown | Network related data. | 
| Zimperium.Reports.behavior.telephony | Unknown | Standard permissions of the application. | 
| Zimperium.Reports.certificate.app_signature | String | Application signature. | 
| Zimperium.Reports.certificate.serial_number_app_instances | Number | Application serial number. | 
| Zimperium.Reports.certificate.serial_number_risk_score | Number | Application risk score. | 
| Zimperium.Reports.distribution | Unknown | Related distribution data. | 
| Zimperium.Reports.md5 | String | Application md5 hash. | 
| Zimperium.Reports.risk_profile.detection_rate | String | Detection rate of the application. | 
| Zimperium.Reports.risk_profile.intell_privacy | String | Privacy intelligence. | 
| Zimperium.Reports.risk_profile.intell_security | String | Security intelligence. | 
| Zimperium.Reports.risk_profile.overall_risk | String | Overall  risk. | 
| Zimperium.Reports.risk_profile.privacy.Category | String | Privacy category | 
| Zimperium.Reports.risk_profile.privacy.Risk Level | String | Privacy risk level. | 
| Zimperium.Reports.risk_profile.privacy.desc | String | Privacy description. | 
| Zimperium.Reports.risk_profile.privacy_risk | Number | Privacy risk. | 
| Zimperium.Reports.risk_profile.security.Category | String | Security category. | 
| Zimperium.Reports.risk_profile.security.Risk Level | String | Security risk level. | 
| Zimperium.Reports.risk_profile.security.desc | String | Security description. | 
| Zimperium.Reports.risk_profile.security_risk | Number | Security risk. | 
| Zimperium.Reports.threats.detected | Number | Threats detected. | 
| Zimperium.Reports.threats.detected_skip | Number | Number of Skipped detected threats. | 
| Zimperium.Reports.threats.status | String | Threats status. | 
| Zimperium.Reports.threats.total | Number | Total threats. | 


#### Command Example
```!zimperium-report-get app_hash=f26cf1135f9d2ea60532a5a13c6fbed5```

#### Context Example
```
{
    "Zimperium": {
        "Reports": {
            "app_analysis": {
                "analysis": [
                    "native_files",
                    "embedded_files",
                    "Accesses the phone calls history.",
                    "The app has been found to be MultiDex",
                    "The app registers a BroadcastReceiver.",
                    "This app uses a secure (https) socket.",
                    "The app is using native function calls.",
                    "The app loads cryptographic key-stores.",
                    "The app retrieves ClipBoard data contents.",
                    "The app uses the primary external storage.",
                    "This app uses network sockets functionality.",
                    "The application uses Bluetooth functionality.",
                    "This app has access to the device microphone.",
                    "The app sets a bundle of additional info data.",
                    "The application stores inline API keys/values.",
                    "This application accesses the user's contacts.",
                    "This app opens a secure (https) URL connection.",
                    "This app can retrieve the list of running apps. ",
                    "The app computes a content URI given a lookup URI.",
                    "This application queries the Calendar on the device.",
                    "This app implements a telephone call state change listener. ",
                    "This app is reading the device model number or manufacturer.",
                    "This app queries for the device version release information.",
                    "This application requests an instance of the SHA1 algorithm.",
                    "The application listens for changes in the telephony environment.",
                    "The app connects to an application service, creating it if needed.",
                    "This app can access and read the contents of the global clipboard.",
                    "This app uses a simplified version of the java.security.cert package.",
                    "This app uses a cryptographically strong random number generator (RNG).",
                    "The app stores key mapped value strings to the SharedPreferences storage.",
                    "Information: The application can obtain all available environment variables.",
                    "This application requests the device type from the system build properties. ",
                    "Information: This application accesses the properties of the device and the OS.",
                    "This application issues SQL database commands. This is an informational finding.",
                    "The application receives a reference to a system service called 'getSystemService'.",
                    "Opens an InputStream for the contact's photo and returns the photo as a byte stream.",
                    "This application requests the build identifier type from the system build properties. ",
                    "Information: The application checks the current ready state of Bluetooth functionality.",
                    "This application requests the device build fingerprint from the system build properties. ",
                    "This application requests the device product information from the system build properties. ",
                    "This application requests the device's brand information from the system build properties. ",
                    "This application requests the device build tag information from the system build properties. ",
                    "This application uses random read-write access to the result set returned by database queries.",
                    "The app retrieves a PendingIntent that performs a broadcast, similar to calling Context.sendBroadcast().",
                    "Information: This provides access to implementations of cryptographic ciphers for encryption and decryption.",
                    "This app implements the Intent 'StartService' which can cause information leakage if not configured correctly.",
                    "Information: This application retrieves information about any application package that is installed on the device.",
                    "Gets an auth token of the specified type for a particular account, prompting the user for credentials if necessary.",
                    "We have identified declared permissions in the code. Permissions should be declared in the Android Manifest.xml file.",
                    "The app uses a method to blindly load all apps and JAR files located in a directory enabling abuse by malicious parties.",
                    "This app can load compiled code in APK and JAR files. This can include files located in external storage and potentially on the Internet.",
                    "This application requests the device manufacture information from the system build properties and is looking for specific Samsung models.",
                    "The application queries the device for the telephone number assigned. This can be data leakage if the phone number is sent outside the device.",
                    "This app used the Java Security interface for parsing and managing certificates, certificate revocation lists (CRLs), and certification paths.",
                    "The application creates a new camera object to programmatically access the back-facing camera and potentially take user photos without consent.",
                    "This app has turned off the ability to use cut copy and paste on some UI fields. This can assist to ensure sensitive information is not exposed.",
                    "This package provides classes and interfaces to use the Secure Sockets Layer (SSL) protocol and the successor Transport Layer Security (TLS) protocol. ",
                    "The application gets the mobile network operator name. This can be considered data leakage when combined with other indicators that can uniquely identify the device.",
                    "As a standard practice with many applications, this application loads external libraries at runtime. It will load the native library specified by the libname argument.",
                    "This application has functionality for cryptographic applications implementing algorithms for encryption, decryption, or key agreement. This is an informational finding.",
                    "Information: The application receives notification when the device is rebooted. This can allow an app to run itself or a separate payload every time the device is restarted. ",
                    "This application uses Base64 encoding and decoding. Base64 is typically used in email/web communications but can be applied to any data set. This is an informational finding.",
                    "Information: The app returns the ISO country code equivalent to the SIM provider's country code. This can be considered data leakage if the information is sent to a remote server.",
                    "Set the enabled setting for a package component (activity, receiver, service, provider). This setting overrides any enabled state which can be set by the component in its manifest.",
                    "A RemoteInput object specifies input to be collected from a user. The object is then passed along with an intent inside a PendingIntent. Care should be taken to see that privacy information is not leaked.",
                    "The app modifies its user agent string. It is recommended that the developer use the properties derived from System.getProperty(\"http.agent\") or WebView(this).getSettings().getUserAgentString() to set the user agent string.",
                    "This app implements checkCallingOrSelf(Uri)Permission. This method is used to determine the permissions of the app being called. This method also has the potential to grant the calling application the same permissions as this app.",
                    "This app is implementing Dropbox API interactivity. The Dropbox API allows developers to integrate a cloud storage solution. The API provides methods to read and write from Dropbox. This risk could allow users to transfer sensitive information.",
                    "This app uses Java code reflection which enables an app to analyze and modify itself. An attacker can create unexpected control flow paths through the application, potentially by-passing security checks. Exploitation of this weakness can result in a form of code injection.",
                    "The app sets an explicit application package name that limits the components this Intent will resolve to. If left to the default value of null, all components in all applications will considered. If non-null, the Intent can only match the components in the given application package.",
                    "The app utilizes the Java.io.File delete() method to perform a file deletion. This method is not a secure method of file deletion. Because the Android API does not provide a method to perform secure file deletion operations it is suggested to overwrite the file with random characters before performing the file delete operation when sensitive data is involved. Files are only marked for deletion and can be recovered using third-party utilities on a rooted device. ",
                    "Content providers are implicitly not secure. They allow other applications on the device to request and share data. If sensitive information is accidentally leaked to a content provider, an attacker can call the content provider and the sensitive data is exposed to the attacker by the application.This is concerning because any third-party application containing malicious code does not require any granted permissions to obtain sensitive information from these applications."
                ],
                "app_version": "91.0.314224792.DR91_RC01",
                "app_version_code": "3014397",
                "application_type": "Android",
                "components": {
                    "activity": {
                        "classes": [
                            {
                                "access": "private",
                                "class": "com.google.android.play.core.missingsplits.PlayCoreMissingSplitsActivity"
                            },
                            {
                                "access": "private",
                                "class": "com.google.android.play.core.common.PlayCoreDialogWrapperActivity"
                            },
                            {
                                "access": "public",
                                "class": "com.google.android.apps.tachyon.ui.main.MainActivity"
                            },
                            {
                                "access": "private",
                                "class": "com.google.android.apps.tachyon.appupdate.HardBlockActivity"
                            },
                            {
                                "access": "private",
                                "class": "com.google.android.apps.tachyon.call.feedback.BadCallRatingActivity"
                            },
                            {
                                "access": "public",
                                "class": "com.google.android.apps.tachyon.call.history.ExportHistoryActivity"
                            },
                            {
                                "access": "private",
                                "class": "com.google.android.apps.tachyon.call.oneonone.ui.OneOnOneCallActivity"
                            },
                            {
                                "access": "private",
                                "class": "com.google.android.apps.tachyon.call.postcall.ui.PostCallActivity"
                            },
                            {
                                "access": "private",
                                "class": "com.google.android.apps.tachyon.call.precall.fullhistory.FullHistoryActivity"
                            },
                            {
                                "access": "private",
                                "class": "com.google.android.apps.tachyon.call.precall.OneOnOnePrecallActivity"
                            },
                            {
                                "access": "public",
                                "class": "com.google.android.apps.tachyon.clips.share.ReceiveShareIntentActivity"
                            },
                            {
                                "access": "private",
                                "class": "com.google.android.apps.tachyon.clips.ui.ClipsComposerActivity"
                            },
                            {
                                "access": "private",
                                "class": "com.google.android.apps.tachyon.clips.ui.gallerypicker.GalleryPickerActivity"
                            },
                            {
                                "access": "private",
                                "class": "com.google.android.apps.tachyon.clips.ui.viewclips.ViewClipsActivity"
                            },
                            {
                                "access": "public",
                                "class": "com.google.android.apps.tachyon.externalcallactivity.ExternalCallActivity"
                            },
                            {
                                "access": "private",
                                "class": "com.google.android.apps.tachyon.groupcalling.creategroup.GroupCreationActivity"
                            },
                            {
                                "access": "private",
                                "class": "com.google.android.apps.tachyon.groupcalling.creategroup.EditGroupActivity"
                            },
                            {
                                "access": "private",
                                "class": "com.google.android.apps.tachyon.groupcalling.incall.InGroupCallActivity"
                            },
                            {
                                "access": "private",
                                "class": "com.google.android.apps.tachyon.groupcalling.incoming.IncomingGroupCallActivity"
                            },
                            {
                                "access": "private",
                                "class": "com.google.android.apps.tachyon.groupcalling.precall.PrecallScreenGroupActivity"
                            },
                            {
                                "access": "private",
                                "class": "com.google.android.apps.tachyon.groupcalling.precall.PrecallScreenGroupInviteActivity"
                            },
                            {
                                "access": "public",
                                "class": "com.google.android.apps.tachyon.invites.externalinvite.ExternalInviteActivity"
                            },
                            {
                                "access": "private",
                                "class": "com.google.android.apps.tachyon.invites.invitescreen.InviteScreenActivity"
                            },
                            {
                                "access": "private",
                                "class": "com.google.android.apps.tachyon.registration.countrycode.CountryCodeActivity"
                            },
                            {
                                "access": "private",
                                "class": "com.google.android.apps.tachyon.registration.enterphonenumber.PhoneRegistrationActivity"
                            },
                            {
                                "access": "private",
                                "class": "com.google.android.apps.tachyon.registration.onboarding.OnboardingActivity"
                            },
                            {
                                "access": "private",
                                "class": "com.google.android.apps.tachyon.settings.blockedusers.BlockedUsersActivity"
                            },
                            {
                                "access": "private",
                                "class": "com.google.android.apps.tachyon.settings.knockknock.KnockKnockSettingActivity"
                            },
                            {
                                "access": "private",
                                "class": "com.google.android.apps.tachyon.settings.notifications.NotificationSettingsActivity"
                            },
                            {
                                "access": "private",
                                "class": "com.google.android.apps.tachyon.settings.v2.ApplicationSettingsActivity"
                            },
                            {
                                "access": "private",
                                "class": "com.google.android.apps.tachyon.settings.v2.AccountSettingsActivity"
                            },
                            {
                                "access": "private",
                                "class": "com.google.android.apps.tachyon.settings.v2.CallSettingsActivity"
                            },
                            {
                                "access": "private",
                                "class": "com.google.android.apps.tachyon.settings.v2.MessageSettingsActivity"
                            },
                            {
                                "access": "private",
                                "class": "com.google.android.apps.tachyon.ui.blockusers.BlockUsersActivity"
                            },
                            {
                                "access": "private",
                                "class": "com.google.android.apps.tachyon.ui.duoprivacy.DuoPrivacyActivity"
                            },
                            {
                                "access": "public",
                                "class": "com.google.android.apps.tachyon.ui.launcher.LauncherActivity"
                            },
                            {
                                "access": "private",
                                "class": "com.google.android.apps.tachyon.ui.lockscreen.LockscreenTrampolineActivity"
                            },
                            {
                                "access": "private",
                                "class": "com.google.android.apps.tachyon.ui.warningdialog.WarningDialogActivity"
                            },
                            {
                                "access": "private",
                                "class": "com.google.android.gms.common.api.GoogleApiActivity"
                            },
                            {
                                "access": "public",
                                "class": "com.google.android.libraries.social.licenses.LicenseMenuActivity"
                            },
                            {
                                "access": "private",
                                "class": "com.google.android.libraries.social.licenses.LicenseActivity"
                            },
                            {
                                "access": "public",
                                "class": "com.google.android.libraries.surveys.internal.view.SurveyActivity"
                            },
                            {
                                "access": "private",
                                "class": "com.google.research.ink.annotate.AnnotateActivity"
                            }
                        ],
                        "description": "An activity represents a single screen with a user interface. For example, an email application might have one activity that shows a list of new emails, another activity to compose an email, and another activity for reading emails. Although the activities work together to form a cohesive user experience in the email application, each one is independent of the others. As such, a different application can start any one of these activities (if the email application allows it). For example, a camera application can start the activity in the email application that composes new mail, in order for the user to share a picture.\r\n\r\nAn activity is implemented as a subclass of Activity and you can learn more about it in the Activities developer guide."
                    },
                    "activity_alias": {
                        "classes": [
                            {
                                "access": "private",
                                "class": "com.google.android.apps.tachyon.RegisterRequestActivity"
                            },
                            {
                                "access": "private",
                                "class": "com.google.android.apps.tachyon.ProcessedCallRequestActivity"
                            },
                            {
                                "access": "private",
                                "class": "com.google.android.apps.tachyon.InternalCallRequestActivity"
                            },
                            {
                                "access": "private",
                                "class": "com.google.android.apps.tachyon.ExternalCallActivity"
                            },
                            {
                                "access": "private",
                                "class": "com.google.android.apps.tachyon.AssistantCallActivity"
                            },
                            {
                                "access": "private",
                                "class": "com.google.android.apps.tachyon.ContactsVideoActionActivity"
                            },
                            {
                                "access": "private",
                                "class": "com.google.android.apps.tachyon.ContactsAudioActionActivity"
                            },
                            {
                                "access": "private",
                                "class": "com.google.android.apps.tachyon.MainActivity"
                            }
                        ],
                        "description": "The alias presents the target activity as a independent entity. It can have its own set of intent filters, and they, rather than the intent filters on the target activity itself, determine which intents can activate the target through the alias and how the system treats the alias. For example, the intent filters on the alias may specify the \"android.intent.action.MAIN\" and \"android.intent.category.LAUNCHER\" flags, causing it to be represented in the application launcher, even though none of the filters on the target activity itself set these flags."
                    },
                    "providers": {
                        "classes": [
                            {
                                "access": "private",
                                "class": "com.google.android.apps.tachyon.clips.ui.viewclips.ShareClipFileProvider"
                            },
                            {
                                "access": "private",
                                "class": "com.google.android.apps.tachyon.common.applifecycle.MainProcessDetector"
                            },
                            {
                                "access": "public",
                                "class": "com.google.android.apps.tachyon.external.googleguide.GoogleGuideContentProvider"
                            },
                            {
                                "access": "private",
                                "class": "androidx.work.impl.WorkManagerInitializer"
                            },
                            {
                                "access": "private",
                                "class": "androidx.lifecycle.ProcessLifecycleOwnerInitializer"
                            }
                        ],
                        "description": "A content provider manages a shared set of application data. You can store the data in the file system, an SQLite database, on the web, or any other persistent storage location your application can access. Through the content provider, other applications can query or even modify the data (if the content provider allows it). For example, the Android system provides a content provider that manages the user's contact information. As such, any application with the proper permissions can query part of the content provider (such as ContactsContract.Data) to read and write information about a particular person.\r\n\r\nContent providers are also useful for reading and writing data that is private to your application and not shared. For example, the Note Pad sample application uses a content provider to save notes.\r\n\r\nA content provider is implemented as a subclass of ContentProvider and must implement a standard set of APIs that enable other applications to perform transactions. For more information, see the Content Providers developer guide."
                    },
                    "receiver": {
                        "classes": [
                            {
                                "access": "private",
                                "class": "com.google.android.apps.tachyon.call.notification.MissedCallNotificationIntentReceiver"
                            },
                            {
                                "access": "private",
                                "class": "com.google.android.apps.tachyon.call.notification.InCallNotificationIntentReceiver"
                            },
                            {
                                "access": "private",
                                "class": "com.google.android.apps.tachyon.call.notification.CallRetryNotifierReceiver"
                            },
                            {
                                "access": "private",
                                "class": "com.google.android.apps.tachyon.clips.notification.MessagesNotificationIntentReceiver"
                            },
                            {
                                "access": "public",
                                "class": "com.google.android.apps.tachyon.common.applifecycle.AppInstallReceiver"
                            },
                            {
                                "access": "private",
                                "class": "com.google.android.apps.tachyon.common.applifecycle.AppUpdateReceiver"
                            },
                            {
                                "access": "public",
                                "class": "com.google.android.apps.tachyon.common.applifecycle.BootReceiver"
                            },
                            {
                                "access": "public",
                                "class": "com.google.android.apps.tachyon.common.applifecycle.LocaleChangeReceiver"
                            },
                            {
                                "access": "private",
                                "class": "com.google.android.apps.tachyon.groupcalling.incall.InGroupCallNotificationIntentReceiver"
                            },
                            {
                                "access": "private",
                                "class": "com.google.android.apps.tachyon.groupcalling.incoming.IncomingGroupCallIntentReceiver"
                            },
                            {
                                "access": "private",
                                "class": "com.google.android.apps.tachyon.groupcalling.incoming.IncomingGroupCallNotificationIntentReceiver"
                            },
                            {
                                "access": "public",
                                "class": "com.google.android.apps.tachyon.groupcalling.notification.GroupUpdateNotificationReceiver"
                            },
                            {
                                "access": "private",
                                "class": "com.google.android.apps.tachyon.invites.invitehelper.IntentChooserCallbackReceiver"
                            },
                            {
                                "access": "private",
                                "class": "com.google.android.apps.tachyon.net.fcm.CjnNotificationIntentReceiver"
                            },
                            {
                                "access": "private",
                                "class": "com.google.android.apps.tachyon.net.fcm.GenericFcmEventHandlerNotificationIntentReceiver"
                            },
                            {
                                "access": "private",
                                "class": "com.google.android.apps.tachyon.notifications.engagement.EngagementNotificationIntentReceiver"
                            },
                            {
                                "access": "private",
                                "class": "com.google.android.apps.tachyon.notifications.receiver.BasicNotificationIntentReceiver"
                            },
                            {
                                "access": "public",
                                "class": "com.google.android.apps.tachyon.phenotype.PhenotypeBroadcastReceiver"
                            },
                            {
                                "access": "private",
                                "class": "com.google.android.apps.tachyon.ping.notification.PingNotificationIntentReceiver"
                            },
                            {
                                "access": "private",
                                "class": "com.google.android.apps.tachyon.registration.SystemAccountChangedReceiver"
                            },
                            {
                                "access": "private",
                                "class": "com.google.android.apps.tachyon.registration.notification.RegistrationNotificationIntentReceiver"
                            },
                            {
                                "access": "public",
                                "class": "com.google.android.apps.tachyon.simdetection.SimStateBroadcastReceiver"
                            },
                            {
                                "access": "public",
                                "class": "com.google.android.libraries.internal.growth.growthkit.inject.GrowthKitBootCompletedBroadcastReceiver"
                            },
                            {
                                "access": "public",
                                "class": "com.google.android.libraries.internal.growth.growthkit.internal.debug.TestingToolsBroadcastReceiver"
                            },
                            {
                                "access": "public",
                                "class": "com.google.android.libraries.internal.growth.growthkit.internal.experiments.impl.PhenotypeBroadcastReceiver"
                            },
                            {
                                "access": "public",
                                "class": "com.google.android.libraries.phenotype.client.stable.PhenotypeStickyAccount$AccountRemovedBroadcastReceiver"
                            },
                            {
                                "access": "public",
                                "class": "com.google.firebase.iid.FirebaseInstanceIdReceiver"
                            },
                            {
                                "access": "private",
                                "class": "androidx.work.impl.utils.ForceStopRunnable$BroadcastReceiver"
                            },
                            {
                                "access": "private",
                                "class": "androidx.work.impl.background.systemalarm.ConstraintProxy$BatteryChargingProxy"
                            },
                            {
                                "access": "private",
                                "class": "androidx.work.impl.background.systemalarm.ConstraintProxy$BatteryNotLowProxy"
                            },
                            {
                                "access": "private",
                                "class": "androidx.work.impl.background.systemalarm.ConstraintProxy$StorageNotLowProxy"
                            },
                            {
                                "access": "private",
                                "class": "androidx.work.impl.background.systemalarm.ConstraintProxy$NetworkStateProxy"
                            },
                            {
                                "access": "private",
                                "class": "androidx.work.impl.background.systemalarm.RescheduleReceiver"
                            },
                            {
                                "access": "private",
                                "class": "androidx.work.impl.background.systemalarm.ConstraintProxyUpdateReceiver"
                            },
                            {
                                "access": "public",
                                "class": "androidx.work.impl.diagnostics.DiagnosticsReceiver"
                            }
                        ],
                        "description": "A broadcast receiver is a component that responds to system-wide broadcast announcements. Many broadcasts originate from the system for example, a broadcast announcing that the screen has turned off, the battery is low, or a picture was captured. Applications can also initiate broadcasts for example, to let other applications know that some data has been downloaded to the device and is available for them to use. Although broadcast receivers don't display a user interface, they may create a status bar notification to alert the user when a broadcast event occurs. More commonly, though, a broadcast receiver is just a \"gateway\" to other components and is intended to do a very minimal amount of work. For instance, it might initiate a service to perform some work based on the event.\r\n\r\nA broadcast receiver is implemented as a subclass of BroadcastReceiver and each broadcast is delivered as an Intent object. For more information, see the BroadcastReceiver class."
                    },
                    "services": {
                        "classes": [
                            {
                                "access": "private",
                                "class": "com.google.android.apps.tachyon.call.service.CallService"
                            },
                            {
                                "access": "public",
                                "class": "com.google.android.apps.tachyon.clientapi.ClientApiService"
                            },
                            {
                                "access": "public",
                                "class": "com.google.android.apps.tachyon.contacts.reachability.ReachabilityService"
                            },
                            {
                                "access": "public",
                                "class": "com.google.android.apps.tachyon.contacts.sync.SyncService"
                            },
                            {
                                "access": "public",
                                "class": "com.google.android.apps.tachyon.contacts.sync.DuoAccountService"
                            },
                            {
                                "access": "private",
                                "class": "com.google.android.apps.tachyon.net.fcm.CallConnectingForegroundService"
                            },
                            {
                                "access": "private",
                                "class": "com.google.android.apps.tachyon.net.fcm.FcmReceivingService"
                            },
                            {
                                "access": "public",
                                "class": "com.google.android.apps.tachyon.telecom.TelecomFallbackService"
                            },
                            {
                                "access": "public",
                                "class": "com.google.android.apps.tachyon.telecom.TachyonTelecomConnectionService"
                            },
                            {
                                "access": "private",
                                "class": "com.google.firebase.components.ComponentDiscoveryService"
                            },
                            {
                                "access": "private",
                                "class": "com.google.android.libraries.internal.growth.growthkit.internal.jobs.impl.GrowthKitJobService"
                            },
                            {
                                "access": "private",
                                "class": "com.google.android.libraries.internal.growth.growthkit.internal.jobs.impl.GrowthKitBelowLollipopJobService"
                            },
                            {
                                "access": "private",
                                "class": "com.google.apps.tiktok.concurrent.InternalForegroundService"
                            },
                            {
                                "access": "private",
                                "class": "com.google.firebase.messaging.FirebaseMessagingService"
                            },
                            {
                                "access": "private",
                                "class": "androidx.work.impl.background.systemalarm.SystemAlarmService"
                            },
                            {
                                "access": "public",
                                "class": "androidx.work.impl.background.systemjob.SystemJobService"
                            },
                            {
                                "access": "private",
                                "class": "androidx.work.impl.foreground.SystemForegroundService"
                            }
                        ],
                        "description": "A service is a component that runs in the background to perform long-running operations or to perform work for remote processes. A service does not provide a user interface. For example, a service might play music in the background while the user is in a different application, or it might fetch data over the network without blocking user interaction with an activity. Another component, such as an activity, can start the service and let it run or bind to it in order to interact with it.\r\n\r\nA service is implemented as a subclass of Service and you can learn more about it in the Services developer guide."
                    }
                },
                "discovered_emails": [],
                "engine_version": "2.4.17",
                "hardware": {
                    "android-hardware-bluetooth": {
                        "classes": [
                            {
                                "class": "ebr"
                            },
                            {
                                "class": "lmx"
                            },
                            {
                                "class": "eaq"
                            },
                            {
                                "class": "owr"
                            }
                        ],
                        "description": "The application uses Bluetooth radio features in the device."
                    },
                    "android-hardware-camera": {
                        "classes": [
                            {
                                "class": "eeq"
                            },
                            {
                                "class": "sye"
                            },
                            {
                                "class": "ejw"
                            }
                        ],
                        "description": "The application uses the device's camera."
                    },
                    "android-hardware-camera-any": {
                        "classes": [],
                        "description": "The application uses at least one camera facing in any direction. Use this in preference toandroid.hardware.cameraif a back-facing camera is not required."
                    },
                    "android-hardware-camera-autofocus": {
                        "classes": [],
                        "description": "Subfeature. The application uses the device camera's autofocus capability."
                    },
                    "android-hardware-location": {
                        "classes": [
                            {
                                "class": "pw"
                            }
                        ],
                        "description": "The application uses one or more features on the device for determining location"
                    },
                    "android-hardware-microphone": {
                        "classes": [
                            {
                                "class": "eaq"
                            },
                            {
                                "class": "eaf"
                            },
                            {
                                "class": "dvn"
                            }
                        ],
                        "description": "The application uses a microphone on the device."
                    },
                    "android-hardware-screen-landscape": {
                        "classes": [],
                        "description": "The application requires landscape orientation."
                    },
                    "android-hardware-screen-portrait": {
                        "classes": [],
                        "description": "The application requires portrait orientation."
                    },
                    "android-hardware-telephony": {
                        "classes": [],
                        "description": "The application uses telephony features on the device"
                    },
                    "android-hardware-wifi": {
                        "classes": [
                            {
                                "class": "uwb"
                            },
                            {
                                "class": "org.chromium.net.AndroidNetworkLibrary"
                            },
                            {
                                "class": "bun"
                            },
                            {
                                "class": "owr"
                            },
                            {
                                "class": "dov"
                            }
                        ],
                        "description": "The application uses 802.11 networking (wifi) features on the device."
                    }
                },
                "intents": {
                    "android.intent.action.ACTION_POWER_CONNECTED": [
                        {
                            "class": "org.chromium.base.PowerMonitor",
                            "description": "Broadcast Action: External power has been connected to the device."
                        },
                        {
                            "class": "anl",
                            "description": "Broadcast Action: External power has been connected to the device."
                        }
                    ],
                    "android.intent.action.ACTION_POWER_DISCONNECTED": [
                        {
                            "class": "org.chromium.base.PowerMonitor",
                            "description": "Broadcast Action: External power has been removed from the device."
                        },
                        {
                            "class": "anl",
                            "description": "Broadcast Action: External power has been removed from the device."
                        }
                    ],
                    "android.intent.action.APPLICATION_MESSAGE_UPDATE": [
                        {
                            "class": "uqu",
                            "description": "No information available"
                        }
                    ],
                    "android.intent.action.APPLICATION_PREFERENCES": [
                        {
                            "class": "fqo",
                            "description": "No information available"
                        }
                    ],
                    "android.intent.action.BADGE_COUNT_UPDATE": [
                        {
                            "class": "uqp",
                            "description": "No information available"
                        },
                        {
                            "class": "uqk",
                            "description": "No information available"
                        },
                        {
                            "class": "uqj",
                            "description": "No information available"
                        }
                    ],
                    "android.intent.action.BATTERY_CHANGED": [
                        {
                            "class": "owr",
                            "description": "Broadcast Action: This is a sticky broadcast containing the charging state, level, and other information about the battery."
                        },
                        {
                            "class": "eet",
                            "description": "Broadcast Action: This is a sticky broadcast containing the charging state, level, and other information about the battery."
                        },
                        {
                            "class": "org.chromium.base.PowerMonitor",
                            "description": "Broadcast Action: This is a sticky broadcast containing the charging state, level, and other information about the battery."
                        },
                        {
                            "class": "nyh",
                            "description": "Broadcast Action: This is a sticky broadcast containing the charging state, level, and other information about the battery."
                        },
                        {
                            "class": "emw",
                            "description": "Broadcast Action: This is a sticky broadcast containing the charging state, level, and other information about the battery."
                        },
                        {
                            "class": "ceh",
                            "description": "Broadcast Action: This is a sticky broadcast containing the charging state, level, and other information about the battery."
                        },
                        {
                            "class": "anm",
                            "description": "Broadcast Action: This is a sticky broadcast containing the charging state, level, and other information about the battery."
                        },
                        {
                            "class": "anl",
                            "description": "Broadcast Action: This is a sticky broadcast containing the charging state, level, and other information about the battery."
                        }
                    ],
                    "android.intent.action.BATTERY_LOW": [
                        {
                            "class": "eet",
                            "description": "Broadcast Action: Indicates low battery condition on the device."
                        },
                        {
                            "class": "anm",
                            "description": "Broadcast Action: Indicates low battery condition on the device."
                        }
                    ],
                    "android.intent.action.BATTERY_OKAY": [
                        {
                            "class": "eet",
                            "description": "Broadcast Action: Indicates the battery is now okay after being low."
                        },
                        {
                            "class": "anm",
                            "description": "Broadcast Action: Indicates the battery is now okay after being low."
                        }
                    ],
                    "android.intent.action.BOOT_COMPLETED": [
                        {
                            "class": "com.google.android.apps.tachyon.common.applifecycle.BootReceiver",
                            "description": "Broadcast Action: This is broadcast once, after the system has finished booting."
                        }
                    ],
                    "android.intent.action.CLOSE_SYSTEM_DIALOGS": [
                        {
                            "class": "jpu",
                            "description": "No information available"
                        }
                    ],
                    "android.intent.action.DEVICE_STORAGE_LOW": [
                        {
                            "class": "anu",
                            "description": "No information available"
                        }
                    ],
                    "android.intent.action.DEVICE_STORAGE_OK": [
                        {
                            "class": "anu",
                            "description": "No information available"
                        }
                    ],
                    "android.intent.action.HEADSET_PLUG": [
                        {
                            "class": "eaq",
                            "description": "Broadcast Action: Wired Headset plugged in or unplugged."
                        }
                    ],
                    "android.intent.action.INSERT_OR_EDIT": [
                        {
                            "class": "gbc",
                            "description": "No information available"
                        }
                    ],
                    "android.intent.action.MAIN": [
                        {
                            "class": "uqg",
                            "description": "Activity Action: Start as a main entry point, does not expect to receive data."
                        },
                        {
                            "class": "mjm",
                            "description": "Activity Action: Start as a main entry point, does not expect to receive data."
                        },
                        {
                            "class": "com.google.android.apps.tachyon.ui.launcher.LauncherActivity",
                            "description": "Activity Action: Start as a main entry point, does not expect to receive data."
                        },
                        {
                            "class": "com.google.android.apps.tachyon.groupcalling.incall.InGroupCallActivity",
                            "description": "Activity Action: Start as a main entry point, does not expect to receive data."
                        },
                        {
                            "class": "com.google.android.apps.tachyon.call.feedback.BadCallRatingActivity",
                            "description": "Activity Action: Start as a main entry point, does not expect to receive data."
                        }
                    ],
                    "android.intent.action.OPEN_DOCUMENT": [
                        {
                            "class": "fcl",
                            "description": "No information available"
                        }
                    ],
                    "android.intent.action.PACKAGE_ADDED": [
                        {
                            "class": "msh",
                            "description": "Broadcast Action: A new application package has been installed on the device."
                        }
                    ],
                    "android.intent.action.PROCESS_TEXT": [
                        {
                            "class": "nr",
                            "description": "No information available"
                        }
                    ],
                    "android.intent.action.PROXY_CHANGE": [
                        {
                            "class": "org.chromium.net.ProxyChangeListener",
                            "description": "No information available"
                        }
                    ],
                    "android.intent.action.SCREEN_OFF": [
                        {
                            "class": "ldy",
                            "description": "Broadcast Action: Sent after the screen turns off."
                        }
                    ],
                    "android.intent.action.SCREEN_ON": [
                        {
                            "class": "ldy",
                            "description": "Broadcast Action: Sent after the screen turns on."
                        }
                    ],
                    "android.intent.action.SEND": [
                        {
                            "class": "ivm",
                            "description": "Activity Action: Deliver some data to someone else."
                        },
                        {
                            "class": "com.google.android.apps.tachyon.clips.share.ReceiveShareIntentActivity",
                            "description": "Activity Action: Deliver some data to someone else."
                        },
                        {
                            "class": "cmf",
                            "description": "Activity Action: Deliver some data to someone else."
                        },
                        {
                            "class": "fhn",
                            "description": "Activity Action: Deliver some data to someone else."
                        }
                    ],
                    "android.intent.action.SENDTO": [
                        {
                            "class": "ivm",
                            "description": "Activity Action: Send a message to someone specified by the data."
                        },
                        {
                            "class": "fqo",
                            "description": "Activity Action: Send a message to someone specified by the data."
                        }
                    ],
                    "android.intent.action.TIMEZONE_CHANGED": [
                        {
                            "class": "fmz",
                            "description": "Broadcast Action: The timezone has changed."
                        }
                    ],
                    "android.intent.action.USER_PRESENT": [
                        {
                            "class": "com.google.android.apps.tachyon.groupcalling.precall.PrecallScreenGroupActivity",
                            "description": "Broadcast Action: Sent when the user is present after device wakes up (e.g when the keyguard is gone)."
                        }
                    ],
                    "android.intent.action.USER_UNLOCKED": [
                        {
                            "class": "rll",
                            "description": "No information available"
                        }
                    ],
                    "android.intent.action.VIEW": [
                        {
                            "class": "dcu",
                            "description": "Activity Action: Display the data to the user."
                        },
                        {
                            "class": "nih",
                            "description": "Activity Action: Display the data to the user."
                        },
                        {
                            "class": "mim",
                            "description": "Activity Action: Display the data to the user."
                        },
                        {
                            "class": "kpm",
                            "description": "Activity Action: Display the data to the user."
                        },
                        {
                            "class": "com.google.android.play.core.missingsplits.PlayCoreMissingSplitsActivity",
                            "description": "Activity Action: Display the data to the user."
                        },
                        {
                            "class": "com.google.android.apps.tachyon.ui.main.MainActivity",
                            "description": "Activity Action: Display the data to the user."
                        },
                        {
                            "class": "pjz",
                            "description": "Activity Action: Display the data to the user."
                        },
                        {
                            "class": "rrp",
                            "description": "Activity Action: Display the data to the user."
                        },
                        {
                            "class": "fqo",
                            "description": "Activity Action: Display the data to the user."
                        },
                        {
                            "class": "mvm",
                            "description": "Activity Action: Display the data to the user."
                        },
                        {
                            "class": "pnm",
                            "description": "Activity Action: Display the data to the user."
                        },
                        {
                            "class": "fya",
                            "description": "Activity Action: Display the data to the user."
                        },
                        {
                            "class": "abk",
                            "description": "Activity Action: Display the data to the user."
                        }
                    ],
                    "android.intent.category.DEFAULT": [
                        {
                            "class": "mjm",
                            "description": "Set if the activity should be an option for the default action (center press) to perform on a piece of data."
                        },
                        {
                            "class": "mim",
                            "description": "Set if the activity should be an option for the default action (center press) to perform on a piece of data."
                        },
                        {
                            "class": "bxe",
                            "description": "Set if the activity should be an option for the default action (center press) to perform on a piece of data."
                        },
                        {
                            "class": "fqo",
                            "description": "Set if the activity should be an option for the default action (center press) to perform on a piece of data."
                        },
                        {
                            "class": "nom",
                            "description": "Set if the activity should be an option for the default action (center press) to perform on a piece of data."
                        },
                        {
                            "class": "jqh",
                            "description": "Set if the activity should be an option for the default action (center press) to perform on a piece of data."
                        }
                    ],
                    "android.intent.category.HOME": [
                        {
                            "class": "uqg",
                            "description": "This is the home activity, that is the first activity that is displayed when the device boots."
                        },
                        {
                            "class": "com.google.android.apps.tachyon.groupcalling.incall.InGroupCallActivity",
                            "description": "This is the home activity, that is the first activity that is displayed when the device boots."
                        }
                    ],
                    "android.intent.category.OPENABLE": [
                        {
                            "class": "fcl",
                            "description": "Used to indicate that a GET_CONTENT intent only wants URIs that can be opened with ContentResolver.openInputStream."
                        }
                    ],
                    "android.intent.extra.CHOSEN_COMPONENT": [
                        {
                            "class": "com.google.android.apps.tachyon.invites.invitehelper.IntentChooserCallbackReceiver",
                            "description": "No information available"
                        }
                    ],
                    "android.intent.extra.EMAIL": [
                        {
                            "class": "ivm",
                            "description": "A String[] holding e-mail addresses that should be delivered to."
                        }
                    ],
                    "android.intent.extra.LOCAL_ONLY": [
                        {
                            "class": "fcl",
                            "description": "Used to indicate that a ACTION_GET_CONTENT intent should only return data that is on the local device."
                        }
                    ],
                    "android.intent.extra.MIME_TYPES": [
                        {
                            "class": "fcl",
                            "description": "No information available"
                        }
                    ],
                    "android.intent.extra.PROCESS_TEXT_READONLY": [
                        {
                            "class": "nr",
                            "description": "No information available"
                        }
                    ],
                    "android.intent.extra.PROXY_INFO": [
                        {
                            "class": "org.chromium.net.ProxyChangeListener",
                            "description": "No information available"
                        }
                    ],
                    "android.intent.extra.STREAM": [
                        {
                            "class": "com.google.android.apps.tachyon.clips.share.ReceiveShareIntentActivity",
                            "description": "A content: URI holding a stream of data associated with the Intent, used with ACTION_SEND to supply the data being sent."
                        },
                        {
                            "class": "com.google.research.ink.annotate.AnnotateActivity",
                            "description": "A content: URI holding a stream of data associated with the Intent, used with ACTION_SEND to supply the data being sent."
                        },
                        {
                            "class": "fhn",
                            "description": "A content: URI holding a stream of data associated with the Intent, used with ACTION_SEND to supply the data being sent."
                        }
                    ],
                    "android.intent.extra.SUBJECT": [
                        {
                            "class": "ivm",
                            "description": "A constant string holding the desired subject line of a message."
                        },
                        {
                            "class": "fqo",
                            "description": "A constant string holding the desired subject line of a message."
                        }
                    ],
                    "android.intent.extra.TEXT": [
                        {
                            "class": "ivm",
                            "description": "A constant CharSequence that is associated with the Intent, used with ACTION_SEND to supply the literal data to be sent."
                        },
                        {
                            "class": "cmf",
                            "description": "A constant CharSequence that is associated with the Intent, used with ACTION_SEND to supply the literal data to be sent."
                        },
                        {
                            "class": "fqo",
                            "description": "A constant CharSequence that is associated with the Intent, used with ACTION_SEND to supply the literal data to be sent."
                        }
                    ],
                    "android.intent.extra.shortcut.ICON": [
                        {
                            "class": "dka",
                            "description": "No information available"
                        }
                    ],
                    "android.intent.extra.shortcut.ICON_RESOURCE": [
                        {
                            "class": "dka",
                            "description": "No information available"
                        }
                    ],
                    "android.intent.extra.shortcut.ID": [
                        {
                            "class": "com.google.android.apps.tachyon.clips.share.ReceiveShareIntentActivity",
                            "description": "No information available"
                        }
                    ],
                    "android.intent.extra.shortcut.INTENT": [
                        {
                            "class": "dka",
                            "description": "No information available"
                        }
                    ],
                    "android.intent.extra.shortcut.NAME": [
                        {
                            "class": "dka",
                            "description": "No information available"
                        }
                    ],
                    "android.intent.extra.update_application_component_name": [
                        {
                            "class": "uqu",
                            "description": "No information available"
                        }
                    ],
                    "android.intent.extra.update_application_message_text": [
                        {
                            "class": "uqu",
                            "description": "No information available"
                        }
                    ],
                    "com.google.android.c2dm.intent.RECEIVE": [
                        {
                            "class": "com.google.firebase.messaging.FirebaseMessagingService",
                            "description": "No information available"
                        }
                    ],
                    "com.google.android.c2dm.intent.REGISTER": [
                        {
                            "class": "rpo",
                            "description": "No information available"
                        },
                        {
                            "class": "rpv",
                            "description": "No information available"
                        },
                        {
                            "class": "rph",
                            "description": "No information available"
                        }
                    ],
                    "com.google.android.c2dm.intent.REGISTRATION": [
                        {
                            "class": "rpu",
                            "description": "No information available"
                        }
                    ]
                },
                "md5_hash": "f26cf1135f9d2ea60532a5a13c6fbed5",
                "name": "Duo",
                "owasp": [
                    {
                        "description": "M1: Improper Platform Usage",
                        "found": false,
                        "name": "m1",
                        "risks": "No information available."
                    },
                    {
                        "description": "M2: Insecure Data Storage",
                        "found": true,
                        "name": "m2",
                        "risks": [
                            "Content Providers are implicitly insecure. They allow other applications on the device to request and share data. If sensitive information is accidentally leaked in one of these content providers all an attacker needs to do is call the content provider and the sensitive data will be exposed to the attacker by the application.This is cause for concern as any 3rd party application containing malicious code does not require any granted permissions in order to obtain sensitive information from these applications.",
                            "The application stores inline API keys/values."
                        ]
                    },
                    {
                        "description": "M3: Insecure Communications",
                        "found": false,
                        "name": "m3",
                        "risks": "No information available."
                    },
                    {
                        "description": "M4: Insecure Authentication",
                        "found": false,
                        "name": "m4",
                        "risks": "No information available."
                    },
                    {
                        "description": "M5: Insufficient Cryptography",
                        "found": false,
                        "name": "m5",
                        "risks": "No information available."
                    },
                    {
                        "description": "M6: Insecure Authorization",
                        "found": false,
                        "name": "m6",
                        "risks": "No information available."
                    },
                    {
                        "description": "M7: Client Code Quality",
                        "found": false,
                        "name": "m7",
                        "risks": "No information available."
                    },
                    {
                        "description": "M8: Code Tampering",
                        "found": false,
                        "name": "m8",
                        "risks": "No information available."
                    },
                    {
                        "description": "M9: Reverse Engineering",
                        "found": true,
                        "name": "m9",
                        "risks": [
                            "This application fails the Static Data Exposure test as outlined by OWASP Mobile Top 10.",
                            "This application exposes source level metadata symbols and fails the testing outlined by OWASP Mobile Top 10.",
                            "This application fails the Source Code Reverse Engineering Exposure test as outlined by OWASP Mobile Top 10."
                        ]
                    },
                    {
                        "description": "M10: Extraneous Functionality",
                        "found": false,
                        "name": "m10",
                        "risks": "No information available."
                    }
                ],
                "package_name": "com.google.android.apps.tachyon",
                "permissions": {
                    "android.permission.ACCESS_NETWORK_STATE": {
                        "classes": [
                            {
                                "class": "vic"
                            },
                            {
                                "class": "uwb"
                            },
                            {
                                "class": "uvq"
                            },
                            {
                                "class": "pjz"
                            },
                            {
                                "class": "jor"
                            }
                        ],
                        "description": "This permission will allow the application to read the state of the networks the device is connected to."
                    },
                    "android.permission.ACCESS_WIFI_STATE": {
                        "classes": [
                            {
                                "class": "uwb"
                            },
                            {
                                "class": "org.chromium.net.AndroidNetworkLibrary"
                            },
                            {
                                "class": "bun"
                            },
                            {
                                "class": "owr"
                            }
                        ],
                        "description": "This permission will allow the application to obtain all information on all Wi-Fi networks within range. "
                    },
                    "android.permission.AUTHENTICATE_ACCOUNTS": {
                        "classes": [
                            {
                                "class": "gla"
                            }
                        ],
                        "description": "Allows an application to act as an AccountAuthenticator for the AccountManager."
                    },
                    "android.permission.BLUETOOTH": {
                        "classes": [
                            {
                                "class": "lmx"
                            },
                            {
                                "class": "ebr"
                            },
                            {
                                "class": "owr"
                            }
                        ],
                        "description": "his application has the ability to connect to a bluetooth device that is already paired with the device."
                    },
                    "android.permission.BROADCAST_STICKY": {
                        "classes": [
                            "Unused permission"
                        ],
                        "description": "Allows an application to broadcast sticky intents. Sticky intents can make your device run slow or and cause instability by introducing memory leaks."
                    },
                    "android.permission.CAMERA": {
                        "classes": [
                            {
                                "class": "eeq"
                            },
                            {
                                "class": "sye"
                            },
                            {
                                "class": "ejw"
                            }
                        ],
                        "description": "Required to be able to access the camera device."
                    },
                    "android.permission.CHANGE_NETWORK_STATE": {
                        "classes": [
                            "Unused permission"
                        ],
                        "description": "Allows applications to change network connectivity state"
                    },
                    "android.permission.FOREGROUND_SERVICE": {
                        "classes": [
                            "Unused permission"
                        ],
                        "description": "No information available"
                    },
                    "android.permission.GET_ACCOUNTS": {
                        "classes": [
                            {
                                "class": "org.chromium.net.HttpNegotiateAuthenticator"
                            },
                            {
                                "class": "ntp"
                            },
                            {
                                "class": "mne"
                            },
                            {
                                "class": "gla"
                            },
                            {
                                "class": "kdl"
                            }
                        ],
                        "description": "Allows access to the list of accounts in the Accounts Service."
                    },
                    "android.permission.GET_PACKAGE_SIZE": {
                        "classes": [
                            "Unused permission"
                        ],
                        "description": "Allows an application to find out the space used by any package."
                    },
                    "android.permission.INTERNET": {
                        "classes": [
                            {
                                "class": "rsf"
                            },
                            {
                                "class": "uzc"
                            },
                            {
                                "class": "rri"
                            },
                            {
                                "class": "nii"
                            },
                            {
                                "class": "mmm"
                            },
                            {
                                "class": "bbd"
                            },
                            {
                                "class": "arf"
                            },
                            {
                                "class": "uym"
                            }
                        ],
                        "description": "This application can create network sockets and use custom network protocols. The browser and other applications provide means to send data to the internet, so this permission is not required to send data to the internet."
                    },
                    "android.permission.MANAGE_ACCOUNTS": {
                        "classes": [
                            {
                                "class": "gla"
                            }
                        ],
                        "description": "Allows an application to manage the list of accounts in the AccountManager."
                    },
                    "android.permission.MANAGE_OWN_CALLS": {
                        "classes": [
                            "Unused permission"
                        ],
                        "description": "No information available"
                    },
                    "android.permission.MODIFY_AUDIO_SETTINGS": {
                        "classes": [
                            {
                                "class": "ebr"
                            },
                            {
                                "class": "eam"
                            },
                            {
                                "class": "eaf"
                            },
                            {
                                "class": "dvn"
                            },
                            {
                                "class": "eaq"
                            },
                            {
                                "class": "eay"
                            }
                        ],
                        "description": "Allows an application to modify global audio settings."
                    },
                    "android.permission.READ_APP_BADGE": {
                        "classes": [
                            "Unused permission"
                        ],
                        "description": "No information available"
                    },
                    "android.permission.READ_CONTACTS": {
                        "classes": [
                            {
                                "class": "iaz"
                            },
                            {
                                "class": "uqp"
                            },
                            {
                                "class": "org.chromium.base.ContentUriUtils"
                            },
                            {
                                "class": "pdi"
                            },
                            {
                                "class": "noo"
                            },
                            {
                                "class": "myz"
                            },
                            {
                                "class": "jl"
                            },
                            {
                                "class": "hjy"
                            },
                            {
                                "class": "gda"
                            },
                            {
                                "class": "fsg"
                            },
                            {
                                "class": "fsk"
                            },
                            {
                                "class": "fsj"
                            },
                            {
                                "class": "fsa"
                            },
                            {
                                "class": "fsh"
                            },
                            {
                                "class": "fsi"
                            },
                            {
                                "class": "epd"
                            },
                            {
                                "class": "dcu"
                            },
                            {
                                "class": "bic"
                            },
                            {
                                "class": "bgi"
                            },
                            {
                                "class": "bbm"
                            },
                            {
                                "class": "bbl"
                            },
                            {
                                "class": "bbk"
                            },
                            {
                                "class": "ie"
                            },
                            {
                                "class": "hq"
                            },
                            {
                                "class": "ho"
                            },
                            {
                                "class": "hm"
                            },
                            {
                                "class": "frt"
                            },
                            {
                                "class": "hu"
                            },
                            {
                                "class": "bbn"
                            }
                        ],
                        "description": "Allows an application to read the user's contacts data."
                    },
                    "android.permission.READ_PHONE_STATE": {
                        "classes": [
                            "Unused permission"
                        ],
                        "description": "Allows read only access to phone state."
                    },
                    "android.permission.READ_PROFILE": {
                        "classes": [
                            "Unused permission"
                        ],
                        "description": "Allows an application to read the user's personal profile data."
                    },
                    "android.permission.READ_SYNC_STATS": {
                        "classes": [
                            "Unused permission"
                        ],
                        "description": "Allows applications to read the sync stats"
                    },
                    "android.permission.RECEIVE_BOOT_COMPLETED": {
                        "classes": [
                            {
                                "class": "com.google.android.apps.tachyon.common.applifecycle.BootReceiver"
                            },
                            {
                                "class": "com.google.android.libraries.internal.growth.growthkit.inject.GrowthKitBootCompletedBroadcastReceiver"
                            },
                            {
                                "class": "androidx.work.impl.background.systemalarm.RescheduleReceiver"
                            },
                            {
                                "class": "com.google.android.apps.tachyon.TachyonApplication"
                            }
                        ],
                        "description": "Allows an application to receive the ACTION_BOOT_COMPLETED that is broadcast after the system finishes booting."
                    },
                    "android.permission.RECORD_AUDIO": {
                        "classes": [
                            {
                                "class": "eeq"
                            }
                        ],
                        "description": "Allows an application to record audio"
                    },
                    "android.permission.SYSTEM_ALERT_WINDOW": {
                        "classes": [
                            "Unused permission"
                        ],
                        "description": "Allows an application to open windows using the type TYPE_SYSTEM_ALERT"
                    },
                    "android.permission.USE_FULL_SCREEN_INTENT": {
                        "classes": [
                            "Unused permission"
                        ],
                        "description": "No information available"
                    },
                    "android.permission.VIBRATE": {
                        "classes": [
                            {
                                "class": "mqe"
                            },
                            {
                                "class": "ftn"
                            },
                            {
                                "class": "com.google.firebase.messaging.FirebaseMessagingService"
                            },
                            {
                                "class": "aoc"
                            },
                            {
                                "class": "lgo"
                            },
                            {
                                "class": "elv"
                            },
                            {
                                "class": "eme"
                            }
                        ],
                        "description": "Allows access to the vibrator"
                    },
                    "android.permission.WAKE_LOCK": {
                        "classes": [
                            {
                                "class": "rss"
                            },
                            {
                                "class": "rqa"
                            },
                            {
                                "class": "roc"
                            },
                            {
                                "class": "lcq"
                            },
                            {
                                "class": "hzt"
                            },
                            {
                                "class": "fxv"
                            },
                            {
                                "class": "fmh"
                            },
                            {
                                "class": "amu"
                            },
                            {
                                "class": "amq"
                            },
                            {
                                "class": "nnf"
                            },
                            {
                                "class": "fmg"
                            },
                            {
                                "class": "cwi"
                            },
                            {
                                "class": "amp"
                            },
                            {
                                "class": "dov"
                            },
                            {
                                "class": "emc"
                            },
                            {
                                "class": "com.google.android.apps.tachyon.ui.common.views.PlaybackView"
                            },
                            {
                                "class": "ely"
                            },
                            {
                                "class": "elv"
                            },
                            {
                                "class": "elz"
                            },
                            {
                                "class": "com.google.android.setupdesign.view.IllustrationVideoView"
                            },
                            {
                                "class": "com.google.android.apps.tachyon.effects.mediapipecalculators.videoplayercalculator.VideoPlayerCalculator"
                            }
                        ],
                        "description": "Allows using PowerManager WakeLocks to keep processor from sleeping or screen from dimming"
                    },
                    "android.permission.WRITE_CALL_LOG": {
                        "classes": [
                            "Unused permission"
                        ],
                        "description": "This application can modify the device's telephony call log, including data about incoming and outgoing calls. Malicious applications may use this to erase or modify the call log."
                    },
                    "android.permission.WRITE_CONTACTS": {
                        "classes": [
                            {
                                "class": "iaz"
                            },
                            {
                                "class": "uqp"
                            },
                            {
                                "class": "org.chromium.base.ContentUriUtils"
                            },
                            {
                                "class": "pdi"
                            },
                            {
                                "class": "noo"
                            },
                            {
                                "class": "myz"
                            },
                            {
                                "class": "jl"
                            },
                            {
                                "class": "hjy"
                            },
                            {
                                "class": "gda"
                            },
                            {
                                "class": "fsg"
                            },
                            {
                                "class": "fsk"
                            },
                            {
                                "class": "fsj"
                            },
                            {
                                "class": "fsa"
                            },
                            {
                                "class": "fsh"
                            },
                            {
                                "class": "fsi"
                            },
                            {
                                "class": "epd"
                            },
                            {
                                "class": "dcu"
                            },
                            {
                                "class": "bic"
                            },
                            {
                                "class": "bgi"
                            },
                            {
                                "class": "bbm"
                            },
                            {
                                "class": "bbl"
                            },
                            {
                                "class": "bbk"
                            },
                            {
                                "class": "ie"
                            },
                            {
                                "class": "hq"
                            },
                            {
                                "class": "ho"
                            },
                            {
                                "class": "hm"
                            },
                            {
                                "class": "frt"
                            },
                            {
                                "class": "hu"
                            },
                            {
                                "class": "bbn"
                            }
                        ],
                        "description": "Allows an application to write (but not read) the user's contacts data."
                    },
                    "android.permission.WRITE_EXTERNAL_STORAGE": {
                        "classes": [
                            "Unused permission"
                        ],
                        "description": "Allows an application to write to external storage."
                    },
                    "android.permission.WRITE_SYNC_SETTINGS": {
                        "classes": [
                            {
                                "class": "gla"
                            }
                        ],
                        "description": "This application can change how the account data is synced and backed up."
                    },
                    "com.anddoes.launcher.permission.UPDATE_COUNT": {
                        "classes": [
                            "Unused permission"
                        ],
                        "description": "No information available"
                    },
                    "com.android.launcher.permission.INSTALL_SHORTCUT": {
                        "classes": [
                            "Unused permission"
                        ],
                        "description": ""
                    },
                    "com.google.android.apps.tachyon": {
                        "classes": [
                            "Unused permission"
                        ],
                        "description": "No information available"
                    },
                    "com.google.android.c2dm.permission.RECEIVE": {
                        "classes": [
                            "Unused permission"
                        ],
                        "description": ""
                    },
                    "com.google.android.providers.gsf.permission.READ_GSERVICES": {
                        "classes": [
                            "Unused permission"
                        ],
                        "description": "No information available"
                    },
                    "com.htc.launcher.permission.READ_SETTINGS": {
                        "classes": [
                            "Unused permission"
                        ],
                        "description": "No information available"
                    },
                    "com.htc.launcher.permission.UPDATE_SHORTCUT": {
                        "classes": [
                            "Unused permission"
                        ],
                        "description": "No information available"
                    },
                    "com.huawei.android.launcher.permission.CHANGE_BADGE": {
                        "classes": [
                            "Unused permission"
                        ],
                        "description": "No information available"
                    },
                    "com.huawei.android.launcher.permission.READ_SETTINGS": {
                        "classes": [
                            "Unused permission"
                        ],
                        "description": "No information available"
                    },
                    "com.huawei.android.launcher.permission.WRITE_SETTINGS": {
                        "classes": [
                            "Unused permission"
                        ],
                        "description": "No information available"
                    },
                    "com.majeur.launcher.permission.UPDATE_BADGE": {
                        "classes": [
                            "Unused permission"
                        ],
                        "description": "No information available"
                    },
                    "com.oppo.launcher.permission.READ_SETTINGS": {
                        "classes": [
                            "Unused permission"
                        ],
                        "description": "No information available"
                    },
                    "com.oppo.launcher.permission.WRITE_SETTINGS": {
                        "classes": [
                            "Unused permission"
                        ],
                        "description": "No information available"
                    },
                    "com.samsung.android.app.telephonyui.permission.READ_SETTINGS_PROVIDER": {
                        "classes": [
                            "Unused permission"
                        ],
                        "description": "No information available"
                    },
                    "com.samsung.android.app.telephonyui.permission.WRITE_SETTINGS_PROVIDER": {
                        "classes": [
                            "Unused permission"
                        ],
                        "description": "No information available"
                    },
                    "com.samsung.android.aremoji.provider.permission.READ_STICKER_PROVIDER": {
                        "classes": [
                            "Unused permission"
                        ],
                        "description": "No information available"
                    },
                    "com.samsung.android.livestickers.provider.permission.READ_STICKER_PROVIDER": {
                        "classes": [
                            "Unused permission"
                        ],
                        "description": "No information available"
                    },
                    "com.samsung.android.provider.filterprovider.permission.READ_FILTER": {
                        "classes": [
                            "Unused permission"
                        ],
                        "description": "No information available"
                    },
                    "com.samsung.android.provider.stickerprovider.permission.READ_STICKER_PROVIDER": {
                        "classes": [
                            "Unused permission"
                        ],
                        "description": "No information available"
                    },
                    "com.sec.android.provider.badge.permission.READ": {
                        "classes": [
                            "Unused permission"
                        ],
                        "description": "No information available"
                    },
                    "com.sec.android.provider.badge.permission.WRITE": {
                        "classes": [
                            "Unused permission"
                        ],
                        "description": "No information available"
                    },
                    "com.sonyericsson.home.permission.BROADCAST_BADGE": {
                        "classes": [
                            "Unused permission"
                        ],
                        "description": "No information available"
                    },
                    "com.sonymobile.home.permission.PROVIDER_INSERT_BADGE": {
                        "classes": [
                            "Unused permission"
                        ],
                        "description": "No information available"
                    }
                },
                "repacked_list": [
                    {
                        "app_name": "Duo",
                        "md5": "de89fa76c1daa958cace2be48f07631a",
                        "score": "Out",
                        "version": "91.0.314224792.DR91_RC01"
                    }
                ],
                "rules_version": "0f9fb1c0f7b18a456955e0adade6c0c2",
                "scan_timestamp": 1591176714,
                "schemes_list": [
                    "content://com.sec.badge/apps?notify=true",
                    "content://com.google.android.gsf.gservices",
                    "content://com.google.android.gsf.gservices/prefix",
                    "content://com.google.android.gms.chimera/",
                    "content://com.sonymobile.home.resourceprovider/badge",
                    "content://com.android.badge/badge"
                ],
                "sdk_version": 21,
                "sha1_hash": "ad25dd83b32441bea9f618bcd638cf7bbe75345f",
                "sha256_hash": "d57c9fdfffbee7ecfb06b723864484fb1581ee33304edaecb4610ee70de68056",
                "status": "Completed",
                "third_party": [
                    {
                        "desc": null,
                        "name": "DropBox",
                        "reference_url": "https://www.dropbox.com",
                        "type": "Cloud Storage"
                    },
                    {
                        "desc": null,
                        "name": "Joda Time",
                        "reference_url": "http://www.joda.org/joda-time",
                        "type": "Library"
                    },
                    {
                        "desc": null,
                        "name": "Google Play Market",
                        "reference_url": "http://developer.android.com/google/play-services/index.html",
                        "type": "Markets"
                    }
                ],
                "urls": [
                    {
                        "source": [
                            {
                                "class": "uqp"
                            }
                        ],
                        "url": "content://com.sec.badge/apps?notify=true",
                        "url_info": {
                            "has_problem": 0,
                            "mcafee_gti_reputation": {
                                "rep": 15,
                                "ufg": ""
                            },
                            "server": {
                                "BGP_Prefix": "",
                                "allocated_date": "",
                                "as_name": "",
                                "as_number": "",
                                "city": "",
                                "country": "",
                                "ip": "Unavailable",
                                "latitude": "",
                                "longitude": "",
                                "region": ""
                            },
                            "site": {
                                "domain": "sec.badge"
                            },
                            "site_reputation": "No reputation violations discovered",
                            "whois": []
                        }
                    },
                    {
                        "source": [
                            {
                                "class": "noo"
                            }
                        ],
                        "url": "content://com.google.android.gsf.gservices",
                        "url_info": {
                            "has_problem": 0,
                            "mcafee_gti_reputation": {
                                "rep": 15,
                                "ufg": ""
                            },
                            "server": {
                                "BGP_Prefix": "",
                                "allocated_date": "",
                                "as_name": "",
                                "as_number": "",
                                "city": "",
                                "country": "",
                                "ip": "Unavailable",
                                "latitude": "",
                                "longitude": "",
                                "region": ""
                            },
                            "site": {
                                "domain": "gsf.gservices"
                            },
                            "site_reputation": "No reputation violations discovered",
                            "whois": []
                        }
                    },
                    {
                        "source": [
                            {
                                "class": "myz"
                            }
                        ],
                        "url": "content://com.google.android.gms.chimera/",
                        "url_info": {
                            "has_problem": 0,
                            "mcafee_gti_reputation": {
                                "rep": 15,
                                "ufg": ""
                            },
                            "server": {
                                "BGP_Prefix": "",
                                "allocated_date": "",
                                "as_name": "",
                                "as_number": "",
                                "city": "",
                                "country": "",
                                "ip": "Unavailable",
                                "latitude": "",
                                "longitude": "",
                                "region": ""
                            },
                            "site": {
                                "domain": "gms.chimera"
                            },
                            "site_reputation": "No reputation violations discovered",
                            "whois": []
                        }
                    },
                    {
                        "source": [
                            {
                                "class": "ivm"
                            }
                        ],
                        "url": "https://g.co/installduo",
                        "url_info": {
                            "exp_check": 0,
                            "freak_vulnerability": false,
                            "has_problem": 0,
                            "hb": 0,
                            "hb_tm": null,
                            "mcafee_gti_reputation": {
                                "cat": [
                                    107
                                ],
                                "rep": 3,
                                "ufg": 6
                            },
                            "robot": 0,
                            "robot_vulnerability": false,
                            "server": {
                                "BGP_Prefix": "1.1.1.0/24",
                                "allocated_date": "2012-04-16",
                                "as_name": "GOOGLE, US",
                                "as_number": "15169",
                                "city": "",
                                "country": "United States",
                                "ip": "1.1.1.1",
                                "latitude": "37.751",
                                "longitude": "-97.822",
                                "region": ""
                            },
                            "site": {
                                "domain": "g.co"
                            },
                            "site_reputation": "No reputation violations discovered",
                            "valid_chain_of_trust": true,
                            "whois": {
                                "creation": "2000-04-26",
                                "name_server": "ns2.google.com,ns4.google.com,ns3.google.com,ns1.google.com"
                            }
                        }
                    },
                    {
                        "source": [
                            {
                                "class": "pjz"
                            }
                        ],
                        "url": "https://www.google.com/policies/terms/",
                        "url_info": {
                            "exp_check": 0,
                            "freak_vulnerability": false,
                            "has_problem": 0,
                            "hb": 0,
                            "hb_tm": "27 Apr 2020",
                            "mcafee_gti_reputation": {
                                "cat": [
                                    145
                                ],
                                "rep": -97,
                                "ufg": 70
                            },
                            "robot": 0,
                            "robot_vulnerability": false,
                            "server": {
                                "BGP_Prefix": "1.1.1.0/24",
                                "allocated_date": "2012-04-16",
                                "as_name": "GOOGLE, US",
                                "as_number": "15169",
                                "city": "",
                                "country": "United States",
                                "ip": "1.1.1.1",
                                "latitude": "37.751",
                                "longitude": "-97.822",
                                "region": ""
                            },
                            "site": {
                                "domain": "google.com"
                            },
                            "site_reputation": "No reputation violations discovered",
                            "valid_chain_of_trust": true,
                            "whois": []
                        }
                    },
                    {
                        "source": [
                            {
                                "class": "Resource Asset"
                            }
                        ],
                        "url": "https://google.com/search?",
                        "url_info": {
                            "exp_check": 0,
                            "freak_vulnerability": false,
                            "has_problem": 0,
                            "hb": 0,
                            "hb_tm": "27 Apr 2020",
                            "mcafee_gti_reputation": {
                                "cat": [
                                    145
                                ],
                                "rep": "",
                                "ufg": 71
                            },
                            "robot": 0,
                            "robot_vulnerability": false,
                            "server": {
                                "BGP_Prefix": "172.217.2.0/24",
                                "allocated_date": "2012-04-16",
                                "as_name": "GOOGLE, US",
                                "as_number": "15169",
                                "city": "",
                                "country": "United States",
                                "ip": "1.1.1.1",
                                "latitude": "37.751",
                                "longitude": "-97.822",
                                "region": ""
                            },
                            "site": {
                                "domain": "google.com"
                            },
                            "site_reputation": "No reputation violations discovered",
                            "valid_chain_of_trust": true,
                            "whois": []
                        }
                    },
                    {
                        "source": [
                            {
                                "class": "Resource Asset"
                            }
                        ],
                        "url": "https://datashare.is.ed.ac.uk/handle/10283/2791;",
                        "url_info": {
                            "exp_check": 0,
                            "freak_vulnerability": false,
                            "has_problem": 0,
                            "hb": 0,
                            "hb_tm": "29 Apr 2020",
                            "mcafee_gti_reputation": {
                                "cat": [
                                    111
                                ],
                                "rep": "",
                                "ufg": 8
                            },
                            "robot": 0,
                            "robot_vulnerability": false,
                            "server": {
                                "BGP_Prefix": "1.1.1.1/16",
                                "allocated_date": "1988-02-29",
                                "as_name": "JANET Jisc Services Limited, GB",
                                "as_number": "786",
                                "city": "Edinburgh",
                                "country": "United Kingdom",
                                "ip": "129.215.41.53",
                                "latitude": "55.95",
                                "longitude": "-3.2",
                                "region": "Scotland"
                            },
                            "site": {
                                "domain": "ed.ac.uk"
                            },
                            "site_reputation": "No reputation violations discovered",
                            "valid_chain_of_trust": true,
                            "whois": {
                                "creation": "before Aug-1996",
                                "name_server": "ns0.ja.net,ns2.ja.net,ns3.ja.net,ns4.ja.net,auth03.ns.uu.net,ns1.surfnet.nl,ws-fra1.win-ip.dfn.de",
                                "registrant_address": "Didcot Library Avenue, OX11 OSG",
                                "registrant_name": "The JNT Association"
                            }
                        }
                    },
                    {
                        "source": [
                            {
                                "class": "Resource Asset"
                            }
                        ],
                        "url": "https://freesound.org/",
                        "url_info": {
                            "exp_check": 0,
                            "freak_vulnerability": false,
                            "has_problem": 0,
                            "hb": 0,
                            "hb_tm": "08 May 2020",
                            "mcafee_gti_reputation": {
                                "cat": [
                                    140,
                                    159
                                ],
                                "rep": 10,
                                "ufg": 38
                            },
                            "robot": 0,
                            "robot_vulnerability": false,
                            "server": {
                                "BGP_Prefix": "84.89.128.0/17",
                                "allocated_date": "2004-04-02",
                                "as_name": "CESCA-AC, ES",
                                "as_number": "13041",
                                "city": "Barcelona",
                                "country": "Spain",
                                "ip": "84.89.136.5",
                                "latitude": "41.3984",
                                "longitude": "2.1741",
                                "region": "Catalonia"
                            },
                            "site": {
                                "domain": "freesound.org"
                            },
                            "site_reputation": "No reputation violations discovered",
                            "valid_chain_of_trust": true,
                            "whois": {
                                "creation": "2002-12-20",
                                "name_server": "ns-178-b.gandi.net,ns-94-c.gandi.net,ns-124-a.gandi.net"
                            }
                        }
                    },
                    {
                        "source": [
                            {
                                "class": "Resource Asset"
                            }
                        ],
                        "url": "https://creativecommons.org/licenses/by-sa/3.0/deed.en_CA",
                        "url_info": {
                            "exp_check": 0,
                            "freak_vulnerability": false,
                            "has_problem": 0,
                            "hb": 0,
                            "hb_tm": "27 Apr 2020",
                            "mcafee_gti_reputation": {
                                "cat": [
                                    105
                                ],
                                "rep": "",
                                "ufg": 2
                            },
                            "robot": 0,
                            "robot_vulnerability": false,
                            "server": {
                                "BGP_Prefix": "1.1.1.0/20",
                                "allocated_date": "2014-03-28",
                                "as_name": "CLOUDFLARENET, US",
                                "as_number": "13335",
                                "city": "",
                                "country": "United States",
                                "ip": "104.20.151.16",
                                "latitude": "37.751",
                                "longitude": "-97.822",
                                "region": ""
                            },
                            "site": {
                                "domain": "creativecommons.org",
                                "http_server_type": "cloudflare"
                            },
                            "site_reputation": "No reputation violations discovered",
                            "valid_chain_of_trust": true,
                            "whois": {
                                "creation": "2001-01-15",
                                "name_server": "fiona.ns.cloudflare.com,isaac.ns.cloudflare.com",
                                "registrant_organization": "Creative Commons Corporation"
                            }
                        }
                    },
                    {
                        "source": [
                            {
                                "class": "Resource Asset"
                            }
                        ],
                        "url": "http://www.opensource.org/licenses/bsd-license.php",
                        "url_info": {
                            "has_problem": 0,
                            "mcafee_gti_reputation": {
                                "cat": [
                                    107,
                                    133
                                ],
                                "rep": -88,
                                "ufg": 2
                            },
                            "server": {
                                "BGP_Prefix": "1.1.1.0/20",
                                "allocated_date": "2017-10-24",
                                "as_name": "DIGITALOCEAN-ASN, US",
                                "as_number": "14061",
                                "city": "Clifton",
                                "country": "United States",
                                "ip": "159.65.34.8",
                                "latitude": "40.8364",
                                "longitude": "-74.1403",
                                "region": "New Jersey"
                            },
                            "site": {
                                "domain": "opensource.org"
                            },
                            "site_reputation": "No reputation violations discovered",
                            "whois": {
                                "creation": "1998-02-10",
                                "name_server": "ns-17-b.gandi.net,ns-52-a.gandi.net,ns-9-c.gandi.net",
                                "registrant_organization": "Open Source Initiative"
                            }
                        }
                    },
                    {
                        "source": [
                            {
                                "class": "Resource Asset"
                            }
                        ],
                        "url": "https://www.apache.org/licenses/LICENSE-2.0",
                        "url_info": {
                            "exp_check": 0,
                            "freak_vulnerability": false,
                            "has_problem": 0,
                            "hb": 0,
                            "hb_tm": null,
                            "mcafee_gti_reputation": {
                                "cat": [
                                    107
                                ],
                                "rep": -4,
                                "ufg": 8
                            },
                            "robot": 0,
                            "robot_vulnerability": false,
                            "server": {
                                "BGP_Prefix": "1.1.0.0/10",
                                "allocated_date": "2015-02-23",
                                "as_name": "MICROSOFT-CORP-MSN-AS-BLOCK, US",
                                "as_number": "8075",
                                "city": "Boydton",
                                "country": "United States",
                                "ip": "40.79.78.1",
                                "latitude": "36.6534",
                                "longitude": "-78.375",
                                "region": "Virginia"
                            },
                            "site": {
                                "domain": "apache.org",
                                "http_server_type": "Apache/2.4.18 (Ubuntu)"
                            },
                            "site_reputation": "No reputation violations discovered",
                            "valid_chain_of_trust": true,
                            "whois": {
                                "creation": "1995-04-10",
                                "name_server": "ns2.surfnet.nl,ns3.no-ip.com,ns2.no-ip.com,ns1.no-ip.com,ns4.no-ip.com",
                                "registrant_organization": "The Apache Software Foundation"
                            }
                        }
                    },
                    {
                        "source": [
                            {
                                "class": "Resource Asset"
                            }
                        ],
                        "url": "http://www.apache.org/licenses/",
                        "url_info": {
                            "has_problem": 0,
                            "mcafee_gti_reputation": {
                                "cat": [
                                    107
                                ],
                                "rep": -4,
                                "ufg": 8
                            },
                            "server": {
                                "BGP_Prefix": "1.1.0.0/10",
                                "allocated_date": "2015-02-23",
                                "as_name": "MICROSOFT-CORP-MSN-AS-BLOCK, US",
                                "as_number": "8075",
                                "city": "Boydton",
                                "country": "United States",
                                "ip": "40.79.78.1",
                                "latitude": "36.6534",
                                "longitude": "-78.375",
                                "region": "Virginia"
                            },
                            "site": {
                                "domain": "apache.org",
                                "http_server_type": "Apache/2.4.18 (Ubuntu)"
                            },
                            "site_reputation": "No reputation violations discovered",
                            "whois": {
                                "creation": "1995-04-10",
                                "name_server": "ns2.surfnet.nl,ns3.no-ip.com,ns2.no-ip.com,ns1.no-ip.com,ns4.no-ip.com",
                                "registrant_organization": "The Apache Software Foundation"
                            }
                        }
                    },
                    {
                        "source": [
                            {
                                "class": "Resource Asset"
                            }
                        ],
                        "url": "http://code.google.com/p/curve25519-donna/",
                        "url_info": {
                            "has_problem": 0,
                            "mcafee_gti_reputation": {
                                "cat": [
                                    107
                                ],
                                "rep": -3,
                                "ufg": 2
                            },
                            "server": {
                                "BGP_Prefix": "172.217.14.0/24",
                                "allocated_date": "2012-04-16",
                                "as_name": "GOOGLE, US",
                                "as_number": "15169",
                                "city": "",
                                "country": "United States",
                                "ip": "1.1.1.1",
                                "latitude": "37.751",
                                "longitude": "-97.822",
                                "region": ""
                            },
                            "site": {
                                "domain": "google.com"
                            },
                            "site_reputation": "No reputation violations discovered",
                            "whois": []
                        }
                    },
                    {
                        "source": [
                            {
                                "class": "njw"
                            }
                        ],
                        "url": "https://www.googleadservices.com/pagead/conversion/app/deeplink?id_type=adid&sdk_version=%s&rdid=%s&bundleid=%s&retry=%s",
                        "url_info": {
                            "exp_check": 0,
                            "freak_vulnerability": false,
                            "has_problem": 0,
                            "hb": 0,
                            "hb_tm": "07 May 2020",
                            "mcafee_gti_reputation": {
                                "cat": [
                                    154
                                ],
                                "rep": -35,
                                "ufg": ""
                            },
                            "robot": 0,
                            "robot_vulnerability": false,
                            "server": {
                                "BGP_Prefix": "1.1.1.0/24",
                                "allocated_date": "2012-04-16",
                                "as_name": "GOOGLE, US",
                                "as_number": "15169",
                                "city": "",
                                "country": "United States",
                                "ip": "172.217.12.34",
                                "latitude": "37.751",
                                "longitude": "-97.822",
                                "region": ""
                            },
                            "site": {
                                "domain": "googleadservices.com",
                                "http_server_type": "sffe"
                            },
                            "site_reputation": "No reputation violations discovered",
                            "valid_chain_of_trust": true,
                            "whois": {
                                "creation": "2003-06-19",
                                "name_server": "ns1.google.com,ns2.google.com,ns3.google.com,ns4.google.com"
                            }
                        }
                    },
                    {
                        "source": [
                            {
                                "class": "mvm"
                            }
                        ],
                        "url": "https://plus.google.com/",
                        "url_info": {
                            "exp_check": 0,
                            "freak_vulnerability": false,
                            "has_problem": 0,
                            "hb": 0,
                            "hb_tm": "27 Apr 2020",
                            "mcafee_gti_reputation": {
                                "cat": [
                                    127
                                ],
                                "rep": -43,
                                "ufg": 2
                            },
                            "robot": 0,
                            "robot_vulnerability": false,
                            "server": {
                                "BGP_Prefix": "172.217.2.0/24",
                                "allocated_date": "2012-04-16",
                                "as_name": "GOOGLE, US",
                                "as_number": "15169",
                                "city": "",
                                "country": "United States",
                                "ip": "1.1.1.1",
                                "latitude": "37.751",
                                "longitude": "-97.822",
                                "region": ""
                            },
                            "site": {
                                "domain": "google.com"
                            },
                            "site_reputation": "No reputation violations discovered",
                            "valid_chain_of_trust": true,
                            "whois": []
                        }
                    },
                    {
                        "source": [
                            {
                                "class": "Resource Asset"
                            }
                        ],
                        "url": "https://duo.google.com",
                        "url_info": {
                            "exp_check": 0,
                            "freak_vulnerability": false,
                            "has_problem": 0,
                            "hb": 0,
                            "hb_tm": null,
                            "mcafee_gti_reputation": {
                                "cat": [
                                    122,
                                    157
                                ],
                                "rep": 2,
                                "ufg": 8
                            },
                            "robot": 0,
                            "robot_vulnerability": false,
                            "server": {
                                "BGP_Prefix": "1.1.1.0/24",
                                "allocated_date": "2012-04-16",
                                "as_name": "GOOGLE, US",
                                "as_number": "15169",
                                "city": "",
                                "country": "United States",
                                "ip": "1.1.1.1",
                                "latitude": "37.751",
                                "longitude": "-97.822",
                                "region": ""
                            },
                            "site": {
                                "domain": "google.com"
                            },
                            "site_reputation": "No reputation violations discovered",
                            "valid_chain_of_trust": true,
                            "whois": []
                        }
                    },
                    {
                        "source": [
                            {
                                "class": "Resource Asset"
                            }
                        ],
                        "url": "https://www.googleapis.com/auth/supportcontent",
                        "url_info": {
                            "exp_check": 0,
                            "freak_vulnerability": false,
                            "has_problem": 0,
                            "hb": 0,
                            "hb_tm": "27 Apr 2020",
                            "mcafee_gti_reputation": {
                                "cat": [
                                    107
                                ],
                                "rep": -30,
                                "ufg": 98
                            },
                            "robot": 0,
                            "robot_vulnerability": false,
                            "server": {
                                "BGP_Prefix": "1.1.1.0/24",
                                "allocated_date": "2012-04-16",
                                "as_name": "GOOGLE, US",
                                "as_number": "15169",
                                "city": "",
                                "country": "United States",
                                "ip": "172.217.1.138",
                                "latitude": "37.751",
                                "longitude": "-97.822",
                                "region": ""
                            },
                            "site": {
                                "domain": "googleapis.com"
                            },
                            "site_reputation": "No reputation violations discovered",
                            "valid_chain_of_trust": true,
                            "whois": {
                                "creation": "2005-01-25",
                                "name_server": "ns1.google.com,ns2.google.com,ns3.google.com,ns4.google.com"
                            }
                        }
                    },
                    {
                        "source": [
                            {
                                "class": "Resource Asset"
                            }
                        ],
                        "url": "https://www.googleapis.com/auth/tachyon",
                        "url_info": {
                            "exp_check": 0,
                            "freak_vulnerability": false,
                            "has_problem": 0,
                            "hb": 0,
                            "hb_tm": "27 Apr 2020",
                            "mcafee_gti_reputation": {
                                "cat": [
                                    107
                                ],
                                "rep": -30,
                                "ufg": 98
                            },
                            "robot": 0,
                            "robot_vulnerability": false,
                            "server": {
                                "BGP_Prefix": "1.1.1.0/24",
                                "allocated_date": "2012-04-16",
                                "as_name": "GOOGLE, US",
                                "as_number": "15169",
                                "city": "",
                                "country": "United States",
                                "ip": "172.217.1.138",
                                "latitude": "37.751",
                                "longitude": "-97.822",
                                "region": ""
                            },
                            "site": {
                                "domain": "googleapis.com"
                            },
                            "site_reputation": "No reputation violations discovered",
                            "valid_chain_of_trust": true,
                            "whois": {
                                "creation": "2005-01-25",
                                "name_server": "ns1.google.com,ns2.google.com,ns3.google.com,ns4.google.com"
                            }
                        }
                    },
                    {
                        "url": "https://firebase.google.com/support/privacy/init-options.",
                        "url_info": {
                            "exp_check": 0,
                            "freak_vulnerability": false,
                            "has_problem": 0,
                            "hb": 0,
                            "hb_tm": "27 Apr 2020",
                            "mcafee_gti_reputation": {
                                "cat": [
                                    105,
                                    107
                                ],
                                "rep": -80,
                                "ufg": 2
                            },
                            "robot": 0,
                            "robot_vulnerability": false,
                            "server": {
                                "BGP_Prefix": "1.1.1.0/24",
                                "allocated_date": "2012-04-16",
                                "as_name": "GOOGLE, US",
                                "as_number": "15169",
                                "city": "",
                                "country": "United States",
                                "ip": "172.217.1.142",
                                "latitude": "37.751",
                                "longitude": "-97.822",
                                "region": ""
                            },
                            "site": {
                                "domain": "google.com"
                            },
                            "site_reputation": "No reputation violations discovered",
                            "valid_chain_of_trust": true,
                            "whois": []
                        }
                    },
                    {
                        "source": [
                            {
                                "class": "Resource Asset"
                            }
                        ],
                        "url": "https://get.duo.google.com/",
                        "url_info": {
                            "exp_check": 0,
                            "freak_vulnerability": false,
                            "has_problem": 0,
                            "hb": 0,
                            "hb_tm": "29 Apr 2020",
                            "mcafee_gti_reputation": {
                                "cat": [
                                    122,
                                    157
                                ],
                                "rep": 2,
                                "ufg": 8
                            },
                            "robot": 0,
                            "robot_vulnerability": false,
                            "server": {
                                "BGP_Prefix": "1.1.1.0/24",
                                "allocated_date": "2012-04-16",
                                "as_name": "GOOGLE, US",
                                "as_number": "15169",
                                "city": "",
                                "country": "United States",
                                "ip": "1.1.1.1",
                                "latitude": "37.751",
                                "longitude": "-97.822",
                                "region": ""
                            },
                            "site": {
                                "domain": "google.com"
                            },
                            "site_reputation": "No reputation violations discovered",
                            "valid_chain_of_trust": true,
                            "whois": []
                        }
                    },
                    {
                        "source": [
                            {
                                "class": "Resource Asset"
                            }
                        ],
                        "url": "https://g.co/duofree",
                        "url_info": {
                            "exp_check": 0,
                            "freak_vulnerability": false,
                            "has_problem": 0,
                            "hb": 0,
                            "hb_tm": null,
                            "mcafee_gti_reputation": {
                                "cat": [
                                    107
                                ],
                                "rep": 3,
                                "ufg": 6
                            },
                            "robot": 0,
                            "robot_vulnerability": false,
                            "server": {
                                "BGP_Prefix": "1.1.1.0/24",
                                "allocated_date": "2012-04-16",
                                "as_name": "GOOGLE, US",
                                "as_number": "15169",
                                "city": "",
                                "country": "United States",
                                "ip": "1.1.1.1",
                                "latitude": "37.751",
                                "longitude": "-97.822",
                                "region": ""
                            },
                            "site": {
                                "domain": "g.co"
                            },
                            "site_reputation": "No reputation violations discovered",
                            "valid_chain_of_trust": true,
                            "whois": {
                                "creation": "2000-04-26",
                                "name_server": "ns2.google.com,ns4.google.com,ns3.google.com,ns1.google.com"
                            }
                        }
                    },
                    {
                        "source": [
                            {
                                "class": "Resource Asset"
                            }
                        ],
                        "url": "http://schemas.android.com/apk/res-auto",
                        "url_info": {
                            "has_problem": 0,
                            "mcafee_gti_reputation": {
                                "cat": [
                                    107
                                ],
                                "rep": 9,
                                "ufg": ""
                            },
                            "server": {
                                "BGP_Prefix": "",
                                "allocated_date": "",
                                "as_name": "",
                                "as_number": "",
                                "city": "",
                                "country": "",
                                "ip": "Unavailable",
                                "latitude": "",
                                "longitude": "",
                                "region": ""
                            },
                            "site": {
                                "domain": "android.com"
                            },
                            "site_reputation": "No reputation violations discovered",
                            "whois": []
                        }
                    },
                    {
                        "source": [
                            {
                                "class": "Resource Asset"
                            }
                        ],
                        "url": "http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time",
                        "url_info": {
                            "has_problem": 0,
                            "mcafee_gti_reputation": {
                                "cat": [
                                    107,
                                    165
                                ],
                                "rep": "",
                                "ufg": 6
                            },
                            "server": {
                                "BGP_Prefix": "216.58.192.0/22",
                                "allocated_date": "2012-01-27",
                                "as_name": "GOOGLE, US",
                                "as_number": "15169",
                                "city": "Mountain View",
                                "country": "United States",
                                "ip": "216.58.193.142",
                                "latitude": "37.4043",
                                "longitude": "-122.0748",
                                "region": "California"
                            },
                            "site": {
                                "domain": "webrtc.org",
                                "http_server_type": "Google Frontend"
                            },
                            "site_reputation": "No reputation violations discovered",
                            "whois": {
                                "creation": "2010-10-22",
                                "name_server": "ns2.google.com,ns1.google.com,ns3.google.com,ns4.google.com",
                                "registrant_organization": "Google Inc."
                            }
                        }
                    },
                    {
                        "url": "https://creativecommons.org/.",
                        "url_info": {
                            "exp_check": 0,
                            "freak_vulnerability": false,
                            "has_problem": 0,
                            "hb": 0,
                            "hb_tm": "27 Apr 2020",
                            "mcafee_gti_reputation": {
                                "cat": [
                                    105
                                ],
                                "rep": "",
                                "ufg": 2
                            },
                            "robot": 0,
                            "robot_vulnerability": false,
                            "server": {
                                "BGP_Prefix": "1.1.1.0/20",
                                "allocated_date": "2014-03-28",
                                "as_name": "CLOUDFLARENET, US",
                                "as_number": "13335",
                                "city": "",
                                "country": "United States",
                                "ip": "104.20.151.16",
                                "latitude": "37.751",
                                "longitude": "-97.822",
                                "region": ""
                            },
                            "site": {
                                "domain": "creativecommons.org",
                                "http_server_type": "cloudflare"
                            },
                            "site_reputation": "No reputation violations discovered",
                            "valid_chain_of_trust": true,
                            "whois": {
                                "creation": "2001-01-15",
                                "name_server": "fiona.ns.cloudflare.com,isaac.ns.cloudflare.com",
                                "registrant_organization": "Creative Commons Corporation"
                            }
                        }
                    },
                    {
                        "source": [
                            {
                                "class": "Resource Asset"
                            }
                        ],
                        "url": "https://instantmessaging-pa.googleapis.com/upload",
                        "url_info": {
                            "exp_check": 0,
                            "freak_vulnerability": false,
                            "has_problem": 0,
                            "hb": 0,
                            "hb_tm": "18 May 2020",
                            "mcafee_gti_reputation": {
                                "cat": [
                                    107
                                ],
                                "rep": -29,
                                "ufg": 98
                            },
                            "robot": 0,
                            "robot_vulnerability": false,
                            "server": {
                                "BGP_Prefix": "172.217.14.0/24",
                                "allocated_date": "2012-04-16",
                                "as_name": "GOOGLE, US",
                                "as_number": "15169",
                                "city": "",
                                "country": "United States",
                                "ip": "172.217.14.170",
                                "latitude": "37.751",
                                "longitude": "-97.822",
                                "region": ""
                            },
                            "site": {
                                "domain": "googleapis.com"
                            },
                            "site_reputation": "No reputation violations discovered",
                            "valid_chain_of_trust": true,
                            "whois": {
                                "creation": "2005-01-25",
                                "name_server": "ns1.google.com,ns2.google.com,ns3.google.com,ns4.google.com"
                            }
                        }
                    },
                    {
                        "source": [
                            {
                                "class": "Resource Asset"
                            }
                        ],
                        "url": "https://developer.android.com/reference/com/google/android/play/core/install/model/InstallErrorCode#",
                        "url_info": {
                            "exp_check": 0,
                            "freak_vulnerability": false,
                            "has_problem": 0,
                            "hb": 0,
                            "hb_tm": "27 Apr 2020",
                            "mcafee_gti_reputation": {
                                "cat": [
                                    107
                                ],
                                "rep": -3,
                                "ufg": 34
                            },
                            "robot": 0,
                            "robot_vulnerability": false,
                            "server": {
                                "BGP_Prefix": "1.1.1.0/24",
                                "allocated_date": "2012-04-16",
                                "as_name": "GOOGLE, US",
                                "as_number": "15169",
                                "city": "",
                                "country": "United States",
                                "ip": "172.217.1.142",
                                "latitude": "37.751",
                                "longitude": "-97.822",
                                "region": ""
                            },
                            "site": {
                                "domain": "android.com"
                            },
                            "site_reputation": "No reputation violations discovered",
                            "valid_chain_of_trust": true,
                            "whois": []
                        }
                    },
                    {
                        "source": [
                            {
                                "class": "Resource Asset"
                            }
                        ],
                        "url": "https://datashare.is.ed.ac.uk/bitstream/handle/10283/2791/license_text?sequence=11&isAllowed=y",
                        "url_info": {
                            "exp_check": 0,
                            "freak_vulnerability": false,
                            "has_problem": 0,
                            "hb": 0,
                            "hb_tm": "29 Apr 2020",
                            "mcafee_gti_reputation": {
                                "cat": [
                                    111
                                ],
                                "rep": "",
                                "ufg": 8
                            },
                            "robot": 0,
                            "robot_vulnerability": false,
                            "server": {
                                "BGP_Prefix": "1.1.1.1/16",
                                "allocated_date": "1988-02-29",
                                "as_name": "JANET Jisc Services Limited, GB",
                                "as_number": "786",
                                "city": "Edinburgh",
                                "country": "United Kingdom",
                                "ip": "129.215.41.53",
                                "latitude": "55.95",
                                "longitude": "-3.2",
                                "region": "Scotland"
                            },
                            "site": {
                                "domain": "ed.ac.uk"
                            },
                            "site_reputation": "No reputation violations discovered",
                            "valid_chain_of_trust": true,
                            "whois": {
                                "creation": "before Aug-1996",
                                "name_server": "ns0.ja.net,ns2.ja.net,ns3.ja.net,ns4.ja.net,auth03.ns.uu.net,ns1.surfnet.nl,ws-fra1.win-ip.dfn.de",
                                "registrant_address": "Didcot Library Avenue, OX11 OSG",
                                "registrant_name": "The JNT Association"
                            }
                        }
                    },
                    {
                        "source": [
                            {
                                "class": "Resource Asset"
                            }
                        ],
                        "url": "https://sites.google.com/site/gaviotachessengine/Home/endgame-tablebases-1",
                        "url_info": {
                            "exp_check": 0,
                            "freak_vulnerability": false,
                            "has_problem": 0,
                            "hb": 0,
                            "hb_tm": "27 Apr 2020",
                            "mcafee_gti_reputation": {
                                "cat": [
                                    107,
                                    140
                                ],
                                "rep": -91,
                                "ufg": 2
                            },
                            "robot": 0,
                            "robot_vulnerability": false,
                            "server": {
                                "BGP_Prefix": "216.58.192.0/22",
                                "allocated_date": "2012-01-27",
                                "as_name": "GOOGLE, US",
                                "as_number": "15169",
                                "city": "Mountain View",
                                "country": "United States",
                                "ip": "216.58.193.142",
                                "latitude": "37.4043",
                                "longitude": "-122.0748",
                                "region": "California"
                            },
                            "site": {
                                "domain": "google.com"
                            },
                            "site_reputation": "No reputation violations discovered",
                            "valid_chain_of_trust": true,
                            "whois": []
                        }
                    },
                    {
                        "source": [
                            {
                                "class": "Resource Asset"
                            }
                        ],
                        "url": "http://troydhanson.github.com/uthash/",
                        "url_info": {
                            "has_problem": 0,
                            "mcafee_gti_reputation": {
                                "cat": [
                                    107,
                                    165
                                ],
                                "rep": -85,
                                "ufg": 102
                            },
                            "server": {
                                "BGP_Prefix": "1.1.1.1/24",
                                "allocated_date": "2017-04-13",
                                "as_name": "FASTLY, US",
                                "as_number": "54113",
                                "city": "",
                                "country": "United States",
                                "ip": "1.1.1.1",
                                "latitude": "37.751",
                                "longitude": "-97.822",
                                "region": ""
                            },
                            "site": {
                                "domain": "github.com"
                            },
                            "site_reputation": "No reputation violations discovered",
                            "whois": {
                                "creation": "2007-10-09",
                                "name_server": "ns-1283.awsdns-32.org,ns-1707.awsdns-21.co.uk,ns-421.awsdns-52.com,ns-520.awsdns-01.net,ns1.p16.dynect.net,ns2.p16.dynect.net,ns3.p16.dynect.net,ns4.p16.dynect.net"
                            }
                        }
                    },
                    {
                        "source": [
                            {
                                "class": "Resource Asset"
                            }
                        ],
                        "url": "http://www.apache.org/",
                        "url_info": {
                            "has_problem": 0,
                            "mcafee_gti_reputation": {
                                "cat": [
                                    107
                                ],
                                "rep": -4,
                                "ufg": 8
                            },
                            "server": {
                                "BGP_Prefix": "1.1.0.0/10",
                                "allocated_date": "2015-02-23",
                                "as_name": "MICROSOFT-CORP-MSN-AS-BLOCK, US",
                                "as_number": "8075",
                                "city": "Boydton",
                                "country": "United States",
                                "ip": "40.79.78.1",
                                "latitude": "36.6534",
                                "longitude": "-78.375",
                                "region": "Virginia"
                            },
                            "site": {
                                "domain": "apache.org",
                                "http_server_type": "Apache/2.4.18 (Ubuntu)"
                            },
                            "site_reputation": "No reputation violations discovered",
                            "whois": {
                                "creation": "1995-04-10",
                                "name_server": "ns2.surfnet.nl,ns3.no-ip.com,ns2.no-ip.com,ns1.no-ip.com,ns4.no-ip.com",
                                "registrant_organization": "The Apache Software Foundation"
                            }
                        }
                    },
                    {
                        "url": "http://www.unicode.org/copyright.html.",
                        "url_info": {
                            "has_problem": 0,
                            "mcafee_gti_reputation": {
                                "cat": [
                                    107
                                ],
                                "rep": -4,
                                "ufg": 2
                            },
                            "server": {
                                "BGP_Prefix": "216.97.0.0/17",
                                "allocated_date": "2000-08-23",
                                "as_name": "CORESPACE-DAL, US",
                                "as_number": "54489",
                                "city": "Dallas",
                                "country": "United States",
                                "ip": "216.97.88.9",
                                "latitude": "32.8137",
                                "longitude": "-96.8704",
                                "region": "Texas"
                            },
                            "site": {
                                "domain": "unicode.org",
                                "http_server_type": "Apache"
                            },
                            "site_reputation": "No reputation violations discovered",
                            "whois": {
                                "creation": "1992-07-23",
                                "name_server": "a.ns.apple.com,b.ns.apple.com,c.ns.apple.com,d.ns.apple.com",
                                "registrant_organization": "Unicode, Inc."
                            }
                        }
                    },
                    {
                        "source": [
                            {
                                "class": "Resource Asset"
                            }
                        ],
                        "url": "http://lao-dictionary.googlecode.com/git/Lao-Dictionary-LICENSE.txt",
                        "url_info": {
                            "has_problem": 0,
                            "mcafee_gti_reputation": {
                                "cat": [
                                    107
                                ],
                                "rep": "",
                                "ufg": 4
                            },
                            "server": {
                                "BGP_Prefix": "1.1.1.1/24",
                                "allocated_date": "2013-04-04",
                                "as_name": "GOOGLE, US",
                                "as_number": "15169",
                                "city": "",
                                "country": "United States",
                                "ip": "1.1.1.1",
                                "latitude": "37.751",
                                "longitude": "-97.822",
                                "region": ""
                            },
                            "site": {
                                "domain": "googlecode.com"
                            },
                            "site_reputation": "No reputation violations discovered",
                            "whois": {
                                "creation": "2005-03-08",
                                "name_server": "ns1.google.com,ns2.google.com,ns3.google.com,ns4.google.com"
                            }
                        }
                    },
                    {
                        "source": [
                            {
                                "class": "Resource Asset"
                            }
                        ],
                        "url": "http://opensource.org/licenses/isc-license.txt",
                        "url_info": {
                            "has_problem": 0,
                            "mcafee_gti_reputation": {
                                "cat": [
                                    107,
                                    133
                                ],
                                "rep": -88,
                                "ufg": 2
                            },
                            "server": {
                                "BGP_Prefix": "1.1.1.0/20",
                                "allocated_date": "2017-10-24",
                                "as_name": "DIGITALOCEAN-ASN, US",
                                "as_number": "14061",
                                "city": "Clifton",
                                "country": "United States",
                                "ip": "159.65.34.8",
                                "latitude": "40.8364",
                                "longitude": "-74.1403",
                                "region": "New Jersey"
                            },
                            "site": {
                                "domain": "opensource.org"
                            },
                            "site_reputation": "No reputation violations discovered",
                            "whois": {
                                "creation": "1998-02-10",
                                "name_server": "ns-17-b.gandi.net,ns-52-a.gandi.net,ns-9-c.gandi.net",
                                "registrant_organization": "Open Source Initiative"
                            }
                        }
                    },
                    {
                        "url": "http://www.sei.cmu.edu/legal/ip/index.cfm.",
                        "url_info": {
                            "has_problem": 0,
                            "mcafee_gti_reputation": {
                                "cat": [
                                    111
                                ],
                                "rep": 1,
                                "ufg": 38
                            },
                            "server": {
                                "BGP_Prefix": "1.1.0.0/16",
                                "allocated_date": "1987-05-06",
                                "as_name": "CMU-ROUTER, US",
                                "as_number": "9",
                                "city": "Pittsburgh",
                                "country": "United States",
                                "ip": "1.1.1.1",
                                "latitude": "40.4442",
                                "longitude": "-79.9557",
                                "region": "Pennsylvania"
                            },
                            "site": {
                                "domain": "cmu.edu"
                            },
                            "site_reputation": "No reputation violations discovered",
                            "whois": {
                                "creation": "1985-04-24",
                                "name_server": "ny-server-03.net.cmu.edu,nsauth1.net.cmu.edu,nsauth2.net.cmu.edu",
                                "registrant_address": " Pittsburgh, PA 15213, US",
                                "registrant_name": "Cyert Hall 216"
                            }
                        }
                    },
                    {
                        "source": [
                            {
                                "class": "Resource Asset"
                            }
                        ],
                        "url": "http://www.mozilla.org/MPL/2.0/",
                        "url_info": {
                            "has_problem": 0,
                            "mcafee_gti_reputation": {
                                "cat": [
                                    107
                                ],
                                "rep": -49,
                                "ufg": 3
                            },
                            "server": {
                                "BGP_Prefix": "104.16.128.0/20",
                                "allocated_date": "2014-03-28",
                                "as_name": "CLOUDFLARENET, US",
                                "as_number": "13335",
                                "city": "",
                                "country": "United States",
                                "ip": "104.16.143.228",
                                "latitude": "37.751",
                                "longitude": "-97.822",
                                "region": ""
                            },
                            "site": {
                                "domain": "mozilla.org"
                            },
                            "site_reputation": "No reputation violations discovered",
                            "whois": {
                                "creation": "1998-01-23",
                                "name_server": "ns5-65.akam.net,ns7-66.akam.net,ns4-64.akam.net,ns1-240.akam.net",
                                "registrant_organization": "Mozilla Corporation"
                            }
                        }
                    },
                    {
                        "source": [
                            {
                                "class": "Resource Asset"
                            }
                        ],
                        "url": "https://sourceforge.net/project/?group_id=1519",
                        "url_info": {
                            "exp_check": 0,
                            "freak_vulnerability": false,
                            "has_problem": 0,
                            "hb": 0,
                            "hb_tm": "27 Apr 2020",
                            "mcafee_gti_reputation": {
                                "cat": [
                                    107,
                                    148
                                ],
                                "rep": -87,
                                "ufg": 66
                            },
                            "robot": 0,
                            "robot_vulnerability": false,
                            "server": {
                                "BGP_Prefix": "216.105.38.0/24",
                                "allocated_date": "2000-07-14",
                                "as_name": "AIS-WEST, US",
                                "as_number": "6130",
                                "city": "Winchester",
                                "country": "United States",
                                "ip": "216.105.38.13",
                                "latitude": "33.6243",
                                "longitude": "-117.0885",
                                "region": "California"
                            },
                            "site": {
                                "domain": "sourceforge.net"
                            },
                            "site_reputation": "No reputation violations discovered",
                            "valid_chain_of_trust": true,
                            "whois": []
                        }
                    },
                    {
                        "source": [
                            {
                                "class": "Resource Asset"
                            }
                        ],
                        "url": "http://casper.beckman.uiuc.edu/~c-tsai4",
                        "url_info": {
                            "has_problem": 0,
                            "mcafee_gti_reputation": {
                                "cat": [
                                    111
                                ],
                                "rep": "",
                                "ufg": 6
                            },
                            "server": {
                                "BGP_Prefix": "",
                                "allocated_date": "",
                                "as_name": "",
                                "as_number": "",
                                "city": "",
                                "country": "",
                                "ip": "Unavailable",
                                "latitude": "",
                                "longitude": "",
                                "region": ""
                            },
                            "site": {
                                "domain": "uiuc.edu"
                            },
                            "site_reputation": "No reputation violations discovered",
                            "whois": {
                                "creation": "1985-07-18",
                                "name_server": "dns1.illinois.edu,dns2.illinois.edu,dns3.illinois.edu"
                            }
                        }
                    },
                    {
                        "source": [
                            {
                                "class": "Resource Asset"
                            }
                        ],
                        "url": "https://jquery.org/",
                        "url_info": {
                            "exp_check": 0,
                            "freak_vulnerability": false,
                            "has_problem": 0,
                            "hb": 0,
                            "hb_tm": "27 Apr 2020",
                            "mcafee_gti_reputation": {
                                "cat": [
                                    107
                                ],
                                "rep": -4,
                                "ufg": 2
                            },
                            "robot": 0,
                            "robot_vulnerability": false,
                            "server": {
                                "BGP_Prefix": "104.16.16.0/20",
                                "allocated_date": "2014-03-28",
                                "as_name": "CLOUDFLARENET, US",
                                "as_number": "13335",
                                "city": "",
                                "country": "United States",
                                "ip": "1.1.1.1",
                                "latitude": "37.751",
                                "longitude": "-97.822",
                                "region": ""
                            },
                            "site": {
                                "domain": "jquery.org"
                            },
                            "site_reputation": "No reputation violations discovered",
                            "valid_chain_of_trust": true,
                            "whois": {
                                "creation": "2006-09-01",
                                "name_server": "lara.ns.cloudflare.com,george.ns.cloudflare.com",
                                "registrant_organization": "Data Protected"
                            }
                        }
                    },
                    {
                        "source": [
                            {
                                "class": "Resource Asset"
                            }
                        ],
                        "url": "http://creativecommons.org/publicdomain/zero/1.0/",
                        "url_info": {
                            "has_problem": 0,
                            "mcafee_gti_reputation": {
                                "cat": [
                                    105
                                ],
                                "rep": "",
                                "ufg": 2
                            },
                            "server": {
                                "BGP_Prefix": "1.1.1.0/20",
                                "allocated_date": "2014-03-28",
                                "as_name": "CLOUDFLARENET, US",
                                "as_number": "13335",
                                "city": "",
                                "country": "United States",
                                "ip": "104.20.151.16",
                                "latitude": "37.751",
                                "longitude": "-97.822",
                                "region": ""
                            },
                            "site": {
                                "domain": "creativecommons.org",
                                "http_server_type": "cloudflare"
                            },
                            "site_reputation": "No reputation violations discovered",
                            "whois": {
                                "creation": "2001-01-15",
                                "name_server": "fiona.ns.cloudflare.com,isaac.ns.cloudflare.com",
                                "registrant_organization": "Creative Commons Corporation"
                            }
                        }
                    },
                    {
                        "url": "http://www.unicode.org/cldr/data/.",
                        "url_info": {
                            "has_problem": 0,
                            "mcafee_gti_reputation": {
                                "cat": [
                                    107
                                ],
                                "rep": -4,
                                "ufg": 2
                            },
                            "server": {
                                "BGP_Prefix": "216.97.0.0/17",
                                "allocated_date": "2000-08-23",
                                "as_name": "CORESPACE-DAL, US",
                                "as_number": "54489",
                                "city": "Dallas",
                                "country": "United States",
                                "ip": "216.97.88.9",
                                "latitude": "32.8137",
                                "longitude": "-96.8704",
                                "region": "Texas"
                            },
                            "site": {
                                "domain": "unicode.org",
                                "http_server_type": "Apache"
                            },
                            "site_reputation": "No reputation violations discovered",
                            "whois": {
                                "creation": "1992-07-23",
                                "name_server": "a.ns.apple.com,b.ns.apple.com,c.ns.apple.com,d.ns.apple.com",
                                "registrant_organization": "Unicode, Inc."
                            }
                        }
                    },
                    {
                        "source": [
                            {
                                "class": "Resource Asset"
                            }
                        ],
                        "url": "https://www.google.com/intl/%s/policies/terms/regional.html",
                        "url_info": {
                            "exp_check": 0,
                            "freak_vulnerability": false,
                            "has_problem": 0,
                            "hb": 0,
                            "hb_tm": "27 Apr 2020",
                            "mcafee_gti_reputation": {
                                "cat": [
                                    145
                                ],
                                "rep": -97,
                                "ufg": 70
                            },
                            "robot": 0,
                            "robot_vulnerability": false,
                            "server": {
                                "BGP_Prefix": "1.1.1.0/24",
                                "allocated_date": "2012-04-16",
                                "as_name": "GOOGLE, US",
                                "as_number": "15169",
                                "city": "",
                                "country": "United States",
                                "ip": "1.1.1.1",
                                "latitude": "37.751",
                                "longitude": "-97.822",
                                "region": ""
                            },
                            "site": {
                                "domain": "google.com"
                            },
                            "site_reputation": "No reputation violations discovered",
                            "valid_chain_of_trust": true,
                            "whois": []
                        }
                    },
                    {
                        "source": [
                            {
                                "class": "Resource Asset"
                            }
                        ],
                        "url": "http://www.apache.org/licenses/LICENSE-2.0",
                        "url_info": {
                            "has_problem": 0,
                            "mcafee_gti_reputation": {
                                "cat": [
                                    107
                                ],
                                "rep": -4,
                                "ufg": 8
                            },
                            "server": {
                                "BGP_Prefix": "1.1.0.0/10",
                                "allocated_date": "2015-02-23",
                                "as_name": "MICROSOFT-CORP-MSN-AS-BLOCK, US",
                                "as_number": "8075",
                                "city": "Boydton",
                                "country": "United States",
                                "ip": "40.79.78.1",
                                "latitude": "36.6534",
                                "longitude": "-78.375",
                                "region": "Virginia"
                            },
                            "site": {
                                "domain": "apache.org",
                                "http_server_type": "Apache/2.4.18 (Ubuntu)"
                            },
                            "site_reputation": "No reputation violations discovered",
                            "whois": {
                                "creation": "1995-04-10",
                                "name_server": "ns2.surfnet.nl,ns3.no-ip.com,ns2.no-ip.com,ns1.no-ip.com,ns4.no-ip.com",
                                "registrant_organization": "The Apache Software Foundation"
                            }
                        }
                    },
                    {
                        "source": [
                            {
                                "class": "Resource Asset"
                            }
                        ],
                        "url": "http://www.test.com/2009/01/25/energy-conservation-in-games/",
                        "url_info": {
                            "has_problem": 0,
                            "mcafee_gti_reputation": {
                                "cat": [
                                    107,
                                    165
                                ],
                                "rep": "",
                                "ufg": 8
                            },
                            "server": {
                                "BGP_Prefix": "1.1.1.1/20",
                                "allocated_date": "2008-07-30",
                                "as_name": "DREAMHOST-AS, US",
                                "as_number": "26347",
                                "city": "Brea",
                                "country": "United States",
                                "ip": "75.119.204.188",
                                "latitude": "33.9339",
                                "longitude": "-117.8854",
                                "region": "California"
                            },
                            "site": {
                                "domain": "test.com",
                                "http_server_type": "Apache"
                            },
                            "site_reputation": "No reputation violations discovered",
                            "whois": {
                                "creation": "2008-05-16",
                                "name_server": "ns1.dreamhost.com,ns2.dreamhost.com,ns3.dreamhost.com",
                                "registrant_address": "92821 Brea, US",
                                "registrant_email": "test.com@proxy.dreamhost.com",
                                "registrant_name": "Proxy Protection LLC",
                                "registrant_organization": "Proxy Protection LLC"
                            }
                        }
                    },
                    {
                        "source": [
                            {
                                "class": "Resource Asset"
                            }
                        ],
                        "url": "http://scripts.sil.org/OFL",
                        "url_info": {
                            "has_problem": 0,
                            "mcafee_gti_reputation": {
                                "cat": [
                                    107
                                ],
                                "rep": "",
                                "ufg": 2
                            },
                            "server": {
                                "BGP_Prefix": "3.208.0.0/12",
                                "allocated_date": "2018-06-25",
                                "as_name": "AMAZON-AES, US",
                                "as_number": "14618",
                                "city": "Ashburn",
                                "country": "United States",
                                "ip": "1.1.1.1",
                                "latitude": "39.0481",
                                "longitude": "-77.4728",
                                "region": "Virginia"
                            },
                            "site": {
                                "domain": "sil.org",
                                "http_server_type": "nginx"
                            },
                            "site_reputation": "No reputation violations discovered",
                            "whois": {
                                "creation": "1991-04-14",
                                "name_server": "nsj1.wsfo.org,nsc1.wsfo.org,nsd1.wsfo.org",
                                "registrant_organization": "Summer Institute of Linguistics"
                            }
                        }
                    },
                    {
                        "source": [
                            {
                                "class": "Resource Asset"
                            }
                        ],
                        "url": "http://www.codingstandard.com/section/conditions-of-use/",
                        "url_info": {
                            "has_problem": 0,
                            "mcafee_gti_reputation": {
                                "cat": [
                                    107
                                ],
                                "rep": "",
                                "ufg": 8
                            },
                            "server": {
                                "BGP_Prefix": "146.20.0.0/16",
                                "allocated_date": "2015-09-17",
                                "as_name": "RACKSPACE, US",
                                "as_number": "27357",
                                "city": "San Antonio",
                                "country": "United States",
                                "ip": "146.20.53.189",
                                "latitude": "29.4963",
                                "longitude": "-98.4004",
                                "region": "Texas"
                            },
                            "site": {
                                "domain": "codingstandard.com"
                            },
                            "site_reputation": "No reputation violations discovered",
                            "whois": null
                        }
                    },
                    {
                        "source": [
                            {
                                "class": "Resource Asset"
                            }
                        ],
                        "url": "content://com.android.badge/badge",
                        "url_info": {
                            "has_problem": 0,
                            "mcafee_gti_reputation": {
                                "rep": 15,
                                "ufg": ""
                            },
                            "server": {
                                "BGP_Prefix": "",
                                "allocated_date": "",
                                "as_name": "",
                                "as_number": "",
                                "city": "",
                                "country": "",
                                "ip": "Unavailable",
                                "latitude": "",
                                "longitude": "",
                                "region": ""
                            },
                            "site": {
                                "domain": "android.badge"
                            },
                            "site_reputation": "No reputation violations discovered",
                            "whois": []
                        }
                    },
                    {
                        "source": [
                            {
                                "class": "Resource Asset"
                            }
                        ],
                        "url": "https://crbug.com/581399",
                        "url_info": {
                            "exp_check": 0,
                            "freak_vulnerability": false,
                            "has_problem": 0,
                            "hb": 0,
                            "hb_tm": "27 Apr 2020",
                            "mcafee_gti_reputation": {
                                "cat": [
                                    107
                                ],
                                "rep": -3,
                                "ufg": 6
                            },
                            "robot": 0,
                            "robot_vulnerability": false,
                            "server": {
                                "BGP_Prefix": "1.1.1.0/24",
                                "allocated_date": "2000-11-22",
                                "as_name": "GOOGLE, US",
                                "as_number": "15169",
                                "city": "Bellevue",
                                "country": "United States",
                                "ip": "216.239.32.29",
                                "latitude": "41.1156",
                                "longitude": "-95.9375",
                                "region": "Nebraska"
                            },
                            "site": {
                                "domain": "crbug.com"
                            },
                            "site_reputation": "No reputation violations discovered",
                            "valid_chain_of_trust": true,
                            "whois": {
                                "creation": "2008-09-15",
                                "name_server": "ns1.googledomains.com,ns2.googledomains.com,ns3.googledomains.com,ns4.googledomains.com"
                            }
                        }
                    },
                    {
                        "source": [
                            {
                                "class": "Resource Asset"
                            }
                        ],
                        "url": "https://g.co/callduo",
                        "url_info": {
                            "exp_check": 0,
                            "freak_vulnerability": false,
                            "has_problem": 0,
                            "hb": 0,
                            "hb_tm": null,
                            "mcafee_gti_reputation": {
                                "cat": [
                                    107
                                ],
                                "rep": 3,
                                "ufg": 6
                            },
                            "robot": 0,
                            "robot_vulnerability": false,
                            "server": {
                                "BGP_Prefix": "1.1.1.0/24",
                                "allocated_date": "2012-04-16",
                                "as_name": "GOOGLE, US",
                                "as_number": "15169",
                                "city": "",
                                "country": "United States",
                                "ip": "1.1.1.1",
                                "latitude": "37.751",
                                "longitude": "-97.822",
                                "region": ""
                            },
                            "site": {
                                "domain": "g.co"
                            },
                            "site_reputation": "No reputation violations discovered",
                            "valid_chain_of_trust": true,
                            "whois": {
                                "creation": "2000-04-26",
                                "name_server": "ns2.google.com,ns4.google.com,ns3.google.com,ns1.google.com"
                            }
                        }
                    },
                    {
                        "source": [
                            {
                                "class": "Resource Asset"
                            }
                        ],
                        "url": "https://storage.googleapis.com/expressive_camera_storage/",
                        "url_info": {
                            "exp_check": 0,
                            "freak_vulnerability": false,
                            "has_problem": 0,
                            "hb": 0,
                            "hb_tm": null,
                            "mcafee_gti_reputation": {
                                "cat": [
                                    107
                                ],
                                "rep": -89,
                                "ufg": 2
                            },
                            "robot": 0,
                            "robot_vulnerability": false,
                            "server": {
                                "BGP_Prefix": "216.58.192.0/22",
                                "allocated_date": "2012-01-27",
                                "as_name": "GOOGLE, US",
                                "as_number": "15169",
                                "city": "Bluffdale",
                                "country": "United States",
                                "ip": "216.58.194.144",
                                "latitude": "40.4953",
                                "longitude": "-111.9439",
                                "region": "Utah"
                            },
                            "site": {
                                "domain": "googleapis.com"
                            },
                            "site_reputation": "No reputation violations discovered",
                            "valid_chain_of_trust": true,
                            "whois": {
                                "creation": "2005-01-25",
                                "name_server": "ns1.google.com,ns2.google.com,ns3.google.com,ns4.google.com"
                            }
                        }
                    },
                    {
                        "source": [
                            {
                                "class": "Resource Asset"
                            }
                        ],
                        "url": "http://www.webrtc.org/experiments/rtp-hdrext/video-timing",
                        "url_info": {
                            "has_problem": 0,
                            "mcafee_gti_reputation": {
                                "cat": [
                                    107,
                                    165
                                ],
                                "rep": "",
                                "ufg": 6
                            },
                            "server": {
                                "BGP_Prefix": "216.58.192.0/22",
                                "allocated_date": "2012-01-27",
                                "as_name": "GOOGLE, US",
                                "as_number": "15169",
                                "city": "Mountain View",
                                "country": "United States",
                                "ip": "216.58.193.142",
                                "latitude": "37.4043",
                                "longitude": "-122.0748",
                                "region": "California"
                            },
                            "site": {
                                "domain": "webrtc.org",
                                "http_server_type": "Google Frontend"
                            },
                            "site_reputation": "No reputation violations discovered",
                            "whois": {
                                "creation": "2010-10-22",
                                "name_server": "ns2.google.com,ns1.google.com,ns3.google.com,ns4.google.com",
                                "registrant_organization": "Google Inc."
                            }
                        }
                    },
                    {
                        "source": [
                            {
                                "class": "Resource Asset"
                            }
                        ],
                        "url": "https://www.gstatic.com/smart_messaging/expressivecamera/%s",
                        "url_info": {
                            "exp_check": 0,
                            "freak_vulnerability": false,
                            "has_problem": 0,
                            "hb": 0,
                            "hb_tm": "27 Apr 2020",
                            "mcafee_gti_reputation": {
                                "cat": [
                                    107
                                ],
                                "rep": 3,
                                "ufg": ""
                            },
                            "robot": 0,
                            "robot_vulnerability": false,
                            "server": {
                                "BGP_Prefix": "216.58.192.0/22",
                                "allocated_date": "2012-01-27",
                                "as_name": "GOOGLE, US",
                                "as_number": "15169",
                                "city": "Mountain View",
                                "country": "United States",
                                "ip": "216.58.193.131",
                                "latitude": "37.4043",
                                "longitude": "-122.0748",
                                "region": "California"
                            },
                            "site": {
                                "domain": "gstatic.com"
                            },
                            "site_reputation": "No reputation violations discovered",
                            "valid_chain_of_trust": true,
                            "whois": {
                                "creation": "2008-02-11",
                                "name_server": "ns1.google.com,ns2.google.com,ns3.google.com,ns4.google.com"
                            }
                        }
                    },
                    {
                        "source": [
                            {
                                "class": "Resource Asset"
                            }
                        ],
                        "url": "http://opendatacommons.org/licenses/odbl/1.0/",
                        "url_info": {
                            "has_problem": 0,
                            "mcafee_gti_reputation": {
                                "cat": [
                                    105
                                ],
                                "rep": "",
                                "ufg": 2
                            },
                            "server": {
                                "BGP_Prefix": "104.26.0.0/20",
                                "allocated_date": "2014-03-28",
                                "as_name": "CLOUDFLARENET, US",
                                "as_number": "13335",
                                "city": "",
                                "country": "United States",
                                "ip": "104.26.9.111",
                                "latitude": "37.751",
                                "longitude": "-97.822",
                                "region": ""
                            },
                            "site": {
                                "domain": "opendatacommons.org"
                            },
                            "site_reputation": "No reputation violations discovered",
                            "whois": {
                                "creation": "2006-11-07",
                                "name_server": "dana.ns.cloudflare.com,carl.ns.cloudflare.com",
                                "registrant_organization": "Open Knowledge Foundation"
                            }
                        }
                    },
                    {
                        "source": [
                            {
                                "class": "noo"
                            }
                        ],
                        "url": "content://com.google.android.gsf.gservices/prefix",
                        "url_info": {
                            "has_problem": 0,
                            "mcafee_gti_reputation": {
                                "rep": 15,
                                "ufg": ""
                            },
                            "server": {
                                "BGP_Prefix": "",
                                "allocated_date": "",
                                "as_name": "",
                                "as_number": "",
                                "city": "",
                                "country": "",
                                "ip": "Unavailable",
                                "latitude": "",
                                "longitude": "",
                                "region": ""
                            },
                            "site": {
                                "domain": "gsf.gservices"
                            },
                            "site_reputation": "No reputation violations discovered",
                            "whois": []
                        }
                    },
                    {
                        "source": [
                            {
                                "class": "mim"
                            }
                        ],
                        "url": "https://support.google.com/%s",
                        "url_info": {
                            "exp_check": 0,
                            "freak_vulnerability": false,
                            "has_problem": 0,
                            "hb": 0,
                            "hb_tm": "17 May 2020",
                            "mcafee_gti_reputation": {
                                "cat": [
                                    107
                                ],
                                "rep": -43,
                                "ufg": 66
                            },
                            "robot": 0,
                            "robot_vulnerability": false,
                            "server": {
                                "BGP_Prefix": "216.58.192.0/22",
                                "allocated_date": "2012-01-27",
                                "as_name": "GOOGLE, US",
                                "as_number": "15169",
                                "city": "Mountain View",
                                "country": "United States",
                                "ip": "1.1.1.1",
                                "latitude": "37.3861",
                                "longitude": "-122.0839",
                                "region": "California"
                            },
                            "site": {
                                "domain": "google.com"
                            },
                            "site_reputation": "No reputation violations discovered",
                            "valid_chain_of_trust": true,
                            "whois": []
                        }
                    },
                    {
                        "source": [
                            {
                                "class": "com.google.android.apps.tachyon.ui.main.MainActivity"
                            }
                        ],
                        "url": "http://tachyon.apps.android.google.com/bots/bacon3",
                        "url_info": {
                            "has_problem": 0,
                            "mcafee_gti_reputation": {
                                "cat": [
                                    145
                                ],
                                "rep": "",
                                "ufg": 70
                            },
                            "server": {
                                "BGP_Prefix": "",
                                "allocated_date": "",
                                "as_name": "",
                                "as_number": "",
                                "city": "",
                                "country": "",
                                "ip": "Unavailable",
                                "latitude": "",
                                "longitude": "",
                                "region": ""
                            },
                            "site": {
                                "domain": "google.com"
                            },
                            "site_reputation": "No reputation violations discovered",
                            "whois": []
                        }
                    },
                    {
                        "source": [
                            {
                                "class": "uqr"
                            }
                        ],
                        "url": "content://com.sonymobile.home.resourceprovider/badge",
                        "url_info": {
                            "has_problem": 0,
                            "mcafee_gti_reputation": {
                                "rep": 15,
                                "ufg": ""
                            },
                            "server": {
                                "BGP_Prefix": "",
                                "allocated_date": "",
                                "as_name": "",
                                "as_number": "",
                                "city": "",
                                "country": "",
                                "ip": "Unavailable",
                                "latitude": "",
                                "longitude": "",
                                "region": ""
                            },
                            "site": {
                                "domain": "home.resourceprovider"
                            },
                            "site_reputation": "No reputation violations discovered",
                            "whois": []
                        }
                    },
                    {
                        "source": [
                            {
                                "class": "Resource Asset"
                            }
                        ],
                        "url": "https://github.com/grpc/grpc-java/issues/5015",
                        "url_info": {
                            "exp_check": 0,
                            "freak_vulnerability": false,
                            "has_problem": 0,
                            "hb": 0,
                            "hb_tm": "19 May 2020",
                            "mcafee_gti_reputation": {
                                "cat": [
                                    107,
                                    165
                                ],
                                "rep": -85,
                                "ufg": 103
                            },
                            "robot": 0,
                            "robot_vulnerability": false,
                            "server": {
                                "BGP_Prefix": "140.82.114.0/24",
                                "allocated_date": "2018-04-25",
                                "as_name": "GITHUB, US",
                                "as_number": "36459",
                                "city": "",
                                "country": "United States",
                                "ip": "140.82.114.3",
                                "latitude": "37.751",
                                "longitude": "-97.822",
                                "region": ""
                            },
                            "site": {
                                "domain": "github.com"
                            },
                            "site_reputation": "No reputation violations discovered",
                            "valid_chain_of_trust": true,
                            "whois": {
                                "creation": "2007-10-09",
                                "name_server": "ns-1283.awsdns-32.org,ns-1707.awsdns-21.co.uk,ns-421.awsdns-52.com,ns-520.awsdns-01.net,ns1.p16.dynect.net,ns2.p16.dynect.net,ns3.p16.dynect.net,ns4.p16.dynect.net"
                            }
                        }
                    },
                    {
                        "source": [
                            {
                                "class": "Resource Asset"
                            }
                        ],
                        "url": "https://app-measurement.com/a",
                        "url_info": {
                            "exp_check": 0,
                            "freak_vulnerability": false,
                            "has_problem": 0,
                            "hb": 0,
                            "hb_tm": "18 May 2020",
                            "mcafee_gti_reputation": {
                                "cat": [
                                    107
                                ],
                                "rep": "",
                                "ufg": 8
                            },
                            "robot": 0,
                            "robot_vulnerability": false,
                            "server": {
                                "BGP_Prefix": "216.58.192.0/22",
                                "allocated_date": "2012-01-27",
                                "as_name": "GOOGLE, US",
                                "as_number": "15169",
                                "city": "Mountain View",
                                "country": "United States",
                                "ip": "216.58.194.110",
                                "latitude": "37.3861",
                                "longitude": "-122.0839",
                                "region": "California"
                            },
                            "site": {
                                "domain": "app-measurement.com",
                                "http_server_type": "sffe"
                            },
                            "site_reputation": "No reputation violations discovered",
                            "valid_chain_of_trust": true,
                            "whois": []
                        }
                    },
                    {
                        "source": [
                            {
                                "class": "Resource Asset"
                            }
                        ],
                        "url": "https://duo.google.com/joingroup",
                        "url_info": {
                            "exp_check": 0,
                            "freak_vulnerability": false,
                            "has_problem": 0,
                            "hb": 0,
                            "hb_tm": null,
                            "mcafee_gti_reputation": {
                                "cat": [
                                    122,
                                    157
                                ],
                                "rep": 2,
                                "ufg": 8
                            },
                            "robot": 0,
                            "robot_vulnerability": false,
                            "server": {
                                "BGP_Prefix": "1.1.1.0/24",
                                "allocated_date": "2012-04-16",
                                "as_name": "GOOGLE, US",
                                "as_number": "15169",
                                "city": "",
                                "country": "United States",
                                "ip": "1.1.1.1",
                                "latitude": "37.751",
                                "longitude": "-97.822",
                                "region": ""
                            },
                            "site": {
                                "domain": "google.com"
                            },
                            "site_reputation": "No reputation violations discovered",
                            "valid_chain_of_trust": true,
                            "whois": []
                        }
                    },
                    {
                        "source": [
                            {
                                "class": "Resource Asset"
                            }
                        ],
                        "url": "https://duo.google.com/invite?token=",
                        "url_info": {
                            "exp_check": 0,
                            "freak_vulnerability": false,
                            "has_problem": 0,
                            "hb": 0,
                            "hb_tm": null,
                            "mcafee_gti_reputation": {
                                "cat": [
                                    122,
                                    157
                                ],
                                "rep": 2,
                                "ufg": 8
                            },
                            "robot": 0,
                            "robot_vulnerability": false,
                            "server": {
                                "BGP_Prefix": "1.1.1.0/24",
                                "allocated_date": "2012-04-16",
                                "as_name": "GOOGLE, US",
                                "as_number": "15169",
                                "city": "",
                                "country": "United States",
                                "ip": "1.1.1.1",
                                "latitude": "37.751",
                                "longitude": "-97.822",
                                "region": ""
                            },
                            "site": {
                                "domain": "google.com"
                            },
                            "site_reputation": "No reputation violations discovered",
                            "valid_chain_of_trust": true,
                            "whois": []
                        }
                    },
                    {
                        "source": [
                            {
                                "class": "Resource Asset"
                            }
                        ],
                        "url": "https://storage.googleapis.com/expressive_camera_authoring_renderable_effects/effect_configs/%s",
                        "url_info": {
                            "exp_check": 0,
                            "freak_vulnerability": false,
                            "has_problem": 0,
                            "hb": 0,
                            "hb_tm": null,
                            "mcafee_gti_reputation": {
                                "cat": [
                                    107
                                ],
                                "rep": -89,
                                "ufg": 2
                            },
                            "robot": 0,
                            "robot_vulnerability": false,
                            "server": {
                                "BGP_Prefix": "216.58.192.0/22",
                                "allocated_date": "2012-01-27",
                                "as_name": "GOOGLE, US",
                                "as_number": "15169",
                                "city": "Bluffdale",
                                "country": "United States",
                                "ip": "216.58.194.144",
                                "latitude": "40.4953",
                                "longitude": "-111.9439",
                                "region": "Utah"
                            },
                            "site": {
                                "domain": "googleapis.com"
                            },
                            "site_reputation": "No reputation violations discovered",
                            "valid_chain_of_trust": true,
                            "whois": {
                                "creation": "2005-01-25",
                                "name_server": "ns1.google.com,ns2.google.com,ns3.google.com,ns4.google.com"
                            }
                        }
                    },
                    {
                        "source": [
                            {
                                "class": "Resource Asset"
                            }
                        ],
                        "url": "http://schemas.android.com/aapt",
                        "url_info": {
                            "has_problem": 0,
                            "mcafee_gti_reputation": {
                                "cat": [
                                    107
                                ],
                                "rep": 9,
                                "ufg": ""
                            },
                            "server": {
                                "BGP_Prefix": "",
                                "allocated_date": "",
                                "as_name": "",
                                "as_number": "",
                                "city": "",
                                "country": "",
                                "ip": "Unavailable",
                                "latitude": "",
                                "longitude": "",
                                "region": ""
                            },
                            "site": {
                                "domain": "android.com"
                            },
                            "site_reputation": "No reputation violations discovered",
                            "whois": []
                        }
                    },
                    {
                        "url": "http://mozilla.org/MPL/2.0/.",
                        "url_info": {
                            "has_problem": 0,
                            "mcafee_gti_reputation": {
                                "cat": [
                                    107
                                ],
                                "rep": -49,
                                "ufg": 3
                            },
                            "server": {
                                "BGP_Prefix": "1.1.1.1/23",
                                "allocated_date": "2006-06-16",
                                "as_name": "MOZILLA-MDC1, US",
                                "as_number": "36856",
                                "city": "Sacramento",
                                "country": "United States",
                                "ip": "1.1.1.1",
                                "latitude": "38.6415",
                                "longitude": "-121.5114",
                                "region": "California"
                            },
                            "site": {
                                "domain": "mozilla.org"
                            },
                            "site_reputation": "No reputation violations discovered",
                            "whois": {
                                "creation": "1998-01-23",
                                "name_server": "ns5-65.akam.net,ns7-66.akam.net,ns4-64.akam.net,ns1-240.akam.net",
                                "registrant_organization": "Mozilla Corporation"
                            }
                        }
                    },
                    {
                        "source": [
                            {
                                "class": "Resource Asset"
                            }
                        ],
                        "url": "http://www.opensource.org/licenses/mit-license.php",
                        "url_info": {
                            "has_problem": 0,
                            "mcafee_gti_reputation": {
                                "cat": [
                                    107,
                                    133
                                ],
                                "rep": -88,
                                "ufg": 2
                            },
                            "server": {
                                "BGP_Prefix": "1.1.1.0/20",
                                "allocated_date": "2017-10-24",
                                "as_name": "DIGITALOCEAN-ASN, US",
                                "as_number": "14061",
                                "city": "Clifton",
                                "country": "United States",
                                "ip": "159.65.34.8",
                                "latitude": "40.8364",
                                "longitude": "-74.1403",
                                "region": "New Jersey"
                            },
                            "site": {
                                "domain": "opensource.org"
                            },
                            "site_reputation": "No reputation violations discovered",
                            "whois": {
                                "creation": "1998-02-10",
                                "name_server": "ns-17-b.gandi.net,ns-52-a.gandi.net,ns-9-c.gandi.net",
                                "registrant_organization": "Open Source Initiative"
                            }
                        }
                    },
                    {
                        "url": "https://goo.gl/NAOOOI.",
                        "url_info": {
                            "eff_url": "https://goo.gl",
                            "exp_check": 0,
                            "freak_vulnerability": false,
                            "has_problem": 0,
                            "hb": 0,
                            "hb_tm": "15 May 2020",
                            "mcafee_gti_reputation": {
                                "cat": [
                                    107
                                ],
                                "rep": -79,
                                "ufg": 6
                            },
                            "robot": 0,
                            "robot_vulnerability": false,
                            "server": {
                                "BGP_Prefix": "1.1.1.1/24",
                                "allocated_date": "2012-04-16",
                                "as_name": "GOOGLE, US",
                                "as_number": "15169",
                                "city": "",
                                "country": "United States",
                                "ip": "172.217.6.142",
                                "latitude": "37.751",
                                "longitude": "-97.822",
                                "region": ""
                            },
                            "short_url": 1,
                            "site": {
                                "domain": "goo.gl"
                            },
                            "site_reputation": "No reputation violations discovered",
                            "valid_chain_of_trust": true,
                            "whois": {
                                "name_server": "ns3.google.com,ns2.google.com,ns4.google.com,ns1.google.com"
                            }
                        }
                    },
                    {
                        "source": [
                            {
                                "class": "Resource Asset"
                            }
                        ],
                        "url": "http://www.gutenberg.org/ebooks/53",
                        "url_info": {
                            "has_problem": 0,
                            "mcafee_gti_reputation": {
                                "cat": [
                                    111
                                ],
                                "rep": "",
                                "ufg": 38
                            },
                            "server": {
                                "BGP_Prefix": "1.1.0.0/16",
                                "allocated_date": "1994-08-08",
                                "as_name": "UNC-CH, US",
                                "as_number": "36850",
                                "city": "Chapel Hill",
                                "country": "United States",
                                "ip": "1.1.1.1",
                                "latitude": "36.0541",
                                "longitude": "-79.1055",
                                "region": "North Carolina"
                            },
                            "site": {
                                "domain": "gutenberg.org",
                                "http_server_type": "Apache"
                            },
                            "site_reputation": "No reputation violations discovered",
                            "whois": {
                                "creation": "1996-11-30",
                                "name_server": "ns2.unc.edu,ns.unc.edu",
                                "registrant_organization": "Greg Newby"
                            }
                        }
                    },
                    {
                        "source": [
                            {
                                "class": "Resource Asset"
                            }
                        ],
                        "url": "http://cr.yp.to/ecdh.html",
                        "url_info": {
                            "has_problem": 0,
                            "mcafee_gti_reputation": {
                                "cat": [
                                    107
                                ],
                                "rep": "",
                                "ufg": 6
                            },
                            "server": {
                                "BGP_Prefix": "1.1.0.0/16",
                                "allocated_date": "1989-01-04",
                                "as_name": "UIC-AS, US",
                                "as_number": "6200",
                                "city": "Chicago",
                                "country": "United States",
                                "ip": "1.1.1.1",
                                "latitude": "41.8783",
                                "longitude": "-87.6907",
                                "region": "Illinois"
                            },
                            "site": {
                                "domain": "yp.to",
                                "http_server_type": "publicfile"
                            },
                            "site_reputation": "No reputation violations discovered",
                            "whois": {
                                "name_server": "uz5jmyqz3gz2bhnuzg0rr0cml9u8pntyhn2jhtqn04yt3sm5h235c1.yp.to"
                            }
                        }
                    },
                    {
                        "source": [
                            {
                                "class": "Resource Asset"
                            }
                        ],
                        "url": "http://www.openssl.org/",
                        "url_info": {
                            "has_problem": 0,
                            "mcafee_gti_reputation": {
                                "cat": [
                                    107
                                ],
                                "rep": -4,
                                "ufg": 2
                            },
                            "server": {
                                "BGP_Prefix": "1.1.1.1/20",
                                "allocated_date": "2011-05-16",
                                "as_name": "AKAMAI-AS, US",
                                "as_number": "16625",
                                "city": "",
                                "country": "United States",
                                "ip": "23.67.210.113",
                                "latitude": "37.751",
                                "longitude": "-97.822",
                                "region": ""
                            },
                            "site": {
                                "domain": "openssl.org",
                                "http_server_type": "Apache/2.4.29 (Ubuntu)"
                            },
                            "site_reputation": "No reputation violations discovered",
                            "whois": []
                        }
                    },
                    {
                        "source": [
                            {
                                "class": "Resource Asset"
                            }
                        ],
                        "url": "http://code.google.com/p/y2038",
                        "url_info": {
                            "has_problem": 0,
                            "mcafee_gti_reputation": {
                                "cat": [
                                    107
                                ],
                                "rep": -3,
                                "ufg": 2
                            },
                            "server": {
                                "BGP_Prefix": "172.217.14.0/24",
                                "allocated_date": "2012-04-16",
                                "as_name": "GOOGLE, US",
                                "as_number": "15169",
                                "city": "",
                                "country": "United States",
                                "ip": "1.1.1.1",
                                "latitude": "37.751",
                                "longitude": "-97.822",
                                "region": ""
                            },
                            "site": {
                                "domain": "google.com"
                            },
                            "site_reputation": "No reputation violations discovered",
                            "whois": []
                        }
                    },
                    {
                        "source": [
                            {
                                "class": "Resource Asset"
                            }
                        ],
                        "url": "https://nuxi.nl/",
                        "url_info": {
                            "exp_check": 0,
                            "freak_vulnerability": false,
                            "has_problem": 0,
                            "hb": 0,
                            "hb_tm": "03 Jun 2020",
                            "mcafee_gti_reputation": {
                                "cat": [
                                    107
                                ],
                                "rep": -4,
                                "ufg": 8
                            },
                            "robot": 0,
                            "robot_vulnerability": false,
                            "server": {
                                "BGP_Prefix": "144.76.0.0/16",
                                "allocated_date": "1990-11-16",
                                "as_name": "HETZNER-AS, DE",
                                "as_number": "24940",
                                "city": "",
                                "country": "Germany",
                                "ip": "1.1.1.1",
                                "latitude": "51.2993",
                                "longitude": "9.491",
                                "region": ""
                            },
                            "site": {
                                "domain": "nuxi.nl"
                            },
                            "site_reputation": "No reputation violations discovered",
                            "valid_chain_of_trust": true,
                            "whois": {
                                "name_server": "ns0.transip.net,ns1.transip.nl,ns2.transip.eu"
                            }
                        }
                    },
                    {
                        "source": [
                            {
                                "class": "Resource Asset"
                            }
                        ],
                        "url": "http://www.unicode.org/Public/,",
                        "url_info": {
                            "has_problem": 0,
                            "mcafee_gti_reputation": {
                                "cat": [
                                    107
                                ],
                                "rep": -4,
                                "ufg": 2
                            },
                            "server": {
                                "BGP_Prefix": "216.97.0.0/17",
                                "allocated_date": "2000-08-23",
                                "as_name": "CORESPACE-DAL, US",
                                "as_number": "54489",
                                "city": "Dallas",
                                "country": "United States",
                                "ip": "216.97.88.9",
                                "latitude": "32.8137",
                                "longitude": "-96.8704",
                                "region": "Texas"
                            },
                            "site": {
                                "domain": "unicode.org",
                                "http_server_type": "Apache"
                            },
                            "site_reputation": "No reputation violations discovered",
                            "whois": {
                                "creation": "1992-07-23",
                                "name_server": "a.ns.apple.com,b.ns.apple.com,c.ns.apple.com,d.ns.apple.com",
                                "registrant_organization": "Unicode, Inc."
                            }
                        }
                    },
                    {
                        "source": [
                            {
                                "class": "Resource Asset"
                            }
                        ],
                        "url": "http://www.unicode.org/reports/,",
                        "url_info": {
                            "has_problem": 0,
                            "mcafee_gti_reputation": {
                                "cat": [
                                    107
                                ],
                                "rep": -4,
                                "ufg": 2
                            },
                            "server": {
                                "BGP_Prefix": "216.97.0.0/17",
                                "allocated_date": "2000-08-23",
                                "as_name": "CORESPACE-DAL, US",
                                "as_number": "54489",
                                "city": "Dallas",
                                "country": "United States",
                                "ip": "216.97.88.9",
                                "latitude": "32.8137",
                                "longitude": "-96.8704",
                                "region": "Texas"
                            },
                            "site": {
                                "domain": "unicode.org",
                                "http_server_type": "Apache"
                            },
                            "site_reputation": "No reputation violations discovered",
                            "whois": {
                                "creation": "1992-07-23",
                                "name_server": "a.ns.apple.com,b.ns.apple.com,c.ns.apple.com,d.ns.apple.com",
                                "registrant_organization": "Unicode, Inc."
                            }
                        }
                    },
                    {
                        "source": [
                            {
                                "class": "Resource Asset"
                            }
                        ],
                        "url": "http://www.unicode.org/cldr/data/",
                        "url_info": {
                            "has_problem": 0,
                            "mcafee_gti_reputation": {
                                "cat": [
                                    107
                                ],
                                "rep": -4,
                                "ufg": 2
                            },
                            "server": {
                                "BGP_Prefix": "216.97.0.0/17",
                                "allocated_date": "2000-08-23",
                                "as_name": "CORESPACE-DAL, US",
                                "as_number": "54489",
                                "city": "Dallas",
                                "country": "United States",
                                "ip": "216.97.88.9",
                                "latitude": "32.8137",
                                "longitude": "-96.8704",
                                "region": "Texas"
                            },
                            "site": {
                                "domain": "unicode.org",
                                "http_server_type": "Apache"
                            },
                            "site_reputation": "No reputation violations discovered",
                            "whois": {
                                "creation": "1992-07-23",
                                "name_server": "a.ns.apple.com,b.ns.apple.com,c.ns.apple.com,d.ns.apple.com",
                                "registrant_organization": "Unicode, Inc."
                            }
                        }
                    },
                    {
                        "url": "https://www.unicode.org/copyright.html.",
                        "url_info": {
                            "exp_check": 0,
                            "freak_vulnerability": false,
                            "has_problem": 0,
                            "hb": 0,
                            "hb_tm": null,
                            "mcafee_gti_reputation": {
                                "cat": [
                                    107
                                ],
                                "rep": -4,
                                "ufg": 2
                            },
                            "robot": 0,
                            "robot_vulnerability": false,
                            "server": {
                                "BGP_Prefix": "216.97.0.0/17",
                                "allocated_date": "2000-08-23",
                                "as_name": "CORESPACE-DAL, US",
                                "as_number": "54489",
                                "city": "Dallas",
                                "country": "United States",
                                "ip": "216.97.88.9",
                                "latitude": "32.8137",
                                "longitude": "-96.8704",
                                "region": "Texas"
                            },
                            "site": {
                                "domain": "unicode.org",
                                "http_server_type": "Apache"
                            },
                            "site_reputation": "No reputation violations discovered",
                            "valid_chain_of_trust": true,
                            "whois": {
                                "creation": "1992-07-23",
                                "name_server": "a.ns.apple.com,b.ns.apple.com,c.ns.apple.com,d.ns.apple.com",
                                "registrant_organization": "Unicode, Inc."
                            }
                        }
                    },
                    {
                        "source": [
                            {
                                "class": "Resource Asset"
                            }
                        ],
                        "url": "http://chasen.aist-nara.ac.jp/chasen/distribution.html",
                        "url_info": {
                            "has_problem": 0,
                            "mcafee_gti_reputation": {
                                "cat": [
                                    111
                                ],
                                "rep": "",
                                "ufg": 6
                            },
                            "server": {
                                "BGP_Prefix": "163.221.0.0/16",
                                "allocated_date": "1993-03-26",
                                "as_name": "WIDE-BB WIDE Project, JP",
                                "as_number": "2500",
                                "city": "Nara",
                                "country": "Japan",
                                "ip": "1.1.1.1",
                                "latitude": "34.6863",
                                "longitude": "135.8166",
                                "region": "Nara"
                            },
                            "site": {
                                "domain": "ac.jp"
                            },
                            "site_reputation": "No reputation violations discovered",
                            "whois": {
                                "creation": "2017-04-01",
                                "name_server": "ns1.sedoparking.com,ns2.sedoparking.com",
                                "registrant_email": "whoisproxy@value-domain.com",
                                "registrant_name": "Whois Privacy Protection Service by VALUE-DOMAIN",
                                "registrant_organization": "sm-ac.jp"
                            }
                        }
                    },
                    {
                        "source": [
                            {
                                "class": "Resource Asset"
                            }
                        ],
                        "url": "https://creativecommons.org/publicdomain/zero/1.0/",
                        "url_info": {
                            "exp_check": 0,
                            "freak_vulnerability": false,
                            "has_problem": 0,
                            "hb": 0,
                            "hb_tm": "27 Apr 2020",
                            "mcafee_gti_reputation": {
                                "cat": [
                                    105
                                ],
                                "rep": "",
                                "ufg": 2
                            },
                            "robot": 0,
                            "robot_vulnerability": false,
                            "server": {
                                "BGP_Prefix": "1.1.1.0/20",
                                "allocated_date": "2014-03-28",
                                "as_name": "CLOUDFLARENET, US",
                                "as_number": "13335",
                                "city": "",
                                "country": "United States",
                                "ip": "104.20.151.16",
                                "latitude": "37.751",
                                "longitude": "-97.822",
                                "region": ""
                            },
                            "site": {
                                "domain": "creativecommons.org",
                                "http_server_type": "cloudflare"
                            },
                            "site_reputation": "No reputation violations discovered",
                            "valid_chain_of_trust": true,
                            "whois": {
                                "creation": "2001-01-15",
                                "name_server": "fiona.ns.cloudflare.com,isaac.ns.cloudflare.com",
                                "registrant_organization": "Creative Commons Corporation"
                            }
                        }
                    },
                    {
                        "source": [
                            {
                                "class": "Resource Asset"
                            }
                        ],
                        "url": "https://datatracker.ietf.org/ipr/1914/",
                        "url_info": {
                            "exp_check": 0,
                            "freak_vulnerability": false,
                            "has_problem": 0,
                            "hb": 0,
                            "hb_tm": "27 Apr 2020",
                            "mcafee_gti_reputation": {
                                "cat": [
                                    105,
                                    107
                                ],
                                "rep": "",
                                "ufg": 38
                            },
                            "robot": 0,
                            "robot_vulnerability": false,
                            "server": {
                                "BGP_Prefix": "4.0.0.0/9",
                                "allocated_date": "1992-12-01",
                                "as_name": "LEVEL3, US",
                                "as_number": "3356",
                                "city": "Santa Clara",
                                "country": "United States",
                                "ip": "1.1.1.1",
                                "latitude": "37.3931",
                                "longitude": "-121.962",
                                "region": "California"
                            },
                            "site": {
                                "domain": "ietf.org",
                                "http_server_type": "Apache"
                            },
                            "site_reputation": "No reputation violations discovered",
                            "valid_chain_of_trust": true,
                            "whois": {
                                "creation": "1995-03-10",
                                "name_server": "ns0.amsl.com,ns1.ams1.afilias-nst.info,ns1.mia1.afilias-nst.info,ns1.sea1.afilias-nst.info,ns1.yyz1.afilias-nst.info,ns1.hkg1.afilias-nst.info",
                                "registrant_organization": "IETF Trust"
                            }
                        }
                    },
                    {
                        "source": [
                            {
                                "class": "nhm"
                            }
                        ],
                        "url": "https://firebase.google.com/support/guides/disable-analytics",
                        "url_info": {
                            "exp_check": 0,
                            "freak_vulnerability": false,
                            "has_problem": 0,
                            "hb": 0,
                            "hb_tm": "27 Apr 2020",
                            "mcafee_gti_reputation": {
                                "cat": [
                                    105,
                                    107
                                ],
                                "rep": -80,
                                "ufg": 2
                            },
                            "robot": 0,
                            "robot_vulnerability": false,
                            "server": {
                                "BGP_Prefix": "1.1.1.0/24",
                                "allocated_date": "2012-04-16",
                                "as_name": "GOOGLE, US",
                                "as_number": "15169",
                                "city": "",
                                "country": "United States",
                                "ip": "172.217.1.142",
                                "latitude": "37.751",
                                "longitude": "-97.822",
                                "region": ""
                            },
                            "site": {
                                "domain": "google.com"
                            },
                            "site_reputation": "No reputation violations discovered",
                            "valid_chain_of_trust": true,
                            "whois": []
                        }
                    },
                    {
                        "url": "market://details?id=",
                        "url_info": {
                            "has_problem": 0,
                            "mcafee_gti_reputation": {
                                "rep": 15,
                                "ufg": ""
                            },
                            "server": {
                                "BGP_Prefix": "",
                                "allocated_date": "",
                                "as_name": "",
                                "as_number": "",
                                "city": "",
                                "country": "",
                                "ip": "Unavailable",
                                "latitude": "",
                                "longitude": "",
                                "region": ""
                            },
                            "site": {
                                "domain": "details"
                            },
                            "site_reputation": "No reputation violations discovered",
                            "whois": []
                        }
                    },
                    {
                        "source": [
                            {
                                "class": "ixr"
                            }
                        ],
                        "url": "https://clients2.google.com/cr/report",
                        "url_info": {
                            "exp_check": 0,
                            "freak_vulnerability": false,
                            "has_problem": 0,
                            "hb": 0,
                            "hb_tm": "27 Apr 2020",
                            "mcafee_gti_reputation": {
                                "cat": [
                                    107
                                ],
                                "rep": -1,
                                "ufg": 2
                            },
                            "robot": 0,
                            "robot_vulnerability": false,
                            "server": {
                                "BGP_Prefix": "1.1.1.0/24",
                                "allocated_date": "2012-04-16",
                                "as_name": "GOOGLE, US",
                                "as_number": "15169",
                                "city": "",
                                "country": "United States",
                                "ip": "172.217.1.142",
                                "latitude": "37.751",
                                "longitude": "-97.822",
                                "region": ""
                            },
                            "site": {
                                "domain": "google.com"
                            },
                            "site_reputation": "No reputation violations discovered",
                            "valid_chain_of_trust": true,
                            "whois": []
                        }
                    },
                    {
                        "source": [
                            {
                                "class": "fqo"
                            }
                        ],
                        "url": "https://play.google.com/store/apps/details?id=",
                        "url_info": {
                            "exp_check": 0,
                            "freak_vulnerability": false,
                            "has_problem": 0,
                            "hb": 0,
                            "hb_tm": null,
                            "mcafee_gti_reputation": {
                                "cat": [
                                    148
                                ],
                                "rep": "",
                                "ufg": 2
                            },
                            "robot": 0,
                            "robot_vulnerability": false,
                            "server": {
                                "BGP_Prefix": "1.1.1.0/24",
                                "allocated_date": "2012-04-16",
                                "as_name": "GOOGLE, US",
                                "as_number": "15169",
                                "city": "",
                                "country": "United States",
                                "ip": "1.1.1.1",
                                "latitude": "37.751",
                                "longitude": "-97.822",
                                "region": ""
                            },
                            "site": {
                                "domain": "google.com"
                            },
                            "site_reputation": "No reputation violations discovered",
                            "valid_chain_of_trust": true,
                            "whois": []
                        }
                    },
                    {
                        "source": [
                            {
                                "class": "mim"
                            },
                            {
                                "class": "rea"
                            }
                        ],
                        "url": "https://www.google.com/policies/privacy/",
                        "url_info": {
                            "exp_check": 0,
                            "freak_vulnerability": false,
                            "has_problem": 0,
                            "hb": 0,
                            "hb_tm": "27 Apr 2020",
                            "mcafee_gti_reputation": {
                                "cat": [
                                    145
                                ],
                                "rep": -97,
                                "ufg": 70
                            },
                            "robot": 0,
                            "robot_vulnerability": false,
                            "server": {
                                "BGP_Prefix": "1.1.1.0/24",
                                "allocated_date": "2012-04-16",
                                "as_name": "GOOGLE, US",
                                "as_number": "15169",
                                "city": "",
                                "country": "United States",
                                "ip": "1.1.1.1",
                                "latitude": "37.751",
                                "longitude": "-97.822",
                                "region": ""
                            },
                            "site": {
                                "domain": "google.com"
                            },
                            "site_reputation": "No reputation violations discovered",
                            "valid_chain_of_trust": true,
                            "whois": []
                        }
                    },
                    {
                        "url": "market://details?id=%s&referrer=duo-app-update",
                        "url_info": {
                            "has_problem": 0,
                            "mcafee_gti_reputation": {
                                "rep": 15,
                                "ufg": ""
                            },
                            "server": {
                                "BGP_Prefix": "",
                                "allocated_date": "",
                                "as_name": "",
                                "as_number": "",
                                "city": "",
                                "country": "",
                                "ip": "Unavailable",
                                "latitude": "",
                                "longitude": "",
                                "region": ""
                            },
                            "site": {
                                "domain": "details"
                            },
                            "site_reputation": "No reputation violations discovered",
                            "whois": []
                        }
                    },
                    {
                        "url": "market://details",
                        "url_info": {
                            "has_problem": 0,
                            "mcafee_gti_reputation": {
                                "rep": 15,
                                "ufg": ""
                            },
                            "server": {
                                "BGP_Prefix": "",
                                "allocated_date": "",
                                "as_name": "",
                                "as_number": "",
                                "city": "",
                                "country": "",
                                "ip": "Unavailable",
                                "latitude": "",
                                "longitude": "",
                                "region": ""
                            },
                            "site": {
                                "domain": "details"
                            },
                            "site_reputation": "No reputation violations discovered",
                            "whois": []
                        }
                    },
                    {
                        "source": [
                            {
                                "class": "Resource Asset"
                            }
                        ],
                        "url": "https://www.googleapis.com/auth/mobile_user_preferences",
                        "url_info": {
                            "exp_check": 0,
                            "freak_vulnerability": false,
                            "has_problem": 0,
                            "hb": 0,
                            "hb_tm": "27 Apr 2020",
                            "mcafee_gti_reputation": {
                                "cat": [
                                    107
                                ],
                                "rep": -30,
                                "ufg": 98
                            },
                            "robot": 0,
                            "robot_vulnerability": false,
                            "server": {
                                "BGP_Prefix": "1.1.1.0/24",
                                "allocated_date": "2012-04-16",
                                "as_name": "GOOGLE, US",
                                "as_number": "15169",
                                "city": "",
                                "country": "United States",
                                "ip": "172.217.1.138",
                                "latitude": "37.751",
                                "longitude": "-97.822",
                                "region": ""
                            },
                            "site": {
                                "domain": "googleapis.com"
                            },
                            "site_reputation": "No reputation violations discovered",
                            "valid_chain_of_trust": true,
                            "whois": {
                                "creation": "2005-01-25",
                                "name_server": "ns1.google.com,ns2.google.com,ns3.google.com,ns4.google.com"
                            }
                        }
                    },
                    {
                        "source": [
                            {
                                "class": "Resource Asset"
                            }
                        ],
                        "url": "http://ns.adobe.com/xap/1.0/",
                        "url_info": {
                            "has_problem": 0,
                            "mcafee_gti_reputation": {
                                "cat": [
                                    105,
                                    107
                                ],
                                "rep": -91,
                                "ufg": 2
                            },
                            "server": {
                                "BGP_Prefix": "",
                                "allocated_date": "",
                                "as_name": "",
                                "as_number": "",
                                "city": "",
                                "country": "",
                                "ip": "Unavailable",
                                "latitude": "",
                                "longitude": "",
                                "region": ""
                            },
                            "site": {
                                "domain": "adobe.com"
                            },
                            "site_reputation": "No reputation violations discovered",
                            "whois": {
                                "creation": "1986-11-16",
                                "name_server": "a1-217.akam.net,a10-64.akam.net,a13-65.akam.net,a26-66.akam.net,a28-67.akam.net,a7-64.akam.net,adobe-dns-01.adobe.com,adobe-dns-03.adobe.com,adobe-dns-04.adobe.com,adobe-dns-05.adobe.com"
                            }
                        }
                    },
                    {
                        "source": [
                            {
                                "class": "Resource Asset"
                            }
                        ],
                        "url": "https://pagead2.googlesyndication.com/pagead/gen_204?id=gmob-apps",
                        "url_info": {
                            "exp_check": 0,
                            "freak_vulnerability": false,
                            "has_problem": 0,
                            "hb": 0,
                            "hb_tm": "27 Apr 2020",
                            "mcafee_gti_reputation": {
                                "cat": [
                                    154
                                ],
                                "rep": "",
                                "ufg": 38
                            },
                            "robot": 0,
                            "robot_vulnerability": false,
                            "server": {
                                "BGP_Prefix": "172.217.14.0/24",
                                "allocated_date": "2012-04-16",
                                "as_name": "GOOGLE, US",
                                "as_number": "15169",
                                "city": "",
                                "country": "United States",
                                "ip": "172.217.14.162",
                                "latitude": "37.751",
                                "longitude": "-97.822",
                                "region": ""
                            },
                            "site": {
                                "domain": "googlesyndication.com"
                            },
                            "site_reputation": "No reputation violations discovered",
                            "valid_chain_of_trust": true,
                            "whois": {
                                "creation": "2003-01-20",
                                "name_server": "ns1.google.com,ns2.google.com,ns3.google.com,ns4.google.com"
                            }
                        }
                    },
                    {
                        "source": [
                            {
                                "class": "Resource Asset"
                            }
                        ],
                        "url": "http://schemas.android.com/apk/res/android",
                        "url_info": {
                            "has_problem": 0,
                            "mcafee_gti_reputation": {
                                "cat": [
                                    107
                                ],
                                "rep": 9,
                                "ufg": ""
                            },
                            "server": {
                                "BGP_Prefix": "",
                                "allocated_date": "",
                                "as_name": "",
                                "as_number": "",
                                "city": "",
                                "country": "",
                                "ip": "Unavailable",
                                "latitude": "",
                                "longitude": "",
                                "region": ""
                            },
                            "site": {
                                "domain": "android.com"
                            },
                            "site_reputation": "No reputation violations discovered",
                            "whois": []
                        }
                    },
                    {
                        "source": [
                            {
                                "class": "Resource Asset"
                            }
                        ],
                        "url": "https://www.googleapis.com/auth/numberer",
                        "url_info": {
                            "exp_check": 0,
                            "freak_vulnerability": false,
                            "has_problem": 0,
                            "hb": 0,
                            "hb_tm": "27 Apr 2020",
                            "mcafee_gti_reputation": {
                                "cat": [
                                    107
                                ],
                                "rep": -30,
                                "ufg": 98
                            },
                            "robot": 0,
                            "robot_vulnerability": false,
                            "server": {
                                "BGP_Prefix": "1.1.1.0/24",
                                "allocated_date": "2012-04-16",
                                "as_name": "GOOGLE, US",
                                "as_number": "15169",
                                "city": "",
                                "country": "United States",
                                "ip": "172.217.1.138",
                                "latitude": "37.751",
                                "longitude": "-97.822",
                                "region": ""
                            },
                            "site": {
                                "domain": "googleapis.com"
                            },
                            "site_reputation": "No reputation violations discovered",
                            "valid_chain_of_trust": true,
                            "whois": {
                                "creation": "2005-01-25",
                                "name_server": "ns1.google.com,ns2.google.com,ns3.google.com,ns4.google.com"
                            }
                        }
                    },
                    {
                        "source": [
                            {
                                "class": "Resource Asset"
                            }
                        ],
                        "url": "http://www.mozilla.org/MPL/2.0/FAQ.html",
                        "url_info": {
                            "has_problem": 0,
                            "mcafee_gti_reputation": {
                                "cat": [
                                    107
                                ],
                                "rep": -49,
                                "ufg": 3
                            },
                            "server": {
                                "BGP_Prefix": "104.16.128.0/20",
                                "allocated_date": "2014-03-28",
                                "as_name": "CLOUDFLARENET, US",
                                "as_number": "13335",
                                "city": "",
                                "country": "United States",
                                "ip": "104.16.143.228",
                                "latitude": "37.751",
                                "longitude": "-97.822",
                                "region": ""
                            },
                            "site": {
                                "domain": "mozilla.org"
                            },
                            "site_reputation": "No reputation violations discovered",
                            "whois": {
                                "creation": "1998-01-23",
                                "name_server": "ns5-65.akam.net,ns7-66.akam.net,ns4-64.akam.net,ns1-240.akam.net",
                                "registrant_organization": "Mozilla Corporation"
                            }
                        }
                    },
                    {
                        "source": [
                            {
                                "class": "Resource Asset"
                            }
                        ],
                        "url": "http://opensource.org/licenses/bsd-license.php",
                        "url_info": {
                            "has_problem": 0,
                            "mcafee_gti_reputation": {
                                "cat": [
                                    107,
                                    133
                                ],
                                "rep": -88,
                                "ufg": 2
                            },
                            "server": {
                                "BGP_Prefix": "1.1.1.0/20",
                                "allocated_date": "2017-10-24",
                                "as_name": "DIGITALOCEAN-ASN, US",
                                "as_number": "14061",
                                "city": "Clifton",
                                "country": "United States",
                                "ip": "159.65.34.8",
                                "latitude": "40.8364",
                                "longitude": "-74.1403",
                                "region": "New Jersey"
                            },
                            "site": {
                                "domain": "opensource.org"
                            },
                            "site_reputation": "No reputation violations discovered",
                            "whois": {
                                "creation": "1998-02-10",
                                "name_server": "ns-17-b.gandi.net,ns-52-a.gandi.net,ns-9-c.gandi.net",
                                "registrant_organization": "Open Source Initiative"
                            }
                        }
                    },
                    {
                        "source": [
                            {
                                "class": "Resource Asset"
                            }
                        ],
                        "url": "http://code.google.com/p/lao-dictionary/",
                        "url_info": {
                            "has_problem": 0,
                            "mcafee_gti_reputation": {
                                "cat": [
                                    107
                                ],
                                "rep": -3,
                                "ufg": 2
                            },
                            "server": {
                                "BGP_Prefix": "172.217.14.0/24",
                                "allocated_date": "2012-04-16",
                                "as_name": "GOOGLE, US",
                                "as_number": "15169",
                                "city": "",
                                "country": "United States",
                                "ip": "1.1.1.1",
                                "latitude": "37.751",
                                "longitude": "-97.822",
                                "region": ""
                            },
                            "site": {
                                "domain": "google.com"
                            },
                            "site_reputation": "No reputation violations discovered",
                            "whois": []
                        }
                    },
                    {
                        "source": [
                            {
                                "class": "Resource Asset"
                            }
                        ],
                        "url": "http://lao-dictionary.googlecode.com/git/Lao-Dictionary.txt",
                        "url_info": {
                            "has_problem": 0,
                            "mcafee_gti_reputation": {
                                "cat": [
                                    107
                                ],
                                "rep": "",
                                "ufg": 4
                            },
                            "server": {
                                "BGP_Prefix": "1.1.1.1/24",
                                "allocated_date": "2013-04-04",
                                "as_name": "GOOGLE, US",
                                "as_number": "15169",
                                "city": "",
                                "country": "United States",
                                "ip": "1.1.1.1",
                                "latitude": "37.751",
                                "longitude": "-97.822",
                                "region": ""
                            },
                            "site": {
                                "domain": "googlecode.com"
                            },
                            "site_reputation": "No reputation violations discovered",
                            "whois": {
                                "creation": "2005-03-08",
                                "name_server": "ns1.google.com,ns2.google.com,ns3.google.com,ns4.google.com"
                            }
                        }
                    },
                    {
                        "source": [
                            {
                                "class": "Resource Asset"
                            }
                        ],
                        "url": "https://zenodo.org/record/1227121#.XRKKxYhKiUk;",
                        "url_info": {
                            "exp_check": 0,
                            "freak_vulnerability": false,
                            "has_problem": 0,
                            "hb": 0,
                            "hb_tm": "29 Apr 2020",
                            "mcafee_gti_reputation": {
                                "cat": [
                                    105
                                ],
                                "rep": 3,
                                "ufg": 2
                            },
                            "robot": 0,
                            "robot_vulnerability": false,
                            "server": {
                                "BGP_Prefix": "188.184.0.0/16",
                                "allocated_date": "2009-06-09",
                                "as_name": "CERN, CH",
                                "as_number": "513",
                                "city": "",
                                "country": "Switzerland",
                                "ip": "1.1.1.1",
                                "latitude": "47.1449",
                                "longitude": "8.1551",
                                "region": ""
                            },
                            "site": {
                                "domain": "zenodo.org"
                            },
                            "site_reputation": "No reputation violations discovered",
                            "valid_chain_of_trust": true,
                            "whois": {
                                "creation": "2012-11-14",
                                "expiration": "2019-11-14",
                                "name_server": "ext-dns-1.cern.ch,ext-dns-2.cern.ch",
                                "registrant_organization": "CERN - European Organisation for Nuclear Research"
                            }
                        }
                    },
                    {
                        "source": [
                            {
                                "class": "Resource Asset"
                            }
                        ],
                        "url": "https://datatracker.ietf.org/ipr/1524/",
                        "url_info": {
                            "exp_check": 0,
                            "freak_vulnerability": false,
                            "has_problem": 0,
                            "hb": 0,
                            "hb_tm": "27 Apr 2020",
                            "mcafee_gti_reputation": {
                                "cat": [
                                    105,
                                    107
                                ],
                                "rep": "",
                                "ufg": 38
                            },
                            "robot": 0,
                            "robot_vulnerability": false,
                            "server": {
                                "BGP_Prefix": "4.0.0.0/9",
                                "allocated_date": "1992-12-01",
                                "as_name": "LEVEL3, US",
                                "as_number": "3356",
                                "city": "Santa Clara",
                                "country": "United States",
                                "ip": "1.1.1.1",
                                "latitude": "37.3931",
                                "longitude": "-121.962",
                                "region": "California"
                            },
                            "site": {
                                "domain": "ietf.org",
                                "http_server_type": "Apache"
                            },
                            "site_reputation": "No reputation violations discovered",
                            "valid_chain_of_trust": true,
                            "whois": {
                                "creation": "1995-03-10",
                                "name_server": "ns0.amsl.com,ns1.ams1.afilias-nst.info,ns1.mia1.afilias-nst.info,ns1.sea1.afilias-nst.info,ns1.yyz1.afilias-nst.info,ns1.hkg1.afilias-nst.info",
                                "registrant_organization": "IETF Trust"
                            }
                        }
                    },
                    {
                        "source": [
                            {
                                "class": "Resource Asset"
                            }
                        ],
                        "url": "https://datatracker.ietf.org/ipr/1526/",
                        "url_info": {
                            "exp_check": 0,
                            "freak_vulnerability": false,
                            "has_problem": 0,
                            "hb": 0,
                            "hb_tm": "27 Apr 2020",
                            "mcafee_gti_reputation": {
                                "cat": [
                                    105,
                                    107
                                ],
                                "rep": "",
                                "ufg": 38
                            },
                            "robot": 0,
                            "robot_vulnerability": false,
                            "server": {
                                "BGP_Prefix": "4.0.0.0/9",
                                "allocated_date": "1992-12-01",
                                "as_name": "LEVEL3, US",
                                "as_number": "3356",
                                "city": "Santa Clara",
                                "country": "United States",
                                "ip": "1.1.1.1",
                                "latitude": "37.3931",
                                "longitude": "-121.962",
                                "region": "California"
                            },
                            "site": {
                                "domain": "ietf.org",
                                "http_server_type": "Apache"
                            },
                            "site_reputation": "No reputation violations discovered",
                            "valid_chain_of_trust": true,
                            "whois": {
                                "creation": "1995-03-10",
                                "name_server": "ns0.amsl.com,ns1.ams1.afilias-nst.info,ns1.mia1.afilias-nst.info,ns1.sea1.afilias-nst.info,ns1.yyz1.afilias-nst.info,ns1.hkg1.afilias-nst.info",
                                "registrant_organization": "IETF Trust"
                            }
                        }
                    },
                    {
                        "source": [
                            {
                                "class": "Resource Asset"
                            }
                        ],
                        "url": "https://creativecommons.org/licenses/by/3.0/",
                        "url_info": {
                            "exp_check": 0,
                            "freak_vulnerability": false,
                            "has_problem": 0,
                            "hb": 0,
                            "hb_tm": "27 Apr 2020",
                            "mcafee_gti_reputation": {
                                "cat": [
                                    105
                                ],
                                "rep": "",
                                "ufg": 2
                            },
                            "robot": 0,
                            "robot_vulnerability": false,
                            "server": {
                                "BGP_Prefix": "1.1.1.0/20",
                                "allocated_date": "2014-03-28",
                                "as_name": "CLOUDFLARENET, US",
                                "as_number": "13335",
                                "city": "",
                                "country": "United States",
                                "ip": "104.20.151.16",
                                "latitude": "37.751",
                                "longitude": "-97.822",
                                "region": ""
                            },
                            "site": {
                                "domain": "creativecommons.org",
                                "http_server_type": "cloudflare"
                            },
                            "site_reputation": "No reputation violations discovered",
                            "valid_chain_of_trust": true,
                            "whois": {
                                "creation": "2001-01-15",
                                "name_server": "fiona.ns.cloudflare.com,isaac.ns.cloudflare.com",
                                "registrant_organization": "Creative Commons Corporation"
                            }
                        }
                    },
                    {
                        "source": [
                            {
                                "class": "Resource Asset"
                            }
                        ],
                        "url": "http://www.ploscompbiol.org/static/license",
                        "url_info": {
                            "has_problem": 0,
                            "mcafee_gti_reputation": {
                                "cat": [
                                    105
                                ],
                                "rep": "",
                                "ufg": 12
                            },
                            "server": {
                                "BGP_Prefix": "1.1.1.0/20",
                                "allocated_date": "1998-09-15",
                                "as_name": "LNH-INC, US",
                                "as_number": "20021",
                                "city": "Denver",
                                "country": "United States",
                                "ip": "216.74.38.76",
                                "latitude": "39.7501",
                                "longitude": "-104.9957",
                                "region": "Colorado"
                            },
                            "site": {
                                "domain": "ploscompbiol.org"
                            },
                            "site_reputation": "No reputation violations discovered",
                            "whois": {
                                "creation": "2004-11-18",
                                "name_server": "dns1.easydns.com,dns3.easydns.org,dns2.easydns.net"
                            }
                        }
                    },
                    {
                        "source": [
                            {
                                "class": "Resource Asset"
                            }
                        ],
                        "url": "https://cla.developers.google.com/clas",
                        "url_info": {
                            "exp_check": 0,
                            "freak_vulnerability": false,
                            "has_problem": 0,
                            "hb": 0,
                            "hb_tm": "27 Apr 2020",
                            "mcafee_gti_reputation": {
                                "cat": [
                                    107
                                ],
                                "rep": 16,
                                "ufg": 2
                            },
                            "robot": 0,
                            "robot_vulnerability": false,
                            "server": {
                                "BGP_Prefix": "1.1.1.0/24",
                                "allocated_date": "2012-04-16",
                                "as_name": "GOOGLE, US",
                                "as_number": "15169",
                                "city": "",
                                "country": "United States",
                                "ip": "1.1.1.1",
                                "latitude": "37.751",
                                "longitude": "-97.822",
                                "region": ""
                            },
                            "site": {
                                "domain": "google.com"
                            },
                            "site_reputation": "No reputation violations discovered",
                            "valid_chain_of_trust": true,
                            "whois": []
                        }
                    },
                    {
                        "source": [
                            {
                                "class": "Resource Asset"
                            }
                        ],
                        "url": "https://github.com/mit-plv/fiat-crypto/blob/master/AUTHORS",
                        "url_info": {
                            "exp_check": 0,
                            "freak_vulnerability": false,
                            "has_problem": 0,
                            "hb": 0,
                            "hb_tm": "19 May 2020",
                            "mcafee_gti_reputation": {
                                "cat": [
                                    107,
                                    165
                                ],
                                "rep": -85,
                                "ufg": 103
                            },
                            "robot": 0,
                            "robot_vulnerability": false,
                            "server": {
                                "BGP_Prefix": "140.82.114.0/24",
                                "allocated_date": "2018-04-25",
                                "as_name": "GITHUB, US",
                                "as_number": "36459",
                                "city": "",
                                "country": "United States",
                                "ip": "140.82.114.3",
                                "latitude": "37.751",
                                "longitude": "-97.822",
                                "region": ""
                            },
                            "site": {
                                "domain": "github.com"
                            },
                            "site_reputation": "No reputation violations discovered",
                            "valid_chain_of_trust": true,
                            "whois": {
                                "creation": "2007-10-09",
                                "name_server": "ns-1283.awsdns-32.org,ns-1707.awsdns-21.co.uk,ns-421.awsdns-52.com,ns-520.awsdns-01.net,ns1.p16.dynect.net,ns2.p16.dynect.net,ns3.p16.dynect.net,ns4.p16.dynect.net"
                            }
                        }
                    },
                    {
                        "source": [
                            {
                                "class": "Resource Asset"
                            }
                        ],
                        "url": "https://llvm.org/docs/DeveloperPolicy.html#legacy",
                        "url_info": {
                            "exp_check": 0,
                            "freak_vulnerability": false,
                            "has_problem": 0,
                            "hb": 0,
                            "hb_tm": "27 Apr 2020",
                            "mcafee_gti_reputation": {
                                "cat": [
                                    107
                                ],
                                "rep": "",
                                "ufg": 70
                            },
                            "robot": 0,
                            "robot_vulnerability": false,
                            "server": {
                                "BGP_Prefix": "1.1.0.0/17",
                                "allocated_date": "2014-06-20",
                                "as_name": "AMAZON-02, US",
                                "as_number": "16509",
                                "city": "San Jose",
                                "country": "United States",
                                "ip": "1.1.1.1",
                                "latitude": "37.3388",
                                "longitude": "-121.8914",
                                "region": "California"
                            },
                            "site": {
                                "domain": "llvm.org",
                                "http_server_type": "Apache/2.4.7 (Ubuntu)"
                            },
                            "site_reputation": "No reputation violations discovered",
                            "valid_chain_of_trust": true,
                            "whois": {
                                "creation": "2004-03-12",
                                "name_server": "ns1.melbourneit.net,ns2.melbourneit.net,ns3.melbourneit.net,ns4.melbourneit.net",
                                "registrant_organization": "Private Registration US"
                            }
                        }
                    },
                    {
                        "source": [
                            {
                                "class": "Resource Asset"
                            }
                        ],
                        "url": "https://github.com/jquery/jquery-ui",
                        "url_info": {
                            "exp_check": 0,
                            "freak_vulnerability": false,
                            "has_problem": 0,
                            "hb": 0,
                            "hb_tm": "19 May 2020",
                            "mcafee_gti_reputation": {
                                "cat": [
                                    107,
                                    165
                                ],
                                "rep": -85,
                                "ufg": 103
                            },
                            "robot": 0,
                            "robot_vulnerability": false,
                            "server": {
                                "BGP_Prefix": "140.82.114.0/24",
                                "allocated_date": "2018-04-25",
                                "as_name": "GITHUB, US",
                                "as_number": "36459",
                                "city": "",
                                "country": "United States",
                                "ip": "140.82.114.3",
                                "latitude": "37.751",
                                "longitude": "-97.822",
                                "region": ""
                            },
                            "site": {
                                "domain": "github.com"
                            },
                            "site_reputation": "No reputation violations discovered",
                            "valid_chain_of_trust": true,
                            "whois": {
                                "creation": "2007-10-09",
                                "name_server": "ns-1283.awsdns-32.org,ns-1707.awsdns-21.co.uk,ns-421.awsdns-52.com,ns-520.awsdns-01.net,ns1.p16.dynect.net,ns2.p16.dynect.net,ns3.p16.dynect.net,ns4.p16.dynect.net"
                            }
                        }
                    },
                    {
                        "source": [
                            {
                                "class": "Resource Asset"
                            }
                        ],
                        "url": "http://modp.com/release/base64",
                        "url_info": {
                            "has_problem": 0,
                            "mcafee_gti_reputation": {
                                "cat": [
                                    107
                                ],
                                "rep": "",
                                "ufg": 8
                            },
                            "server": {
                                "BGP_Prefix": "1.1.1.0/24",
                                "allocated_date": "2015-11-13",
                                "as_name": "NAMECHEAP-NET, US",
                                "as_number": "22612",
                                "city": "Los Angeles",
                                "country": "United States",
                                "ip": "198.54.117.197",
                                "latitude": "34.0318",
                                "longitude": "-118.4252",
                                "region": "California"
                            },
                            "site": {
                                "domain": "modp.com"
                            },
                            "site_reputation": "No reputation violations discovered",
                            "whois": {
                                "creation": "2000-05-16",
                                "name_server": "dns1.stabletransit.com,dns2.stabletransit.com"
                            }
                        }
                    },
                    {
                        "source": [
                            {
                                "class": "Resource Asset"
                            }
                        ],
                        "url": "https://eigen.googlesource.com/mirror/",
                        "url_info": {
                            "exp_check": 0,
                            "freak_vulnerability": false,
                            "has_problem": 0,
                            "hb": 0,
                            "hb_tm": "27 Apr 2020",
                            "mcafee_gti_reputation": {
                                "cat": [
                                    107
                                ],
                                "rep": "",
                                "ufg": ""
                            },
                            "robot": 0,
                            "robot_vulnerability": false,
                            "server": {
                                "BGP_Prefix": "1.1.1.1/24",
                                "allocated_date": "2003-08-18",
                                "as_name": "GOOGLE, US",
                                "as_number": "15169",
                                "city": "",
                                "country": "",
                                "ip": "64.233.178.82",
                                "latitude": "47",
                                "longitude": "8",
                                "region": ""
                            },
                            "site": {
                                "domain": "googlesource.com"
                            },
                            "site_reputation": "No reputation violations discovered",
                            "valid_chain_of_trust": true,
                            "whois": {
                                "creation": "2004-10-20",
                                "name_server": "ns1.google.com,ns2.google.com,ns3.google.com,ns4.google.com"
                            }
                        }
                    },
                    {
                        "source": [
                            {
                                "class": "Resource Asset"
                            }
                        ],
                        "url": "http://scripts.sil.org/OFLhttp",
                        "url_info": {
                            "has_problem": 0,
                            "mcafee_gti_reputation": {
                                "cat": [
                                    107
                                ],
                                "rep": "",
                                "ufg": 2
                            },
                            "server": {
                                "BGP_Prefix": "3.208.0.0/12",
                                "allocated_date": "2018-06-25",
                                "as_name": "AMAZON-AES, US",
                                "as_number": "14618",
                                "city": "Ashburn",
                                "country": "United States",
                                "ip": "1.1.1.1",
                                "latitude": "39.0481",
                                "longitude": "-77.4728",
                                "region": "Virginia"
                            },
                            "site": {
                                "domain": "sil.org",
                                "http_server_type": "nginx"
                            },
                            "site_reputation": "No reputation violations discovered",
                            "whois": {
                                "creation": "1991-04-14",
                                "name_server": "nsj1.wsfo.org,nsc1.wsfo.org,nsd1.wsfo.org",
                                "registrant_organization": "Summer Institute of Linguistics"
                            }
                        }
                    },
                    {
                        "source": [
                            {
                                "class": "Resource Asset"
                            }
                        ],
                        "url": "https://www.apache.org/licenses/",
                        "url_info": {
                            "exp_check": 0,
                            "freak_vulnerability": false,
                            "has_problem": 0,
                            "hb": 0,
                            "hb_tm": null,
                            "mcafee_gti_reputation": {
                                "cat": [
                                    107
                                ],
                                "rep": -4,
                                "ufg": 8
                            },
                            "robot": 0,
                            "robot_vulnerability": false,
                            "server": {
                                "BGP_Prefix": "1.1.0.0/10",
                                "allocated_date": "2015-02-23",
                                "as_name": "MICROSOFT-CORP-MSN-AS-BLOCK, US",
                                "as_number": "8075",
                                "city": "Boydton",
                                "country": "United States",
                                "ip": "40.79.78.1",
                                "latitude": "36.6534",
                                "longitude": "-78.375",
                                "region": "Virginia"
                            },
                            "site": {
                                "domain": "apache.org",
                                "http_server_type": "Apache/2.4.18 (Ubuntu)"
                            },
                            "site_reputation": "No reputation violations discovered",
                            "valid_chain_of_trust": true,
                            "whois": {
                                "creation": "1995-04-10",
                                "name_server": "ns2.surfnet.nl,ns3.no-ip.com,ns2.no-ip.com,ns1.no-ip.com,ns4.no-ip.com",
                                "registrant_organization": "The Apache Software Foundation"
                            }
                        }
                    },
                    {
                        "source": [
                            {
                                "class": "Resource Asset"
                            }
                        ],
                        "url": "http://oss.sgi.com/projects/FreeB/",
                        "url_info": {
                            "has_problem": 0,
                            "mcafee_gti_reputation": {
                                "cat": [
                                    107
                                ],
                                "rep": -2,
                                "ufg": 2
                            },
                            "server": {
                                "BGP_Prefix": "23.43.60.0/22",
                                "allocated_date": "2011-05-16",
                                "as_name": "AKAMAI-ASN1, EU",
                                "as_number": "20940",
                                "city": "Astoria",
                                "country": "United States",
                                "ip": "1.1.1.1",
                                "latitude": "40.7579",
                                "longitude": "-73.9332",
                                "region": "New York"
                            },
                            "site": {
                                "domain": "sgi.com"
                            },
                            "site_reputation": "No reputation violations discovered",
                            "whois": {
                                "creation": "1994-05-09",
                                "name_server": "ns1.hpe.com,ns2.hpe.com,ns3.hpe.com,ns4.hpe.com,ns5.hpe.com,ns6.hpe.com,ns7.hpe.com,ns8.hpe.com"
                            }
                        }
                    },
                    {
                        "source": [
                            {
                                "class": "Resource Asset"
                            }
                        ],
                        "url": "http://ctrio.sourceforge.net/",
                        "url_info": {
                            "has_problem": 0,
                            "mcafee_gti_reputation": {
                                "cat": [
                                    107,
                                    148
                                ],
                                "rep": -87,
                                "ufg": 66
                            },
                            "server": {
                                "BGP_Prefix": "216.105.38.0/24",
                                "allocated_date": "2000-07-14",
                                "as_name": "AIS-WEST, US",
                                "as_number": "6130",
                                "city": "Winchester",
                                "country": "United States",
                                "ip": "216.105.38.10",
                                "latitude": "33.6243",
                                "longitude": "-117.0885",
                                "region": "California"
                            },
                            "site": {
                                "domain": "sourceforge.net",
                                "http_server_type": "nginx/1.14.0 (Ubuntu)"
                            },
                            "site_reputation": "No reputation violations discovered",
                            "whois": []
                        }
                    },
                    {
                        "source": [
                            {
                                "class": "Resource Asset"
                            }
                        ],
                        "url": "https://www.spsc.tugraz.at/databases-and-tools/ptdb-tug-pitch-tracking-database-from-graz-university-of-technology.html;",
                        "url_info": {
                            "exp_check": 0,
                            "freak_vulnerability": false,
                            "has_problem": 0,
                            "hb": 0,
                            "hb_tm": "08 May 2020",
                            "mcafee_gti_reputation": {
                                "cat": [
                                    111
                                ],
                                "rep": "",
                                "ufg": ""
                            },
                            "robot": 0,
                            "robot_vulnerability": false,
                            "server": {
                                "BGP_Prefix": "129.27.0.0/16",
                                "allocated_date": "1989-11-02",
                                "as_name": "TUGNET Technische Universitaet Graz, AT",
                                "as_number": "1113",
                                "city": "Graz",
                                "country": "Austria",
                                "ip": "129.27.140.151",
                                "latitude": "47.0833",
                                "longitude": "15.5667",
                                "region": "Styria"
                            },
                            "site": {
                                "domain": "tugraz.at"
                            },
                            "site_reputation": "No reputation violations discovered",
                            "valid_chain_of_trust": true,
                            "whois": {
                                "name_server": "ns1.tu-graz.ac.at,ns2.tu-graz.ac.at,ns5.univie.ac.at"
                            }
                        }
                    },
                    {
                        "source": [
                            {
                                "class": "Resource Asset"
                            }
                        ],
                        "url": "https://storage.googleapis.com/expressive_camera_authoring_renderable_effects/graphs/%s",
                        "url_info": {
                            "exp_check": 0,
                            "freak_vulnerability": false,
                            "has_problem": 0,
                            "hb": 0,
                            "hb_tm": null,
                            "mcafee_gti_reputation": {
                                "cat": [
                                    107
                                ],
                                "rep": -89,
                                "ufg": 2
                            },
                            "robot": 0,
                            "robot_vulnerability": false,
                            "server": {
                                "BGP_Prefix": "216.58.192.0/22",
                                "allocated_date": "2012-01-27",
                                "as_name": "GOOGLE, US",
                                "as_number": "15169",
                                "city": "Bluffdale",
                                "country": "United States",
                                "ip": "216.58.194.144",
                                "latitude": "40.4953",
                                "longitude": "-111.9439",
                                "region": "Utah"
                            },
                            "site": {
                                "domain": "googleapis.com"
                            },
                            "site_reputation": "No reputation violations discovered",
                            "valid_chain_of_trust": true,
                            "whois": {
                                "creation": "2005-01-25",
                                "name_server": "ns1.google.com,ns2.google.com,ns3.google.com,ns4.google.com"
                            }
                        }
                    },
                    {
                        "source": [
                            {
                                "class": "Resource Asset"
                            }
                        ],
                        "url": "http://www.cisl.ucar.edu/css/software/fftpack5/ftpk.html",
                        "url_info": {
                            "has_problem": 0,
                            "mcafee_gti_reputation": {
                                "cat": [
                                    111
                                ],
                                "rep": "",
                                "ufg": ""
                            },
                            "server": {
                                "BGP_Prefix": "128.117.0.0/16",
                                "allocated_date": "1986-03-24",
                                "as_name": "NCAR-AS, US",
                                "as_number": "194",
                                "city": "",
                                "country": "United States",
                                "ip": "1.1.1.1",
                                "latitude": "37.751",
                                "longitude": "-97.822",
                                "region": ""
                            },
                            "site": {
                                "domain": "ucar.edu"
                            },
                            "site_reputation": "No reputation violations discovered",
                            "whois": {
                                "creation": "1986-10-03",
                                "name_server": "dns.ucar.edu,dnsx1.ucar.edu,dnsnx1.nwsc.ucar.edu,dnsnx2.nwsc.ucar.edu,dnsx2.ucar.edu"
                            }
                        }
                    },
                    {
                        "source": [
                            {
                                "class": "Resource Asset"
                            }
                        ],
                        "url": "https://goo.gl/NAOOOI",
                        "url_info": {
                            "eff_url": "https://goo.gl",
                            "exp_check": 0,
                            "freak_vulnerability": false,
                            "has_problem": 0,
                            "hb": 0,
                            "hb_tm": "15 May 2020",
                            "mcafee_gti_reputation": {
                                "cat": [
                                    107
                                ],
                                "rep": -79,
                                "ufg": 6
                            },
                            "robot": 0,
                            "robot_vulnerability": false,
                            "server": {
                                "BGP_Prefix": "1.1.1.1/24",
                                "allocated_date": "2012-04-16",
                                "as_name": "GOOGLE, US",
                                "as_number": "15169",
                                "city": "",
                                "country": "United States",
                                "ip": "172.217.6.142",
                                "latitude": "37.751",
                                "longitude": "-97.822",
                                "region": ""
                            },
                            "short_url": 1,
                            "site": {
                                "domain": "goo.gl"
                            },
                            "site_reputation": "No reputation violations discovered",
                            "valid_chain_of_trust": true,
                            "whois": {
                                "name_server": "ns3.google.com,ns2.google.com,ns4.google.com,ns1.google.com"
                            }
                        }
                    }
                ]
            },
            "behavior": {
                "broadcast_receivers": [],
                "count_sms": 0,
                "network": {
                    "http_requests": null
                },
                "sms": [],
                "telephony": null
            },
            "certificate": {
                "app_signature": "\tMETA-INF/BNDLTOOL.RSA\nOwner: CN=corp_tachyon, OU=Android, O=Google Inc., L=Mountain View, ST=California, C=US\nIssuer: CN=corp_tachyon, OU=Android, O=Google Inc., L=Mountain View, ST=California, C=US\nSerial number: a2b9317c3188d2b8\nValid from: Fri Jan 23 19:11:23 UTC 2015 until: Tue Jun 10 19:11:23 UTC 2042\nCertificate fingerprints:\n\t SHA1: A0:BC:09:AF:52:7B:63:97:C7:A9:EF:17:1D:6C:F7:6F:75:7B:EC:C3\n\t SHA256: 7C:AA:B6:E6:BA:70:0E:0D:DC:F7:5C:CA:52:B8:C3:B1:9A:3C:7D:23:30:8F:7E:B1:77:A6:4E:B2:47:61:97:BD\nSignature algorithm name: SHA1withRSA\nSubject Public Key Algorithm: 2048-bit RSA key\nVersion: 3\n\nExtensions: \n\n#1: ObjectId: 2.5.29.35 Criticality=false\nAuthorityKeyIdentifier [\nKeyIdentifier [\n0000: 16 BD 59 23 FE 59 51 1F   85 E2 80 AD 45 47 37 BA  ..Y#.YQ.....EG7.\n0010: C6 90 F2 4E                                        ...N\n]\n]\n\n#2: ObjectId: 2.5.29.19 Criticality=false\nBasicConstraints:[\n  CA:true\n  PathLen:2147483647\n]\n\n#3: ObjectId: 2.5.29.14 Criticality=false\nSubjectKeyIdentifier [\nKeyIdentifier [\n0000: 16 BD 59 23 FE 59 51 1F   85 E2 80 AD 45 47 37 BA  ..Y#.YQ.....EG7.\n0010: C6 90 F2 4E                                        ...N\n]\n]\n\n",
                "serial_number_app_instances": 1435,
                "serial_number_risk_score": 35
            },
            "distribution": {
                "file_share": [
                    {
                        "app_name": "Duo Good.apk",
                        "file_size": "Size:",
                        "site_name": "Getwapi",
                        "url": "http://getwapi.com/software/getload/zxyBJGrtba/duo_good.html"
                    },
                    {
                        "app_name": "Duo Mobile.apk",
                        "file_size": "Size:",
                        "site_name": "Getwapi",
                        "url": "http://getwapi.com/software/getload/y1-xPdxpba/duo_mobile.html"
                    },
                    {
                        "app_name": "Duo Comgoogleandroidappstachyo.apk",
                        "file_size": "Size:",
                        "site_name": "Getwapi",
                        "url": "http://getwapi.com/software/getload/9T4xOy9Ace/duo_comgoogleandroidappstachyo.html"
                    },
                    {
                        "app_name": "Duo Mobile v3.8.2 Free.apk",
                        "file_size": "11.46 MB",
                        "site_name": "Getwapi",
                        "url": "http://getwapi.com/software/download/mobile/O1ZYfMEnba/Duo_Mobile_v382_Free.html"
                    },
                    {
                        "app_name": "Chicky Duo Latest Version.apk",
                        "file_size": "Size:",
                        "site_name": "Getwapi",
                        "url": "http://getwapi.com/software/getload/_Cq77Uxuba/chicky_duo_latest_version.html"
                    },
                    {
                        "app_name": "Duo Mobile V382 Free.apk",
                        "file_size": "Size:",
                        "site_name": "Getwapi",
                        "url": "http://getwapi.com/software/getload/dvmisuwWce/duo_mobile_v382_free.html"
                    },
                    {
                        "app_name": "Duo Mobile v3.8.2 free.apk",
                        "file_size": "11.46 MB",
                        "site_name": "Getwapi",
                        "url": "http://getwapi.com/software/download/mobile/8IX5mzp_ba/download_Duo_Mobile_v382_free.html"
                    },
                    {
                        "app_name": "Chicky Duo No Ads.apk",
                        "file_size": "Size:",
                        "site_name": "Getwapi",
                        "url": "http://getwapi.com/software/getload/Sua6zIbmba/chicky_duo_no_ads.html"
                    },
                    {
                        "app_name": "Chicky Duo Guide Android.apk",
                        "file_size": "Size:",
                        "site_name": "Getwapi",
                        "url": "http://getwapi.com/software/getload/Vv0v4Pw_ce/chicky_duo_guide_android.html"
                    },
                    {
                        "app_name": "Chicky Duo Mod.apk",
                        "file_size": "Size:",
                        "site_name": "Getwapi",
                        "url": "http://getwapi.com/software/getload/ibZUY48Tba/chicky_duo_mod.html"
                    },
                    {
                        "app_name": "Chicky Duo Premio Jogo.apk",
                        "file_size": "Size:",
                        "site_name": "Getwapi",
                        "url": "http://getwapi.com/software/getload/fdjDrBOvce/chicky_duo_premio_jogo.html"
                    },
                    {
                        "app_name": "Chicky Duo Updated Pocket.apk",
                        "file_size": "Size:",
                        "site_name": "Getwapi",
                        "url": "http://getwapi.com/software/getload/rLBHfvl3ce/chicky_duo_updated_pocket.html"
                    },
                    {
                        "app_name": "Duo Mobile V382 Hd.apk",
                        "file_size": "Size:",
                        "site_name": "Getwapi",
                        "url": "http://getwapi.com/software/getload/66WdBFZIce/duo_mobile_v382_hd.html"
                    },
                    {
                        "app_name": "Duo Mobile V397 Free.apk",
                        "file_size": "Size:",
                        "site_name": "Getwapi",
                        "url": "http://getwapi.com/software/getload/CYIsyqkSce/download_duo_mobile_v397_free.html"
                    },
                    {
                        "app_name": "Chicky Duo Free Purchases.apk",
                        "file_size": "Size:",
                        "site_name": "Getwapi",
                        "url": "http://getwapi.com/software/getload/vGe0ndazba/chicky_duo_free_purchases.html"
                    }
                ],
                "market_data": {
                    "app_market": "google",
                    "app_type": "apk",
                    "product_id": "com.google.android.apps.tachyon"
                },
                "markets": {
                    "1Mobile": "No",
                    "Amazon": "No",
                    "AndroidPit": "No",
                    "AppChina": "http://m.appchina.com/app/com.google.android.apps.tachyon",
                    "Baidu": "No",
                    "Brothersoft": "No",
                    "F-Droid": "No",
                    "GetJAR": "No",
                    "GooglePlay": "https://play.google.com/store/apps/details?id=com.google.android.apps.tachyon",
                    "Slide me": "No",
                    "Socio": "No",
                    "VShare": "No",
                    "Wandoujia": "No",
                    "ZIP Apk": "No"
                },
                "torrents": "Not present"
            },
            "md5": "f26cf1135f9d2ea60532a5a13c6fbed5",
            "risk_profile": {
                "detection_rate": "0/0",
                "intell_privacy": [
                    "A RemoteInput object specifies input to be collected from a user. The object is then passed along with an intent inside a PendingIntent. Care should be taken to see that privacy information is not leaked.",
                    "The application listens for changes in the telephony environment.",
                    "The application uses Bluetooth functionality.",
                    "This application accesses the user's contacts.",
                    "This application queries the Calendar on the device.",
                    "This application requests the device build tag information from the system build properties. ",
                    "Information: The app returns the ISO country code equivalent to the SIM provider's country code. This can be considered data leakage if the information is sent to a remote server.",
                    "This app is reading the device model number or manufacturer.",
                    "The app computes a content URI given a lookup URI.",
                    "The application gets the mobile network operator name. This can be considered data leakage when combined with other indicators that can uniquely identify the device.",
                    "This application requests the device build fingerprint from the system build properties. ",
                    "This app is implementing Dropbox API interactivity. The Dropbox API allows developers to integrate a cloud storage solution. The API provides methods to read and write from Dropbox. This risk could allow users to transfer sensitive information.",
                    "This application requests the device's brand information from the system build properties. ",
                    "This app queries for the device version release information.",
                    "This application requests the device product information from the system build properties. ",
                    "This application requests the build identifier type from the system build properties. ",
                    "This application requests the device type from the system build properties. ",
                    "Information: This application accesses the properties of the device and the OS.",
                    "The application queries the device for the telephone number assigned. This can be data leakage if the phone number is sent outside the device.",
                    "The app sets a bundle of additional info data.",
                    "Opens an InputStream for the contact's photo and returns the photo as a byte stream.",
                    "This app implements a telephone call state change listener. ",
                    "Information: The application checks the current ready state of Bluetooth functionality.",
                    "Gets an auth token of the specified type for a particular account, prompting the user for credentials if necessary.",
                    "This app has turned off the ability to use cut copy and paste on some UI fields. This can assist to ensure sensitive information is not exposed.",
                    "Information: This provides access to implementations of cryptographic ciphers for encryption and decryption.",
                    "The app loads cryptographic key-stores."
                ],
                "intell_security": [
                    "The app connects to an application service, creating it if needed.",
                    "This application requests an instance of the SHA1 algorithm.",
                    "Information: The application receives notification when the device is rebooted. This can allow an app to run itself or a separate payload every time the device is restarted. ",
                    "The app uses the primary external storage.",
                    "Information: The application can obtain all available environment variables.",
                    "The application receives a reference to a system service called 'getSystemService'.",
                    "This package provides classes and interfaces to use the Secure Sockets Layer (SSL) protocol and the successor Transport Layer Security (TLS) protocol. ",
                    "This app can retrieve the list of running apps. ",
                    "The app utilizes the Java.io.File delete() method to perform a file deletion. This method is not a secure method of file deletion. Because the Android API does not provide a method to perform secure file deletion operations it is suggested to overwrite the file with random characters before performing the file delete operation when sensitive data is involved. Files are only marked for deletion and can be recovered using third-party utilities on a rooted device. ",
                    "The app retrieves a PendingIntent that performs a broadcast, similar to calling Context.sendBroadcast().",
                    "Information: This application retrieves information about any application package that is installed on the device.",
                    "We have identified declared permissions in the code. Permissions should be declared in the Android Manifest.xml file.",
                    "This app is configured to allow instant apps to be installed and executed.",
                    "This app uses a simplified version of the java.security.cert package.",
                    "The app is using native function calls.",
                    "This application issues SQL database commands. This is an informational finding.",
                    "This application uses random read-write access to the result set returned by database queries.",
                    "Multiple application names were discovered with the same code. Because this application may not be the original, close scrutiny of the technical report is advised. ",
                    "As a standard practice with many applications, this application loads external libraries at runtime. It will load the native library specified by the libname argument.",
                    "The application was found to contain highly obfuscated code at the binary level. This is an indication of binary protections put in place to prevent reverse engineering. ",
                    "This application uses Base64 encoding and decoding. Base64 is typically used in email/web communications but can be applied to any data set. This is an informational finding.",
                    "The app stores key mapped value strings to the SharedPreferences storage.",
                    "This application has functionality for cryptographic applications implementing algorithms for encryption, decryption, or key agreement. This is an informational finding.",
                    "The app registers a BroadcastReceiver.",
                    "This application fails the Source Code Reverse Engineering Exposure test as outlined by OWASP Mobile Top 10.",
                    "This application exposes source level metadata symbols and fails the testing outlined by OWASP Mobile Top 10.",
                    "This application fails the Static Data Exposure test as outlined by OWASP Mobile Top 10.",
                    "The app has been found to be MultiDex",
                    "This application has functionality that can allow a potential spoofing of the application's package name.",
                    "This app used the Java Security interface for parsing and managing certificates, certificate revocation lists (CRLs), and certification paths.",
                    "This app opens a secure (https) URL connection.",
                    "This app uses a secure (https) socket.",
                    "The app sets an explicit application package name that limits the components this Intent will resolve to. If left to the default value of null, all components in all applications will considered. If non-null, the Intent can only match the components in the given application package.",
                    "This app uses a cryptographically strong random number generator (RNG)."
                ],
                "overall_risk": "Out",
                "privacy": [
                    {
                        "Category": "Vulnerability",
                        "Risk Level": "High",
                        "desc": "Content Providers are implicitly insecure. They allow other applications on the device to request and share data. If sensitive information is accidentally leaked in one of these content providers all an attacker needs to do is call the content provider and the sensitive data will be exposed to the attacker by the application.This is cause for concern as any 3rd party application containing malicious code does not require any granted permissions in order to obtain sensitive information from these applications."
                    },
                    {
                        "Category": "Telephony",
                        "Risk Level": "High",
                        "desc": "Accesses the phone calls history."
                    },
                    {
                        "Category": "Data Leakage",
                        "Risk Level": "Medium",
                        "desc": "The app retrieves ClipBoard data contents."
                    },
                    {
                        "Category": "Media",
                        "Risk Level": "Medium",
                        "desc": "This app has access to the device microphone."
                    },
                    {
                        "Category": "Vulnerability",
                        "Risk Level": "Medium",
                        "desc": "The application stores inline API keys/values."
                    },
                    {
                        "Category": "Camera",
                        "Risk Level": "Medium",
                        "desc": "The application creates a new camera object to programmatically access the back-facing camera and potentially take user photos without consent."
                    },
                    {
                        "Category": "System",
                        "Risk Level": "Medium",
                        "desc": "This application requests the device manufacture information from the system build properties and is looking for specific Samsung models."
                    },
                    {
                        "Category": "Content",
                        "Risk Level": "Medium",
                        "desc": "This app can access and read the contents of the global clipboard."
                    },
                    {
                        "Category": "Camera",
                        "Risk Level": "Low",
                        "desc": "The application has access to the camera. Ensure it cannot take photo's without your knowledge. This is an information finding."
                    },
                    {
                        "Category": "Audio",
                        "Risk Level": "Low",
                        "desc": "This application has the functionality to record audio with the microphone. This functionality could allow the app to record audio at any time and without notification. This is an informational finding."
                    },
                    {
                        "Category": "Context",
                        "Risk Level": "Low",
                        "desc": "This application can read personal profile information stored on your device, such as your name and contact information. This means the app can identify you and may send your profile information to others. This is an informational finding."
                    },
                    {
                        "Category": "Identity",
                        "Risk Level": "Low",
                        "desc": "This application can read the contact data (phone numbers, addresses etc) and potentially with other functionality send it off the device. This is an informational finding."
                    },
                    {
                        "Category": "Telephony",
                        "Risk Level": "Low",
                        "desc": "This application can access the phone features of the device. This permission allows the application to determine the phone number and device IDs, whether a call is active, and the remote number connected by a call. This is an informational finding."
                    },
                    {
                        "Category": "Accounts",
                        "Risk Level": "Low",
                        "desc": "Allows access to the list of accounts in the Accounts Service."
                    },
                    {
                        "Category": "Logs",
                        "Risk Level": "Low",
                        "desc": "Allows an application to write (but not read) the user's contacts data."
                    },
                    {
                        "Category": "Storage",
                        "Risk Level": "Low",
                        "desc": "This application can write to external storage such as an SD Card. This is an informational finding."
                    }
                ],
                "privacy_risk": 64,
                "security": [
                    {
                        "Category": "System",
                        "Risk Level": "High",
                        "desc": "This app can load compiled code in APK and JAR files. This can include files located in external storage and potentially on the Internet."
                    },
                    {
                        "Category": "System",
                        "Risk Level": "High",
                        "desc": "The app uses a method to blindly load all apps and JAR files located in a directory enabling abuse by malicious parties."
                    },
                    {
                        "Category": "Context",
                        "Risk Level": "Medium",
                        "desc": "This app implements an app permissions method that can grant another calling app (potentially including a malicious one) the same permissions as the legitimate app."
                    },
                    {
                        "Category": "Package Manager",
                        "Risk Level": "Medium",
                        "desc": "Set the enabled setting for a package component (activity, receiver, service, provider). This setting overrides any enabled state which can be set by the component in its manifest."
                    },
                    {
                        "Category": "Code Analysis",
                        "Risk Level": "Medium",
                        "desc": "This app uses Java code reflection which enables an app to analyze and modify itself. An attacker can create unexpected control flow paths through the application, potentially by-passing security checks. Exploitation of this weakness can result in a form of code injection."
                    },
                    {
                        "Category": "Code Analysis",
                        "Risk Level": "Medium",
                        "desc": "This app implements the Intent 'StartService' which can cause information leakage if not configured correctly."
                    },
                    {
                        "Category": "Network",
                        "Risk Level": "Medium",
                        "desc": "The app modifies its user agent string. It is recommended that the developer use the properties derived from System.getProperty(\"http.agent\") or WebView(this).getSettings().getUserAgentString() to set the user agent string."
                    },
                    {
                        "Category": "Network",
                        "Risk Level": "Medium",
                        "desc": "This app uses network sockets functionality."
                    },
                    {
                        "Category": "Network",
                        "Risk Level": "Low",
                        "desc": "This application can change the network connectivity state. This is an informational finding."
                    },
                    {
                        "Category": "Address Book",
                        "Risk Level": "Low",
                        "desc": "This application can modify the data about contacts stored on the device, including the frequency with which they have been called, emailed, or communicated in other ways with specific contacts. This permission allows this application to delete contact data as well. This is an informational finding."
                    },
                    {
                        "Category": "Network",
                        "Risk Level": "Low",
                        "desc": "This application can create network sockets and use custom network protocols. The browser and other applications provide means to send data to the internet, so this permission is not required to send data to the internet. This is an informational finding."
                    },
                    {
                        "Category": "System",
                        "Risk Level": "Low",
                        "desc": "This application can change how the account data is synced and backed up. This is an informational finding."
                    },
                    {
                        "Category": "Accounts",
                        "Risk Level": "Low",
                        "desc": "This application can authenticate through the accounts on the device. This permission allows the application to add and remove accounts, confirm credentials and retrieve access tokens. This is an informational finding."
                    },
                    {
                        "Category": "Accounts",
                        "Risk Level": "Low",
                        "desc": "This application can perform operations like adding and removing accounts, and deleting their password. This is an informational finding."
                    },
                    {
                        "Category": "System",
                        "Risk Level": "Low",
                        "desc": "This application can generate a pop-up window that could potentially overlay other applications."
                    },
                    {
                        "Category": "System",
                        "Risk Level": "Low",
                        "desc": "This application can keep the device from going into sleep mode. If used improperly this could drain the device's power. This is an informational finding."
                    },
                    {
                        "Category": "Bluetooth",
                        "Risk Level": "Low",
                        "desc": "This application has the ability to connect to a bluetooth device that is already paired with the device. This is an informational finding."
                    },
                    {
                        "Category": "Audio",
                        "Risk Level": "Low",
                        "desc": "This application can control your audio settings such as volume levels. This is an informational finding."
                    },
                    {
                        "Category": "System",
                        "Risk Level": "Low",
                        "desc": "This application has the functionality to allow it to automatically start itself after a reboot. This is an informational finding."
                    }
                ],
                "security_risk": 66
            },
            "threats": {
                "detected": null,
                "detected_skip": 0,
                "scan_details": [],
                "status": "Waiting in the queue",
                "total": null
            }
        }
    }
}
```

#### Human Readable Output

>### Report:
>|behavior|md5|threats|
>|---|---|---|
>| sms: network: {"http_requests": null} count_sms: 0 telephony: null broadcast_receivers:  | f26cf1135f9d2ea60532a5a13c6fbed5 | total: null status: Waiting in the queue detected: null scan_details: detected_skip: 0 |


### file
***
Checks the reputation of an app in Zimperium.


#### Base Command

`file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file | The MD5 hash of the file. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| File.MD5 | String | MD5 hash of the file. | 
| File.SHA1 | String | SHA1 hash of the file. | 
| File.SHA256 | String | SHA256 hash of the file. | 
| File.Malicious.Vendor | String | For malicious files, the vendor that made the decision. | 


#### Command Example
```!file file=85525e9c1fd30a20848812e417f3bb1a using-brand=Zimperium```

#### Context Example
```
{
    "DBotScore": {
        "Indicator": "85525e9c1fd30a20848812e417f3bb1a",
        "Score": 1,
        "Type": "file",
        "Vendor": "Zimperium"
    },
    "File": {
        "MD5": "85525e9c1fd30a20848812e417f3bb1a"
    },
    "Zimperium": {
        "Application": {
            "classification": "Legitimate",
            "deviceCount": 1,
            "hash": "85525e9c1fd30a20848812e417f3bb1a",
            "metadata": {
                "activities": [
                    "com.google.android.apps.tachyon.appupdate.HardBlockActivity",
                    "com.google.android.apps.tachyon.call.feedback.BadCallRatingActivity",
                    "com.google.android.apps.tachyon.call.history.ExportHistoryActivity",
                    "com.google.android.apps.tachyon.call.oneonone.ui.OneOnOneCallActivity",
                    "com.google.android.apps.tachyon.call.postcall.ui.PostCallActivity",
                    "com.google.android.apps.tachyon.call.precall.OneOnOnePrecallActivity",
                    "com.google.android.apps.tachyon.call.precall.fullhistory.FullHistoryActivity",
                    "com.google.android.apps.tachyon.clips.share.ReceiveShareIntentActivity",
                    "com.google.android.apps.tachyon.clips.ui.ClipsComposerActivity",
                    "com.google.android.apps.tachyon.clips.ui.gallerypicker.GalleryPickerActivity",
                    "com.google.android.apps.tachyon.clips.ui.viewclips.ViewClipsActivity",
                    "com.google.android.apps.tachyon.externalcallactivity.ExternalCallActivity",
                    "com.google.android.apps.tachyon.groupcalling.creategroup.EditGroupActivity",
                    "com.google.android.apps.tachyon.groupcalling.creategroup.GroupCreationActivity",
                    "com.google.android.apps.tachyon.groupcalling.incall.InGroupCallActivity",
                    "com.google.android.apps.tachyon.groupcalling.incoming.IncomingGroupCallActivity",
                    "com.google.android.apps.tachyon.groupcalling.precall.PrecallScreenGroupActivity",
                    "com.google.android.apps.tachyon.groupcalling.precall.PrecallScreenGroupInviteActivity",
                    "com.google.android.apps.tachyon.invites.externalinvite.ExternalInviteActivity",
                    "com.google.android.apps.tachyon.invites.invitescreen.InviteScreenActivity",
                    "com.google.android.apps.tachyon.registration.countrycode.CountryCodeActivity",
                    "com.google.android.apps.tachyon.registration.enterphonenumber.PhoneRegistrationActivity",
                    "com.google.android.apps.tachyon.registration.onboarding.OnboardingActivity",
                    "com.google.android.apps.tachyon.settings.blockedusers.BlockedUsersActivity",
                    "com.google.android.apps.tachyon.settings.knockknock.KnockKnockSettingActivity",
                    "com.google.android.apps.tachyon.settings.notifications.NotificationSettingsActivity",
                    "com.google.android.apps.tachyon.settings.v2.AccountSettingsActivity",
                    "com.google.android.apps.tachyon.settings.v2.ApplicationSettingsActivity",
                    "com.google.android.apps.tachyon.settings.v2.CallSettingsActivity",
                    "com.google.android.apps.tachyon.settings.v2.MessageSettingsActivity",
                    "com.google.android.apps.tachyon.ui.blockusers.BlockUsersActivity",
                    "com.google.android.apps.tachyon.ui.duoprivacy.DuoPrivacyActivity",
                    "com.google.android.apps.tachyon.ui.launcher.LauncherActivity",
                    "com.google.android.apps.tachyon.ui.lockscreen.LockscreenTrampolineActivity",
                    "com.google.android.apps.tachyon.ui.main.MainActivity",
                    "com.google.android.apps.tachyon.ui.warningdialog.WarningDialogActivity",
                    "com.google.android.gms.common.api.GoogleApiActivity",
                    "com.google.android.libraries.social.licenses.LicenseActivity",
                    "com.google.android.libraries.social.licenses.LicenseMenuActivity",
                    "com.google.android.libraries.surveys.internal.view.SurveyActivity",
                    "com.google.android.play.core.common.PlayCoreDialogWrapperActivity",
                    "com.google.android.play.core.missingsplits.PlayCoreMissingSplitsActivity",
                    "com.google.research.ink.annotate.AnnotateActivity"
                ],
                "filename": "/data/app/com.google.android.apps.tachyon-5hQwDR1DIKxnBrAIkdNlmg==/base.apk",
                "package": "com.google.android.apps.tachyon",
                "permissions": [
                    "android.permission.ACCESS_NETWORK_STATE",
                    "android.permission.ACCESS_WIFI_STATE",
                    "android.permission.AUTHENTICATE_ACCOUNTS",
                    "android.permission.BLUETOOTH",
                    "android.permission.BROADCAST_STICKY",
                    "android.permission.CAMERA",
                    "android.permission.CHANGE_NETWORK_STATE",
                    "android.permission.FOREGROUND_SERVICE",
                    "android.permission.GET_ACCOUNTS",
                    "android.permission.GET_PACKAGE_SIZE",
                    "android.permission.INTERNET",
                    "android.permission.MANAGE_ACCOUNTS",
                    "android.permission.MODIFY_AUDIO_SETTINGS",
                    "android.permission.READ_APP_BADGE",
                    "android.permission.READ_CONTACTS",
                    "android.permission.READ_PHONE_STATE",
                    "android.permission.READ_PROFILE",
                    "android.permission.READ_SYNC_STATS",
                    "android.permission.RECEIVE_BOOT_COMPLETED",
                    "android.permission.RECORD_AUDIO",
                    "android.permission.VIBRATE",
                    "android.permission.WAKE_LOCK",
                    "android.permission.WRITE_CALL_LOG",
                    "android.permission.WRITE_CONTACTS",
                    "android.permission.WRITE_SYNC_SETTINGS",
                    "com.anddoes.launcher.permission.UPDATE_COUNT",
                    "com.android.launcher.permission.INSTALL_SHORTCUT",
                    "com.google.android.c2dm.permission.RECEIVE",
                    "com.google.android.providers.gsf.permission.READ_GSERVICES",
                    "com.htc.launcher.permission.READ_SETTINGS",
                    "com.htc.launcher.permission.UPDATE_SHORTCUT",
                    "com.huawei.android.launcher.permission.CHANGE_BADGE",
                    "com.huawei.android.launcher.permission.READ_SETTINGS",
                    "com.huawei.android.launcher.permission.WRITE_SETTINGS",
                    "com.majeur.launcher.permission.UPDATE_BADGE",
                    "com.oppo.launcher.permission.READ_SETTINGS",
                    "com.oppo.launcher.permission.WRITE_SETTINGS",
                    "com.samsung.android.app.telephonyui.permission.READ_SETTINGS_PROVIDER",
                    "com.samsung.android.app.telephonyui.permission.WRITE_SETTINGS_PROVIDER",
                    "com.samsung.android.aremoji.provider.permission.READ_STICKER_PROVIDER",
                    "com.samsung.android.livestickers.provider.permission.READ_STICKER_PROVIDER",
                    "com.samsung.android.provider.filterprovider.permission.READ_FILTER",
                    "com.samsung.android.provider.stickerprovider.permission.READ_STICKER_PROVIDER",
                    "com.sec.android.provider.badge.permission.READ",
                    "com.sec.android.provider.badge.permission.WRITE",
                    "com.sonyericsson.home.permission.BROADCAST_BADGE",
                    "com.sonymobile.home.permission.PROVIDER_INSERT_BADGE"
                ],
                "receivers": [
                    "androidx.work.impl.background.systemalarm.ConstraintProxy$BatteryChargingProxy",
                    "androidx.work.impl.background.systemalarm.ConstraintProxy$BatteryNotLowProxy",
                    "androidx.work.impl.background.systemalarm.ConstraintProxy$NetworkStateProxy",
                    "androidx.work.impl.background.systemalarm.ConstraintProxy$StorageNotLowProxy",
                    "androidx.work.impl.background.systemalarm.ConstraintProxyUpdateReceiver",
                    "androidx.work.impl.background.systemalarm.RescheduleReceiver",
                    "androidx.work.impl.diagnostics.DiagnosticsReceiver",
                    "androidx.work.impl.utils.ForceStopRunnable$BroadcastReceiver",
                    "com.google.android.apps.tachyon.call.notification.CallRetryNotifierReceiver",
                    "com.google.android.apps.tachyon.call.notification.InCallNotificationIntentReceiver",
                    "com.google.android.apps.tachyon.call.notification.MissedCallNotificationIntentReceiver",
                    "com.google.android.apps.tachyon.clips.notification.MessagesNotificationIntentReceiver",
                    "com.google.android.apps.tachyon.common.applifecycle.AppInstallReceiver",
                    "com.google.android.apps.tachyon.common.applifecycle.AppUpdateReceiver",
                    "com.google.android.apps.tachyon.common.applifecycle.BootReceiver",
                    "com.google.android.apps.tachyon.common.applifecycle.LocaleChangeReceiver",
                    "com.google.android.apps.tachyon.groupcalling.incall.InGroupCallNotificationIntentReceiver",
                    "com.google.android.apps.tachyon.groupcalling.incoming.IncomingGroupCallIntentReceiver",
                    "com.google.android.apps.tachyon.groupcalling.incoming.IncomingGroupCallNotificationIntentReceiver",
                    "com.google.android.apps.tachyon.groupcalling.notification.GroupUpdateNotificationReceiver",
                    "com.google.android.apps.tachyon.invites.invitehelper.IntentChooserCallbackReceiver",
                    "com.google.android.apps.tachyon.net.fcm.CjnNotificationIntentReceiver",
                    "com.google.android.apps.tachyon.net.fcm.GenericFcmEventHandlerNotificationIntentReceiver",
                    "com.google.android.apps.tachyon.notifications.engagement.EngagementNotificationIntentReceiver",
                    "com.google.android.apps.tachyon.notifications.receiver.BasicNotificationIntentReceiver",
                    "com.google.android.apps.tachyon.phenotype.PhenotypeBroadcastReceiver",
                    "com.google.android.apps.tachyon.ping.notification.PingNotificationIntentReceiver",
                    "com.google.android.apps.tachyon.registration.SystemAccountChangedReceiver",
                    "com.google.android.apps.tachyon.registration.notification.RegistrationNotificationIntentReceiver",
                    "com.google.android.apps.tachyon.simdetection.SimStateBroadcastReceiver",
                    "com.google.android.libraries.internal.growth.growthkit.inject.GrowthKitBootCompletedBroadcastReceiver",
                    "com.google.android.libraries.internal.growth.growthkit.internal.debug.TestingToolsBroadcastReceiver",
                    "com.google.android.libraries.internal.growth.growthkit.internal.experiments.impl.PhenotypeBroadcastReceiver",
                    "com.google.android.libraries.phenotype.client.stable.PhenotypeStickyAccount$AccountRemovedBroadcastReceiver",
                    "com.google.firebase.iid.FirebaseInstanceIdReceiver"
                ],
                "services": [
                    "androidx.work.impl.background.systemalarm.SystemAlarmService",
                    "androidx.work.impl.background.systemjob.SystemJobService",
                    "androidx.work.impl.foreground.SystemForegroundService",
                    "com.google.android.apps.tachyon.call.service.CallService",
                    "com.google.android.apps.tachyon.clientapi.ClientApiService",
                    "com.google.android.apps.tachyon.contacts.reachability.ReachabilityService",
                    "com.google.android.apps.tachyon.contacts.sync.DuoAccountService",
                    "com.google.android.apps.tachyon.contacts.sync.SyncService",
                    "com.google.android.apps.tachyon.net.fcm.CallConnectingForegroundService",
                    "com.google.android.apps.tachyon.net.fcm.FcmReceivingService",
                    "com.google.android.apps.tachyon.telecom.TachyonTelecomConnectionService",
                    "com.google.android.apps.tachyon.telecom.TelecomFallbackService",
                    "com.google.android.libraries.internal.growth.growthkit.internal.jobs.impl.GrowthKitBelowLollipopJobService",
                    "com.google.android.libraries.internal.growth.growthkit.internal.jobs.impl.GrowthKitJobService",
                    "com.google.apps.tiktok.concurrent.InternalForegroundService",
                    "com.google.firebase.components.ComponentDiscoveryService",
                    "com.google.firebase.messaging.FirebaseMessagingService"
                ],
                "signature": "6c22867349d7e4b05b7ebb333056236f",
                "subject": {
                    "commonName": "corp_tachyon",
                    "countryName": "US",
                    "localityName": "Mountain View",
                    "organizationName": "Google Inc.",
                    "organizationalUnitName": "Android",
                    "stateOrProvinceName": "California"
                }
            },
            "modifiedDate": "2020-06-10 10:07:22 UTC",
            "name": "Duo",
            "namespace": "com.google.android.apps.tachyon",
            "objectId": "ebdfed24-951e-45f5-845a-2c163c53fc47",
            "privacyEnum": 1,
            "privacyRisk": "Medium",
            "processState": "AVAILABLE",
            "score": 0,
            "securityEnum": 1,
            "securityRisk": "Medium",
            "systemToken": "paxsoar",
            "type": 0,
            "version": "91.0.315322534.DR91_RC03"
        }
    }
}
```

#### Human Readable Output

>### Hash 85525e9c1fd30a20848812e417f3bb1a reputation:
>|objectId|hash|name|version|classification|score|privacyEnum|securityEnum|
>|---|---|---|---|---|---|---|---|
>| ebdfed24-951e-45f5-845a-2c163c53fc47 | 85525e9c1fd30a20848812e417f3bb1a | Duo | 91.0.315322534.DR91_RC03 | Legitimate | 0.0 | 1 | 1 |
