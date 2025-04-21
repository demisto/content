Fetch and investigate mobile security alerts, generated based on anomalous or unauthorized activities detected on a user's mobile device.
This integration was integrated and tested with version v.5.24.0 of Zimperium v2.

This is the default integration for this content pack when configured by the Data Onboarder in Cortex XSIAM.

Some changes have been made that might affect your existing content. 
If you are upgrading from a previous version of this integration, see [Breaking Changes](#breaking-changes-from-the-previous-version-of-this-integration).

## Configure Zimperium v2 in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL (e.g., https://mtduat.zimperium.com) |  | True |
| Client ID |  | True |
| Client Secret |  | True |
| Fetch incidents |  | False |
| Search Params (e.g, severityName=CRITICAL,teamId=myId) | Comma-separated list of search parameters and its values. Same as for the "zimperium-threat-search" command. | False |
| Max fetch |  | False |
| First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days) |  | False |
| Advanced: Minutes to look back when fetching | Use this parameter to determine how far back to look in the search for incidents that were created before the last run time and did not match the query when they were created. | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Incident type |  |  |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### zimperium-users-search

***
Search users. Only a user created as a "Team admin" is authorized to perform this request. Also, it will only get information about the teams that this user is associated with. Users that are not part of any team (such as account admin) won’t appear in the response.

#### Base Command

`zimperium-users-search`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | The ID of the user to search. | Optional | 
| page_size | Maximum number of results to retrieve in each page. If a limit is not provided, default is 50. | Optional | 
| page | Page number. Default is 0. | Optional | 
| limit | Number of total results to return. Default is 50. | Optional | 
| team_id | Used to filter the user data by the team the user belongs to. | Optional | 
| email | The email of the user to search. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Zimperium.User.id | String | The ID of the Zimperium user. | 
| Zimperium.User.created | Date | The date and time that the user was created. | 
| Zimperium.User.email | String | The email address of the user. | 
| Zimperium.User.firstName | String | The first name of the user. | 
| Zimperium.User.languagePreference | Unknown | The language preference for the user. | 
| Zimperium.User.lastLogin | Unknown | The time of the last login of the user. | 
| Zimperium.User.lastName | String | The last name of the user. | 
| Zimperium.User.middleName | Unknown | The middle name of the user. | 
| Zimperium.User.modified | Date | The date and time that the user was modified. | 
| Zimperium.User.notificationEmail | String | The email address for the user's notifications. | 
| Zimperium.User.phone | Unknown | The phone number of the user. | 
| Zimperium.User.role.id | String | The role identifier of the user. | 
| Zimperium.User.role.name | String | The role name of the user. | 
| Zimperium.User.role.scopeBounds | String | The role scope for a user. | 
| Zimperium.User.teams.id | String | The ID of the team of the user. | 
| Zimperium.User.teams.name | String | The name of the team of the user. | 
| Zimperium.User.validated | Boolean | The user's validated status. | 

#### Command example
```!zimperium-users-search user_id="1" team_id="1"```
#### Context Example
```json
{
    "Zimperium": {
        "User": {
            "created": "2024-01-21T11:02:08.789+00:00",
            "email": "email1@email.com",
            "firstName": "name",
            "id": "1",
            "languagePreference": null,
            "lastLogin": null,
            "lastName": "name",
            "middleName": null,
            "modified": "2024-01-21T11:02:08.789+00:00",
            "notificationEmail": "email1@email.com",
            "phone": null,
            "role": {
                "id": "1",
                "name": "Team Admin",
                "scopeBounds": "TEAM_BOUNDED"
            },
            "teams": [
                {
                    "id": "1",
                    "name": "Default"
                }
            ],
            "validated": false
        }
    }
}
```

#### Human Readable Output

>### Users Search Results
>| Id | First Name | Last Name |Email|Created|Role|Teams|
>|----|------------|-----------|---|---|---|---|
>| 1  | name       | name      | email1@email.com | 2024-01-21T11:02:08.789+00:00 | scopeBounds: TEAM_BOUNDED<br/>name: Team Admin<br/>id: 1 | {'name': 'Default', 'id': '1'} |


### zimperium-devices-search

***
Search devices.

#### Base Command

`zimperium-devices-search`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | The ID of the device to search for. | Optional | 
| page_size | Maximum number of results to retrieve in each page. If a limit is not provided, default is 50. | Optional | 
| page | Page number. Default is 0. | Optional | 
| limit | Number of total results to return. Default is 50. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Zimperium.Device.accountId | String | The account identifier of the device. | 
| Zimperium.Device.activationName | String | The activation name of the device. | 
| Zimperium.Device.additionalDeviceInfo | Unknown | The additional device information. | 
| Zimperium.Device.agentType | Number | The agent type of the device. | 
| Zimperium.Device.appStatus | String | The app status. | 
| Zimperium.Device.appVersions | Unknown | The app version of the device. | 
| Zimperium.Device.bundleId | Unknown | The bundle identifier of the device. | 
| Zimperium.Device.created | Date | The date and time that the device was created. | 
| Zimperium.Device.deleted | Boolean | Whether the device was deleted. | 
| Zimperium.Device.developerOptionsOn | Boolean | Whether the developer options are on. | 
| Zimperium.Device.deviceOwner.email | String | The email address of the device owner. | 
| Zimperium.Device.fullType | String | The device's full type. | 
| Zimperium.Device.groupId | String | The device group identifier. | 
| Zimperium.Device.id | String | The unique identifier of the device. | 
| Zimperium.Device.lastSeen | Date | The time when the device was last seen. | 
| Zimperium.Device.lockScreenUnprotected | Boolean | Whether the device's lockscreen is unprotected or not. | 
| Zimperium.Device.model | String | The model of the device. | 
| Zimperium.Device.os.id | Number | The operating system identifier of the device. | 
| Zimperium.Device.os.maxOsVersion | String | The maximum operating system version of the device. | 
| Zimperium.Device.os.name | String | The operating system name. | 
| Zimperium.Device.os.osVersionId | Number | The operating system version identifier of the device. | 
| Zimperium.Device.os.policyCompliant | Boolean | Whether the operating system policy is compliant in the device. | 
| Zimperium.Device.os.type | String | The operating system type of the device. | 
| Zimperium.Device.os.version | String | The operating system version of the device. | 
| Zimperium.Device.processed | Boolean | Whether the device is processed. | 
| Zimperium.Device.processedAt | Date | The date and time that the device was processed. | 
| Zimperium.Device.riskPosture | Number | The risk posture of the device. | 
| Zimperium.Device.riskPostureName | String | The risk posture name of the device. | 
| Zimperium.Device.teamId | String | The team ID of the device. | 
| Zimperium.Device.teamName | String | The team name of the device. | 
| Zimperium.Device.threatState | Unknown | The threat state information. | 
| Zimperium.Device.zappInstance.agentType | Number | The agent type of the device. | 
| Zimperium.Device.zappInstance.buildNumber | String | The build number of the zappInstance. | 
| Zimperium.Device.zappInstance.bundleId | String | The bundle identifier of the zappInstance. | 
| Zimperium.Device.zappInstance.groupId | String | The Zimperium device group identifier for the zappInstance. | 
| Zimperium.Device.zappInstance.id | String | The ID of the zappInstance. | 
| Zimperium.Device.zappInstance.lastSeen | Date | The last seen timestamp for the zappInstance. | 
| Zimperium.Device.zappInstance.name | String | The name of the zappInstance. | 
| Zimperium.Device.zappInstance.policiesInfo | String | The policies information. | 
| Zimperium.Device.zappInstance.version | String | The version of the zappInstance. | 
| Zimperium.Device.zappInstance.zappId | String | The ID of the zappInstance. | 
| Zimperium.Device.zappInstance.zbuildNumber | String | The Zimperium device's zappInstance. | 
| Zimperium.Device.zappInstance.zversion | String | The device's zappInstance version. | 
| Zimperium.Device.zdeviceId | String | The zdevice ID. | 
| Zimperium.Device.appVersions.appVersionId | String | The app version ID of the device. | 
| Zimperium.Device.appVersions.bundleId | String | The bundle identifier of the app versions. | 
| Zimperium.Device.os.maxOsPatchDate | String | The max patch date of operating system of the device. | 
| Zimperium.Device.os.patchDate | Date | The operating system patch date of the device. | 
| Zimperium.Device.threatState.numberOfCriticalThreats | Number | The number of critical threats detected on the device. | 
| Zimperium.Device.zappInstance.permissionsState | Unknown | The permissions state on the device. | 
| Zimperium.Device.dormancyProcessed | Boolean | The device's dormancy processed status. | 
| Zimperium.Device.os.versionUpgradeable | Boolean | The operating system version upgradeable for the device. | 
| Zimperium.Device.threatState | Unknown | The threat state of the device. | 
| Zimperium.Device.zappInstance.policiesInfo | Unknown | The device policies info. | 
| Zimperium.Device.isJailbroken | Boolean | Whether the endpoint's device is jailbroken or not. | 

#### Command example
```!zimperium-devices-search device_id="5"```
#### Context Example
```json
{
    "Zimperium": {
        "Device": {
            "accountId": "2",
            "additionalDeviceInfo": [],
            "agentType": 2,
            "appStatus": "ACTIVE",
            "appVersions": [],
            "bundleId": "com.zimperium",
            "created": 1703082619686,
            "deleted": false,
            "developerOptionsOn": true,
            "deviceOwner": {
                "email": "email"
            },
            "dormancyProcessed": false,
            "fullType": "iPhone14,5",
            "groupId": "1",
            "id": "5",
            "lastSeen": 1703083587626,
            "lockScreenUnprotected": true,
            "model": "iphone145",
            "os": {
                "id": 2,
                "maxOsVersion": "17.2",
                "name": "ios",
                "osVersionId": 57106,
                "policyCompliant": false,
                "type": "iOS",
                "version": "16.3",
                "versionUpgradeable": true
            },
            "processed": true,
            "processedAt": 1703082624526,
            "riskPosture": 2,
            "riskPostureName": "ELEVATED",
            "teamId": "1",
            "teamName": "Default",
            "threatState": {
                "addOrRemoveCritical": false,
                "addOrRemoveRisky": false,
                "criticalThreats": [],
                "hadCriticalMitigation": false,
                "hadRiskyMitigation": false,
                "numberOfRiskyThreats": 5,
                "riskyThreats": [
                    "5"
                ]
            },
            "zappInstance": [
                {
                    "agentType": 2,
                    "buildNumber": "202",
                    "bundleId": "com.zimperium",
                    "externalTrackingId1": "",
                    "externalTrackingId2": "",
                    "groupId": "1",
                    "id": "3",
                    "lastSeen": 1703083587626,
                    "name": "MTD",
                    "policiesInfo": [
                        
                        {
                            "deployedAt": 1702300970000,
                            "downloadedAt": 1703082621000,
                            "hash": "0d",
                            "type": "Threat iOS"
                        }
                    ],
                    "serverlessDetection": false,
                    "version": "5.2.16",
                    "zappId": "c2",
                    "zbuildNumber": "202",
                    "zversion": "5.2.16"
                }
            ],
            "zdeviceId": "AF"
        }
    }
}
```

#### Human Readable Output

>### Device Search Results
>|Risk Posture Name|Id|Model|Os|Bundle Id|Last Seen|
>|---|---|---|---|---|---|
>| ELEVATED | 5 | iphone145 | id: 2<br/>name: ios<br/>type: iOS<br/>version: 16.3<br/>versionUpgradeable: true<br/>maxOsVersion: 17.2<br/>osVersionId: 57106<br/>policyCompliant: false | com.zimperium | 2023-12-20 14:46:27 |


### zimperium-report-get

***
Gets a report.

#### Base Command

`zimperium-report-get`

#### Input

| **Argument Name** | **Description**                                                                                                                                                  | **Required** |
| --- |------------------------------------------------------------------------------------------------------------------------------------------------------------------| --- |
| importance | The importance of the threat. Possible values are: Low, Medium, High, All. Default is High.                                                                      | Optional |
| app_version_id | The ID of the app version for which to get a JSON report. Can be retrieved using the zimperium-app-version-list command, in the field "Zimperium.AppVersion.id". | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Zimperium.Report.ContentInformation | String | The content of the report. | 
| Zimperium.Report.glob | Number | The glob pattern for the Zimperium report. | 
| Zimperium.Report.platform | String | The platform on which the report was created. | 
| Zimperium.Report.report.androidAnalysis | String | The android analysis of the report. | 
| Zimperium.Report.report.appProperties | String | The app properties. | 
| Zimperium.Report.report.certificate | String | The certificate. | 
| Zimperium.Report.report.communications | String | The communications. | 
| Zimperium.Report.report.contentInformation | String | The content information of the report. | 
| Zimperium.Report.report.distribution | String | The report distribution. | 
| Zimperium.Report.report.jsonVersion | String | The JSON version of the report. | 
| Zimperium.Report.report.riskProfile | String | The risk profile. | 
| Zimperium.Report.report.scanDetails | Unknown | The description of the scan details for the report. | 
| Zimperium.Report.report.scanVersion | Unknown | The scan version of the Zimperium report. | 
| Zimperium.Report.report.vulnerabilities | Unknown | The vulnerabilities found in the report. | 
| Zimperium.Report.result | Number | The Zimperium report result. | 

#### Command example
```!zimperium-report-get app_version_id="61" importance="Low"```
#### Context Example
```json
{
    "Zimperium": {
        "Report": {
            "ContentInformation": "Copyright 2024 Zimperium",
            "glob": 1,
            "platform": "android",
            "report": {
                "androidAnalysis": {},
                "appProperties": {
                    "extra": {
                        "itunesAppID": ""
                    },
                    "md5": "1",
                    "name": "Name",
                    "packageName": "com.url",
                    "packageSize": 101918436,
                    "platform": "android",
                    "sdkVersion": 22,
                    "sha1": "1",
                    "sha256": "1",
                    "version": "2.12.0",
                    "versionCode": "1"
                },
                "certificate": {
                    "SHA1 fingerprint": "1",
                    "SHA256 fingerprint": "1",
                    "issuer": {
                        "CN": "CN",
                        "O": "O"
                    },
                    "owner": {
                        "CN": "CN",
                        "O": "O"
                    }
                },
                "contentInformation": {
                    "copyright": "Copyright 2024 Zimperium"
                },
                "distribution": {
                    "marketData": []
                },
                "jsonVersion": "https://json-schema.org/draft/2020-12/schema",
                "riskProfile": {
                    "malwareDetection": "",
                    "malwareFamily": "",
                    "malwareName": "",
                    "overallRisk": "High",
                    "privacyRisk": 30,
                    "securityRisk": 79
                },
                "scanDetails": [
                    {
                        "compliance": [],
                        "description": "The app is using unity",
                        "importance": "Low",
                        "kind": "Code Analysis",
                        "location": [],
                        "riskType": "security"
                    }
                ],
                "scanVersion": {
                    "dynamicScan": false,
                    "ruleVersion": "1",
                    "scanDateTime": "2023-12-19T18:49:01+0000",
                    "scanEngine": "2.6.7",
                    "scanSucces": "Done",
                    "scanTargetOS": "android",
                    "scoreDateTime": "2023-12-19T18:49:00+0000"
                },
                "vulnerabilities": {}
            },
            "result": 1
        }
    }
}
```

#### Human Readable Output

>### Report
>|Risk Type|Kind|Description|Location|Importance|
>|---|---|---|---|---|
>| security | Code Analysis | The app is using unity |  | Low |
>| privacy | Capabilities | This app implements the SDK. This SDK has functionality that could create screenshots or screen recordings and potentially send them off device too an external resource. | com.sdk | Low |
>| privacy | Backup | This app has disabled the backup feature in Android. This can assist in protecting sensitive information from being exposed in the backup location. |  | Low |



#### Base Command

`zimperium-threat-search`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| after | The date in the criteria after which the threat occurred. | Required | 
| before | The date in the criteria before which the threat occurred. | Optional | 
| search_params | A comma-separated list of parameter and their values by which to filter your request. For example: 'device.os.version=7.1.1,vectorName=Device'. The parameters table is available under "Threat API Details" section in the "Threats" section, of the Zimperium API documentation, or on the website at https://mtduat.zimperium.com/ziap-docs/zips-docs/api/api_details_threat.html#optional-search-parameters-supported.| Optional | 
| team_id | Used to filter the user data by the team the user belongs to. | Optional | 
| os | Used to filter by the operating system. Possible values are: ios, android. | Optional | 
| severity | The severity of the threat. Possible values are: LOW, NORMAL, ELEVATED, CRITICAL. | Optional | 
| page_size | Maximum number of results to retrieve in each page. If a limit is not provided, default is 50. | Optional | 
| page | Page number. Default is 0. | Optional | 
| limit | Number of total results to return. Default is 50. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Zimperium.Threat.id | String | The ID of the threat. | 
| Zimperium.Threat.accountId | String | The account identifier of the threat. | 
| Zimperium.Threat.activationName | String | The activation name of the threat. | 
| Zimperium.Threat.agentType | Number | The agent type for the threat. | 
| Zimperium.Threat.arpTablesInfo | Unknown | The ARP tables information for the devices. | 
| Zimperium.Threat.categoryId | Number | The category of the threat. | 
| Zimperium.Threat.classification | Number | The classification of the threat. | 
| Zimperium.Threat.classificationName | String | The classification name for the threat. | 
| Zimperium.Threat.detectionFiles | Unknown | The threat detection files. | 
| Zimperium.Threat.device.id | String | The unique identifier of the device. | 
| Zimperium.Threat.device.mamDeviceId | String | The mobile application management (MAM) ID of the device. | 
| Zimperium.Threat.device.mdmDeviceId | String | The mobile device management (MDM) ID of the device. | 
| Zimperium.Threat.device.model | String | The model of the device the threat was detected on. | 
| Zimperium.Threat.device.os.id | Number | The operating system identifier of the device the threat was detected on. | 
| Zimperium.Threat.device.os.name | String | The operating system name for the device. | 
| Zimperium.Threat.device.os.version | String | The operating system version of the device. | 
| Zimperium.Threat.device.zdeviceId | String | The zDevice ID of the device. | 
| Zimperium.Threat.deviceId | String | The unique identifier of the device the threat was detected on. | 
| Zimperium.Threat.deviceOwner | String | The owner of the device. | 
| Zimperium.Threat.eventProcessedTimestamp | Date | The timestamp when the threat event was processed. | 
| Zimperium.Threat.eventReceivedTimestamp | Date | The timestamp when the threat event was received. | 
| Zimperium.Threat.generalInfo.actionTriggered | String | The threat action triggered on a threat. | 
| Zimperium.Threat.generalInfo.bssid | String | The Basic Service Set Identifier (BSSID) of the threat. | 
| Zimperium.Threat.generalInfo.deviceTimestamp | Date | The timestamp of the endpoint's device. | 
| Zimperium.Threat.generalInfo.jailbreakReasons | String | The jailbreak reasons for the threat. | 
| Zimperium.Threat.generalInfo.ssid | String | The service set identifier (SSID) for the threat. | 
| Zimperium.Threat.generalInfo.timeInterval | Number | The time interval for a threat. | 
| Zimperium.Threat.groupId | String | The ID of the threat group. | 
| Zimperium.Threat.lastModified | Date | The time the threat was last modified. | 
| Zimperium.Threat.mitigationEvents | Unknown | The mitigation events for the threat. | 
| Zimperium.Threat.nearByNetworks | Unknown | The nearby networks for the threat. | 
| Zimperium.Threat.networkStatistics | Unknown | The Zimperium threat network statistics. | 
| Zimperium.Threat.os | String | The operating system. | 
| Zimperium.Threat.policiesInfo.deployedAt | Date | The date that the threat policy was deployed. | 
| Zimperium.Threat.policiesInfo.downloadedAt | Date | The date when the threat policy was downloaded. | 
| Zimperium.Threat.policiesInfo.hash | String | The hash of the threat policy information. | 
| Zimperium.Threat.policiesInfo.type | String | The threat policy type. | 
| Zimperium.Threat.processList.parentProcessId | String | The parent process ID for a threat's process. | 
| Zimperium.Threat.processList.processId | String | The process ID for the threat process. | 
| Zimperium.Threat.processList.processName | String | The process name for the threat. | 
| Zimperium.Threat.processList.service | String | The services associated with the process list. | 
| Zimperium.Threat.processList.user | String | The users and processes that are involved in the threat process. | 
| Zimperium.Threat.responses.eventId | String | The unique identifier for an event in the threat response. | 
| Zimperium.Threat.responses.responseId | Number | The response identifier for a threat's response. | 
| Zimperium.Threat.responses.timestamp | Date | The timestamp of the threat response. | 
| Zimperium.Threat.runningServices | Unknown | The running services. | 
| Zimperium.Threat.severity | Number | The severity of the threat. | 
| Zimperium.Threat.severityName | String | The severity name of the threat. | 
| Zimperium.Threat.simulated | Boolean | Is the threat simulated. | 
| Zimperium.Threat.state | Number | The threat state. | 
| Zimperium.Threat.suspiciousUrlInfo | Unknown | The suspicious URL information. | 
| Zimperium.Threat.teamId | String | The ID of the threat team for an incident. | 
| Zimperium.Threat.teamName | String | The threat team name for the Incident. | 
| Zimperium.Threat.threatTypeId | Number | The threat type identifier for the threat. | 
| Zimperium.Threat.threatTypeName | String | The threat type for the threat. | 
| Zimperium.Threat.timestamp | Date | The timestamp of the threat. | 
| Zimperium.Threat.timestampInfo | Unknown | The timestamp information of the threat. | 
| Zimperium.Threat.vector | Number | The threat vector for the incident. | 
| Zimperium.Threat.vectorName | String | The vector name for a threat. | 
| Zimperium.Threat.zappId | String | The Zimperium threat app identifier. | 
| Zimperium.Threat.zappInstance | Unknown | The threat Zapp instance information. | 
| Zimperium.Threat.zappInstanceId | String | The Zapp threat instance ID. | 
| Zimperium.Threat.zeventId | String | The Zimperium threat event identifier. | 
| Zimperium.Threat.arpTablesInfo | Unknown | The ARP tables info for the threat. | 
| Zimperium.Threat.locationInfo.geoPoint.lat | Number | The latitude of the geoPoint. | 
| Zimperium.Threat.locationInfo.geoPoint.lon | Number | The longitude of the geoPoint. | 
| Zimperium.Threat.locationInfo.source | String | The threat's source location information. | 
| Zimperium.Threat.generalInfo.expectedOsVersion | String | The expected operating system version for the threat. | 
| Zimperium.Threat.generalInfo.vulnerableOsVersion | String | The vulnerable operating system version for the threat. | 
| Zimperium.Threat.generalInfo.vulnerableSecurityPatch | String | The vulnerable security patch for the endpoint. | 
| Zimperium.Threat.mitigatedAt | Date | The date when the Threat was mitigated. | 

#### Command example
```!zimperium-threat-search after="3 month" team_id="33" limit=1```
#### Context Example
```json
{
    "Zimperium": {
        "Threat": {
            "accountId": "25",
            "activationName": "user@email.com",
            "agentType": 2,
            "arpTablesInfo": {
                "before": [
                    {
                        "ip": "1.1.1.1",
                        "mac": "1.1.1.1"
                    }
                ]
            },
            "categoryId": 15,
            "classification": 1,
            "classificationName": "CRITICAL",
            "detectionFiles": [],
            "device": {
                "id": "6",
                "mamDeviceId": "",
                "mdmDeviceId": "",
                "model": "ONEPLUS A5000",
                "os": {
                    "id": 1,
                    "name": "ANDROID",
                    "version": "7.1.1"
                },
                "zdeviceId": "5"
            },
            "deviceId": "6",
            "deviceOwner": "user@email.com",
            "eventProcessedTimestamp": 1702393167374,
            "eventReceivedTimestamp": 1702393167359,
            "generalInfo": {
                "actionTriggered": "Silent Alert",
                "deviceTimestamp": 1702393165000,
                "jailbreakReasons": "SELinux disabled",
                "timeInterval": 8
            },
            "groupId": "37",
            "id": "d7",
            "lastModified": 1702393165000,
            "mitigationEvents": [],
            "nearByNetworks": [],
            "networkStatistics": [],
            "os": "android",
            "policiesInfo": [
                {
                    "deployedAt": 1701806956000,
                    "downloadedAt": 1702393157000,
                    "type": "App Policy Android v2"
                }
            ],
            "processList": [
                {
                    "parentProcessId": "1585",
                    "processId": "7839",
                    "processName": "com.zimperium",
                    "service": "n/a",
                    "user": "1"
                }
            ],
            "responses": [
                {
                    "eventId": "1",
                    "responseId": 3,
                    "timestamp": 1702393165000
                }
            ],
            "runningServices": [],
            "severity": 3,
            "severityName": "CRITICAL",
            "simulated": false,
            "state": 1,
            "suspiciousUrlInfo": {},
            "teamId": "33",
            "teamName": "Default",
            "threatTypeId": 37,
            "threatTypeName": "SYSTEM TAMPERING",
            "timestamp": 1702393165000,
            "timestampInfo": {
                "timestamp": 1702393165000,
                "toTheDay": 1702339200000,
                "toTheHour": 1702389600000,
                "toTheMinute": 1702393140000,
                "toTheSecond": 1702393165000
            },
            "vector": 2,
            "vectorName": "Device",
            "zappId": "40",
            "zappInstance": {
                "buildNumber": "230829190",
                "bundleId": "com.zimperium",
                "id": "63",
                "name": "MTD",
                "version": "5.2.14",
                "zbuildNumber": "23082919",
                "zversion": "5.2.14"
            },
            "zappInstanceId": "63",
            "zeventId": "a1"
        }
    }
}
```

#### Human Readable Output

>### Threat Search Result
>|Id|Severity Name|State|Vector Name|Threat Type Name|Os|Device Owner|Device Id|Team Name|Timestamp|
>|---|---|---|---|---|---|---|---|---|---|
>| d7 | CRITICAL | 1 | Device | SYSTEM TAMPERING | android | user@email.com | 6 | Default | 2023-12-12 14:59:25 |



### zimperium-app-version-list

***
List the app versions.

#### Base Command

`zimperium-app-version-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| bundle_id | The bundle ID of the app for which to get its app version. | Optional | 
| page_size | Maximum number of results to retrieve in each page. If a limit is not provided, default is 50. | Optional | 
| page | Page number. Default is 0. | Optional | 
| limit | Number of total results to return. Default is 50. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Zimperium.AppVersion.id | String | The ID of the threat. | 
| Zimperium.AppVersion.accountId | String | The account identifier for the Zimperium app version. | 
| Zimperium.AppVersion.bundleId | String | The bundle identifier for the Zimperium app version. | 
| Zimperium.AppVersion.classification | String | The classification of the Zimperium app version. | 
| Zimperium.AppVersion.created | Date | When the app version was created. | 
| Zimperium.AppVersion.hash | String | The hash of the Zimperium app version. | 
| Zimperium.AppVersion.name | String | The name of the Zimperium app version. | 
| Zimperium.AppVersion.platform | String | The platform on which the Zimperium app version is running. | 
| Zimperium.AppVersion.platformId | Number | The platform identifier for the Zimperium app version. | 
| Zimperium.AppVersion.privacy | String | The privacy setting for the app version. | 
| Zimperium.AppVersion.privacyRisk | Number | The privacy risk for the Zimperium app version. | 
| Zimperium.AppVersion.processState | String | The process state of the app version. | 
| Zimperium.AppVersion.reportRequestId | String | The Zimperium app version report request ID. | 
| Zimperium.AppVersion.riskVersion | String | The risk version of the Zimperium app version. | 
| Zimperium.AppVersion.security | String | The security of the Zimperium app version. | 
| Zimperium.AppVersion.securityRisk | Number | The security risk of the  Zimperium app version. | 
| Zimperium.AppVersion.source | String | The Zimperium app version source. | 
| Zimperium.AppVersion.updatedOn | Date | The date and time when the app version was updated. | 
| Zimperium.AppVersion.version | String | The version of the  Zimperium app version. | 
| Zimperium.AppVersion.developerName | String | The developer name for the Zimperium app version. | 
| Zimperium.AppVersion.developerSignature | String | The developer signature for the  Zimperium app version. | 
| Zimperium.AppVersion.filename | String | The filename of the Zimperium app version. | 
| Zimperium.AppVersion.managed | Boolean | Whether the app version is managed. | 

#### Command example
```!zimperium-app-version-list bundle_id="com.url"```
#### Context Example
```json
{
    "Zimperium": {
        "AppVersion": [
            {
                "accountId": "2",
                "bundleId": "com.url",
                "classification": "LEGIT",
                "created": 1702304668599,
                "hash": "E3",
                "id": "7",
                "name": "Name",
                "platform": "android",
                "platformId": 1,
                "privacy": "Low",
                "privacyRisk": 30,
                "processState": "AVAILABLE",
                "reportRequestId": "E3",
                "riskVersion": "2.12.0",
                "security": "High",
                "securityRisk": 79,
                "source": "UPLOAD",
                "updatedOn": 1702308488217,
                "version": "2.12.0"
            },
            {
                "accountId": "2",
                "bundleId": "com.url",
                "classification": "LEGIT",
                "created": 1702305485276,
                "developerName": "TShih",
                "developerSignature": "02",
                "filename": "/tmp/sample",
                "hash": "04",
                "id": "61",
                "managed": false,
                "name": "Name",
                "platform": "android",
                "platformId": 1,
                "privacy": "Low",
                "privacyRisk": 30,
                "processState": "AVAILABLE",
                "riskVersion": "2.12.0",
                "security": "High",
                "securityRisk": 79,
                "source": "GLOBAL",
                "updatedOn": 1702308488294,
                "version": "2.12.0"
            }
        ]
    }
}
```

#### Human Readable Output

>### App Version List
>|Id|Name|Bundle Id|Version|Platform|Security|Privacy|Classification|Developer Name|Created|Updated On|
>|---|---|---|---|---|---|---|---|---|---|---|
>| 7 | Name | com.url | 2.12.0 | android | High | Low | LEGIT |  | 2023-12-11 14:24:28 | 2023-12-11 15:28:08 |
>| 61 | Name | com.url | 2.12.0 | android | High | Low | LEGIT | TShih | 2023-12-11 14:38:05 | 2023-12-11 15:28:08 |


### zimperium-get-devices-by-cve

***
Gets a devices associated with a specific CVE.

#### Base Command

`zimperium-get-devices-by-cve`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cve_id | The ID of the CVE which is input. | Required | 
| after | The date in the criteria after which the threat occurred. | Optional | 
| before | The date in the criteria before which the threat occurred. | Optional | 
| team_id | Used to filter the user data by the team the user belongs to. | Optional | 
| page_size | Maximum number of results to retrieve in each page. If a limit is not provided, default is 50. | Optional | 
| page | Page number. Default is 0. | Optional | 
| limit | Number of total results to return. Default is 50. | Optional | 

#### Context Output

| **Path**                                    | **Type** | **Description**                                                   |
|---------------------------------------------| --- |-------------------------------------------------------------------|
| Zimperium.DeviceByCVE.id                    | String | The ID of the device.                                             | 
| Zimperium.DeviceByCVE.cveId                 | String | The ID of the CVE.                                                | 
| Zimperium.DeviceByCVE.os.id | Number | The operating system identifier of the device.                    | 
| Zimperium.DeviceByCVE.os.maxOsPatchDate     | String | The device operating system max patch date.                       | 
| Zimperium.DeviceByCVE.os.maxOsVersion       | String | The device operating system max version.                          | 
| Zimperium.DeviceByCVE.os.name               | String | The operating system name of the device.                          | 
| Zimperium.DeviceByCVE.os.osVersionId        | Number | The operating system version identifier of the device.            | 
| Zimperium.DeviceByCVE.os.patchDate          | Date | The patch date for of the operating system.                       | 
| Zimperium.DeviceByCVE.os.policyCompliant    | Boolean | Whether the operating system policy is compliant with the device. | 
| Zimperium.DeviceByCVE.os.type               | String | The operating system type of the device.                          | 
| Zimperium.DeviceByCVE.os.version            | String | The operating system version of the device.                       | 
| Zimperium.DeviceByCVE.os.versionUpgradeable | Boolean | Whether the operating system version was upgradeable.             | 
| Zimperium.DeviceByCVE.teamId                | String | The team ID of the device.                                        | 
| Zimperium.DeviceByCVE.zdeviceId             | String | The zdevice ID of the device.                                     | 


#### Command example
```!zimperium-get-devices-by-cve cve_id="CVE-2021-1886" limit=1```
#### Context Example
```json
{
    "Zimperium": {
        "DeviceCVE": {
            "id": "6",
            "cveId": "CVE-2021-1886",
            "os": {
                "id": 1,
                "maxOsPatchDate": "20200901",
                "maxOsVersion": "10",
                "name": "android",
                "osVersionId": 57063,
                "patchDate": "2017-09-01",
                "policyCompliant": false,
                "type": "Android",
                "version": "7.1.1",
                "versionUpgradeable": true
            },
            "teamId": "33",
            "zdeviceId": "5"
        }
    }
}
```

#### Human Readable Output

>### Devices Associated with CVE-2021-1886
>|Id|Zdevice Id|Team Id|Os|
>|---|---|---|---|
>| 6 | 5 | 33 | id: 1<br/>name: android<br/>type: Android<br/>version: 7.1.1<br/>patchDate: 2017-09-01<br/>versionUpgradeable: true<br/>maxOsVersion: 10<br/>maxOsPatchDate: 20200901<br/>osVersionId: 57063<br/>policyCompliant: false |


### zimperium-devices-os-version

***
Gets devices associated with a specific operating system version.

#### Base Command

`zimperium-devices-os-version`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| os_version | The name of the version which is input. Can be retrieved using zimperium-devices-search command under "Zimperium.Device.os.version". | Required | 
| os_patch_date | The date of the patch for a specific version. The date format is YYYY-MM-DD. This field is only applicable to Android. If you include this field, only CVEs for Android are returned since this value does not apply to iOS. | Optional | 
| deleted | This is used to request the devices that have been deleted. Possible values are: true, false. | Optional | 
| after | The date in the criteria after which the threat occurred. | Optional | 
| before | The date in the criteria before which the threat occurred. | Optional | 
| team_id | This is used to filter the data to their respective teams. | Optional | 
| page_size | Maximum number of results to retrieve in each page. If a limit is not provided, default is 50. | Optional | 
| page | Page number. Default is 0. | Optional | 
| limit | Number of total results to return. Default is 50. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Zimperium.DeviceOsVersion.id | String | The ID of the device. | 
| Zimperium.DeviceOsVersion.os.id | Number | The operating system identifier of the device. | 
| Zimperium.DeviceOsVersion.os.maxOsPatchDate | String | The device operating system max patch date. | 
| Zimperium.DeviceOsVersion.os.maxOsVersion | String | The device operating system max version. | 
| Zimperium.DeviceOsVersion.os.name | String | The operating system name of the device. | 
| Zimperium.DeviceOsVersion.os.osVersionId | Number | The operating system version identifier of the device. | 
| Zimperium.DeviceOsVersion.os.patchDate | Date | The patch date of the device's operating system. | 
| Zimperium.DeviceOsVersion.os.policyCompliant | Boolean | Whether the endpoint's operating system is compliant with the policy. | 
| Zimperium.DeviceOsVersion.os.type | String | The operating system type. | 
| Zimperium.DeviceOsVersion.os.version | String | The operating system version. | 
| Zimperium.DeviceOsVersion.os.versionUpgradeable | Boolean | Whether the device's operating system is upgradeable. | 
| Zimperium.DeviceOsVersion.teamId | String | The team ID of the device. | 
| Zimperium.DeviceOsVersion.zdeviceId | String | The zdevice ID of the device. | 

#### Command example
```!zimperium-devices-os-version os_version="9"```
#### Context Example
```json
{
    "Zimperium": {
        "DeviceOsVersion": {
            "id": "2a",
            "os": {
                "id": 1,
                "maxOsPatchDate": "20230501",
                "maxOsVersion": "13",
                "name": "android",
                "osVersionId": 57062,
                "patchDate": "2019-08-05",
                "policyCompliant": false,
                "type": "Android",
                "version": "9",
                "versionUpgradeable": true
            },
            "teamId": "1",
            "zdeviceId": "a8"
        }
    }
}
```

#### Human Readable Output

>### Device Os Version
>|Id|Team Id|Os|
>|---|---|---|
>| 2a | 1 | id: 1<br/>name: android<br/>type: Android<br/>version: 9<br/>patchDate: 2019-08-05<br/>versionUpgradeable: true<br/>maxOsVersion: 13<br/>maxOsPatchDate: 20230501<br/>osVersionId: 57062<br/>policyCompliant: false |


### zimperium-get-cves-by-device

***
Gets the CVEs associated with a specific device.

#### Base Command

`zimperium-get-cves-by-device`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | The device ID to get CVEs for. | Required | 
| page_size | Maximum number of results to retrieve in each page. If a limit is not provided, default is 50. | Optional | 
| page | Page number. Default is 0. | Optional | 
| limit | Number of total results to return. Default is 50. | Optional | 

#### Context Output

| **Path** | **Type** | **Description**                      |
| --- | --- |--------------------------------------|
| Zimperium.CVEByDevice.id | String | The ID of the CVE.                   | 
| Zimperium.CVEByDevice.deviceId | String | The ID of the device.                | 
| Zimperium.CVEByDevice.activeExploit | Boolean | Whether the CVE is active or not.    | 
| Zimperium.CVEByDevice.exploitPocUrl.exploitPocUrls | Unknown | The exploit POC URLs for the CVE.    | 
| Zimperium.CVEByDevice.severity | String | The severity of a CVE on the device. | 
| Zimperium.CVEByDevice.type | String | The CVE type.                        | 
| Zimperium.CVEByDevice.url | String | The URL of the CVE.                  | 

#### Command example
```!zimperium-get-cves-by-device device_id="2a"```
#### Context Example
```json
{
    "Zimperium": {
        "CVEDevice": [
            {
                "activeExploit": false,
                "exploitPocUrl": {
                    "exploitPocUrls": []
                },
                "id": "CVE-2019-2173",
                "severity": "High",
                "type": "Elevation of privilege",
                "url": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-2173",
                "deviceId": "2a"
            },
            {
                "activeExploit": false,
                "exploitPocUrl": {
                    "exploitPocUrls": []
                },
                "id": "CVE-2019-2176",
                "severity": "Critical",
                "type": "Remote code execution",
                "url": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-2176",
                "deviceId": "2a"
            }
        ]
    }
}
```

#### Human Readable Output

>### CVE on Device 2a
>|Id|Type|Severity|Url|Active Exploit|Exploit Poc Url|
>|---|---|---|---|---|---|
>| CVE-2019-2173 | Elevation of privilege | High | https:<span>//</span>cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-2173 | false | exploitPocUrls:  |
>| CVE-2019-2176 | Remote code execution | Critical | https:<span>//</span>cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-2176 | false | exploitPocUrls:  |


### zimperium-vulnerability-get

***
Gets the vulnerabilities.

#### Base Command

`zimperium-vulnerability-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page_size | Maximum number of results to retrieve in each page. If a limit is not provided, default is 50. | Optional | 
| page | Page number. Default is 0. | Optional | 
| limit | Number of total results to return. Default is 50. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Zimperium.Vulnerability.id | String | The ID of the vulnerability. | 
| Zimperium.Vulnerability.blueBorneVulnerable | Boolean | Whether the operating system is blue born vulnerable. | 
| Zimperium.Vulnerability.cveCount | Number | Number of CVEs on the operating system. | 
| Zimperium.Vulnerability.lastCveSync | Date | The date of the last CVE sync. | 
| Zimperium.Vulnerability.os | Number | The vulnerability operating system. | 
| Zimperium.Vulnerability.osPatchDate | Unknown | The max patch date of operating system. | 
| Zimperium.Vulnerability.osRiskChecksum | String | The operating system risk checksum. | 
| Zimperium.Vulnerability.osVersion | String | The operating system version. | 
| Zimperium.Vulnerability.osVersionAndPatchDate | String | The operating system version and the patch date. | 
| Zimperium.Vulnerability.risk | String | The risk classification. |


#### Command example
```!zimperium-vulnerability-get limit=1```
#### Context Example
```json
{
    "Zimperium": {
        "Vulnerability": {
            "blueBorneVulnerable": false,
            "cveCount": 432,
            "id": 56745,
            "lastCveSync": 1707218387516,
            "os": 2,
            "osPatchDate": null,
            "osRiskChecksum": "6A",
            "osVersion": "14.6",
            "osVersionAndPatchDate": "14.6",
            "risk": "Critical"
        }
    }
}
```

#### Human Readable Output

>### Vulnerabilities List
>|Id|Os|Os Version And Patch Date|Os Version|Os Patch Date|Risk|Cve Count|Last Cve Sync|Os Risk Checksum|Blue Borne Vulnerable|
>|---|---|---|---|---|---|---|---|---|---|
>| 56745 | 2 | 14.6 | 14.6 |  | Critical | 432 | 2024-02-06 11:19:47 | 6A | false |



### zimperium-policy-group-list

***
Get policy groups.

#### Base Command

`zimperium-policy-group-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| module | The module parameter is required to get the groups related to EMM connection or ZIPS connection. Default is "ZIPS". Possible values are: EMM, ZIPS. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Zimperium.PolicyGroup.id | String | The ID of the policy group. | 
| Zimperium.PolicyGroup.accountId | String | The account identifier for the policy group's content. | 
| Zimperium.PolicyGroup.appPolicyId | String | The app policy ID of the policy group. | 
| Zimperium.PolicyGroup.appSettingsId | String | The app settings ID of the policy group. | 
| Zimperium.PolicyGroup.brandingPolicyId | Unknown | The branding policy identifier of the policy group. | 
| Zimperium.PolicyGroup.created | Date | The date and time the policy group was created. | 
| Zimperium.PolicyGroup.description | String | The description of the policy group. | 
| Zimperium.PolicyGroup.dormancyPolicyId | String | The dormancy policy identifier of the policy group. | 
| Zimperium.PolicyGroup.emmConnectionId | Unknown | The enterprise mobile management (EMM) connection ID of the policy group. | 
| Zimperium.PolicyGroup.emmGroupId | Unknown | The enterprise mobile management (EMM) group ID of the policy group. | 
| Zimperium.PolicyGroup.emmPriority | Unknown | The enterprise mobile management (EMM) priority of the policy group. | 
| Zimperium.PolicyGroup.extensionPolicyId | String | The extension policy identifier of the policy group. | 
| Zimperium.PolicyGroup.content.global | Boolean | Whether the policy group is global. | 
| Zimperium.PolicyGroup.knoxPolicyId | Unknown | The Knox policy ID of the policy group. | 
| Zimperium.PolicyGroup.modified | Date | The date and time when the policy group was last modified. | 
| Zimperium.PolicyGroup.name | String | The name of the policy group. | 
| Zimperium.PolicyGroup.networkPolicyId | String | The network policy ID of the policy group. | 
| Zimperium.PolicyGroup.osRiskPolicyId | String | The operating system risk policy ID of the policy group. | 
| Zimperium.PolicyGroup.phishingPolicyId | String | The phishing policy identifier of the policy group. | 
| Zimperium.PolicyGroup.privacyId | String | The privacy identifier of the policy group. | 
| Zimperium.PolicyGroup.team.id | String | The ID of the team associated with the policy group. | 
| Zimperium.PolicyGroup.team.name | String | The team name of the policy group. | 
| Zimperium.PolicyGroup.trmId | String | The Threat Response Matrix (TRM) ID of the policy group. | 
| Zimperium.PolicyGroup.team | Unknown | The policy group's team information. | 

#### Command example
```!zimperium-policy-group-list```
#### Context Example
```json
{
    "Zimperium": {
        "PolicyGroup": [
            {
                "accountId": "2",
                "appPolicyId": "2",
                "appSettingsId": "a5",
                "brandingPolicyId": null,
                "created": "2024-01-22T11:37:36.749+00:00",
                "description": "test",
                "dormancyPolicyId": "2",
                "emmConnectionId": null,
                "emmGroupId": null,
                "emmPriority": null,
                "extensionPolicyId": "2",
                "global": false,
                "id": "65",
                "knoxPolicyId": null,
                "modified": "2024-01-22T11:37:36.749+00:00",
                "name": "Test",
                "networkPolicyId": "2",
                "osRiskPolicyId": "2",
                "phishingPolicyId": "2",
                "privacyId": "a2",
                "team": {
                    "id": "1",
                    "name": "Default"
                },
                "trmId": "er"
            }
        ]
    }
}
```

#### Human Readable Output

>### Policy Group List
>|Id|Name|Team|Privacy Id|Trm Id|Phishing Policy Id|App Settings Id|App Policy Id|Network Policy Id|Os Risk Policy Id|
>|---|---|---|---|---|---|---|---|---|---|
>| 65 | Test | id: 1<br/>name: Default | a2 | er | 2 | a5 | 2 | 2 | 2 |


### zimperium-policy-privacy-get

***
Get a privacy policy by its identifier.

#### Base Command

`zimperium-policy-privacy-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_id | The identifier of the policy. Can be retrieved using zimperium-policy-group-list in the Zimperium.PolicyGroup.privacyId field. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Zimperium.PolicyPrivacy.id | String | The policy privacy identifier. | 
| Zimperium.PolicyPrivacy.accountId | String | The account identifier of the policy. | 
| Zimperium.PolicyPrivacy.assigned | Boolean | Whether the policy privacy is assigned. | 
| Zimperium.PolicyPrivacy.created | Date | The date and time the policy was created. | 
| Zimperium.PolicyPrivacy.global | Boolean | Whether the policy settings are global. | 
| Zimperium.PolicyPrivacy.groups | String | The groups the policy are associated with. | 
| Zimperium.PolicyPrivacy.jsonHash | String | The JSON hash for the policy privacy policy. | 
| Zimperium.PolicyPrivacy.locationAccuracy | Number | The location accuracy for the policy. | 
| Zimperium.PolicyPrivacy.modified | Date | The date and time when the policy was modified. | 
| Zimperium.PolicyPrivacy.name | String | The name of the policy. | 
| Zimperium.PolicyPrivacy.protoHash | String | The hash of the policy. | 
| Zimperium.PolicyPrivacy.rules | Unknown | The policy rules list. | 
| Zimperium.PolicyPrivacy.rules.id | String | The ID of the rule. | 
| Zimperium.PolicyPrivacy.team | Unknown | The team for the policy. | 
| Zimperium.PolicyPrivacy.teamId | Unknown | The team ID the policy is associated with. | 

#### Command example
```!zimperium-policy-privacy-get policy_id="a2"```
#### Context Example
```json
{
    "Zimperium": {
        "PolicyPrivacy": {
            "accountId": "2",
            "assigned": true,
            "created": "2023-12-05T20:09:16.621+00:00",
            "global": true,
            "groups": [
                {
                    "accountId": "2",
                    "created": "2024-01-22T11:37:36.749+00:00",
                    "description": "test",
                    "emm": false,
                    "global": false,
                    "groupActivations": [],
                    "id": "65",
                    "modified": "2024-01-22T11:37:36.749+00:00",
                    "name": "Test",
                    "staticFilesWritten": "2024-02-05T06:00:03.460+00:00",
                    "userActivations": [],
                    "zapps": []
                },
                {
                    "accountId": "2",
                    "created": "2023-12-05T20:09:16.621+00:00",
                    "description": "Default Group",
                    "emm": false,
                    "global": true,
                    "groupActivations": [],
                    "id": "37",
                    "modified": "2023-12-05T20:09:16.621+00:00",
                    "name": "Default Group",
                    "staticFilesWritten": "2024-02-06T06:00:37.129+00:00",
                    "userActivations": [
                        {
                            "id": "40"
                        }
                    ],
                    "zapps": []
                }
            ],
            "id": "a2",
            "jsonHash": "7d",
            "locationAccuracy": 0,
            "modified": "2023-12-05T20:09:16.853+00:00",
            "name": "Default",
            "rules": [
                {
                    "collectibleId": 0,
                    "id": "3b",
                    "shouldCollect": false
                }
            ],
            "staticFilesWritten": "2023-12-05T20:09:19.079+00:00",
            "team": null,
            "teamId": null
        }
    }
}
```

#### Human Readable Output

>### Privacy Policy
>|Id|Name|Created|Modified|
>|---|---|---|---|
>| a2 | Default | 2023-12-05T20:09:16.621+00:00 | 2023-12-05T20:09:16.853+00:00 |


### zimperium-policy-threat-get

***
Get a threat policy by its identifier.

#### Base Command

`zimperium-policy-threat-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_id | The identifier of the policy. Can be retrieved using zimperium-policy-group-list in the Zimperium.PolicyGroup.trmId field. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Zimperium.PolicyThreat.id | String | The identifier of the policy. | 
| Zimperium.PolicyThreat.accountId | String | The account identifier of the policy. | 
| Zimperium.PolicyThreat.androidJsonHash | String | The Android JSON hash. | 
| Zimperium.PolicyThreat.androidProtoHash | String | The Android Proto hash. | 
| Zimperium.PolicyThreat.assigned | Boolean | Whether the policy is assigned. | 
| Zimperium.PolicyThreat.created | Date | The date and time the policy threat was created. | 
| Zimperium.PolicyThreat.deploymentDate | Date | The date when the policy deployment occurred. | 
| Zimperium.PolicyThreat.global | Boolean | Whether the policy settings are global. | 
| Zimperium.PolicyThreat.groups | Unknown | The groups the policy are associated with. | 
| Zimperium.PolicyThreat.iosJsonHash | String | IOS JSON hash. | 
| Zimperium.PolicyThreat.iosProtoHash | String | IOS Proto hash. | 
| Zimperium.PolicyThreat.isDeployed | Boolean | Whether the policy threat is deployed or not. | 
| Zimperium.PolicyThreat.modified | Date | The date and time when the policy was modified. | 
| Zimperium.PolicyThreat.name | String | The name of the policy. | 
| Zimperium.PolicyThreat.rules | Unknown | The policy rules list. | 
| Zimperium.PolicyThreat.rules.id | String | The ID of the policy rule. | 

#### Command example
```!zimperium-policy-threat-get policy_id="er"```
#### Context Example
```json
{
    "Zimperium": {
        "PolicyThreat": {
            "accountId": "2",
            "androidJsonHash": "eb",
            "androidProtoHash": "4f",
            "assigned": true,
            "created": "2023-12-05T20:09:16.621+00:00",
            "deploymentDate": "2023-12-05T20:09:18.474+00:00",
            "emm": false,
            "global": true,
            "groups": [
                {
                    "accountId": "2",
                    "created": "2024-01-22T11:37:36.749+00:00",
                    "description": "test",
                    "emm": false,
                    "global": false,
                    "groupActivations": [],
                    "id": "65",
                    "modified": "2024-01-22T11:37:36.749+00:00",
                    "name": "Test",
                    "staticFilesWritten": "2024-02-05T06:00:03.460+00:00",
                    "userActivations": [],
                    "zapps": []
                },
                {
                    "accountId": "2",
                    "created": "2023-12-05T20:09:16.621+00:00",
                    "description": "Default Group",
                    "emm": false,
                    "global": true,
                    "groupActivations": [],
                    "id": "37",
                    "modified": "2023-12-05T20:09:16.621+00:00",
                    "name": "Default Group",
                    "staticFilesWritten": "2024-02-06T06:00:37.129+00:00",
                    "userActivations": [
                        {
                            "id": "40"
                        }
                    ],
                    "zapps": []
                }
            ],
            "id": "er",
            "iosJsonHash": "eb",
            "iosProtoHash": "4f",
            "isDeployed": true,
            "modified": "2023-12-05T20:09:17.184+00:00",
            "name": "Default",
            "rules": [
                {
                    "alertUser": false,
                    "customResponses": [],
                    "id": "b9",
                    "legacyMdmMitigationAction": null,
                    "legacyMdmThreatAction": null,
                    "mdmMitigationAction": null,
                    "mdmMitigationTarget": null,
                    "mdmThreatAction": null,
                    "mdmThreatTarget": null,
                    "responses": [],
                    "severity": 0,
                    "shouldCollect": true,
                    "threatTypeId": 0
                }
            ],
            "staticFilesWritten": "2023-12-05T20:09:18.129+00:00"
        }
    }
}
```

#### Human Readable Output

>### Threat Policy
>|Id|Is Deployed|Name|Created|Modified|
>|---|---|---|---|---|
>| er | true | Default | 2023-12-05T20:09:16.621+00:00 | 2023-12-05T20:09:17.184+00:00 |


### zimperium-policy-phishing-get

***
Get a phishing policy by its identifier.

#### Base Command

`zimperium-policy-phishing-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_id | The identifier of the policy. Can be retrieved using zimperium-policy-group-list in the Zimperium.PolicyGroup.phishingPolicyId field. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Zimperium.PolicyPhishing.id | String | The identifier of the policy. | 
| Zimperium.PolicyPhishing.accessControlList | Unknown | The access control list for the policy resource. | 
| Zimperium.PolicyPhishing.accountId | String | The account identifier of the policy. | 
| Zimperium.PolicyPhishing.allowEndUserControl | Boolean | Whether the end user is allowed to control the policy. | 
| Zimperium.PolicyPhishing.contentCategoryActionList | Unknown | The content of the policy category action. | 
| Zimperium.PolicyPhishing.created | Date | The date and time the policy threat was created. | 
| Zimperium.PolicyPhishing.enableDnsPhishingTutorial | Boolean | Whether the DNS phishing tutorial is enabled. | 
| Zimperium.PolicyPhishing.enableMessageFilterTutorial | Boolean | Whether the message filter tutorial is enabled. | 
| Zimperium.PolicyPhishing.enableSafariBrowserExtensionTutorial | Boolean | Whether the Safari Browser Extension tutorial is enabled. | 
| Zimperium.PolicyPhishing.global | Boolean | Whether the policy settings are global. | 
| Zimperium.PolicyPhishing.groups | Unknown | The groups the policy are associated with. | 
| Zimperium.PolicyPhishing.isDnsEnabled | Boolean | Whether DNS is enabled or not. | 
| Zimperium.PolicyPhishing.modified | Date | The date and time when the policy was modified. | 
| Zimperium.PolicyPhishing.name | String | The name of the policy. | 
| Zimperium.PolicyPhishing.phishingDetectionAction | String | The phishing detection action. | 
| Zimperium.PolicyPhishing.phishingPolicyType | String | The phishing policy type. | 
| Zimperium.PolicyPhishing.team | Unknown | The team the policy is associated with. | 
| Zimperium.PolicyPhishing.teamId | Unknown | The ID of the team. | 
| Zimperium.PolicyPhishing.useLocalVpn | Boolean | Whether to use a local VPN or not. | 
| Zimperium.PolicyPhishing.useRemoteContentInspection | Boolean | Whether to use remote content inspection. | 
| Zimperium.PolicyPhishing.useUrlSharing | Boolean | Whether the URL sharing is enabled or not. | 

#### Command example
```!zimperium-policy-phishing-get policy_id="2"```
#### Context Example
```json
{
    "Zimperium": {
        "PolicyPhishing": {
            "accessControlList": null,
            "accountId": "2",
            "allowEndUserControl": false,
            "contentCategoryActionList": [],
            "created": "2023-12-05T20:09:16.621+00:00",
            "enableDnsPhishingTutorial": false,
            "enableMessageFilterTutorial": true,
            "enableSafariBrowserExtensionTutorial": true,
            "global": true,
            "groups": [
                {
                    "accountId": "2",
                    "created": "2024-01-22T11:37:36.749+00:00",
                    "description": "test",
                    "emm": false,
                    "global": false,
                    "groupActivations": [],
                    "id": "65",
                    "modified": "2024-01-22T11:37:36.749+00:00",
                    "name": "Test",
                    "staticFilesWritten": "2024-02-05T06:00:03.460+00:00",
                    "userActivations": [],
                    "zapps": []
                },
                {
                    "accountId": "2",
                    "created": "2023-12-05T20:09:16.621+00:00",
                    "description": "Default Group",
                    "emm": false,
                    "global": true,
                    "groupActivations": [],
                    "id": "37",
                    "modified": "2023-12-05T20:09:16.621+00:00",
                    "name": "Default Group",
                    "staticFilesWritten": "2024-02-06T06:00:37.129+00:00",
                    "userActivations": [
                        {
                            "id": "40"
                        }
                    ],
                    "zapps": []
                }
            ],
            "id": "2",
            "isDnsEnabled": false,
            "modified": "2023-12-11T13:33:08.481+00:00",
            "name": "Default",
            "phishingDetectionAction": "WARN",
            "phishingPolicyType": "ON_DEVICE",
            "team": null,
            "teamId": null,
            "useLocalVpn": true,
            "useRemoteContentInspection": true,
            "useUrlSharing": true
        }
    }
}
```

#### Human Readable Output

>### Phishing Policy
>|Id|Name|Created|Modified|Enable Safari Browser Extension Tutorial|Enable Dns Phishing Tutorial|Use Local Vpn|Use Url Sharing|Allow End User Control|Use Remote Content Inspection|Enable Message Filter Tutorial|Phishing Detection Action|Phishing Policy Type|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 2 | Default | 2023-12-05T20:09:16.621+00:00 | 2023-12-11T13:33:08.481+00:00 | true | false | true | true | false | true | true | WARN | ON_DEVICE |


### zimperium-policy-app-settings-get

***
List the app versions.

#### Base Command

`zimperium-policy-app-settings-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| app_settings_policy_id | The identifier of the policy. Can be retrieved using zimperium-policy-group-list in the Zimperium.PolicyGroup.appSettingsId field. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Zimperium.PolicyAppSetting.id | String | The identifier of the policy. | 
| Zimperium.PolicyAppSetting.accountId | String | The account identifier of the policy. | 
| Zimperium.PolicyAppSetting.appRiskLookupEnabled | Boolean | Whether the app risk lookup is enabled or not. | 
| Zimperium.PolicyAppSetting.assigned | Boolean | Whether the policy is assigned. | 
| Zimperium.PolicyAppSetting.autoActivateKnox | Boolean | Whether Knox should be automatically activated. | 
| Zimperium.PolicyAppSetting.autoBatteryOptimizationEnabled | Boolean | Whether the battery optimization is enabled. | 
| Zimperium.PolicyAppSetting.cogitoEnabled | Boolean | Whether the cogito is enabled. | 
| Zimperium.PolicyAppSetting.cogitoThreshold | Number | The cogito threshold. | 
| Zimperium.PolicyAppSetting.created | Date | The date and time the policy was created. | 
| Zimperium.PolicyAppSetting.dangerzoneEnabled | Boolean | Whether the danger zone is enabled or not. | 
| Zimperium.PolicyAppSetting.detectionEnabled | Boolean | Whether detection is enabled. | 
| Zimperium.PolicyAppSetting.forensicAnalysisEnabled | Boolean | Whether forensic analysis is enabled. | 
| Zimperium.PolicyAppSetting.global | Boolean | Whether the policy is global. | 
| Zimperium.PolicyAppSetting.groups | Unknown | The groups information. | 
| Zimperium.PolicyAppSetting.jsonHash | String | The JSON hash of the policy. | 
| Zimperium.PolicyAppSetting.modified | Date | The modified date of the policy. | 
| Zimperium.PolicyAppSetting.name | String | The name of the policy. | 
| Zimperium.PolicyAppSetting.phishingEnabled | Boolean | Whether phishing is enabled or not. | 
| Zimperium.PolicyAppSetting.phishingLocalClassifierEnabled | Boolean | Whether the phishing local classifier is enabled. | 
| Zimperium.PolicyAppSetting.phishingThreshold | Number | The phishing threshold. | 
| Zimperium.PolicyAppSetting.privacySummaryEnabled | Boolean | Whether the privacy summary is enabled. | 
| Zimperium.PolicyAppSetting.protoHash | String | The proto hash. | 
| Zimperium.PolicyAppSetting.siteInsightEnabled | Boolean | Whether the site insight is enabled or not. | 
| Zimperium.PolicyAppSetting.staticFilesWritten | Date | The date when the static files were written. | 
| Zimperium.PolicyAppSetting.team | Unknown | The team name the policy is associated with. | 
| Zimperium.PolicyAppSetting.teamId | Unknown | The ID of the team to which the policy belongs. | 

#### Command example
```!zimperium-policy-app-settings-get app_settings_policy_id="9e"```
#### Context Example
```json
{
    "Zimperium": {
        "PolicyAppSetting": {
            "accountId": "2",
            "appRiskLookupEnabled": true,
            "assigned": true,
            "autoActivateKnox": false,
            "autoBatteryOptimizationEnabled": true,
            "cogitoEnabled": true,
            "cogitoThreshold": 70,
            "created": "2023-12-05T20:09:16.621+00:00",
            "dangerzoneEnabled": true,
            "detectionEnabled": true,
            "forensicAnalysisEnabled": false,
            "global": true,
            "groups": [
                {
                    "accountId": "2",
                    "created": "2023-12-05T20:09:16.621+00:00",
                    "description": "Default Group",
                    "emm": false,
                    "global": true,
                    "groupActivations": [],
                    "id": "37",
                    "modified": "2023-12-05T20:09:16.621+00:00",
                    "name": "Default Group",
                    "staticFilesWritten": "2024-02-06T06:00:37.129+00:00",
                    "userActivations": [
                        {
                            "id": "40"
                        }
                    ],
                    "zapps": []
                }
            ],
            "id": "9e",
            "jsonHash": "616",
            "modified": "2023-12-05T20:09:16.729+00:00",
            "name": "Default",
            "phishingDBRefreshMinutes": 480,
            "phishingEnabled": true,
            "phishingLocalClassifierEnabled": true,
            "phishingThreshold": 75,
            "privacySummaryEnabled": true,
            "protoHash": "ea9",
            "siteInsightEnabled": false,
            "staticFilesWritten": "2023-12-05T20:09:17.418+00:00",
            "team": null,
            "teamId": null
        }
    }
}
```

#### Human Readable Output

>### Policy App Settings
>|Id|Name|Detection Enabled|Cogito Enabled|Cogito Threshold|Phishing Enabled|Phishing Threshold|Phishing DB Refresh Minutes|Created|Modified|Static Files Written|Json Hash|Proto Hash|Dangerzone Enabled|Site Insight Enabled|Phishing Local Classifier Enabled|App Risk Lookup Enabled|Auto Battery Optimization Enabled|Auto Activate Knox|Privacy Summary Enabled|Forensic Analysis Enabled|Team|Assigned|Team Id|Global|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 9e | Default | true | true | 70 | true | 75 | 480 | 2023-12-05T20:09:16.621+00:00 | 2023-12-05T20:09:16.729+00:00 | 2023-12-05T20:09:17.418+00:00 | 616 | ea9 | true | false | true | true | true | false | true | false |  | true |  | true |


### zimperium-policy-device-inactivity-list

***
Get the policy device inactivity list.

#### Base Command

`zimperium-policy-device-inactivity-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page_size | Maximum number of results to retrieve in each page. If a limit is not provided, default is 50. | Optional | 
| page | Page number. Default is 0. | Optional | 
| limit | Number of total results to return. Default is 50. | Optional | 
| team_id | Used to filter the data by the team the user belongs to. If you provide this the query returns matching entries plus the policies without a team. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Zimperium.PolicyDeviceInactivity.teamId | String | The team ID for the policy device inactivity list. | 
| Zimperium.PolicyDeviceInactivity.id | String | The policy device inactivity list ID. | 
| Zimperium.PolicyDeviceInactivity.name | String | The name of the policy device inactivity list. | 

#### Command example
```!zimperium-policy-device-inactivity-list team_id="1"```
#### Context Example
```json
{
    "Zimperium": {
        "PolicyDeviceInactivity": [
            {
                "id": "2",
                "name": "Default",
                "teamId": null
            },
            {
                "id": "ff3",
                "name": "InactivityTest",
                "teamId": "1"
            }
        ]
    }
}
```

#### Human Readable Output

>### Device Inactivity List
>|Id|Name|Team Id|
>|---|---|---|
>| 2 | Default |  |
>| ff3 | InactivityTest | 1 |


### zimperium-policy-device-inactivity-get

***
Get policy device inactivity.

#### Base Command

`zimperium-policy-device-inactivity-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_id | The identifier of the policy. Can be retrieved using zimperium-policy-device-inactivity-list. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Zimperium.PolicyDeviceInactivity.id | String | The policy device inactivity ID. | 
| Zimperium.PolicyDeviceInactivity.accountId | String | The account identifier. | 
| Zimperium.PolicyDeviceInactivity.created | Date | The date and time the policy was created. | 
| Zimperium.PolicyDeviceInactivity.groups.id | String | The group ID. | 
| Zimperium.PolicyDeviceInactivity.groups.name | String | The group name. | 
| Zimperium.PolicyDeviceInactivity.inactiveAppSettings.enabled | Boolean | Whether the app settings inactivity is enabled. | 
| Zimperium.PolicyDeviceInactivity.inactiveAppSettings.maxWarningsCount | Number | The maximum number of warnings that can be issued for an app. | 
| Zimperium.PolicyDeviceInactivity.inactiveAppSettings | Boolean | The inactive app settings. | 
| Zimperium.PolicyDeviceInactivity.modified | Date | The policy modified date. | 
| Zimperium.PolicyDeviceInactivity.name | String | The name of the policy. | 
| Zimperium.PolicyDeviceInactivity.pendingActivationSettings.enabled | Boolean | Whether the device's policy setting is enabled or not. | 
| Zimperium.PolicyDeviceInactivity.pendingActivationSettings.maxWarningsCount | Number | The maximum number of warnings that can be issued for the policy. | 
| Zimperium.PolicyDeviceInactivity.pendingActivationSettings.sendEmailAndroid | Boolean | Whether to send an email. | 
| Zimperium.PolicyDeviceInactivity.pendingActivationSettings.sendEmailIos | Boolean | Whether to send an email. | 
| Zimperium.PolicyDeviceInactivity.pendingActivationSettings.timeBeforeWarningDisplayUnits | String | The time before the warning display. | 
| Zimperium.PolicyDeviceInactivity.pendingActivationSettings.timeBeforeWarningSeconds | Number | The time before the warning seconds. | 
| Zimperium.PolicyDeviceInactivity.pendingActivationSettings.timeBetweenWarningsDisplayUnits | String | The time interval between warning displays. | 
| Zimperium.PolicyDeviceInactivity.pendingActivationSettings.timeBetweenWarningsSeconds | Number | The time in seconds between warnings. | 
| Zimperium.PolicyDeviceInactivity.teamId | String | The Team ID for the policy device inactivity. | 

#### Command example
```!zimperium-policy-device-inactivity-get policy_id="ff3"```
#### Context Example
```json
{
    "Zimperium": {
        "PolicyDeviceInactivity": {
            "accountId": "2",
            "created": 1702305515652,
            "groups": [
                {
                    "id": "1",
                    "name": "GroupTest"
                }
            ],
            "id": "ff3",
            "inactiveAppSettings": {
                "enabled": false,
                "maxWarningsCount": 2,
                "notifyDevicesAndroid": false,
                "notifyDevicesIos": false,
                "sendEmailAndroid": false,
                "sendEmailIos": false,
                "timeBeforeWarningDisplayUnits": "DAYS",
                "timeBeforeWarningSeconds": 259200,
                "timeBetweenWarningsDisplayUnits": "DAYS",
                "timeBetweenWarningsSeconds": 86400
            },
            "modified": 1702305515652,
            "name": "InactivityTest",
            "pendingActivationSettings": {
                "enabled": false,
                "maxWarningsCount": 2,
                "sendEmailAndroid": false,
                "sendEmailIos": false,
                "timeBeforeWarningDisplayUnits": "DAYS",
                "timeBeforeWarningSeconds": 259200,
                "timeBetweenWarningsDisplayUnits": "DAYS",
                "timeBetweenWarningsSeconds": 86400
            },
            "teamId": "1"
        }
    }
}
```

#### Human Readable Output

>### Device Inactivity
>|Id|Name|Team Id|Pending Activation Settings|Inactive App Settings|Created|Modified|
>|---|---|---|---|---|---|---|
>| ff3 | InactivityTest | 1 | enabled: false<br/>timeBeforeWarningSeconds: 259200<br/>timeBeforeWarningDisplayUnits: DAYS<br/>timeBetweenWarningsSeconds: 86400<br/>timeBetweenWarningsDisplayUnits: DAYS<br/>maxWarningsCount: 2<br/>sendEmailIos: false<br/>sendEmailAndroid: false | enabled: false<br/>timeBeforeWarningSeconds: 259200<br/>timeBeforeWarningDisplayUnits: DAYS<br/>timeBetweenWarningsSeconds: 86400<br/>timeBetweenWarningsDisplayUnits: DAYS<br/>maxWarningsCount: 2<br/>notifyDevicesIos: false<br/>notifyDevicesAndroid: false<br/>sendEmailIos: false<br/>sendEmailAndroid: false | 2023-12-11 14:38:35 | 2023-12-11 14:38:35 |


## Breaking changes from the previous version of this integration
The following sections list the changes in this version.

### Commands
#### The following commands were removed in this version:
* ***zimperium-events-search*** - this command was replaced by ***zimperium-threat-search***.
* ***zimperium-user-get-by-id*** - this command was replaced by ***zimperium-users-search***.
* ***zimperium-device-get-by-id*** - this command was replaced by ***zimperium-devices-search***.
* ***zimperium-app-classification-get*** - this command was replaced by ***zimperium-app-version-list***.
* ***zimperium-devices-search*** - this command was removed.
* ***file*** - this command was removed.


### Arguments
#### The following arguments were removed in this version:

In the *zimperium-users-search* command:
* *query*
* *email*

In the *zimperium-devices-search* command:
* *query*

In the ***zimperium-report-get*** command:
* *bundle_id*
* *itunes_id*
* *app_hash*
* *platform*