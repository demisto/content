CyberArk EPM Event Collector fetches events.
This integration was integrated and tested with version 23.12.0 of CyberArk EPM.

## Configure CyberArk EPM Event Collector in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| SAML/EPM Logon URL | SAML example: https://login.epm.cyberark.com/SAML/Logon. | True |
| Username |  | True |
| Password |  | True |
| Set name | A comma-separated list of set names. | True |
| Application ID | Required for local\(EPM\) authentication only. | False |
| Authentication URL | Required for SAML authentication only, Example for PAN OKTA: https://paloaltonetworks.okta.com/api/v1/authn. | False |
| Application URL | Required for SAML authentication only, Example for PAN OKTA: https://paloaltonetworks.okta.com/home/\[APP_NAME\]/\[APP_ID\]. | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Maximum number of events per fetch |  | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### cyberarkepm-get-admin-audits

***
Gets admin audits from Cyber Ark EPM.

#### Base Command

`cyberarkepm-get-admin-audits`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | If true, the command will create events, otherwise it will only display them. Possible values are: true, false. Default is false. | Required | 
| limit | Maximum number of results to return. | Optional | 
| from_date | Date to return results from. (in ISO format '01-01-24T00:00:00.123Z'). | Optional | 

#### Human Readable Output

### Admin Audits

|Administrator|Description|EventTime|Feature|InternalSessionId|LoggedAt|LoggedFrom|PermissionDescription|Role|SetName|_time|eventTypeXsiam|
|---|---|---|---|---|---|---|---|---|---|---|---|
| admin@paloaltonetworks.com | API Get Admin audit data /API/Sets/47f5830e-383a-4db1-9e5f-b38ed0448a92/AdminAudit?dateFrom=2023-12-17T12:17:35.384Z&limit=250 GET DateFrom: 2023-12-17T12:17:35.384Z, DateTo: , offset: 0, limit: 250 | 2023-12-17T12:38:26.53Z | Public API | 239076 | 2023-12-14T13:09:49.81Z | 1.1.1.1 | None | SetUser | PANW Production(palo alto networks inc.) | 2023-12-17T12:38:26.53Z | set admin audit data |
| admin@paloaltonetworks.com | API Get Admin audit data /API/Sets/47f5830e-383a-4db1-9e5f-b38ed0448a92/AdminAudit?dateFrom=2023-12-17T12:38:01.454Z&limit=250 GET DateFrom: 2023-12-17T12:38:01.454Z, DateTo: , offset: 0, limit: 250 | 2023-12-17T12:39:26.703Z | Public API | 239076 | 2023-12-14T13:09:49.81Z | 1.1.1.1 | None | SetUser | PANW Production(palo alto networks inc.) | 2023-12-17T12:39:26.703Z | set admin audit data |

#### Context Output

There is no context output for this command.

### cyberarkepm-get-policy-audits

***
Gets policy audits from Cyber Ark EPM.

#### Base Command

`cyberarkepm-get-policy-audits`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | If true, the command will create events, otherwise it will only display them. Possible values are: true, false. Default is false. | Required | 
| limit | Maximum number of results to return. | Optional | 
| from_date | Date to return results from. (in ISO format '01-01-24T00:00:00.123Z'). | Optional | 

#### Human Readable Output

### Policy Audits

|_time|accessTargetName|accessTargetType|agentEventCount|agentId|applicationSubType|arguments|arrivalTime|authorizationRights|bundleName|bundleVersion|codeURL|commandInfo|company|computerName|displayName|eventType|eventTypeXsiam|fileAccessPermission|fileDescription|fileName|filePath|fileQualifier|fileSize|fileVersion|firstEventDate|hash|interpreter|justification|justificationEmail|lastEventDate|mimeType|modificationTime|operatingSystemType|originUserUID|originalFileName|owner|packageName|policyAction|policyName|productCode|productName|productVersion|publisher|runAsUsername|skippedCount|sourceName|sourceType|symLink|upgradeCode|userIsAdmin|userName|workingDirectory|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 2023-12-17T12:43:54.659Z |  | Internet | 363 | 6ebc011f-bdbd-4e0c-84ac-8ea7611c4019 |  |  | 2023-12-17T12:43:54.659Z |  | Google Chrome Helper (Renderer) | 6045.199 |  |  |  | M-VKY33Q227Q | Google Chrome Helper (Renderer) (Google Chrome Helper (Renderer)) | Launch | policy audit raw event details |  |  | Google Chrome Helper (Renderer) | /Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/Versions/119.0.6045.199/Helpers/Google Chrome Helper (Renderer).app/Contents/MacOS/Google Chrome Helper (Renderer) | 6843642769839712425 | 518832 |  | 2023-12-17T04:44:50Z | 537ce868dd185f032e7ae18900eb3ec100ed35ef |  |  |  | 2023-12-17T12:43:37Z |  | 2023-11-27T22:43:23Z | MacOS |  |  | root | Google Chrome Helper (Renderer) (Google Chrome Helper (Renderer)) | Run Normally | panw-macos-prod-all-users-allow |  |  |  | Google LLC (EQHXZ8M8AV) |  | 0 | /Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/Versions/119.0.6045.199/Helpers/Google Chrome Helper (Renderer).app/Contents/MacOS/Google Chrome Helper (Renderer) | LocalDisk |  |  | true | .\csvensson |  |
| 2023-12-17T12:43:54.658Z |  | Internet | 16 | 6ebc011f-bdbd-4e0c-84ac-8ea7611c4019 |  |  | 2023-12-17T12:43:54.658Z |  | WeatherWidget | 484 |  |  |  | M-VKY33Q227Q | WeatherWidget (WeatherWidget) | Launch | policy audit raw event details |  |  | WeatherWidget | /System/Applications/Weather.app/Contents/PlugIns/WeatherWidget.appex/Contents/MacOS/WeatherWidget | 2810527046663450530 | 3733952 |  | 2023-12-17T04:52:33Z | 951815b591c7255b6de67adac3931549892c2fee |  |  |  | 2023-12-17T12:43:30Z |  | 2023-11-02T22:44:56Z | MacOS |  |  | root | WeatherWidget (WeatherWidget) | Run Normally | panw-macos-prod-all-users-allow |  |  |  | Software Signing |  | 0 | /System/Applications/Weather.app/Contents/PlugIns/WeatherWidget.appex/Contents/MacOS/WeatherWidget | LocalDisk |  |  | true | .\csvensson |  |

#### Context Output

There is no context output for this command.

### cyberarkepm-get-events

***
Gets events from Cyber Ark EPM.

#### Base Command

`cyberarkepm-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | If true, the command will create events, otherwise it will only display them. Possible values are: true, false. Default is false. | Required | 
| limit | Maximum number of results to return. | Optional | 
| from_date | Date to return results from. (in ISO format '01-01-24T00:00:00.123Z'). | Optional | 

#### Human Readable Output

### Detailed Evens
|_time|accessAction|accessTargetName|accessTargetType|agentEventCount|agentId|applicationSubType|arrivalTime|authorizationRights|bundleId|bundleName|bundleVersion|company|computerName|deceptionType|displayName|eventCount|eventType|eventTypeXsiam|evidences|exposedUsers|fatherProcess|fileAccessPermission|fileDescription|fileName|filePath|filePathWithoutFilename|fileQualifier|fileSize|fileVersion|firstEventDate|hash|interpreter|justification|justificationEmail|lastEventDate|logonAttemptTypeId|logonStatusId|lureUser|modificationTime|operatingSystemType|originUserUID|originalFileName|owner|packageName|policyCategory|policyName|processCertificateIssuer|processCommandLine|productCode|productName|productVersion|publisher|runAsUsername|skippedCount|sourceName|sourceProcessCertificateIssuer|sourceProcessCommandLine|sourceProcessHash|sourceProcessPublisher|sourceProcessSigner|sourceProcessUsername|sourceType|sourceWSIp|sourceWSName|symLink|threatProtectionAction|threatProtectionActionId|upgradeCode|userIsAdmin|userName|winEventRecordId|winEventType|workingDirectory|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 2023-12-17T12:37:11.855Z | false |  | Internet | 1 | f8443d50-4e35-442e-a886-d543080d5def |  | 2023-12-17T12:37:11.855Z |  |  |  |  | Microsoft Corporation | W-5CG3423Q0T | 0 | Settings (SystemSettingsAdminFlows.exe) | 1 | Trust | detailed raw |  |  |  |  | Settings | SystemSettingsAdminFlows.exe | C:\WINDOWS\system32\SystemSettingsAdminFlows.exe | C:\WINDOWS\system32\ | 4965081445568567330 | 683304 | 10.0.22621.2792 | 2023-12-17T12:37:06.555Z | 6F15BDE5240C45B44449A82B0F7F834D7993AE8C |  |  |  | 2023-12-17T12:37:06.555Z | 0 | 0 |  | 2023-12-15T02:32:22.31Z | Windows |  | SystemSettingsAdminFlows.EXE | NT SERVICE\TrustedInstaller | Microsoft® Windows® Operating System (TiWorker.exe) |  |  |  | ChangeStartupTaskStatus 9223372036854775808 \"Logitech Download Assistant\" 0 |  | Microsoft® Windows® Operating System | 10.0.22621.2792 | Microsoft Windows |  | 0 | Microsoft® Windows® Operating System (TiWorker.exe) |  |  |  |  |  |  | LocalDisk |  |  |  | ALL | 0 |  | true | PALOALTONETWORK\cbartuvia | 0 | 0 |  |
| 2023-12-17T12:36:16.408Z | false |  | Internet | 1 | f8443d50-4e35-442e-a886-d543080d5def |  | 2023-12-17T12:36:16.408Z |  |  |  |  | Microsoft Corporation | W-5CG3423Q0T | 0 | Settings (SystemSettingsAdminFlows.exe) | 1 | Trust | detailed raw |  |  |  |  | Settings | SystemSettingsAdminFlows.exe | C:\WINDOWS\system32\SystemSettingsAdminFlows.exe | C:\WINDOWS\system32\ | 4965081445568567330 | 683304 | 10.0.22621.2792 | 2023-12-17T12:36:10.435Z | 6F15BDE5240C45B44449A82B0F7F834D7993AE8C |  |  |  | 2023-12-17T12:36:10.435Z | 0 | 0 |  | 2023-12-15T02:32:22.31Z | Windows |  | SystemSettingsAdminFlows.EXE | NT SERVICE\TrustedInstaller | Microsoft® Windows® Operating System (TiWorker.exe) |  |  |  | ChangeStartupTaskStatus 9223372036854775808 \"RTKUGUI\" 0 |  | Microsoft® Windows® Operating System | 10.0.22621.2792 | Microsoft Windows |  | 0 | Microsoft® Windows® Operating System (TiWorker.exe) |  |  |  |  |  |  | LocalDisk |  |  |  | ALL | 0 |  | true | PALOALTONETWORK\cbartuvia | 0 | 0 |  |

#### Context Output

There is no context output for this command.