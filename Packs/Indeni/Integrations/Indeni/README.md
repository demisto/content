## Overview
---

Indeni Integration
This integration was integrated and tested with version 7.1.1 of Indeni
## Indeni Playbook
---

## Use Cases
---

## Configure Indeni on Demisto
---

1. Navigate to __Settings__ > __Integrations__ > __Servers & Services__.
2. Search for Indeni.
3. Click __Add instance__ to create and configure a new integration instance.
    * __Name__: a textual name for the integration instance.
    * __Use system proxy settings__
    * __Trust any certificate (not secure)__
    * __API url__:for example https://10.11.80.21:9443
    * __API Key__: obtained from Indeni settings -> about
    * __Fetch incidents__
    * __Incident type__
    * __Long running instance__
    * __Issue Type To Pull__: prefix match for unique_identifier field in the Indeni API response
4. Click __Test__ to validate the URLs, token, and connection.
## Fetched Incidents Data
---
```
{
    [ 
        {
            "occurred": "2019-10-07T19:55:44.236Z", 
            "updated": "2020-02-13T06:51:41.461Z", 
            "rawJSON": "{....}",
            "details": "Palo Alto Networks makes use of a 3rd-party component...",
            "Indeni Device ID": " 01178b51-b8af-4249-aecf-6e5b8da4a04f",
            "indeni Issue ID": "2b95a696-e8ff-49fa-a194-c3e908aabcbf",
            "name": "Denial of Service in PAN-OS Management Web Interface PAN-SA-2018-0008"
        }
    ]
}
```
## Commands
---
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
1. indeni-get-device-info
2. indeni-get-alert-info
3. indeni-get-alert-summary
4. indeni-post-note
5. indeni-archive-issue
6. indeni-unarchive-issue
7. indeni-get-notes
### 1. indeni-get-device-info
---
get the device information
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`indeni-get-device-info`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | device id string | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Indeni.DeviceInfo.DeviceId | string | device id string | 
| Indeni.DeviceInfo.DeviceIP | string | device ip string | 
| Indeni.DeviceInfo.DeviceName | string | device hostname | 
| Indeni.DeviceInfo.DeviceModel | string | device model | 
| Indeni.DeviceInfo.OSVersion | string | device OS version | 
| Indeni.DeviceInfo.CriticalAlertStats | number | # of critical alerts on the device | 
| Indeni.DeviceInfo.ErrorAlertStats | number | # of error alerts on the device | 
| Indeni.DeviceInfo.WarnAlertStats | number | # of warn alerts on the device | 
| Indeni.DeviceInfo.InfoAlertStats | number | # of info alerts on the device | 


##### Command Example
```!indeni-get-device-info device_id=01178b51-b8af-4249-aecf-6e5b8da4a04f```

##### Context Example
```
{
    "Indeni.DeviceInfo": {
        "DeviceIP": "172.16.20.80", 
        "DeviceModel": "PA-200", 
        "DeviceName": "kdlab-pa200", 
        "WarnAlertStats": 7, 
        "DeviceId": "01178b51-b8af-4249-aecf-6e5b8da4a04f", 
        "CriticalAlertStats": 3, 
        "ErrorAlertStats": 9, 
        "OSVersion": "7.0.9", 
        "InfoAlertStats": 1
    }
}
```

##### Human Readable Output
### Device Info
|CriticalAlertStats|DeviceIP|DeviceId|DeviceModel|DeviceName|ErrorAlertStats|InfoAlertStats|OSVersion|WarnAlertStats|
|---|---|---|---|---|---|---|---|---|
|3|172.16.20.80|01178b51-b8af-4249-aecf-6e5b8da4a04f|PA-200|kdlab-pa200|9|1|7.0.9|7|


### 2. indeni-get-alert-info
---
get detailed alert info
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`indeni-get-alert-info`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | the id of the alert | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Indeni.AlertInfo.AlertId | string | id of the alert | 
| Indeni.AlertInfo.Headline | string | headline of the alert | 
| Indeni.AlertInfo.DeviceId | string | device id | 
| Indeni.AlertInfo.AlertType | string | the alert type unique identifier | 


##### Command Example
```!indeni-get-alert-info alert_id=7f0a5ded-571a-4ba0-835d-ba2f76469226```

##### Context Example
```
{
    "Indeni.AlertInfo": {
        "Headline": "Vulnerability in the PAN-OS DNS Proxy PAN-SA-2017-0021", 
        "AlertType": "panos_vulnerability_pansa_20170021_rule", 
        "DeviceId": "01178b51-b8af-4249-aecf-6e5b8da4a04f", 
        "AlertId": "7f0a5ded-571a-4ba0-835d-ba2f76469226"
    }
}
```

##### Human Readable Output
### Alert ID 7f0a5ded-571a-4ba0-835d-ba2f76469226
|acknowledged|alert_blocks|alert_id|alert_type|configuration_set_id|create_at|device_id|evidence|headline|id|notes|resolved|revalidated_at|severity|unique_identifier|updated_at|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
|false|{'header': 'Description', 'body': 'A Remote Code Execution vulnerability exists in the PAN-OS DNS Proxy. This issue affects customers who have DNS Proxy enabled in PAN-OS. This issue affects both the Data and Management planes of the firewall. When DNS Proxy processes a specially crafted fully qualified domain names (FQDN), it is possible to execute code on the firewall. (Ref # PAN-77516 / CVE-2017-8390).\nVendor Severity Rating: Critical', 'type': 'text', 'position': 0},<br>{'header': 'Remediation Steps', 'body': 'Palo Alto Networks recommends disabling DNS Proxy for those customers who are affected and are unable to apply the update.\nFor more information please review: https://securityadvisories.paloaltonetworks.com/Home/Detail/91', 'type': 'text', 'position': 1}|49517|UNAUTOREMEDIATABLE_ISSUE|3409|2019-10-07T19:55:41.344Z|01178b51-b8af-4249-aecf-6e5b8da4a04f|ts: <br>snapshot: |Vulnerability in the PAN-OS DNS Proxy PAN-SA-2017-0021|7f0a5ded-571a-4ba0-835d-ba2f76469226|{'text': 'Issue has been marked as unacknowledged.', 'timestamp': 1581370678025, 'id': 'c2687096-14c0-496c-9cd1-49442cf183ff'},<br>{'text': 'Jira ticket created ["IKP-3864"]', 'timestamp': 1581369933755, 'id': '849f9acc-ffc8-4822-9476-d4babc241cfa'},<br>{'text': 'This issue is currently been handled by Demisto', 'timestamp': 1581369928340, 'id': 'ae3dc4b9-68b0-4ff8-a43f-e7a1bf0afd16'},<br>{'text': 'Issue has been marked as acknowledged.', 'timestamp': 1580851503217, 'id': '4be83182-adc7-4a72-ad02-50ecd3a2b06c'},<br>{'text': 'Jira ticket is resolved. ', 'timestamp': 1580851501985, 'id': 'db88d492-a721-4a5f-a7e4-937db94a029f'},<br>{'text': 'Jira ticket created ["IKP-3849"]', 'timestamp': 1580850843665, 'id': '6b7bd790-5a85-4ae7-953b-e2b3e6da83c4'},<br>{'text': 'This issue is currently been handled by Demisto', 'timestamp': 1580850839545, 'id': 'ae733b78-e697-44f4-ab1a-3c90715698ac'},<br>{'text': 'This issue is currently been handled by Demisto', 'timestamp': 1580501809210, 'id': '9ad4f6bb-0590-45f5-9be6-d1553939de18'},<br>{'text': 'Issue created.', 'timestamp': 1570478141344, 'id': '8d7ef6e3-d5ed-4f6d-b933-d369a8176072'}|false|2020-02-10T21:38:45.891Z|level: 0<br>description: CRITICAL|panos_vulnerability_pansa_20170021_rule|2020-02-10T21:37:58.027Z|


### 3. indeni-get-alert-summary
---
gets summary of given alert type for all devices
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`indeni-get-alert-summary`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_type_identifier | identifier for alert type | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Indeni.AlertSummary.Devices | string | device name | 


##### Command Example
```!indeni-get-alert-summary alert_type_identifier=panos_vulnerability_pansa_20170021_rule```

##### Context Example
```
{
    "Devices": [
        {
            "DeviceName": "kdlab-pa200", 
            "Items": []
        }
    ]
}
```

##### Human Readable Output
### Devices Experiencing Same Issue
|Devices|
|---|
|{'DeviceName': 'kdlab-pa200', 'Items': []}|


### 4. indeni-post-note
---
Post a note to a given issue id
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`indeni-post-note`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | the id of the alert | Required | 
| note | the content of the note | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
```!indeni-post-note alert_id=7f0a5ded-571a-4ba0-835d-ba2f76469226 note=Demisto```

##### Human Readable Output


### 5. indeni-archive-issue
---
Archive an issue for the given alert id
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`indeni-archive-issue`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | the alert id of the issue | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
```!indeni-archive-issue alert_id=7f0a5ded-571a-4ba0-835d-ba2f76469226```

##### Human Readable Output


### 6. indeni-unarchive-issue
---
Unarchive an existing issue
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`indeni-unarchive-issue`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | the alert id of the issue | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
```!indeni-unarchive-issue alert_id=7f0a5ded-571a-4ba0-835d-ba2f76469226```

##### Human Readable Output


### 7. indeni-get-notes
---
Gets the notes from issue
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`indeni-get-notes`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | The id of the alert | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Indeni.AlertInfo.Notes | Unknown | The notes of issue | 


##### Command Example
```!indeni-get-notes alert_id=7f0a5ded-571a-4ba0-835d-ba2f76469226```

##### Context Example
```
{
    "Notes": [
        {
            "note": "Issue has been marked as unacknowledged.", 
            "timestamp": 1581370787322
        }, 
        {
            "note": "Issue has been marked as acknowledged.", 
            "timestamp": 1581370786316
        }, 
        {
            "note": "Demisto", 
            "timestamp": 1581370785278
        }, 
        {
            "note": "Issue has been marked as unacknowledged.", 
            "timestamp": 1581370678025
        }, 
        {
            "note": "Jira ticket created [\"IKP-3864\"]", 
            "timestamp": 1581369933755
        }, 
        {
            "note": "This issue is currently been handled by Demisto", 
            "timestamp": 1581369928340
        }, 
        {
            "note": "Issue has been marked as acknowledged.", 
            "timestamp": 1580851503217
        }, 
        {
            "note": "Jira ticket is resolved. ", 
            "timestamp": 1580851501985
        }, 
        {
            "note": "Jira ticket created [\"IKP-3849\"]", 
            "timestamp": 1580850843665
        }, 
        {
            "note": "This issue is currently been handled by Demisto", 
            "timestamp": 1580850839545
        }, 
        {
            "note": "This issue is currently been handled by Demisto", 
            "timestamp": 1580501809210
        }, 
        {
            "note": "Issue created.", 
            "timestamp": 1570478141344
        }
    ]
}
```

##### Human Readable Output
### Issue Notes
|Notes|
|---|
|{'note': 'Issue has been marked as unacknowledged.', 'timestamp': 1581370787322},<br>{'note': 'Issue has been marked as acknowledged.', 'timestamp': 1581370786316},<br>{'note': 'Demisto', 'timestamp': 1581370785278},<br>{'note': 'Issue has been marked as unacknowledged.', 'timestamp': 1581370678025},<br>{'note': 'Jira ticket created ["IKP-3864"]', 'timestamp': 1581369933755},<br>{'note': 'This issue is currently been handled by Demisto', 'timestamp': 1581369928340},<br>{'note': 'Issue has been marked as acknowledged.', 'timestamp': 1580851503217},<br>{'note': 'Jira ticket is resolved. ', 'timestamp': 1580851501985},<br>{'note': 'Jira ticket created ["IKP-3849"]', 'timestamp': 1580850843665},<br>{'note': 'This issue is currently been handled by Demisto', 'timestamp': 1580850839545},<br>{'note': 'This issue is currently been handled by Demisto', 'timestamp': 1580501809210},<br>{'note': 'Issue created.', 'timestamp': 1570478141344}|


## Additional Information
---

## Known Limitations
---

## Troubleshooting
---


## Possible Errors (DO NOT PUBLISH ON ZENDESK):
