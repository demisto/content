## Overview
---

Indeni Integration
This integration was integrated and tested with version xx of Indeni
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
    * __Trust any certificate (not secure)__
    * __API url__
    * __API Key__
    * __Fetch incidents__
    * __Incident type__
    * __Only Pull PAN Vulnerability Issues__
    * __Use system proxy settings__
    * __Issue Severities To Pull__
4. Click __Test__ to validate the URLs, token, and connection.
## Fetched Incidents Data
---

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
|false|A Remote Code Execution vulnerability exists in the PAN-OS DNS Proxy. This issue affects customers who have DNS Proxy enabled in PAN-OS. This issue affects both the Data and Management planes of the firewall. When DNS Proxy processes a specially crafted fully qualified domain names (FQDN), it is possible to execute code on the firewall. (Ref # PAN-77516 / CVE-2017-8390).<br>Vendor Severity Rating: Critical<br>Palo Alto Networks recommends disabling DNS Proxy for those customers who are affected and are unable to apply the update.<br>For more information please review: https://securityadvisories.paloaltonetworks.com/Home/Detail/91|49517|UNAUTOREMEDIATABLE_ISSUE|3409|2019-10-07T19:55:41.344Z|01178b51-b8af-4249-aecf-6e5b8da4a04f|ts: <br>snapshot: |Vulnerability in the PAN-OS DNS Proxy PAN-SA-2017-0021|7f0a5ded-571a-4ba0-835d-ba2f76469226|Demisto<br>Demisto<br>Issue has been marked as unacknowledged.<br>Issue has been marked as acknowledged.<br>Demisto<br>Issue has been marked as unacknowledged.<br>Issue has been marked as acknowledged.<br>Demisto<br>Issue has been marked as unacknowledged.<br>Jira ticket created ["IKP-3864"]<br>This issue is currently been handled by Demisto<br>Issue has been marked as acknowledged.<br>Jira ticket is resolved. <br>Jira ticket created ["IKP-3849"]<br>This issue is currently been handled by Demisto<br>This issue is currently been handled by Demisto<br>Issue created.|false|2020-02-14T08:40:45.891Z|level: 0<br>description: CRITICAL|panos_vulnerability_pansa_20170021_rule|2020-02-13T08:38:23.445Z|


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
| Indeni.AffectedDevices.AlertType | String | Alert type that's affecting the devices | 
| Indeni.AffectedDevices.Device.DeviceName | String | Name of the affected device | 
| Indeni.AffectedDevices.Device.DeviceId | String | Id of the affected device | 


##### Command Example
```!indeni-get-alert-summary alert_type_identifier=panos_vulnerability_pansa_20170021_rule```

##### Context Example
```
{
    "Indeni.AffectedDevices": {
        "Device": [
            {
                "DeviceName": "kdlab-pa200", 
                "DeviceId": "01178b51-b8af-4249-aecf-6e5b8da4a04f", 
                "Items": []
            }
        ], 
        "AlertType": "panos_vulnerability_pansa_20170021_rule"
    }
}
```

##### Human Readable Output
### Devices Experiencing Alert panos_vulnerability_pansa_20170021_rule
|DeviceId|DeviceName|
|---|---|
|01178b51-b8af-4249-aecf-6e5b8da4a04f|kdlab-pa200|


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
Done

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
Done

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
Done

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
| Indeni.AlertInfo.Note | Unknown | Notes for the given issue | 


##### Command Example
```!indeni-get-notes alert_id=7f0a5ded-571a-4ba0-835d-ba2f76469226```

##### Context Example
```
{
    "Indeni.AlertInfo": [
        {
            "note": "Issue has been marked as unacknowledged.", 
            "timestamp": "2020-02-14T08:41:21.000Z"
        }, 
        {
            "note": "Issue has been marked as acknowledged.", 
            "timestamp": "2020-02-14T08:41:20.000Z"
        }, 
        {
            "note": "Demisto", 
            "timestamp": "2020-02-14T08:41:19.000Z"
        }, 
        {
            "note": "Demisto", 
            "timestamp": "2020-02-14T08:31:29.000Z"
        }, 
        {
            "note": "Demisto", 
            "timestamp": "2020-02-14T08:27:59.000Z"
        }, 
        {
            "note": "Issue has been marked as unacknowledged.", 
            "timestamp": "2020-02-13T08:38:23.000Z"
        }, 
        {
            "note": "Issue has been marked as acknowledged.", 
            "timestamp": "2020-02-13T08:37:51.000Z"
        }, 
        {
            "note": "Demisto", 
            "timestamp": "2020-02-13T08:35:33.000Z"
        }, 
        {
            "note": "Issue has been marked as unacknowledged.", 
            "timestamp": "2020-02-10T21:39:47.000Z"
        }, 
        {
            "note": "Issue has been marked as acknowledged.", 
            "timestamp": "2020-02-10T21:39:46.000Z"
        }, 
        {
            "note": "Demisto", 
            "timestamp": "2020-02-10T21:39:45.000Z"
        }, 
        {
            "note": "Issue has been marked as unacknowledged.", 
            "timestamp": "2020-02-10T21:37:58.000Z"
        }, 
        {
            "note": "Jira ticket created [\"IKP-3864\"]", 
            "timestamp": "2020-02-10T21:25:33.000Z"
        }, 
        {
            "note": "This issue is currently been handled by Demisto", 
            "timestamp": "2020-02-10T21:25:28.000Z"
        }, 
        {
            "note": "Issue has been marked as acknowledged.", 
            "timestamp": "2020-02-04T21:25:03.000Z"
        }, 
        {
            "note": "Jira ticket is resolved. ", 
            "timestamp": "2020-02-04T21:25:01.000Z"
        }, 
        {
            "note": "Jira ticket created [\"IKP-3849\"]", 
            "timestamp": "2020-02-04T21:14:03.000Z"
        }, 
        {
            "note": "This issue is currently been handled by Demisto", 
            "timestamp": "2020-02-04T21:13:59.000Z"
        }, 
        {
            "note": "This issue is currently been handled by Demisto", 
            "timestamp": "2020-01-31T20:16:49.000Z"
        }, 
        {
            "note": "Issue created.", 
            "timestamp": "2019-10-07T19:55:41.000Z"
        }
    ]
}
```

##### Human Readable Output
### Issue Notes
|note|timestamp|
|---|---|
|Issue has been marked as unacknowledged.|2020-02-14T08:41:21.000Z|
|Issue has been marked as acknowledged.|2020-02-14T08:41:20.000Z|
|Demisto|2020-02-14T08:41:19.000Z|
|Demisto|2020-02-14T08:31:29.000Z|
|Demisto|2020-02-14T08:27:59.000Z|
|Issue has been marked as unacknowledged.|2020-02-13T08:38:23.000Z|
|Issue has been marked as acknowledged.|2020-02-13T08:37:51.000Z|
|Demisto|2020-02-13T08:35:33.000Z|
|Issue has been marked as unacknowledged.|2020-02-10T21:39:47.000Z|
|Issue has been marked as acknowledged.|2020-02-10T21:39:46.000Z|
|Demisto|2020-02-10T21:39:45.000Z|
|Issue has been marked as unacknowledged.|2020-02-10T21:37:58.000Z|
|Jira ticket created ["IKP-3864"]|2020-02-10T21:25:33.000Z|
|This issue is currently been handled by Demisto|2020-02-10T21:25:28.000Z|
|Issue has been marked as acknowledged.|2020-02-04T21:25:03.000Z|
|Jira ticket is resolved. |2020-02-04T21:25:01.000Z|
|Jira ticket created ["IKP-3849"]|2020-02-04T21:14:03.000Z|
|This issue is currently been handled by Demisto|2020-02-04T21:13:59.000Z|
|This issue is currently been handled by Demisto|2020-01-31T20:16:49.000Z|
|Issue created.|2019-10-07T19:55:41.000Z|


## Additional Information
---

## Known Limitations
---

## Troubleshooting
---


## Possible Errors (DO NOT PUBLISH ON ZENDESK):
