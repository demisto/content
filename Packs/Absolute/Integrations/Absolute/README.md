Absolute is an adaptive endpoint security solution that delivers device security, data security, and asset management of endpoints.
This integration was integrated and tested with the API version 1.7 of Absolute.

## Configure Absolute in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Your Absolute server URL |  | True |
| Token ID | Token ID and Secret Key. | True |
| Secret Key |  | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### absolute-custom-device-field-list
***
Returns a list of custom device fields associated with the given device_id, based on the authorization token.


#### Base Command

`absolute-custom-device-field-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | The system unique identifier of the device. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Absolute.CustomDeviceField.DeviceUID | String | The system-defined unique identifier of the device. | 
| Absolute.CustomDeviceField.ESN | String | The unique ESN \(identifier\) assigned to the Absolute agent that is installed on a device. | 
| Absolute.CustomDeviceField.CDFValues.CDFUID | String | The unique identifier of the custom device field. | 
| Absolute.CustomDeviceField.CDFValues.FieldKey | String | The unique identifier of the custom device field in the classic version of Absolute. | 
| Absolute.CustomDeviceField.CDFValues.FieldName | String | The name assigned to the custom device field. | 
| Absolute.CustomDeviceField.CDFValues.CategoryCode | String | The type of custom device field. Possible values are: PREDEFINED, ESNCOLUMN, UDF. | 
| Absolute.CustomDeviceField.CDFValues.FieldValue | String | The current value of the custom device field. | 
| Absolute.CustomDeviceField.CDFValues.Type | String | The data type of the field value. Possible values are: Text, Date, Dropdown. | 

#### Command example
```!absolute-custom-device-field-list device_id=1234```
#### Context Example
```json
{
    "Absolute": {
        "CustomDeviceField": {
            "CDFValues": [
                {
                    "CDFUID": "4m9fUCZqTYec1bJgDSNg",
                    "CategoryCode": "ESNCOLUMN",
                    "FieldKey": 1,
                    "FieldName": "Asset Number",
                    "FieldValue": "aa",
                    "Type": "Text"
                },
                {
                    "CDFUID": "2iS3ryiSvSDsksJ289vtQ",
                    "CategoryCode": "UDF",
                    "FieldKey": 30,
                    "FieldName": "Custom2",
                    "FieldValue": "TPB",
                    "Type": "Text"
                }
            ],
            "DeviceUID": "1234",
            "ESN": "D0004"
        }
    }
}
```

#### Human Readable Output

>### Absolute Custom device field list
>|CDF ID|Field Value|Filed Name|
>|---|---|---|
>| 4m9fUCZqTYec1bJgDSNg | Asset Number | Asset Number |
>| 2iS3ryiSvSDsksJ289vtQ | Custom2 | Custom2 |


### absolute-custom-device-field-update
***
Updates the value of the included custom device fields for the given device_id.


#### Base Command

`absolute-custom-device-field-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | The system unique identifier of the device. | Required | 
| cdf_uid | The unique identifier of the custom device field. Note: In order to get this value, use the "absolute-custom-device-field-list" command. | Required | 
| value | The new value of the custom device field to be set. | Required | 


#### Context Output

There is no context output for this command.
#### Command example
```!absolute-custom-device-field-update device_id=1234 cdf_uid=4m9fUCZqTYec1bJgDSNg value="test2"```
#### Human Readable Output

>Device 1234 with value test2 was updated successfully.

### absolute-device-freeze-request
***
Creates a new Freeze request for the devices specified in the device_ids argument.


#### Base Command

`absolute-device-freeze-request`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_ids | A comma-separated list of the unique identifiers of devices included in the request. The recommendation is to use up to 10,000 devices per request. | Required | 
| request_name | The user-defined name for the Freeze request. The name should be a non-unique string and has 1-250 characters. | Required | 
| html_message | The user-defined, HTML coded message shown on devices when the Freeze is applied. The message should be in a non-unique HTML format and has 1-4000 characters. | Required | 
| message_name | The user-defined name for the Freeze message. | Required | 
| device_freeze_type | The type of Freeze. You cannot freeze a device that has been reported Stolen in the Absolute console.<br />- OnDemand: Freezes a device on its next connection to the Absolute Monitoring Center, which is typically within 15 minutes. This applies for all supported operating systems.<br />- Scheduled: Freezes a device on its next connection to the Absolute Monitoring Center on or after a specified date and time. This applies to Windows and Mac devices. The scheduled freeze date is specified in the scheduled_freeze_date argument. Scheduled Freeze requests are only supported on Windows and Mac devices with an active Absolute agent that is regularly connecting to the Absolute Monitoring Center.<br/>- Offline: Freezes a device if it has been offline for a specified period of time. Applies to Windows and Mac devices. Offline period is specified in the offline_time_seconds arguments. Offline freeze is not available if your Absolute account has been migrated to Offline Freeze Rules. For more information, see the console Help.<br/> Possible values are: OnDemand, Scheduled, Offline. | Required | 
| scheduled_freeze_date | The date and time (in UTC) when the device should be frozen in ISO 8601 format: YYYY-MM-DDThh:mm:ss.SSSZ. Required if device_freeze_type is Scheduled. For example, 2022-01-01T00:00:00.000Z. | Optional | 
| offline_time_seconds | The length of time (in seconds) that a device can be offline before the device is frozen. Required if device_freeze_type is Offline. Must be between 1200 seconds (20 minutes) and 172800000 seconds (2000 days). Default value is 30 days. Default is 22592000. | Optional | 
| passcode_type | The type of passcode to unfreeze a device.<br />- UserDefined: Manually set the passcode in passcode. You must specify the passcode argument.<br />- RandomForEach: A unique passcode is randomly generated for each device. You must specify the passcode_length argument.<br />- RandomForAll: A passcode is randomly generated and is the same for all devices. You must specify the passcode_length argument. Possible values are: UserDefined, RandomForEach, RandomForAll. | Required | 
| passcode | The passcode used to unfreeze the devices. Required if passcode_type is UserDefined. A valid passcode is a number that has 4-8 characters. For example, 12345678. | Optional | 
| passcode_length | The length of the passcode when it is randomly generated. Required if passcode_type is RandomForEach or RandomForAll. A valid passcode is a number from 4-8. For example, 8. | Optional | 
| notification_emails | A comma-separated list of user-entered email addresses that will receive an email notification when the status of the Freeze request changes. The API supports up to 10 email addresses. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Absolute.FreezeRequest.RequestUID | String | The system-defined, unique identifier of the Freeze request. | 
| Absolute.FreezeRequest.SucceededDeviceUIDs | Unknown | An array of the unique devices identifiers that succeeded in creating a Freeze request. | 
| Absolute.FreezeRequest.Errors.detail.deviceUids | Unknown | An array of the unique identifiers of devices for the Freeze request error. | 
| Absolute.FreezeRequest.Errors.message | String | The reason for the Freeze failure. | 
| Absolute.FreezeRequest.Errors.messageKey | String | The reference key for the error message. | 

#### Command example
```!absolute-device-freeze-request device_ids=123456 device_freeze_type=Scheduled html_message="test" message_name="new name" request_name="name1" scheduled_freeze_date=2022-04-03T13:30:00.000Z passcode_type=RandomForEach passcode_length=5```
#### Context Example
```json
{
    "Absolute": {
        "FreezeRequest": {
            "RequestUID": "2b62b290-d590-4237-8ba0-57e4779b9f1c",
            "SucceededDeviceUIDs": [
                "123456"
            ]
        }
    }
}
```

#### Human Readable Output

>### Absolute device freeze requests results
>|RequestUID|SucceededDeviceUIDs|
>|---|---|
>| 2b62b290-d590-4237-8ba0-57e4779b9f1c | 123456 |


### absolute-device-remove-freeze-request
***
Creates a new Remove Freeze request for one or more devices, regardless of their Freeze status. You can submit Remove Freeze requests to perform the following actions: unfreeze frozen devices, remove newly submitted Freeze requests, or remove outstanding Scheduled and Offline Freeze requests.


#### Base Command

`absolute-device-remove-freeze-request`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_ids | A comma-separated list of the unique identifiers of devices included in the request. The recommendation is to use up to 10,000 devices per request. | Required | 
| remove_scheduled | Whether to remove only a Scheduled Freeze request. Note: When setting to true, if the Freeze request is a Scheduled Freeze request, the Freeze request is removed. Otherwise, when setting to false, if the Freeze request is not a Scheduled Freeze request, the Freeze request is not removed. Possible values are: true, false. | Optional | 
| remove_offline | Whether to remove only an Offline Freeze request. Note: When setting to true, if the Freeze request is an Offline Freeze request, the Freeze request is removed. Otherwise, when setting to false, if the Freeze request is not an Offline Freeze request, the Freeze request is not removed. Possible values are: true, false. | Optional | 


#### Context Output

There is no context output for this command.
#### Command example
```!absolute-device-remove-freeze-request device_ids=123456 remove_scheduled=true```
#### Human Readable Output

>Successfully removed freeze request for devices ids: 123456.

### absolute-device-freeze-request-get
***
Gets detailed information about the Freeze request specified by request_uid.


#### Base Command

`absolute-device-freeze-request-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| request_uid | The system-defined, unique identifier of the Freeze request. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Absolute.FreezeRequestDetail.ID | String | The system-defined, unique identifier of the Freeze request. | 
| Absolute.FreezeRequestDetail.AccountUid | String | The system-defined, unique identifier associated with this Absolute account. | 
| Absolute.FreezeRequestDetail.ActionRequestUid | String | The system-defined, unique identifier of the Freeze request \(the same as ID\). | 
| Absolute.FreezeRequestDetail.DeviceUid | String | The system-defined, unique identifier of the device. | 
| Absolute.FreezeRequestDetail.Statuses.actionUid | String | The system-defined, unique identifier of the Freeze action. | 
| Absolute.FreezeRequestDetail.Statuses.statusUid | String | The system-defined, unique identifier of the Freeze status. | 
| Absolute.FreezeRequestDetail.Statuses.messageKey | String | The reference key for the error message or the info message. Error messages start with 'dds'. Info messages start with 'ddsui'. | 
| Absolute.FreezeRequestDetail.Statuses.messageParams | Unknown | A list of strings describing the error message when the status is LaunchFailed. If the status isn't LaunchFailed, messageParams is empty. | 
| Absolute.FreezeRequestDetail.Statuses.message | String | The message for the status change that occurred. | 
| Absolute.FreezeRequestDetail.Statuses.updatedBy | String | The last entity to update the Freeze request. | 
| Absolute.FreezeRequestDetail.Statuses.updatedUtc | Date | The time \(in Unix epoch\) when the Freeze request was last updated. | 
| Absolute.FreezeRequestDetail.Statuses.triggerActionUid | String | The system-defined, unique identifier of a new Freeze request that replaces another Freeze request of the same type. | 
| Absolute.FreezeRequestDetail.Statuses.eventType | String | Device freeze type event. | 
| Absolute.FreezeRequestDetail.Statuses.ackClientTS | Number | The acknowledgment timestamp \(in Unix epoch local time\) when the request was downloaded on the device. | 
| Absolute.FreezeRequestDetail.Statuses.ackClientUtc | Number | The acknowledgment timestamp \(in Unix epoch UTC\) when the request was downloaded to the device. | 
| Absolute.FreezeRequestDetail.Statuses.instruction | String | All action instructions which are sent from the device DFZ agent component. | 
| Absolute.FreezeRequestDetail.Statuses.scheduledFreezeDateUTC | Number | The date and time \(in Unix epoch\) when a Scheduled Freeze request was scheduled to be performed. | 
| Absolute.FreezeRequestDetail.Configuration.messageName | String | The user-defined name for the Freeze message. | 
| Absolute.FreezeRequestDetail.Configuration.htmlClear | String | The user-defined, HTML coded message shown on the device when the Freeze is applied \(the same as Configuration.freezeMessage except it contains the HTML tags\). | 
| Absolute.FreezeRequestDetail.Configuration.passcodeClear | String | The passcode that can be used to unfreeze the device. | 
| Absolute.FreezeRequestDetail.Configuration.passcodeOption | String | The type of passcode to unfreeze a device. | 
| Absolute.FreezeRequestDetail.Configuration.freezeMessage | String | The content of the Freeze message without the HTML tags. | 
| Absolute.FreezeRequestDetail.Configuration.freezeId | String | The user-friendly identifier of the request that is displayed in the event history in the Absolute console \(same as EventHistoryId\). | 
| Absolute.FreezeRequestDetail.Configuration.configurationUid | String | The system-defined unique identifier assigned to the Freeze configuration. | 
| Absolute.FreezeRequestDetail.Configuration.action | String | The type of action being performed on the device. | 
| Absolute.FreezeRequestDetail.Configuration.type | String | The type of Freeze. | 
| Absolute.FreezeRequestDetail.Configuration.passcodeLength | Number | The length of the device unfreeze passcode when it is randomly generated. | 
| Absolute.FreezeRequestDetail.Configuration.passcodeSalt | String | The salt used for hashing the passcode before the passcode is sent to the device. | 
| Absolute.FreezeRequestDetail.Configuration.passcodeHashed | String | The hashed value of the passcode. | 
| Absolute.FreezeRequestDetail.Configuration.html | String | The encoded value of Configuration.htmlClear. | 
| Absolute.FreezeRequestDetail.Configuration.disableRemoteLogin | Boolean | Whether remote login is disabled on the device. | 
| Absolute.FreezeRequestDetail.Configuration.disableFileSharing | Boolean | Whether file sharing is disabled on the device. | 
| Absolute.FreezeRequestDetail.Configuration.Conditions.secondsUntilFreeze | Number | The amount of time \(in seconds\) a device can be offline before the device is frozen. | 
| Absolute.FreezeRequestDetail.Configuration.Conditions.scheduledFreezeDate | Date | The date and time \(in UTC\) that a Scheduled Freeze request is scheduled to be performed. | 
| Absolute.FreezeRequestDetail.Configuration.issuedUtc | Date | The date and time \(in Unix epoch\) when the Freeze request was created. | 
| Absolute.FreezeRequestDetail.Configuration.preLoginEnabled | Boolean | Whether pre-login is enabled on the device. | 
| Absolute.FreezeRequestDetail.Configuration.serviceControlList | String | List of service controls that the server sends to the device. | 
| Absolute.FreezeRequestDetail.Name | String | The user-defined name for the Freeze request. | 
| Absolute.FreezeRequestDetail.Requester | String | The user ID of the entity that created the Freeze request. | 
| Absolute.FreezeRequestDetail.RequesterUid | String | The system-defined unique identifier of the user who created the Freeze request. | 
| Absolute.FreezeRequestDetail.CreatedUTC | Date | The date and time \(in Unix epoch\) when the Freeze request was created. | 
| Absolute.FreezeRequestDetail.ChangedUTC | Date | The date and time \(in Unix epoch\) when the Freeze request was last modified. | 
| Absolute.FreezeRequestDetail.NotificationEmails | Unknown | An array of user-entered email addresses that will receive an email notification when the status of the Freeze request changes. Supports up to 10 email addresses. | 
| Absolute.FreezeRequestDetail.EventHistoryId | String | The user-friendly identifier of the request that is displayed in the event history in the Absolute console \(same as freezeId\). | 
| Absolute.FreezeRequestDetail.PolicyGroupUid | String | The system-defined unique identifier of the policy group that the device belongs to. | 
| Absolute.FreezeRequestDetail.PolicyConfigurationVersion | Number | The version of the configuration for the policy. | 
| Absolute.FreezeRequestDetail.FreezePolicyUid | String | The unique identifier of the Freeze policy. | 
| Absolute.FreezeRequestDetail.Downloaded | Boolean | Whether the Freeze request has been downloaded to the device. | 
| Absolute.FreezeRequestDetail.IsCurrent | Boolean | Internal flag. | 

#### Command example
```!absolute-device-freeze-request-get request_uid=c638c2dc-1dd1-4cfa-8708-46f368012398```
#### Context Example
```json
{
    "Absolute": {
        "FreezeRequestDetail": {
            "AccountUid": "accountID",
            "ActionRequestUid": "c638c2dc-1dd1-4cfa-8708-46f368012398",
            "ChangedBy": null,
            "ChangedUTC": "2022-03-29T10:30:55.462+00:00",
            "Configuration": {
                "action": "DFZ",
                "conditions": [
                    {
                        "scheduledFreezeDate": "2022-03-29T10:30:22.000+00:00"
                    }
                ],
                "configurationUid": "c61b0cb7-3846-4d1e-9e78-641084b7747a",
                "disableFileSharing": true,
                "disableRemoteLogin": true,
                "forceReboot": false,
                "freezeId": "DeviceFreeze-0010",
                "freezeMessage": "test",
                "htmlClear": "<html><head><meta http-equiv=\"Content-Type\" content=\"text/html; charset=UTF-8\"></head><body><p style=\"font-size: small\">DeviceFreeze-0010</p><hr>test</body></html>",
                "issuedUTC": "2022-03-29T10:30:24.268+00:00",
                "messageName": "new name",
                "passcodeClear": "26148",
                "passcodeHashed": "c5pr+oaojn37SFZJ3uokRe0Uy/+kAhzPNv6TyrCzXOdL1vu/KyoFF7T6rQfLK6ej2jYWXPGRzxWCfrS9f/S8JA==",
                "passcodeLength": 5,
                "passcodeOption": "RandomForEach",
                "passcodeSalt": "/4VA8uE3DUv04mWy9iGkZp5rL3zDwtEP/YsqAvL190VIn9bhPZUzYXozoSSEPro0tVSVMtG9Rfssqpy2yvsm6g==",
                "preLoginEnabled": true,
                "type": "Scheduled"
            },
            "Content": null,
            "CreatedBy": null,
            "CreatedUTC": "2022-03-29T10:30:24.279+00:00",
            "DeviceUid": "123456",
            "Downloaded": false,
            "EventHistoryId": "DeviceFreeze-0010",
            "FreezePolicyUid": null,
            "ID": "fa72b6ed-62f4-40bd-b581-ef5c114efb8e",
            "IsCurrent": false,
            "Name": "name1",
            "NotificationEmails": [],
            "PolicyConfigurationVersion": 0,
            "PolicyGroupUid": null,
            "Requester": "example@test.com",
            "RequesterUid": "778f8cce-8cc6-4de1-b025-e0538f97e072",
            "Statuses": [
                {
                    "ackClientTS": 0,
                    "ackClientUTC": 1,
                    "eventType": "Remove",
                    "scheduledFreezeDateUTC": 0,
                    "status": "Removed",
                    "statusUid": "9e413f56-8b2d-4605-9527-536427b9ad02",
                    "updatedBy": "example@test.com",
                    "updatedUTC": "2022-03-29T10:30:55.462+00:00"
                },
                {
                    "ackClientTS": 0,
                    "ackClientUTC": 0,
                    "scheduledFreezeDateUTC": 0,
                    "status": "FreezeRequested",
                    "updatedBy": "example@test.com",
                    "updatedUTC": "2022-03-29T10:30:24.268+00:00"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Absolute Freeze request details for: c638c2dc-1dd1-4cfa-8708-46f368012398
>|ID|Name|AccountUid|ActionRequestUid|EventHistoryId|CreatedUTC|ChangedUTC|Requester|
>|---|---|---|---|---|---|---|---|
>| fa72b6ed-62f4-40bd-b581-ef5c114efb8e | name1 | accountID | c638c2dc-1dd1-4cfa-8708-46f368012398 | DeviceFreeze-0010 | 2022-03-29T10:30:24.279+00:00 | 2022-03-29T10:30:55.462+00:00 | example@test.com |


### absolute-device-freeze-message-list
***
Gets all the Freeze messages that are configured for the account by the given message_id. If message_id is not given all the messages will be returned.


#### Base Command

`absolute-device-freeze-message-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| message_id | The system-defined, unique identifier of the Freeze message. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Absolute.FreezeMessage.ID | String | The system-defined, unique identifier of the Freeze message. | 
| Absolute.FreezeMessage.Name | String | The user-defined name for the Freeze message. | 
| Absolute.FreezeMessage.Content | String | The user-defined, HTML coded message that shows on a device when a Freeze is applied. | 
| Absolute.FreezeMessage.CreatedBy | String | The username of the entity that created the Freeze message. | 
| Absolute.FreezeMessage.ChangedBy | String | The username of the entity that last updated the Freeze message. | 
| Absolute.FreezeMessage.CreatedUTC | String | The date and time when the Freeze message was created. | 
| Absolute.FreezeMessage.ChangedUTC | String | The date and time when the Freeze message was last modified. | 

#### Command example
```!absolute-device-freeze-message-list```
#### Context Example
```json
{
    "Absolute": {
        "FreezeMessage": {
            "ChangedBy": "778f8cce-8cc6-4de1-b025-e0538f97e072",
            "ChangedUTC": "2022-04-03T07:45:01.487+00:00",
            "Content": "some text- new",
            "CreatedBy": "example@test.com",
            "CreatedUTC": "2022-04-03T07:45:01.487+00:00",
            "ID": "711b5da9-3867-473f-9d8f-9aba3de42b7a",
            "Name": "name"
        }
    }
}
```

#### Human Readable Output

>### Absolute Device freeze message details:
>|ID|Name|CreatedUTC|ChangedUTC|ChangedBy|CreatedBy|
>|---|---|---|---|---|---|
>| 711b5da9-3867-473f-9d8f-9aba3de42b7a | name | 2022-04-03T07:45:01.487+00:00 | 2022-04-03T07:45:01.487+00:00 | 778f8cce-8cc6-4de1-b025-e0538f97e072 | example@test.com |


### absolute-device-freeze-message-create
***
Creates a new Freeze message for the account.


#### Base Command

`absolute-device-freeze-message-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| html_message | The user-defined, HTML coded message that shows on a device when a Device Freeze is applied. Should be in HTML format with 1-4000 characters. | Required | 
| message_name | The user-defined name for the Device Freeze message. The name should be a string with 1-255 characters. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Absolute.FreezeMessage.ID | String | The system-defined, unique identifier of the Freeze message. | 

#### Command example
```!absolute-device-freeze-message-create html_message="some text" message_name="name name"```
#### Context Example
```json
{
    "Absolute": {
        "FreezeMessage": {
            "ID": "bdaf3a55-411a-4393-a0bf-7340f38fbc68"
        }
    }
}
```

#### Human Readable Output

>Absolute New freeze message was created with ID: bdaf3a55-411a-4393-a0bf-7340f38fbc68

### absolute-device-freeze-message-update
***
Updates the content of an existing Freeze message.


#### Base Command

`absolute-device-freeze-message-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| html_message | The user-defined, HTML coded message that shows on a device when a Device Freeze is applied. Should be in HTML format with 1-4000 characters. | Required | 
| message_name | The user-defined name for the Device Freeze message. The name should be a string with 1-255 characters. | Required | 
| message_id | The system-defined, unique identifier of the Freeze message. | Required | 


#### Context Output

There is no context output for this command.
#### Command example
```!absolute-device-freeze-message-update html_message="new mesg" message_id=711b5da9-3867-473f-9d8f-9aba3de42b7a message_name="name-new"```
#### Human Readable Output

>Absolute Freeze message: 711b5da9-3867-473f-9d8f-9aba3de42b7a was updated successfully

### absolute-device-freeze-message-delete
***
Deletes an existing Freeze message for the account.


#### Base Command

`absolute-device-freeze-message-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| message_id | The system-defined, unique identifier of the Freeze message. | Required | 


#### Context Output

There is no context output for this command.
#### Command example
```!absolute-device-freeze-message-delete message_id="711b5da9-3867-473f-9d8f-9aba3de42b7a"```
#### Human Readable Output

>Absolute Freeze message: 711b5da9-3867-473f-9d8f-9aba3de42b7a was deleted successfully

### absolute-device-unenroll
***
Initiates an unenroll request on a list of eligible devices.


#### Base Command

`absolute-device-unenroll`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_ids | A comma-separated list of device UIDs that should be unenrolled. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Absolute.DeviceUnenroll.DeviceUid | String | The unique GUID identifier of the device. | 
| Absolute.DeviceUnenroll.SystemName | String | The name assigned to the device. | 
| Absolute.DeviceUnenroll.Username | String | The unique user name of the user who was logged into the device at the time of the agent call. | 
| Absolute.DeviceUnenroll.EligibleStatus | Number | The eligibility status of the device. Possible vales are: 0 for eligible, 1 for inactive or disabled, and 2 for stolen. | 
| Absolute.DeviceUnenroll.Serial | String | The identification number that is assigned to the device by the device manufacturer. | 
| Absolute.DeviceUnenroll.ESN | String | The unique Electronic SerialNumber \(ESN\) that is assigned to the agent installed on the device. | 

#### Command example
```!absolute-device-unenroll device_ids="1"```
#### Context Example
```json
{
    "Absolute": {
        "DeviceUnenroll": [
            {
                "DeviceUid": "1",
                "ESN": "2BU2PJD28VAA1UYL0008",
                "EligibleStatus": 0,
                "Serial": "CNF83051BN",
                "SystemName": "user1",
                "Username": "example@test.com"
            },
            {
                "DeviceUid": "2",
                "ESN": "2BU2PJ545L0008",
                "EligibleStatus": 1,
                "Serial": "CNF43051BN",
                "SystemName": "user2",
                "Username": "example2@test.com"
            }
        ]
    }
}
```

#### Human Readable Output

>### Absolute unenroll devices:
>|DeviceUid|ESN|EligibleStatus|Serial|SystemName|Username|
>|---|---|---|---|---|---|
>| 1 | 2BU2PJD28VAA1UYL0008 | 0 | CNF83051BN | user1 | example@test.com |
>| 2 | 2BU2PJ545L0008 | 1 | CNF43051BN | user2 | example2@test.com |


### absolute-device-application-list
***
Gets a list of device records and the corresponding software application data for each device on the account that you have access to or that meets the given filter.


#### Base Command

`absolute-device-application-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter | The query by which to filter the device applications. If this argument is set, it overrides the others. For example, appName eq 'someName' or availableVirtualMemoryBytes lt 1073741824. | Optional | 
| return_fields | A comma-separated list of all specific values to return. If not set, all possible values will be returned. | Optional | 
| account_uids | A comma-separated list of the unique ID associated with this Absolute accounts. | Optional | 
| device_ids | A comma-separated list of the system-defined unique identifier of the devices. | Optional | 
| device_names | A comma-separated list of the devices names. | Optional | 
| app_names | A comma-separated list of the applications names. | Optional | 
| app_publishers | A comma-separated list of the name of the software publishers of the application. | Optional | 
| user_names | A comma-separated list of the user names of the users logged in to the device. | Optional | 
| os | A comma-separated list of the operating systems that are installed on the device. | Optional | 
| esn | A comma-separated list of the system-defined unique Electronic Serial Numbers (ESN) assigned to the Absolute agent installed on the device. | Optional | 
| limit | Maximum number of results to return. The default is 50. Default is 50. | Optional | 
| page | The page number of the results to retrieve. Minimum value is 0. Default is 0. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Absolute.DeviceApplication.DeviceAppId | String | The unique ID of the application. | 
| Absolute.DeviceApplication.DeviceUid | String | The system-defined unique identifier of the device. | 
| Absolute.DeviceApplication.AccountUid | String | The unique ID associated with this Absolute account. | 
| Absolute.DeviceApplication.AppId | String | The identifier of the application. | 
| Absolute.DeviceApplication.AppName | String | The name of the application. | 
| Absolute.DeviceApplication.AppPublisher | String | The name of the software publisher of the application. | 
| Absolute.DeviceApplication.AppOriginalPublisher | String | The original name of the software publisher of the application. | 
| Absolute.DeviceApplication.AppVersion | String | The version of the application. | 
| Absolute.DeviceApplication.Ens | String | The system-defined unique Electronic Serial Number \(ESN\) assigned to the Absolute agent installed on the device. | 
| Absolute.DeviceApplication.DeviceName | String | The name of the device. | 
| Absolute.DeviceApplication.DeviceSerialNumber | String | The identification number that is assigned to the device by the device manufacturer. | 
| Absolute.DeviceApplication.UserName | String | Includes the device name and the username of the user logged in to the device at the time of the agent call. | 
| Absolute.DeviceApplication.InstallPath | String | The location where the application is installed. | 
| Absolute.DeviceApplication.InstallDate | Date | The date \(in Unix epoch time\) when the application was installed. | 
| Absolute.DeviceApplication.FirstDetectUtc | Date | The date and time \(in Unix epoch time\) when the indicated version of the application was first detected on the device. | 
| Absolute.DeviceApplication.OsName | String | The operating system that is installed on the device. | 
| Absolute.DeviceApplication.LastScanTimeUtc | Date | The date and time \(in Unix epoch time\) of the most recent installed software \(SNG\) scan. | 

#### Command example
```!absolute-device-application-list device_ids=1234 filter="appName eq 'Notepad++' or appName eq 'Settings'"```
#### Context Example
```json
{
    "Absolute": {
        "DeviceApplication": [
            {
                "AccountUid": "accountID",
                "AppId": "U2V0dGluZ3N8fE1pY3Jvc29mdHx8MTAuMC4yLjEwMDA=",
                "AppName": "Settings",
                "AppOriginalName": "Settings",
                "AppOriginalPublisher": "Microsoft Corporation",
                "AppOriginalVersion": "10.0.2.1000",
                "AppPublisher": "Microsoft",
                "AppVersion": "10.0.2.1000",
                "DeviceAppId": "123456_24222cfe5ccbe45e6d5a78faa58cd977921b4c1dd552884ec38653934c3b75f9",
                "DeviceName": "ABSOLUTE-ASSET-",
                "DeviceSerialNumber": "GoogleCloud-B8736A4405BF0E968020BCBC46EDA096",
                "DeviceUid": "123456",
                "Esn": "D0001",
                "FirstDetectUtc": 1648601001193,
                "InstallDate": 1536995941018,
                "InstallPath": "C:\\Windows\\ImmersiveControlPanel",
                "LastScanTimeUtc": 1648627356120,
                "OsName": "Microsoft Windows Server 2019 Datacenter"
            },
            {
                "AccountUid": "accountID",
                "AppId": "Tm90ZXBhZCsrfHxOb3RlUGFkfHw4LjMuMw==",
                "AppName": "Notepad++",
                "AppOriginalName": "Notepad++ (64-bit x64)",
                "AppOriginalPublisher": "Notepad++ Team",
                "AppOriginalVersion": "8.3.3",
                "AppPublisher": "NotePad",
                "AppVersion": "8.3.3",
                "DeviceAppId": "1234_3653d2a872cd1208dfc4845a20670a6c9364a626cd6c987cd5e916ca71f38105",
                "DeviceName": "ABSOLUTE-ASSET-",
                "DeviceSerialNumber": "GoogleCloud-6420CF930DEE84DE8497CF40F0D56AFA",
                "DeviceUid": "1234",
                "Esn": "D0004",
                "FirstDetectUtc": 1648027180153,
                "InstallDate": 1648026266334,
                "InstallPath": "C:\\Program Files\\Notepad++",
                "LastScanTimeUtc": 1648894013571,
                "OsName": "Microsoft Windows Server 2022 Datacenter"
            },
            {
                "AccountUid": "accountID",
                "AppId": "U2V0dGluZ3N8fE1pY3Jvc29mdHx8MTAuMC40LjEwMDA=",
                "AppName": "Settings",
                "AppOriginalName": "Settings",
                "AppOriginalPublisher": "Microsoft Corporation",
                "AppOriginalVersion": "10.0.4.1000",
                "AppPublisher": "Microsoft",
                "AppVersion": "10.0.4.1000",
                "DeviceAppId": "1234_f3ef442d95c3b7155fe9b138384bda2219afb3048c2a9466f1174fc1488ca671",
                "DeviceName": "ABSOLUTE-ASSET-",
                "DeviceSerialNumber": "GoogleCloud-6420CF930DEE84DE8497CF40F0D56AFA",
                "DeviceUid": "1234",
                "Esn": "D0004",
                "FirstDetectUtc": 1648027180153,
                "InstallDate": 1620462024187,
                "InstallPath": "C:\\Windows\\ImmersiveControlPanel",
                "LastScanTimeUtc": 1648894013571,
                "OsName": "Microsoft Windows Server 2022 Datacenter"
            }
        ]
    }
}
```

#### Human Readable Output

>### Absolute device applications list:
>|AccountUid|AppId|AppName|AppOriginalName|AppOriginalPublisher|AppOriginalVersion|AppPublisher|AppVersion|DeviceAppId|DeviceName|DeviceSerialNumber|DeviceUid|Esn|FirstDetectUtc|InstallDate|InstallPath|LastScanTimeUtc|OsName|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| accountID | U2V0dGluZ3N8fE1pY3Jvc29mdHx8MTAuMC4yLjEwMDA= | Settings | Settings | Microsoft Corporation | 10.0.2.1000 | Microsoft | 10.0.2.1000 | 123456_24222cfe5ccbe45e6d5a78faa58cd977921b4c1dd552884ec38653934c3b75f9 | ABSOLUTE-ASSET- | GoogleCloud-B8736A4405BF0E968020BCBC46EDA096 | 123456 | D0001 | 1648601001193 | 1536995941018 | C:\Windows\ImmersiveControlPanel | 1648627356120 | Microsoft Windows Server 2019 Datacenter |
>| accountID | Tm90ZXBhZCsrfHxOb3RlUGFkfHw4LjMuMw== | Notepad++ | Notepad++ (64-bit x64) | Notepad++ Team | 8.3.3 | NotePad | 8.3.3 | 1234_3653d2a872cd1208dfc4845a20670a6c9364a626cd6c987cd5e916ca71f38105 | ABSOLUTE-ASSET- | GoogleCloud-6420CF930DEE84DE8497CF40F0D56AFA | 1234 | D0004 | 1648027180153 | 1648026266334 | C:\Program Files\Notepad++ | 1648894013571 | Microsoft Windows Server 2022 Datacenter |
>| accountID | U2V0dGluZ3N8fE1pY3Jvc29mdHx8MTAuMC40LjEwMDA= | Settings | Settings | Microsoft Corporation | 10.0.4.1000 | Microsoft | 10.0.4.1000 | 1234_f3ef442d95c3b7155fe9b138384bda2219afb3048c2a9466f1174fc1488ca671 | ABSOLUTE-ASSET- | GoogleCloud-6420CF930DEE84DE8497CF40F0D56AFA | 1234 | D0004 | 1648027180153 | 1620462024187 | C:\Windows\ImmersiveControlPanel | 1648894013571 | Microsoft Windows Server 2022 Datacenter |
>Above results are with page number: 0 and with size: 50.

### absolute-device-list
***
Gets a list of device records and their corresponding data that meets the required filter for all devices in your account, based on your authorization token.


#### Base Command

`absolute-device-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter | The query by which to filter all the devices managed by the account. If this argument is set, it overrides the others. For example, agentStatus eq 'A' or lastConnectedUtc lt datetime'2021-01-01T00:00:00Z'. | Optional | 
| agent_status | The status of the Absolute agent on the device. Possible values are: Active, Disabled, Inactive. | Optional | 
| os_name | Short description of the operating system expressed as a one-line string that includes the version of the operating system. | Optional | 
| os_version | The version of the operating system. | Optional | 
| manufacturer | The manufacturer of the device. | Optional | 
| model | The product name from the manufacturer. | Optional | 
| user_names | A comma-separated list of the usernames of the users who were logged in to the device at the time of the most recent agent call. If no user was logged in during the last agent call, the last detected username is used. | Optional | 
| limit | Maximum number of results to return. Default is 50. | Optional | 
| page | The page number of the results to retrieve. Minimum value is 0. Default is 0. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Absolute.Device.Id | String | The unique identifier assigned to the device. | 
| Absolute.Device.Esn | String | The unique ESN \(Absolute Identifier\) assigned to the agent installed on the device. | 
| Absolute.Device.LastConnectedUtc | Number | The date and time \(in Unix epoch\) when the device last connected to the Absolute Monitoring Center. | 
| Absolute.Device.SystemName | String | The name assigned to the device. | 
| Absolute.Device.FullSystemName | String | The full name assigned to the device consisting of the system name and the domain name. | 
| Absolute.Device.AgentStatus | String | The status of the Absolute agent on the device. | 
| Absolute.Device.osName | String | Short description of the operating system expressed as a one-line string that includes the version of the operating system. | 
| Absolute.Device.SystemManufacturer | String | The manufacturer of the device. | 
| Absolute.Device.SystemModel | String | The product name from the manufacturer. | 
| Absolute.Device.SystemType | String | The system running on the Windows-based computer. | 
| Absolute.Device.Serial | String | The manufacturer-defined unique identifier assigned to the device. May correspond to the serial number of the BIOS, the motherboard, or the chassis, depending on the manufacturer. | 
| Absolute.Device.LocalIp | String | Last known local IP address of this device. | 
| Absolute.Device.PublicIp | String | Last known public IP address of this device. | 
| Absolute.Device.EncryptionStatus | String | The summarized encryption status of the device. | 

#### Command example
```!absolute-device-list os_name="Microsoft Windows Server 2019 Datacenter"```
#### Context Example
```json
{
    "Absolute": {
        "Device": {
            "AgentStatus": "A",
            "Esn": "D0001",
            "FullSystemName": "ABSOLUTE-ASSET-.WORKGROUP",
            "Id": "123456",
            "LastConnectedUtc": 1648971645189,
            "LocalIp": "127.0.0.1",
            "PublicIp": "127.0.0.1",
            "Serial": "GoogleCloud-B8736A4405BF0E968020BCBC46EDA096",
            "SystemManufacturer": "Google",
            "SystemModel": "GOOGLE COMPUTE ENGINE",
            "SystemName": "ABSOLUTE-ASSET-",
            "SystemType": "x64-based PC",
            "osName": "Microsoft Windows Server 2019 Datacenter"
        }
    }
}
```

#### Human Readable Output

>### Absolute devices list:
>|AgentStatus|Esn|FullSystemName|Id|LastConnectedUtc|LocalIp|PublicIp|Serial|SystemManufacturer|SystemModel|SystemName|SystemType|osName|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| A | D0001 | ABSOLUTE-ASSET-.WORKGROUP | 123456 | 1648971645189 | 127.0.0.1 | 127.0.0.1 | GoogleCloud-B8736A4405BF0E968020BCBC46EDA096 | Google | GOOGLE COMPUTE ENGINE | ABSOLUTE-ASSET- | x64-based PC | Microsoft Windows Server 2019 Datacenter |
>Above results are with page number: 0 and with size: 50.

### absolute-device-get
***
Gets a list of device records and their corresponding data that meets the required fields for all devices in your account.


#### Base Command

`absolute-device-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| fields | A comma-separated list of all specific values to return. | Optional | 
| device_ids | A comma-separated list of the system-defined unique identifier of the devices. | Optional | 
| device_names | A comma-separated list of the devices names. | Optional | 
| local_ips | A comma-separated list of the last known local IP addresses of a device. | Optional | 
| public_ips | A comma-separated list of the last known public IP addresses of a device. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Absolute.Device.Id | String | The unique identifier assigned to the device. | 
| Absolute.Device.Esn | String | The unique ESN \(Absolute Identifier\) assigned to the agent installed on the device. | 
| Absolute.Device.Domain | String | The name of the Windows domain to which this device belongs. | 
| Absolute.Device.LastConnectedUtc | Number | The date and time \(in Unix epoch\) when the device last connected to the Absolute Monitoring Center. | 
| Absolute.Device.SystemName | String | The name assigned to the device. | 
| Absolute.Device.FullSystemName | String | The full name assigned to the device consisting of the system name and the domain name. | 
| Absolute.Device.AgentStatus | String | The status of the Absolute agent on the device. | 
| Absolute.Device.Os.name | String | Short description of the operating system expressed as a one-line string that includes the version of the operating system. | 
| Absolute.Device.Os.version | String | The version of the operating system. | 
| Absolute.Device.Os.currentBuild | String | The current build number of the operating system. | 
| Absolute.Device.Os.architecture | String | The architecture of the operating system. | 
| Absolute.Device.Os.installDate | Number | The date and time \(in Unix epoch\) when the operating system was installed. | 
| Absolute.Device.Os.productKey | String | The product key of the operating system. | 
| Absolute.Device.Os.serialNumber | String | The serial identification number of the operating system. | 
| Absolute.Device.Os.lastBootTime | Number | The date and time \(in Unix epoch\) when the operating system was last restarted. | 
| Absolute.Device.Bios.id | String | The unique identifier of this BIOS given by the manufacturer. | 
| Absolute.Device.Bios.serialNumber | String | The serial number assigned to the BIOS. | 
| Absolute.Device.Bios.smBiosVersion | String | The major version number of the BIOS, as reported by SMBIOS. | 
| Absolute.Device.Bios.version | String | The version of the BIOS, as reported by SMBIOS. | 
| Absolute.Device.Bios.versionDate | String | A substring of the manufacturer of the BIOS \+ the version of the BIOS version, as reported by SMBIOS \+ the release date of the Window BIOS. | 
| Absolute.Device.SystemManufacturer | String | The manufacturer of the device. | 
| Absolute.Device.SystemModel | String | The product name from the manufacturer. | 
| Absolute.Device.SystemType | String | The system running on the Windows-based computer. | 
| Absolute.Device.Serial | String | The manufacturer-defined unique identifier assigned to the device. May correspond to the serial number of the BIOS, the motherboard, or the chassis, depending on the manufacturer. | 
| Absolute.Device.LocalIp | String | Last known local IP address of this device. | 
| Absolute.Device.PublicIp | String | Last known public IP address of this device. | 
| Absolute.Device.EncryptionStatus | String | The summarized encryption status of the device. | 
| Absolute.Device.Username | String | The unique username of the user that was logged in to the device at the time of the most recent agent call. | 
| Absolute.Device.PolicyGroupUid | String | The unique identifier of the policy group that the device belongs to. | 
| Absolute.Device.PolicyGroupName | String | The name of the policy group that the device belongs to. | 
| Absolute.Device.IsStolen | String | Indicates whether this device was reported as stolen. | 
| Absolute.Device.DeviceStatus.type | String | The status of the device. Possible values are STOLEN or MISSING. | 
| Absolute.Device.DeviceStatus.reported | Number | The data and time \(in Unix epoch\) when the device was reported missing or stolen. | 
| Absolute.Device.NetworkAdapters.networkSSID | String | The Service Set Identifier \(SSID\) of the connected Wi-Fi adapter. | 

#### Command example
```!absolute-device-get device_names="ABSOLUTE-ASSET-"```
#### Context Example
```json
{
    "Absolute": {
        "Device": [
            {
                "AgentStatus": "A",
                "Bios": {
                    "id": "Google - 1 Google ",
                    "serialNumber": "GoogleCloud-B8736A4405BF0E968020BCBC46EDA096",
                    "smBiosVersion": "2.4",
                    "version": "Google - 1 Google ",
                    "versionDate": "Google Google, 01/01/2011"
                },
                "Domain": "WORKGROUP",
                "Esn": "D0001",
                "FullSystemName": "ABSOLUTE-ASSET-.WORKGROUP",
                "Id": "123456",
                "LastConnectedUtc": 1648971645189,
                "LocalIp": "127.0.0.1",
                "NetworkAdapters": [
                    {},
                    {}
                ],
                "Os": {
                    "architecture": "64-bit",
                    "currentBuild": "17763",
                    "installDate": 1643800616000,
                    "lastBootTime": 1646884562500,
                    "name": "Microsoft Windows Server 2019 Datacenter",
                    "productKey": "WMDGN-G9PQG-XVVXX-R3X43-63DFG",
                    "serialNumber": "00430-00000-00000-AA691",
                    "version": "10.0.17763"
                },
                "PolicyGroupName": "Global Policy Group",
                "PublicIp": "127.0.0.1",
                "Serial": "GoogleCloud-B8736A4405BF0E968020BCBC46EDA096",
                "SystemManufacturer": "Google",
                "SystemModel": "GOOGLE COMPUTE ENGINE",
                "SystemName": "ABSOLUTE-ASSET-",
                "SystemType": "x64-based PC",
                "Username": "Administrator"
            },
            {
                "AgentStatus": "A",
                "Bios": {
                    "id": "Google - 1 Google ",
                    "serialNumber": "GoogleCloud-6420CF930DEE84DE8497CF40F0D56AFA",
                    "smBiosVersion": "2.4",
                    "version": "Google - 1 Google ",
                    "versionDate": "Google Google, 01/01/2011"
                },
                "Domain": "WORKGROUP",
                "Esn": "D0004",
                "FullSystemName": "ABSOLUTE-ASSET-.WORKGROUP",
                "Id": "1234",
                "LastConnectedUtc": 1648971873079,
                "LocalIp": "127.0.0.1",
                "NetworkAdapters": [
                    {},
                    {}
                ],
                "Os": {
                    "architecture": "64-bit",
                    "currentBuild": "20348",
                    "installDate": 1648025097000,
                    "lastBootTime": 1648025060499,
                    "name": "Microsoft Windows Server 2022 Datacenter",
                    "productKey": "WX4NM-KYWYW-QJJR4-XV3QB-6VM33",
                    "serialNumber": "00454-60000-00001-AA937",
                    "version": "10.0.20348"
                },
                "PolicyGroupName": "Global Policy Group",
                "PublicIp": "127.0.0.1",
                "Serial": "GoogleCloud-6420CF930DEE84DE8497CF40F0D56AFA",
                "SystemManufacturer": "Google",
                "SystemModel": "GOOGLE COMPUTE ENGINE",
                "SystemName": "ABSOLUTE-ASSET-",
                "SystemType": "x64-based PC",
                "Username": "Administrator"
            }
        ]
    }
}
```

#### Human Readable Output

>### Absolute devices list:
>|AgentStatus|Bios|Domain|Esn|FullSystemName|Id|LastConnectedUtc|LocalIp|NetworkAdapters|Os|PolicyGroupName|PublicIp|Serial|SystemManufacturer|SystemModel|SystemName|SystemType|Username|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| A | id: Google - 1 Google <br/>serialNumber: GoogleCloud-B8736A4405BF0E968020BCBC46EDA096<br/>version: Google - 1 Google <br/>versionDate: Google Google, 01/01/2011<br/>smBiosVersion: 2.4 | WORKGROUP | D0001 | ABSOLUTE-ASSET-.WORKGROUP | 123456 | 1648971645189 | 127.0.0.1 | {},<br/>{} | architecture: 64-bit<br/>installDate: 1643800616000<br/>lastBootTime: 1646884562500<br/>name: Microsoft Windows Server 2019 Datacenter<br/>productKey: WMDGN-G9PQG-XVVXX-R3X43-63DFG<br/>serialNumber: 00430-00000-00000-AA691<br/>version: 10.0.17763<br/>currentBuild: 17763 | Global Policy Group | 127.0.0.1 | GoogleCloud-B8736A4405BF0E968020BCBC46EDA096 | Google | GOOGLE COMPUTE ENGINE | ABSOLUTE-ASSET- | x64-based PC | Administrator |
>| A | id: Google - 1 Google <br/>serialNumber: GoogleCloud-6420CF930DEE84DE8497CF40F0D56AFA<br/>version: Google - 1 Google <br/>versionDate: Google Google, 01/01/2011<br/>smBiosVersion: 2.4 | WORKGROUP | D0004 | ABSOLUTE-ASSET-.WORKGROUP | 1234 | 1648971873079 | 127.0.0.1 | {},<br/>{} | architecture: 64-bit<br/>installDate: 1648025097000<br/>lastBootTime: 1648025060499<br/>name: Microsoft Windows Server 2022 Datacenter<br/>productKey: WX4NM-KYWYW-QJJR4-XV3QB-6VM33<br/>serialNumber: 00454-60000-00001-AA937<br/>version: 10.0.20348<br/>currentBuild: 20348 | Global Policy Group | 127.0.0.1 | GoogleCloud-6420CF930DEE84DE8497CF40F0D56AFA | Google | GOOGLE COMPUTE ENGINE | ABSOLUTE-ASSET- | x64-based PC | Administrator |


### absolute-device-location-get
***
Gets a list of devices geo locations records and their corresponding data that meets the required devices IDs.


#### Base Command

`absolute-device-location-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_ids | A comma-separated list of the system-defined unique identifier of the devices. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Absolute.LocationReport.Coordinates | Unknown | A comma-separated list where the first number is the estimated latitude and the second number is the estimated longitude \(in degrees\) where the device is located. | 
| Absolute.LocationReport.ID | String | The system-defined unique identifier of the device. | 
| Absolute.LocationReport.City | String | The city where the device is located. | 
| Absolute.LocationReport.State | String | The state or province where the device is located. | 
| Absolute.LocationReport.CountryCode | String | The country code for the country where the device is located. | 
| Absolute.LocationReport.Country | String | The country where the device is located. | 
| Absolute.LocationReport.LocationTechnology | String | The technology used to get the location. | 
| Absolute.LocationReport.Accuracy | Number | The estimated accuracy \(in meters\) of the technology used to locate the device. | 
| Absolute.LocationReport.LastUpdate | Number | The date and time \(in Unix epoch\) when the device last changed its location. | 

#### Command example
```!absolute-device-location-get device_ids=1234```
#### Human Readable Output

>No device locations found in Absolute for the given filters: {'device_ids': '1234'}


### Creating a filtering and sorting query
The following commands have the option to insert a **filter** argument:
- ***absolute-device-application-list***
- ***absolute-device-list***

Absolute uses a subset of query options from Open Data Protocol (OData) for filtering and sorting. 
OData version 1 and 2 are supported. OData query parameters must be alphabetized and URI encoded.
For more information about OData, see: https://www.odata.org/documentation.

A few examples of creating a query (i.e., passing a filter argument):
- Using the eq operator
   - Get a list of all devices with an active status: agentStatus eq 'A'
   - Get a list of all devices that are currently frozen: dfStatus.statusCode eq 'FRZN'
   - Get a list of all devices that have 1734 in their ESN (Identifier): substringof('1734',esn) eq true
- Using the ne operator
   - Get a list of all devices that are not active: agentStatus ne 'A'
- Using the gt operator
   - Get a list of all devices with greater than 1 GB (1073741824 bytes) of available physical: availablePhysicalRamBytes gt 1073741824
- Using the or operator:
   - Get a list of all devices with less than 1 GB (1073741824 bytes) of available physical ram or less than 1 GB (1073741824 bytes) of available virtual raml: availablePhysicalMemroyBytes lt 1073741824 or availableVirtualMemoryBytes lt 1073741824

For more examples and explanations, see the [Absolute docs](https://www.absolute.com/media/2221/abt-api-working-with-absolute.pdf) (from page 10).