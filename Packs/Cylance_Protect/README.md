Manage Endpoints using Cylance protect
This integration was integrated and tested with Cylance Optics

## Configure Cylance Optics on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Cylance Optics.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Server URL | True |
    | Application ID | True |
    | Application Secret | True |
    | Tenant API Key | True |
    | Use system proxy settings | False |
    | Trust any certificate (not secure) | False |
    | Fetch incidents | False |
    | Incident type | False |
    | File Threshold | False |
    | Incidents Fetch Interval | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### cylance-optics-create-instaquery
***
Create a cylance InstaQuery


#### Base Command

`cylance-optics-create-instaquery`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | InstaQuery name. | Required | 
| description | InstaQuery description. | Required | 
| artifact | InstaQuery artifact, select from the list. Possible values are: File, Process, NetworkConnection, RegistryKey. | Required | 
| match_value_type | InstaQuery value type to match, select from the list. Possible values are: File.Path, File.Md5, File.Sha2, File.Owner, File.CreationDateTime, Process.Name, Process.Commandline, Process.PrimaryImagePath, Process.PrimaryImageMd5, Process.StartDateTime, NetworkConnection.DestAddr, NetworkConnection.DestPort, RegistryKey.ProcessName, RegistryKey.ProcessPrimaryImagePath, RegistryKey.ValueName, RegistryKey.FilePath, RegistryKey.FileMd5, RegistryKey.IsPersistencePoint. | Required | 
| match_values | Value to search in InstaQuery. | Required | 
| zone | Zone of the object. | Required | 
| match_type | Match type fuzzy or exact. Possible values are: Fuzzy, Exact. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| InstaQuery.New.id | string | The unique identifier of the created InstaQuery. | 
| InstaQuery.New.created_at | date | The Date and Time that the InstaQuery was created. | 
| InstaQuery.New.progress | string | The progress of the InstaQuery. | 


#### Command Example
``` 
!cylance-optics-create-instaquery name="Test Insta continue" description="Test only" artifact="File" match_value_type="File.Path" match_values="exe" zone="6608ca0e-88c6-4647-b276-271cc5ea4295" match_type="Fuzzy"
```

#### Human Readable Output
| Result            |                                  |
|-------------------|----------------------------------|
| case_sensitive    | false                            |
| artifact          | File                             |
| created_at        | 2022-05-05T05:52:36Z             |
| description       | Test only                        |
| id                | 9E2CCDA5A93918C588E6865ED6FEEA70 |
| match_type        | Fuzzy                            |
| match_value_type  | Path                             |
| match_values      | exe                              |
| name              | Test Insta continue              |
| progress          |                                  |
| results_available | false                            |
| zones             | 6608CA0E88C64647B276271CC5EA4295 |

### cylance-optics-get-instaquery-result
***
Get a cylance InstaQuery search result


#### Base Command

`cylance-optics-get-instaquery-result`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query_id | InstaQuery ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| InstaQuery.Results.result | string | The InstaQuery results. | 


#### Command Example
``` 
!cylance-optics-get-instaquery-result query_id=9E2CCDA5A93918C588E6865ED6FEEA70
```

#### Human Readable Output

|        | Result                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
|--------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id     | 9E2CCDA5A93918C588E6865ED6FEEA70                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| result | false                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| status | {u'@timestamp': 1651729959.177779, u'HostName': u'windows-server-', u'DeviceId': u' 65DB26864E364409B50DDC23291A3511 ', u'@version': u'1', u'CorrelationId': u' 9E2CCDA5A93918C588E6865ED6FEEA70 ', u'Result': u'{"FirstObservedTime": "1970-01-01T00:00:00.000Z", "LastObservedTime": "1970-01-01T00:00:00.000Z", "Uid": "dHrtLYQzbt9oJPxO8HaeyA==", "Type": "File", "Properties": {"Path": "c:\\program files\\cylance\\optics\\ cyoptics.exe ", "CreationDateTime": "2021-03-29T22:34:14.000Z", "Md5": " A081D3268531485BF95DC1A15A5BC6B0 ", "Sha256": " 256809AABD3AB57949003B9AFCB556A9973222CDE81929982DAE7D306648E462 ", "Owner": "NT AUTHORITY\\SYSTEM", "SuspectedFileType": "Executable/PE", "FileSignature": "", "Size": "594104", "OwnerUid": "P3p6fdq3FlMsld6Rz95EOA=="}}'} |

### cylance-optics-list-instaquery
***
Get a list of InstaQuery


#### Base Command

`cylance-optics-list-instaquery`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | number of page to collect. | Optional | 
| page_size | number of items per page to collect. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| InstaQuery.List | string | The list of InstaQuery | 


#### Command Example
``` 
!cylance-optics-list-instaquery page_size="10"
```

#### Human Readable Output
|                       | Result                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
|-----------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| page_items            | {u'match_type': u'Fuzzy', u'name': u'Test Insta continue', u'created_at': u'2022-05-05T05:52:36Z', u'artifact': u'File', u'case_sensitive': False, u'zones': [u'6608CA0E88C64647B276271CC5EA4295'], u'progress': {u'queried': 0, u'responded': 0}, u'match_value_type': u'Path', u'results_available': True, u'match_values': [u'exe'], u'id': u'9E2CCDA5A93918C588E6865ED6FEEA70', u'description': u'Test only'} |
| page_number           | 1                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| page_size             | 10                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| total_number_of_items | 8                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| total_pages           | 1                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
