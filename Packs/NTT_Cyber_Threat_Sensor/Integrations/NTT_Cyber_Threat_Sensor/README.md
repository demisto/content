Retrieve alerts and recommendations from NTT CTS
This integration was integrated and tested with version 1.0 of NTT Cyber Threat Sensor
## Configure NTT Cyber Threat Sensor on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for NTT Cyber Threat Sensor.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| APIKEY | The API key for accessing CTS over AWS  | True |
| TENANT_ID | Tenant identification. UUID formatted string | True |
| DAYS_BACK | Days to fetch for the first time this application runs | True |
| ITEMS_TO_FETCH | Number of items to fetch each iteration \(1 to 100\) | True |
| SOARTOKEN | The unique key for accessing the alerts and active response recommendations | True |
| isFetch | Fetch incidents | False |
| incidentType | Incident type | False |
| BASEURL | The base URL for the backend to consume from | True |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### fetch-blobs
***
Collecting blobs, most commonly pcap from an incident


#### Base Command

`fetch-blobs`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| event_id |  | Required | 
| timestamp | ISO timestamp for when alert was triggered | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.Size | number | The size of the file. | 
| File.SHA1 | string | The SHA1 hash of the file. | 
| File.SHA256 | string | The SHA256 hash of the file. | 
| File.Name | string | The name of the file. | 
| File.SSDeep | string | The SSDeep hash of the file. | 
| File.EntryID | string | The entry ID of the file. | 
| File.Info | string | File information. | 
| File.Type | string | The file type. | 
| File.MD5 | string | The MD5 hash of the file. | 
| File.Extension | string | The file extension. | 
| CTS.HasBlob | boolean | If one or more blobs exist then True | 


#### Command Example
```fetch-blobs event_id=974eee6a-bc40-11ea-aed0-00155d5da0e1```

#### Human Readable Output


