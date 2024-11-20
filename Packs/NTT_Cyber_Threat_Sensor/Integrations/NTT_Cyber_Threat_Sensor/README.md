Retrieve alerts and recommendations from NTT CTS
This integration was integrated and tested with version 1.0 of NTT Cyber Threat Sensor
## Configure NTT Cyber Threat Sensor in Cortex


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

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### ntt-cyber-threat-sensor-poll-blobs
***
Check if blobs is available


#### Base Command

`ntt-cyber-threat-sensor-poll-blobs`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| event_id | ID of the incident from whom to fetch blobs for | Required | 
| timestamp | ISO timestamp for when alert was triggered | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CTS.FetchBlob | boolean | True if there are blobs to fetch | 
| CTS.Blob.ID | string | ID of the incident | 
| CTS.Blob.Status | string | hold to wait and release to run | 


#### Command Example
```!ntt-cyber-threat-sensor-poll-blobs event_id=07be6916957da6dc0b4c7fbf6995b1e44dccb9e7 timestamp=2020-08-12T07:29:01.464841```

#### Context Example
```
{
    "CTS": {
        "Blobs": {
            "ID": "07be6916957da6dc0b4c7fbf6995b1e44dccb9e7",
            "Status": "release"
        }
    }
}
```

#### Human Readable Output

>CTS blob(s) was found and has been sceduled for download

### ntt-cyber-threat-sensor-fetch-blobs
***
Collecting blobs, most commonly pcap from an incident


#### Base Command

`ntt-cyber-threat-sensor-fetch-blobs`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| event_id | ID of the incident from whom to fetch blobs for | Required | 


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
```!ntt-cyber-threat-sensor-fetch-blobs event_id=07be6916957da6dc0b4c7fbf6995b1e44dccb9e7```

#### Context Example
```
{
    "CTS": {
        "HasBlob": [
            false,
            true
        ]
    },
    "File": {
        "EntryID": "226@b969e30d-f6de-490a-8f35-81a8939b5b97",
        "Extension": "pcap",
        "Info": "application/vnd.tcpdump.pcap",
        "MD5": "f6362d15102678983db75e7b764d973f",
        "Name": "6f5f0353-9ff6-4544-b6d9-1741a9842445.pcap",
        "SHA1": "a031573de579dea138351bb6742887baf9a5bf5a",
        "SHA256": "22cf474ab9be274078f4fc3796a7893f2bed9fe7920a921593ea43b8a4705a9f",
        "SHA512": "a751c7b436755aea5d7bbe3bfd0bc2e5a1ff5ddf8aadd956b50df18acaba4a43d969105bf9d28b66f8d2f9dcd1add1c0f73a5c9e6ccb01f0e34924f52acebee8",
        "SSDeep": "12288:90nf6/GBLS0c9s+txFd9Ri6KSIb9zK9RmnM:Of6/OYs+9kSaJKHmnM",
        "Size": 567348,
        "Type": "pcap capture file, microsecond ts (little-endian) - version 2.4 (Ethernet, capture length 65535)"
    }
}
```

#### Human Readable Output

>CTS blob(s) downloaded:
>['6f5f0353-9ff6-4544-b6d9-1741a9842445.pcap']