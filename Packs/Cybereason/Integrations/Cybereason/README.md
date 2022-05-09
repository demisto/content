Endpoint detection and response to manage and query malops, connections and processes.
This integration was integrated and tested with version xx of Cybereason

## Configure Cybereason on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Cybereason.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Server URL (e.g. https://192.168.0.1) | True |
    | Credentials | False |
    | Password | False |
    | Trust any certificate (not secure) | False |
    | Use system proxy settings | False |
    | Fetch incidents | False |
    | Incident type | False |
    | First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days, 3 months, 1 year) | False |
    | Fetch by "MALOP CREATION TIME" or by "MALOP UPDATE TIME" (Fetching by Malop update time might create duplicates of Malops as incidents) | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### cybereason-archive-sensor
***
Archives a Sensor.


#### Base Command

`cybereason-archive-sensor`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sensorID | Sensor ID of Cybereason Sensor. | Required | 
| archiveReason | Reason for Archiving Cybereason Sensor. | Required | 


#### Context Output

There is no context output for this command.
#### Command example
```!cybereason-archive-sensor sensorID=5e77883de4b0575ddcf824ef:PYLUMCLIENT_INTEGRATION_EC2AMAZ-4CTUN1V_123CC99CA7E5 archiveReason="Archive this Sensor"```
#### Human Readable Output

>Sensor archive status: Failed Actions: 0. Succeeded Actions: 1

### cybereason-unarchive-sensor
***
Unarchives a Sensor.


#### Base Command

`cybereason-unarchive-sensor`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sensorID | Sensor ID of Cybereason Sensor. | Required | 
| unarchiveReason | Reason for Unarchiving Cybereason Sensor. | Required | 


#### Context Output

There is no context output for this command.
#### Command example
```!cybereason-unarchive-sensor sensorID=5e77883de4b0575ddcf824ef:PYLUMCLIENT_INTEGRATION_EC2AMAZ-4CTUN1V_123CC99CA7E5 unarchiveReason="Unarchive this Sensor"```
#### Human Readable Output

>Sensor unarchive status: Failed Actions: 0. Succeeded Actions: 1

### cybereason-delete-sensor
***
Deletes a Sensor.


#### Base Command

`cybereason-delete-sensor`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sensorID | Sensor ID of Cybereason Sensor. | Required | 


#### Context Output

There is no context output for this command.
#### Command example
```!cybereason-delete-sensor sensorID=5e77883de4b0575ddcf824ef:PYLUMCLIENT_INTEGRATION_EC2AMAZ-4CTUN1V_123CC99CA7E5```
#### Human Readable Output

>Sensor deleted successfully.

### cybereason-query-processes
***
Searches for processes with various filters.


#### Base Command

`cybereason-query-processes`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| machine | The hostname of the machine. | Optional | 
| onlySuspicious | Show only suspicious processes. Possible values are: true, false. Default is false. | Optional | 
| limit | Maximum number of results to retrieve. Default is 10000. | Optional | 
| processName | Process name to filter by. | Optional | 
| saveToContext | If true, save the result to the context. Possible values are: true, false. Default is false. | Optional | 
| hasIncomingConnection | Filter only processes with incoming connections. Possible values are: true, false. Default is false. | Optional | 
| hasOutgoingConnection | Filter only processes with outgoing connections. Possible values are: true, false. Default is false. | Optional | 
| hasExternalConnection | If process has external connection. Possible values are: true, false. | Optional | 
| unsignedUnknownReputation | If process is not known to reputation services and its image file is unsigned. Possible values are: true, false. | Optional | 
| fromTemporaryFolder | If process is running from temporary folder. Possible values are: true, false. | Optional | 
| privilegesEscalation | If process was identified elevating its privileges to local system user. Possible values are: true, false. | Optional | 
| maliciousPsExec | If the process was executed by PsExec service and is suspicious as being executed maliciously. Possible values are: true, false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Process.Name | Unknown | The process name | 
| Process.Malicious | Unknown | Malicious status of the process | 
| Process.CreationTime | Unknown | The process creation time | 
| Process.EndTime | Unknown | The process end time | 
| Process.CommandLine | Unknown | The command line of the process | 
| Process.SignedAndVerified | Unknown | Is the process signed and verified | 
| Process.ProductType | Unknown | The product type | 
| Process.Children | Unknown | Children of the process | 
| Process.Parent | Unknown | The parent process | 
| Process.OwnerMachine | Unknown | The machine's hostname | 
| Process.User | Unknown | The user who ran the process | 
| Process.ImageFile | Unknown | Image file of the process | 
| Process.SHA1 | Unknown | SHA1 of the process file | 
| Process.MD5 | Unknown | MD5 of the process file | 
| Process.CompanyName | Unknown | The company's name | 
| Process.ProductName | Unknown | The product's name | 

### cybereason-is-probe-connected
***
Checks if the machine is currently connected to the Cybereason server


#### Base Command

`cybereason-is-probe-connected`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| machine | The hostname of the machine to check. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cybereason.Machine.isConnected | boolean | true if machine is connected, else false | 
| Cybereason.Machine.Name | string | Machine name | 

### cybereason-query-connections
***
Searches for connections.


#### Base Command

`cybereason-query-connections`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | Filter connections which contain this IP (in or out). | Optional | 
| machine | Filter connections on the given machine. | Optional | 
| saveToContext | If true, save the result to the context. Possible values are: true, false. Default is false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Connection.Name | Unknown | The connection's name | 
| Connection.Direction | Unknown | OUTGOING/INCOMING | 
| Connection.ServerAddress | Unknown | Address of the Cybereason machine | 
| Connection.ServerPort | Unknown | Port of the Cybereason machine | 
| Connection.PortType | Unknown | Type of the connection | 
| Connection.ReceivedBytes | Unknown | Received bytes count | 
| Connection.TransmittedBytes | Unknown | Transmitted bytes count | 
| Connection.RemoteCountry | Unknown | The connection's remote country | 
| Connection.OwnerMachine | Unknown | The machine's hostname | 
| Connection.OwnerProcess | Unknown | The process which performed the connection | 
| Connection.CreationTime | Unknown | Creation time of the connection | 
| Connection.EndTime | Unknown | End time of the connection | 

### cybereason-isolate-machine
***
Isolates a machine that has been infected from the rest of the network


#### Base Command

`cybereason-isolate-machine`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| machine | Machine name to be isolated. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cybereason.Machine | string | Machine name | 
| Cybereason.IsIsolated | boolean | Is the machine isolated | 
| Endpoint.Hostname | string | Machine name | 

### cybereason-unisolate-machine
***
Stops isolation of a machine


#### Base Command

`cybereason-unisolate-machine`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| machine | Machine name to be un-isolated. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cybereason.Machine | string | Machine name | 
| Cybereason.IsIsolated | boolean | Is the machine isolated | 
| Endpoint.Hostname | string | Machine name | 

### cybereason-query-malops
***
Returns a list of all Malops and details on the Malops.


#### Base Command

`cybereason-query-malops`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filters | Filter to filter response by, given in Cybereason API syntax. | Optional | 
| totalResultLimit | The total number of results to return for your Server. Ensure you make the limit a reasonable number to maximize Server performance and not to overload the system. | Optional | 
| perGroupLimit | The number of items to return per Malop group. | Optional | 
| templateContext | The level of detail to provide in the response. Possible values include:  SPECIFIC:  References value contain only the count in the ElementValues class. The Suspicions map is calculated for each results, with the suspicion name and the first time the suspicion appeared. The Evidence map is not calculated for the results. CUSTOM:  Reference values contain the specific Elements, up to the limit defined in the perFeatureLimit parameter. The Suspicions map is not calculated for the results. The Evidence map is not calculated for the results. DETAILS:  Reference values contain the specific Elements, up to the limit defined in the perFeatureLimit parameter. The Suspicions map is calculated for each result, containing the suspicion name and the first time the suspicion appeared. The Evidence map is not calculated for the results. Possible values are: MALOP, SPECIFIC, CUSTOM, DETAILS, OVERVIEW. Default is MALOP. | Optional | 
| withinLastDays | Return all the malops within the last days. | Optional | 
| malopGuid | Malop GUIDs to filter by (Comma separated values supported, e.g. 11.5681864988155542407,11.1773255057963879999). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cybereason.Malops.GUID | string | The unique globally unique identifier \(guid\) for the Malop. | 
| Cybereason.Malops.CreationTime | string | The time reported as when the malicious behavior began on the system. This is not the time that the Malop was first detected by Cybereason. | 
| Cybereason.Malops.DecisionFeature | string | The reason that Cybereason has raised the Malop. | 
| Cybereason.Malops.Link | string | Link to the Malop on Cybereason. | 
| Cybereason.Malops.Suspects | string | Malop suspect type and name | 
| Cybereason.Malops.LastUpdatedTime | string | Last updated time of malop | 
| Cybereason.Malops.AffectedMachine | string | List of machines affected by this Malop | 
| Cybereason.Malops.InvolvedHash | string | List of file hashes involved in this Malop | 
| Cybereason.Malops.Status | string | Malop managemant status | 

### cybereason-malop-processes
***
Returns a list of malops


#### Base Command

`cybereason-malop-processes`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| malopGuids | Array of malop GUIDs separated by comma. (Malop GUID can be retrieved with the command cybereason-query-malops command). | Required | 
| machineName | Machine names which were affected by malop. Comma separated values supported (e.g., machine1,machine2). | Optional | 
| dateTime | Starting Date and Time to filter the Processes based on their creation date. The format for the input is ("YYYY/MM/DD HH:MM:SS"). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Process.Name | string | The process name | 
| Process.Malicious | Unknown | Malicious status of the process | 
| Process.CreationTime | date | The process creation time | 
| Process.EndTime | date | The process end time | 
| Process.CommandLine | string | The command line of the process | 
| Process.SignedAndVerified | Unknown | Is the process signed and verified | 
| Process.ProductType | Unknown | The product type | 
| Process.Children | Unknown | Children of the process | 
| Process.Parent | Unknown | The parent process | 
| Process.OwnerMachine | Unknown | The machine's hostname | 
| Process.User | string | The user who ran the process | 
| Process.ImageFile | Unknown | Image file of the process | 
| Process.SHA1 | string | SHA1 of the process file | 
| Process.MD5 | string | MD5 of the process file | 
| Process.CompanyName | string | The company's name | 
| Process.ProductName | string | The product's name | 

### cybereason-add-comment
***
Add new comment to malop


#### Base Command

`cybereason-add-comment`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| comment | Comment to add to the malop. | Required | 
| malopGuid | Malop GUID to add comment to. (Malop GUID can be retrieved with the command cybereason-query-malops command). | Required | 


#### Context Output

There is no context output for this command.
### cybereason-update-malop-status
***
Updates malop status


#### Base Command

`cybereason-update-malop-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| malopGuid | Malop GUID to update its status. | Required | 
| status | Status to update. Possible values are: To Review, Unread, Remediated, Not Relevant, Open. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cybereason.Malops.GUID | string | Malop GUID | 
| Cybereason.Malops.Status | string | Malop status: To Review,Unread,Remediated,Not Relevant | 

### cybereason-prevent-file
***
Prevent malop process file


#### Base Command

`cybereason-prevent-file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| md5 | Malop process file MD5 to prevent. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Process.MD5 | string | Process file MD5 | 
| Process.Prevent | boolean | True if process file is prevented, else false | 

### cybereason-unprevent-file
***
Unprevent malop process file


#### Base Command

`cybereason-unprevent-file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| md5 | Malop process file MD5 to unprevent. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Process.MD5 | string | Process file MD5 | 
| Process.Prevent | boolean | True if process file is prevented, else false | 

### cybereason-query-file
***
Query files as part of investigation


#### Base Command

`cybereason-query-file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file_hash | File hash (SHA-1 and MD5 supported). | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cybereason.File.Path | string | File path | 
| Cybereason.File.SHA1 | string | File SHA-1 hash | 
| Cybereason.File.Machine | string | Machine name on which file is located | 
| Cybereason.File.SuspicionsCount | number | File suspicions count | 
| Cybereason.File.Name | string | File name | 
| Cybereason.File.CreationTime | date | File creation time | 
| Cybereason.File.Suspicion | string | File suspicions object of suspicion as key and detected date as value | 
| Cybereason.File.OSVersion | string | Machine OS version on which file is located | 
| Cybereason.File.ModifiedTime | date | File modified date | 
| Cybereason.File.Malicious | boolean | Is file malicious | 
| Cybereason.File.Company | string | Company name | 
| Cybereason.File.MD5 | string | File MD5 hash | 
| Cybereason.File.IsConnected | boolean | Is machine connected to Cybereason | 
| Cybereason.File.Signed | boolean | Is file signed | 
| Cybereason.File.Evidence | string | File evidences | 
| Endpoint.Hostname | string | Hostname on which file is located | 
| Endpoint.OSVersion | string | Machine OS version on which file is located | 
| File.Hostname | string | Hostname on which file is located | 
| File.MD5 | string | File MD5 hash | 
| File.SHA1 | string | File SHA-1 hash | 
| File.Name | string | File name | 
| File.Path | string | File path | 

### cybereason-query-domain
***
Query domains as part of investigation


#### Base Command

`cybereason-query-domain`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | Domain to query. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cybereason.Domain.Name | string | Domain name | 
| Cybereason.Domain.Malicious | boolean | Is domain malicious | 
| Cybereason.Domain.IsInternalDomain | boolean | Is domain internal | 
| Cybereason.Domain.Reputation | string | Domain reputation | 
| Cybereason.Domain.SuspicionsCount | number | Domain suspicions count | 
| Cybereason.Domain.WasEverResolved | boolean | Was domain ever resolved | 
| Cybereason.Domain.WasEverResolvedAsASecondLevelDomain | boolean | Was domain ever resolved as a second level domain | 
| Domain.Name | string | Domain name | 

### cybereason-query-user
***
Query users as part of investigation


#### Base Command

`cybereason-query-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | Username to query. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cybereason.User.Username | string | User name | 
| Cybereason.User.Domain | string | User domain | 
| Cybereason.User.LastMachineLoggedInTo | string | Last machine which user logged in to | 
| Cybereason.User.LocalSystem | boolean | Is local system | 
| Cybereason.User.Organization | string | User organization | 

### cybereason-start-fetchfile
***
Start fetching the file to download


#### Base Command

`cybereason-start-fetchfile`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| malopGUID | Malop GUID for fetching a file from a sensor to download. | Required | 
| userName | The complete Cybereason user name string for the user performing the request. | Required | 


#### Context Output

There is no context output for this command.
#### Command example
```!cybereason-start-fetchfile malopGUID=11.-7780537507363356527 userName=prashant@metronlabs.com```
#### Human Readable Output

>Successfully started fetching file for the given malop

### cybereason-fetchfile-progress
***
Return a batch id for files waiting for download


#### Base Command

`cybereason-fetchfile-progress`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| malopGuid | Malop GUID to know the progress for downloading a file. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Download.progress.fileName | unknown | Filename for tha given malop | 
| Download.progress.status | unknown | Status for batch ID | 
| Download.progress.batchID | unknown | Unique batch id | 

#### Command example
```!cybereason-fetchfile-progress malopGuid=11.-7780537507363356527```
#### Context Example
```json
{
    "Download": {
        "progress": {
            "MalopID": "11.-7780537507363356527",
            "batchID": [
                -796720096
            ],
            "fileName": [
                "winrar-x64-602.pdf.exe"
            ],
            "status": [
                true
            ]
        }
    }
}
```

#### Human Readable Output

>Filename: ['winrar-x64-602.pdf.exe'] Status: [True] Batch ID: [-796720096]

### cybereason-download-file
***
Downloads the actual file to the machine


#### Base Command

`cybereason-download-file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| batchID | The batch id for the file download operation. | Required | 


#### Context Output

There is no context output for this command.
#### Command example
```!cybereason-download-file batchID=-1044817479```
#### Context Example
```json
{
    "File": {
        "EntryID": "15836@1282f695-fa2d-4fdd-8c2a-965a7722044b",
        "Extension": "zip",
        "Info": "application/zip",
        "MD5": "753ce5f6014c7cd549f751752978d4cf",
        "Name": "download.zip",
        "SHA1": "9d5ef11989f0294929b572fdd4be2aefae94810d",
        "SHA256": "532fd3122f405471f48077bf0c24bfbd2b6fa13decb9916530b86f2f8802a827",
        "SHA512": "59a9649736c464546cc582128a2694ec797b34d558b7e845485b7688f6a536d7acac3bf5912b0725a77c02177445ec90da9982d955e5d393ff40af7109586e3b",
        "SSDeep": "49152:PkGHRBEjJ9ui4nMSThv4TdRBdUPHy+OjtHgPiszD/Uh1Dkhru9Ly:PdHDE6ISTgbBkS+IkiADMhCru4",
        "Size": 3168792,
        "Type": "Zip archive data, at least v2.0 to extract"
    }
}
```

#### Human Readable Output

>Integration log: Downloading the file with this Batch ID: -1044817479

### cybereason-close-file-batch-id
***
Aborts a file download operation that is in progress


#### Base Command

`cybereason-close-file-batch-id`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| batchID | The batch id to abort a file download operation. | Required | 


#### Context Output

There is no context output for this command.

#### Command example
```!cybereason-close-file-batch-id batchID=-796720096```
#### Human Readable Output

>Successfully aborts a file download operation that is in progress.
### cybereason-available-remediation-actions
***
Get all remediation action details whatever available for that malop


#### Base Command

`cybereason-available-remediation-actions`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| malopGuid | The unique ID assigned by the Cybereason platform for the Malop. | Required | 


#### Context Output

There is no context output for this command.
#### Command example
```!cybereason-available-remediation-actions malopGuid=11.-7780537507363356527```
#### Human Readable Output

>```
>{
>    "data": [
>        {
>            "machineConnected": false,
>            "machineId": "-1845090846.1198775089551518743",
>            "machineName": "desktop-vg9ke2u",
>            "machinesCount": 1,
>            "malopId": "11.-7780537507363356527",
>            "malopType": "MalopProcess",
>            "remediationType": "BLOCK_FILE",
>            "targetId": "-1845090846.-1424333057657783286",
>            "targetName": "fc61fdcad5a9d52a01bd2d596f2c92b9",
>            "uniqueId": "BLOCK_FILE::-1845090846.-1424333057657783286"
>        },
>        {
>            "machineConnected": false,
>            "machineId": "-1845090846.1198775089551518743",
>            "machineName": "desktop-vg9ke2u",
>            "machinesCount": 1,
>            "malopId": "11.-7780537507363356527",
>            "malopType": "MalopProcess",
>            "remediationType": "UNQUARANTINE_FILE",
>            "targetId": "-1845090846.-4034595808369608762",
>            "targetName": "winrar-x64-602.pdf.exe",
>            "uniqueId": "UNQUARANTINE_FILE::-1845090846.-4034595808369608762"
>        }
>    ],
>    "errorMessage": "",
>    "status": "SUCCESS"
>}
>```

### cybereason-kill-process
***
Kill a processes for the malicious file. (User will get inputs by executing the 'cybereason-available-remediation-actions' command if this remediation action is available for that Malop)


#### Base Command

`cybereason-kill-process`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| malopGuid | The unique ID assigned by the Cybereason platform for the Malop. | Required | 
| machine | Machine name to kill the process. | Required | 
| targetId | Target ID to kill the process. | Required | 
| userName | The complete Cybereason user name string for the user performing the request. | Required | 
| timeout | Timeout (in seconds) to wait for the remediation response. Possible values are: 30, 60. Default is 60. | Optional | 
| comment | Comment to add to the malop. | Optional | 


#### Context Output

There is no context output for this command.
#### Command example
```!cybereason-kill-process machine=desktop-vg9ke2u malopGuid=11.-8663995271209729248 targetId=-1845090846.-4009552791065461433 userName=prashant@metronlabs.com comment="Kill the Process" timeout=60```
#### Human Readable Output

>Kill process remediation action status is: SUCCESS
>Remediation ID: 3dc597e8-d829-47ea-b7e6-79d872769916

### cybereason-quarantine-file
***
Quarantine the detected malicious file in a secure location. (User will get inputs by executing the 'cybereason-available-remediation-actions' command if this remediation action is available for that Malop)


#### Base Command

`cybereason-quarantine-file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| malopGuid | The unique ID assigned by the Cybereason platform for the Malop. | Required | 
| machine | Machine name to quarantine a file. | Required | 
| targetId | Target ID to quarantine a file. | Required | 
| userName | The complete Cybereason user name string for the user performing the request. | Required | 
| timeout | Timeout (in seconds) to wait for the remediation response. Possible values are: 30, 60. Default is 60. | Optional | 
| comment | Comment to add to the malop. | Optional | 


#### Context Output

There is no context output for this command.
#### Command example
```!cybereason-quarantine-file machine=desktop-vg9ke2u malopGuid=11.-7780537507363356527 targetId=-1845090846.-1424333057657783286 userName=prashant@metronlabs.com comment="Quarantine the File" timeout=60```
#### Human Readable Output

>Quarantine file remediation action status is: SUCCESS
>Remediation ID: 566b57ac-de77-4128-92d7-3dd0b504ecfb

### cybereason-unquarantine-file
***
Unquarantine the detected malicious file in a secure location. (User will get inputs by executing the 'cybereason-available-remediation-actions' command if this remediation action is available for that Malop)


#### Base Command

`cybereason-unquarantine-file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| malopGuid | The unique ID assigned by the Cybereason platform for the Malop. | Required | 
| machine | Machine name to unquarantine a file. | Required | 
| targetId | Target ID to unquarantine a file. | Required | 
| userName | The complete Cybereason user name string for the user performing the request. | Required | 
| timeout | Timeout (in seconds) to wait for the remediation response. Possible values are: 30, 60. Default is 60. | Optional | 
| comment | Comment to add to the malop. | Optional | 


#### Context Output

There is no context output for this command.
#### Command example
```!cybereason-unquarantine-file machine=desktop-vg9ke2u malopGuid=11.-7780537507363356527 targetId=-1845090846.-8162972223469398301 userName=prashant@metronlabs.com comment="Unquarantine the File" timeout=60```
#### Human Readable Output

>Unquarantine file remediation action status is: SUCCESS
>Remediation ID: 47146e65-320c-4663-905d-c2b561459933

### cybereason-block-file
***
Block a file only in particular machine. (User will get inputs by executing the 'cybereason-available-remediation-actions' command if this remediation action is available for that Malop)


#### Base Command

`cybereason-block-file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| malopGuid | The unique ID assigned by the Cybereason platform for the Malop. | Required | 
| machine | Machine name whose files needs to be blocked. | Required | 
| targetId | Target ID of file to be blocked. | Required | 
| userName | The complete Cybereason user name string for the user performing the request. | Required | 
| timeout | Timeout (in seconds) to wait for the remediation response. Possible values are: 30, 60. Default is 60. | Optional | 
| comment | Comment to add to the malop. | Optional | 


#### Context Output

There is no context output for this command.
#### Command example
```!cybereason-block-file machine=desktop-vg9ke2u malopGuid=11.-7780537507363356527 targetId=-1845090846.-1424333057657783286 userName=prashant@metronlabs.com comment="Block a File" timeout=60```
#### Human Readable Output

>Block file remediation action status is: SUCCESS
>Remediation ID: 51a3e113-1346-4189-89fe-5981ed2cbd5c

### cybereason-delete-registry-key
***
Delete a registry entry associated with a malicious process. (User will get inputs by executing the 'cybereason-available-remediation-actions' command if this remediation action is available for that Malop)


#### Base Command

`cybereason-delete-registry-key`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| malopGuid | The unique ID assigned by the Cybereason platform for the Malop. | Required | 
| machine | Machine name to delete the registry key. | Required | 
| targetId | Target ID to delete the registry key. | Required | 
| userName | The complete Cybereason user name string for the user performing the request. | Required | 
| timeout | Timeout (in seconds) to wait for the remediation response. Possible values are: 30, 60. Default is 60. | Optional | 
| comment | Comment to add to the malop. | Optional | 


#### Context Output

There is no context output for this command.
#### Command example
```!cybereason-delete-registry-key machine=desktop-vg9ke2u malopGuid=11.-7780537507363356527 targetId=-1845090846.-1424333057657783286 userName=prashant@metronlabs.com comment="Remove the registry key" timeout=30```
#### Human Readable Output

>Delete registry key remediation action status is: SUCCESS
>Remediation ID: 6beda94f-d331-4f60-aa84-790fbdc5aab4

### cybereason-kill-prevent-unsuspend
***
Prevent detected ransomware from running on the machine. (User will get inputs by executing the 'cybereason-available-remediation-actions' command if this remediation action is available for that Malop)


#### Base Command

`cybereason-kill-prevent-unsuspend`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| malopGuid | The unique ID assigned by the Cybereason platform for the Malop. | Required | 
| machine | Machine name to prevent detected ransomware from running on the machine. | Required | 
| targetId | Target ID to prevent detected ransomware from running on the machine. | Required | 
| userName | The complete Cybereason user name string for the user performing the request. | Required | 
| timeout | Timeout (in seconds) to wait for the remediation response. Possible values are: 30, 60. Default is 60. | Optional | 
| comment | Comment to add to the malop. | Optional | 


#### Context Output

There is no context output for this command.
#### Command example
```!cybereason-kill-prevent-unsuspend machine=desktop-vg9ke2u malopGuid=11.-8663995271209729248 targetId=-1845090846.3240952457134939180 userName=prashant@metronlabs.com comment="Kill Prevent" timeout=30```
#### Human Readable Output

>Kill prevent unsuspend remediation action status is: SUCCESS
>Remediation ID: 6f951d29-2516-47c8-9fb9-d82f11771496

### cybereason-unsuspend-process
***
Prevent a file associated with ransomware. (User will get inputs by executing the 'cybereason-available-remediation-actions' command if this remediation action is available for that Malop)


#### Base Command

`cybereason-unsuspend-process`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| malopGuid | The unique ID assigned by the Cybereason platform for the Malop. | Required | 
| machine | Machine name to prevent a file associated with ransomware. | Required | 
| targetId | Target ID to prevent a file associated with ransomware. | Required | 
| userName | The complete Cybereason user name string for the user performing the request. | Required | 
| timeout | Timeout (in seconds) to wait for the remediation response. Possible values are: 30, 60. Default is 60. | Optional | 
| comment | Comment to add to the malop. | Optional | 


#### Context Output

There is no context output for this command.
#### Command example
```!cybereason-unsuspend-process machine=desktop-vg9ke2u malopGuid=11.-8663995271209729248 targetId=-1845090846.3240952457134939180 userName=prashant@metronlabs.com comment="Unsuspend Process" timeout=60```
#### Human Readable Output

>Unsuspend process remediation action status is: SUCCESS
>Remediation ID: 1ad1bce3-ee77-4fae-ac59-37865dc4a9f4

### cybereason-malware-query
***
Malware query with options and values to filter


#### Base Command

`cybereason-malware-query`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| needsAttention | Filter for Fetching Malwares by Malware needsAttention. Possible values are: True, False. | Optional | 
| type | Filter for Fetching Malwares by Malware Type. (Possible filter values for Type are "KnownMalware,UnknownMalware,FilelessMalware,ApplicationControlMalware,RansomwareMalware"). | Optional | 
| status | Filter for Fetching Malwares by Malware Status. (Possible filter values for Status are "Done,Excluded,Detected,Prevented,Remediated,DeleteOnRestart,Quarantined"). | Optional | 
| timestamp | Filter for Fetching Malwares by Timestamp. Enter the time (in epoch). | Optional | 
| limit | Filter for Fetching Malwares by Malware Limit. | Required | 


#### Context Output

There is no context output for this command.
#### Command example
```!cybereason-malware-query limit=5 needsAttention=True status=Done type=KnownMalware timestamp=1582206286000```
#### Human Readable Output

>```
>{
>    "data": {
>        "hasMoreResults": false,
>        "malwares": [],
>        "totalResults": 0
>    },
>    "expectedResults": 0,
>    "failedServersInfo": null,
>    "failures": 0,
>    "hidePartialSuccess": false,
>    "message": "",
>    "status": "SUCCESS"
>}
>```
