Endpoint detection and response to manage and query malops, connections and processes.
This integration was integrated and tested with version 21.2 of Cybereason

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
| Cybereason.Process.Name | Unknown | The process name | 
| Cybereason.Process.Malicious | Unknown | Malicious status of the process | 
| Cybereason.Process.CreationTime | Unknown | The process creation time | 
| Cybereason.Process.EndTime | Unknown | The process end time | 
| Cybereason.Process.CommandLine | Unknown | The command line of the process | 
| Cybereason.Process.SignedAndVerified | Unknown | Is the process signed and verified | 
| Cybereason.Process.ProductType | Unknown | The product type | 
| Cybereason.Process.Children | Unknown | Children of the process | 
| Cybereason.Process.Parent | Unknown | The parent process | 
| Cybereason.Process.OwnerMachine | Unknown | The machine's hostname | 
| Cybereason.Process.User | Unknown | The user who ran the process | 
| Cybereason.Process.ImageFile | Unknown | Image file of the process | 
| Cybereason.Process.SHA1 | Unknown | SHA1 of the process file | 
| Cybereason.Process.MD5 | Unknown | MD5 of the process file | 
| Cybereason.Process.CompanyName | Unknown | The company's name | 
| Cybereason.Process.ProductName | Unknown | The product's name | 

#### Command example
```!cybereason-query-processes machine=desktop-vg9ke2u hasOutgoingConnection=true hasIncomingConnection=true```
#### Context Example
```json
{
    "Process": [
        {
            "Children": null,
            "CommandLine": "C:\\WINDOWS\\system32\\svchost.exe -k LocalService -s W32Time",
            "CompanyName": "Microsoft Corporation",
            "CreationTime": "2022-05-06T04:15:33.939000",
            "EndTime": "",
            "ImageFile": "svchost.exe",
            "MD5": "cd10cb894be2128fca0bf0e2b0c27c16",
            "Malicious": "indifferent",
            "Name": "svchost.exe",
            "OwnerMachine": "desktop-vg9ke2u",
            "Parent": "services.exe",
            "ProductName": "Microsoft\u00ae Windows\u00ae Operating System",
            "ProductType": "SVCHOST",
            "SHA1": "1f912d4bec338ef10b7c9f19976286f8acc4eb97",
            "SignedandVerified": "true",
            "User": "desktop-vg9ke2u\\local service"
        }
    ]
}
```

#### Human Readable Output

>### Cybereason Processes
>|Name|Malicious|Creation Time|End Time|Command Line|Signed and Verified|Product Type|Children|Parent|Owner Machine|User|Image File|SHA1|MD5|Company Name|Product Name|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| svchost.exe | indifferent | 2022-05-06T04:15:33.939000 |  | C:\WINDOWS\system32\svchost.exe -k LocalService -s W32Time | true | SVCHOST |  | services.exe | desktop-vg9ke2u | desktop-vg9ke2u\local service | svchost.exe | 1f912d4bec338ef10b7c9f19976286f8acc4eb97 | cd10cb894be2128fca0bf0e2b0c27c16 | Microsoft Corporation | Microsoft® Windows® Operating System |

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

#### Command example
```!cybereason-is-probe-connected machine=desktop-vg9ke2u```
#### Context Example
```json
{
    "Cybereason": {
        "Machine": {
            "Name": "desktop-vg9ke2u",
            "isConnected": true
        }
    }
}
```

#### Human Readable Output

>true

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
| Cybereason.Connection.Name | Unknown | The connection's name | 
| Cybereason.Connection.Direction | Unknown | OUTGOING/INCOMING | 
| Cybereason.Connection.ServerAddress | Unknown | Address of the Cybereason machine | 
| Cybereason.Connection.ServerPort | Unknown | Port of the Cybereason machine | 
| Cybereason.Connection.PortType | Unknown | Type of the connection | 
| Cybereason.Connection.ReceivedBytes | Unknown | Received bytes count | 
| Cybereason.Connection.TransmittedBytes | Unknown | Transmitted bytes count | 
| Cybereason.Connection.RemoteCountry | Unknown | The connection's remote country | 
| Cybereason.Connection.OwnerMachine | Unknown | The machine's hostname | 
| Cybereason.Connection.OwnerProcess | Unknown | The process which performed the connection | 
| Cybereason.Connection.CreationTime | Unknown | Creation time of the connection | 
| Cybereason.Connection.EndTime | Unknown | End time of the connection | 

#### Command example
```!cybereason-query-connections ip=192.168.1.103```
#### Context Example
```json
{
    "Connection": [
        {
            "CreationTime": "2021-04-20T03:38:56.386000",
            "Direction": "OUTGOING",
            "EndTime": "2021-04-20T03:40:04.466000",
            "Name": "<connection_ip_addresses>",
            "OwnerMachine": "siemplify-cyber",
            "OwnerProcess": "nbtscan.exe",
            "PortType": "SERVICE_WINDOWS",
            "ReceivedBytes": "0",
            "RemoteCountry": null,
            "ServerAddress": "192.168.1.103",
            "ServerPort": "137",
            "TransmittedBytes": "50"
        }
    ]
}
```

#### Human Readable Output

>### Cybereason Connections for: 192.168.1.103
>|Creation Time|Direction|End Time|Name|Owner Machine|Owner Process|Port Type|Received Bytes|Remote Country|Server Address|Server Port|Transmitted Bytes|
>|---|---|---|---|---|---|---|---|---|---|---|---|
>| 2021-04-20T03:38:56.386000 | OUTGOING | 2021-04-20T03:40:04.466000 | connection_ip_addresses | siemplify-cyber | nbtscan.exe | SERVICE_WINDOWS | 0 |  | 192.168.1.103 | 137 | 50 |

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

#### Command example
```!cybereason-isolate-machine machine=desktop-vg9ke2u```
#### Context Example
```json
{
    "Cybereason": {
        "IsIsolated": true,
        "Machine": "desktop-vg9ke2u"
    }
}
```

#### Human Readable Output

>Machine was isolated successfully.

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

#### Command example
```!cybereason-unisolate-machine machine=desktop-vg9ke2u```
#### Context Example
```json
{
    "Cybereason": {
        "IsIsolated": false,
        "Machine": "desktop-vg9ke2u"
    }
}
```

#### Human Readable Output

>Machine was un-isolated successfully.

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

#### Command example
```!cybereason-query-malops```
#### Context Example
```json
{
    "Cybereason": {
        "Malops": [
            {
                "AffectedMachine": [
                    "win10-cybereaso",
                    "marketing"
                ],
                "CreationTime": "2021-07-12T09:11:42.641000",
                "DecisionFailure": "blackListedFileHash",
                "GUID": "11.3651150229438589171",
                "InvolvedHash": [
                    1
                ],
                "LastUpdateTime": "2021-08-28T23:19:12.430000",
                "Link": "https://integration.cybereason.net:8443/#/malop/11.3651150229438589171",
                "Status": "OPEN",
                "Suspects": "Process: viagra_.exe"
            }
        ]
    }
}
```

#### Human Readable Output

>### Cybereason Malops
>|GUID|Link|CreationTime|Status|LastUpdateTime|DecisionFailure|Suspects|AffectedMachine|InvolvedHash|
>|---|---|---|---|---|---|---|---|---|
>| 11.3651150229438589171 | https:<span>//</span>integration.cybereason.net:8443/#/malop/11.3651150229438589171 | 2021-07-12T09:11:42.641000 | OPEN | 2021-08-28T23:19:12.430000 | blackListedFileHash | Process: viagra_.exe | affected_machine_name | 1 |

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
| Cybereason.Process.Name | string | The process name | 
| Cybereason.Process.Malicious | Unknown | Malicious status of the process | 
| Cybereason.Process.CreationTime | date | The process creation time | 
| Cybereason.Process.EndTime | date | The process end time | 
| Cybereason.Process.CommandLine | string | The command line of the process | 
| Cybereason.Process.SignedAndVerified | Unknown | Is the process signed and verified | 
| Cybereason.Process.ProductType | Unknown | The product type | 
| Cybereason.Process.Children | Unknown | Children of the process | 
| Cybereason.Process.Parent | Unknown | The parent process | 
| Cybereason.Process.OwnerMachine | Unknown | The machine's hostname | 
| Cybereason.Process.User | string | The user who ran the process | 
| Cybereason.Process.ImageFile | Unknown | Image file of the process | 
| Cybereason.Process.SHA1 | string | SHA1 of the process file | 
| Cybereason.Process.MD5 | string | MD5 of the process file | 
| Cybereason.Process.CompanyName | string | The company's name | 
| Cybereason.Process.ProductName | string | The product's name | 

#### Command example
```!cybereason-malop-processes malopGuids=<malop_id>```
#### Context Example
```json
{
    "Process": [
        {
            "Children": null,
            "CommandLine": "\"C:\\Users\\prase\\Downloads\\winrar-x64-602.pdf.exe\"",
            "CompanyName": "Alexander Roshal",
            "CreationTime": "2022-03-14T13:25:56.309000",
            "EndTime": "2022-03-14T13:26:01.712000",
            "ImageFile": "<image_file_name>",
            "MD5": "fc61fdcad5a9d52a01bd2d596f2c92b9",
            "Malicious": "indifferent",
            "Name": "<file_name>",
            "OwnerMachine": "desktop-vg9ke2u",
            "Parent": "explorer.exe",
            "ProductName": "WinRAR",
            "ProductType": null,
            "SHA1": "77ab1e20c685e716b82c7c90b373316fc84cde23",
            "SignedandVerified": null,
            "User": "desktop-vg9ke2u\\prase"
        }
    ]
}
```

#### Human Readable Output

>### Cybereason Malop Processes
>|Name|Malicious|Creation Time|End Time|Command Line|Parent|Owner Machine|User|Image File|SHA1|MD5|Company Name|Product Name|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| winrar-x64-602.pdf.exe | indifferent | 2022-03-14T13:25:56.309000 | 2022-03-14T13:26:01.712000 | "C:\Users\prase\Downloads\winrar-x64-602.pdf.exe" | explorer.exe | desktop-vg9ke2u | desktop-vg9ke2u\prase | winrar-x64-602.pdf.exe | 77ab1e20c685e716b82c7c90b373316fc84cde23 | fc61fdcad5a9d52a01bd2d596f2c92b9 | Alexander Roshal | WinRAR |

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
#### Command example
```!cybereason-add-comment comment=NewComment malopGuid=<malop_id>```
#### Human Readable Output

>Comment added successfully

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

#### Command example
```!cybereason-update-malop-status malopGuid=<malop_id> status="To Review"```
#### Context Example
```json
{
    "Cybereason": {
        "Malops": {
            "GUID": "11.-7780537507363356527",
            "Status": "To Review"
        }
    }
}
```

#### Human Readable Output

>Successfully updated malop 11.-7780537507363356527 to status To Review

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
| Cybereason.Process.MD5 | string | Process file MD5 | 
| Cybereason.Process.Prevent | boolean | True if process file is prevented, else false | 

#### Command example
```!cybereason-prevent-file md5=fc61fdcad5a9d52a01bd2d596f2c92b9```
#### Context Example
```json
{
    "Process": {
        "MD5": "fc61fdcad5a9d52a01bd2d596f2c92b9",
        "Prevent": true
    }
}
```

#### Human Readable Output

>File was prevented successfully

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
| Cybereason.Process.MD5 | string | Process file MD5 | 
| Cybereason.Process.Prevent | boolean | True if process file is prevented, else false | 

#### Command example
```!cybereason-unprevent-file md5=fc61fdcad5a9d52a01bd2d596f2c92b9```
#### Context Example
```json
{
    "Process": {
        "MD5": "fc61fdcad5a9d52a01bd2d596f2c92b9",
        "Prevent": false
    }
}
```

#### Human Readable Output

>File was unprevented successfully

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

#### Command example
```!cybereason-query-file file_hash=<file_hash>```
#### Context Example
```json
{
    "Cybereason": {
        "File": {
            "Company": "Alexander Roshal",
            "CreationTime": "2022-02-28T07:03:48.000Z",
            "Evidence": [],
            "IsConnected": false,
            "MD5": "fc61fdcad5a9d52a01bd2d596f2c92b9",
            "Machine": "desktop-vg9ke2u",
            "Malicious": false,
            "ModifiedTime": "2022-05-09T16:21:18.000Z",
            "Name": "<file_name>",
            "OSVersion": null,
            "Path": "c:\\users\\prase\\downloads\\winrar-x64-602.pdf.exe",
            "SHA1": "77ab1e20c685e716b82c7c90b373316fc84cde23",
            "Signed": true,
            "Suspicion": {},
            "SuspicionsCount": null
        }
    }
}
```

#### Human Readable Output

>### Cybereason file query results for the file hash: 77ab1e20c685e716b82c7c90b373316fc84cde23
>|Company|CreationTime|IsConnected|MD5|Machine|Malicious|ModifiedTime|Name|Path|SHA1|Signed|
>|---|---|---|---|---|---|---|---|---|---|---|
>| Alexander Roshal | 2022-02-28T07:03:48.000Z | false | fc61fdcad5a9d52a01bd2d596f2c92b9 | desktop-vg9ke2u | false | 2022-05-09T16:21:18.000Z | winrar-x64-602.pdf.exe | c:\users\prase\downloads\winrar-x64-602.pdf.exe | 77ab1e20c685e716b82c7c90b373316fc84cde23 | true |

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
#### Command example
```!cybereason-query-domain domain=www2.bing.com```
#### Context Example
```json
{
    "Cybereason": {
        "Domain": {
            "IsInternalDomain": false,
            "Malicious": false,
            "Name": "www2.bing.com",
            "Reputation": null,
            "SuspicionsCount": 0,
            "WasEverResolved": false,
            "WasEverResolvedAsASecondLevelDomain": true
        }
    }
}
```

#### Human Readable Output

>### Cybereason domain query results for the domain: www2.bing.com
>|Name|Reputation|IsInternalDomain|WasEverResolved|WasEverResolvedAsASecondLevelDomain|Malicious|SuspicionsCount|
>|---|---|---|---|---|---|---|
>| www2.bing.com | indifferent | false | false | true | false | 0 |
>| www2.bing.com |  | false | false | true | false | 0 |

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

#### Command example
```!cybereason-query-user username="desktop-vg9ke2u\\prase"```
#### Context Example
```json
{
    "Cybereason": {
        "User": {
            "Domain": "desktop-vg9ke2u",
            "LastMachineLoggedInTo": "desktop-vg9ke2u",
            "LocalSystem": false,
            "Organization": "INTEGRATION",
            "Username": "desktop-vg9ke2u\\prase"
        }
    }
}
```

#### Human Readable Output

>### Cybereason user query results for the username: desktop-vg9ke2u\prase
>|Username|Domain|LastMachineLoggedInTo|Organization|LocalSystem|
>|---|---|---|---|---|
>| desktop-vg9ke2u\prase | desktop-vg9ke2u | desktop-vg9ke2u | INTEGRATION | false |

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
```!cybereason-start-fetchfile malopGUID=<malop_id> userName=<user_name>```
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
| Cybereason.Download.Progress.fileName | unknown | Filename for tha given malop | 
| Cybereason.Download.Progress.status | unknown | Status for batch ID | 
| Cybereason.Download.Progress.batchID | unknown | Unique batch id | 

#### Command example
```!cybereason-fetchfile-progress malopGuid=<malop_id>```
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
                "<file_name>"
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
        "SSDeep": "<SSDeep_value>",
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
```!cybereason-available-remediation-actions malopGuid=<malop_id>```
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
>            "targetName": "<target_name>",
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
| comment | Comment to add to the malop. | Optional | 


#### Context Output

There is no context output for this command.
#### Command example
```!cybereason-kill-process machine=desktop-vg9ke2u malopGuid=<malop_id> targetId=<target_id> userName=<user_name> comment="Kill the Process"```
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
| comment | Comment to add to the malop. | Optional | 


#### Context Output

There is no context output for this command.
#### Command example
```!cybereason-quarantine-file machine=desktop-vg9ke2u malopGuid=<malop_id> targetId=<target_id> userName=<user_name> comment="Quarantine the File"```
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
| comment | Comment to add to the malop. | Optional | 


#### Context Output

There is no context output for this command.
#### Command example
```!cybereason-unquarantine-file machine=desktop-vg9ke2u malopGuid=<malop_id> targetId=<target_id> userName=<user_name> comment="Unquarantine the File"```
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
| comment | Comment to add to the malop. | Optional | 


#### Context Output

There is no context output for this command.
#### Command example
```!cybereason-block-file machine=desktop-vg9ke2u malopGuid=<malop_id> targetId=<target_id> userName=<user_name> comment="Block a File"```
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
| comment | Comment to add to the malop. | Optional | 


#### Context Output

There is no context output for this command.
#### Command example
```!cybereason-delete-registry-key machine=desktop-vg9ke2u malopGuid=<malop_id> targetId=<target_id> userName=<user_name> comment="Remove the registry key"```
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
| comment | Comment to add to the malop. | Optional | 


#### Context Output

There is no context output for this command.
#### Command example
```!cybereason-kill-prevent-unsuspend machine=desktop-vg9ke2u malopGuid=<malop_id> targetId=<target_id> userName=<user_name> comment="Kill Prevent"```
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
| comment | Comment to add to the malop. | Optional | 


#### Context Output

There is no context output for this command.
#### Command example
```!cybereason-unsuspend-process machine=desktop-vg9ke2u malopGuid=<malop_id> targetId=<target_id> userName=<user_name> comment="Unsuspend Process"```
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

### cybereason-start-host-scan
***
Start or stop a full or quick scan for a host.


#### Base Command

`cybereason-start-host-scan`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sensorID | Sensor ID of a sensor. (Comma separated values supported.). | Required | 
| scanType | Select a method/type to scan a host. Possible values are: FULL, QUICK, STOP. | Required | 


#### Context Output

There is no context output for this command.
#### Command example
```!cybereason-start-host-scan sensorID=5e77883de4b0575ddcf824ef:PYLUMCLIENT_INTEGRATION_DESKTOP-VG9KE2U_0800273ADC2F scanType=FULL```
#### Human Readable Output

>Batch ID: -1112786456

### cybereason-fetch-scan-status
***
Get the results for host scanning.


#### Base Command

`cybereason-fetch-scan-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| batchID | The batch ID obtained after initiating the scan. | Required | 


#### Context Output

There is no context output for this command.
#### Command example
```!cybereason-fetch-scan-status batchID=-1112786456```
#### Human Readable Output

>```
>{
>    "abortHttpStatusCode": null,
>    "abortTime": 0,
>    "abortTimeout": false,
>    "aborterUser": null,
>    "actionArguments": [
>        "com.cybereason.configuration.models.ScheduleScanAction",
>        "FULL"
>    ],
>    "actionType": "SchedulerScan",
>    "batchId": -1112786456,
>    "creatorUser": "<user_name>",
>    "finalState": true,
>    "globalStats": {
>        "stats": {
>            "AbortTimeout": 0,
>            "Aborted": 0,
>            "Aborting": 0,
>            "AlreadyUpdated": 0,
>            "BadArgument": 0,
>            "ChunksRequired": 0,
>            "Disconnected": 0,
>            "EndedWithInvalidParam": 0,
>            "EndedWithNoValidFolder": 0,
>            "EndedWithSensorTimeout": 0,
>            "EndedWithTooManyResults": 0,
>            "EndedWithTooManySearches": 0,
>            "EndedWithUnknownError": 0,
>            "EndedWithUnsupportedFilter": 0,
>            "EndedWithYaraCompileError": 0,
>            "Failed": 0,
>            "FailedSending": 0,
>            "FailedSendingToServer": 0,
>            "GettingChunks": 0,
>            "InProgress": 0,
>            "InvalidState": 0,
>            "MsiFileCorrupted": 0,
>            "MsiSendFail": 0,
>            "NewerInstalled": 0,
>            "None": 0,
>            "NotSupported": 0,
>            "Pending": 0,
>            "Primed": 0,
>            "ProbeRemoved": 0,
>            "SendingMsi": 0,
>            "SendingPlatform": 0,
>            "Started": 0,
>            "Succeeded": 1,
>            "Timeout": 0,
>            "TimeoutSending": 0,
>            "UnauthorizedUser": 0,
>            "UnknownProbe": 0,
>            "partialResponse": 0
>        }
>    },
>    "initiatorUser": "<user_name>",
>    "startTime": 1652279731232,
>    "totalNumberOfProbes": 1
>}
>```

### cybereason-get-sensor-id
***
Get the Sensor ID of a machine.


#### Base Command

`cybereason-get-sensor-id`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| machineName | The hostname of the machine. | Optional | 


#### Context Output

There is no context output for this command.
#### Command example
```!cybereason-get-sensor-id machineName=desktop-vg9ke2u```
#### Human Readable Output

>Sensor ID for the machine 'desktop-vg9ke2u' is: 5e77883de4b0575ddcf824ef:PYLUMCLIENT_INTEGRATION_DESKTOP-VG9KE2U_0800273ADC2F