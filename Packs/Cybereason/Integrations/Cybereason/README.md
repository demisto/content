Endpoint detection and response to manage and query malops, connections and processes.
This integration was integrated and tested with version 21.2 of Cybereason

## Configure Cybereason in Cortex


| **Parameter** | **Required** |
| --- | --- |
| Server URL (e.g. <https://192.168.0.1>) | True |
| Credentials | False |
| Password | False |
| Trust any certificate (not secure) | False |
| Use system proxy settings | False |
| Fetch incidents | False |
| Incident type | False |
| First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days, 3 months, 1 year) | False |
| Fetch by "MALOP CREATION TIME" or by "MALOP UPDATE TIME" (Fetching by Malop update time might create duplicates of Malops as incidents) | False |


## Cybereason MalOp to XSOAR Incident Map

This involves the mapping of response fields to XSOAR incidents, enhancing the ability to manage and track security incidents effectively.

### Overview

1. **Incident Mapping:** The integration maps specific response fields to corresponding incident fields within XSOAR, ensuring that all relevant information is captured accurately.
2. **Custom Fields:** In addition to standard incident fields, custom fields have been introduced to accommodate unique data requirements specific to our workflow. These fields provide flexibility and enhance the granularity of the incident information.
- `malopcreationtime`
- `malopupdatetime`
- `maloprootcauseelementname`
- `maloprootcauseelementtype`
- `malopseverity`
- `malopdetectiontype`
- `malopedr`
- `malopurl`
- `malopgroup`

These custom fields provide flexibility and enhance the granularity of the incident information.

### Usage

1. **Configure Custom Fields:** Ensure that all custom fields are properly set up in XSOAR before running the fetch function.
2. **Enable Fetch Incidents:**  Functionality responsible to fetch Malops.
3. **Monitor Incidents:** Once the MalOps are converted, they will appear as incidents in XSOAR, allowing for effective incident management.

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
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

```!cybereason-query-processes machine=machine-name hasOutgoingConnection=true hasIncomingConnection=true```

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
            "MD5": "<md5>",
            "Malicious": "indifferent",
            "Name": "svchost.exe",
            "OwnerMachine": "<machine-name>",
            "Parent": "services.exe",
            "ProductName": "Microsoft\u00ae Windows\u00ae Operating System",
            "ProductType": "SVCHOST",
            "SHA1": "<sha1>",
            "SignedandVerified": "true",
            "User": "machine-name\\local service"
        }
    ]
}
```

#### Human Readable Output

>### Cybereason Processes

>|Name|Malicious|Creation Time|End Time|Command Line|Signed and Verified|Product Type|Children|Parent|Owner Machine|User|Image File|SHA1|MD5|Company Name|Product Name|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| svchost.exe | indifferent | 2022-05-06T04:15:33.939000 |  | C:\WINDOWS\system32\svchost.exe -k LocalService -s W32Time | true | SVCHOST |  | services.exe | machine-name | machine-name\local service | svchost.exe | wxyz1234 | abc123 | Microsoft Corporation | Microsoft® Windows® Operating System |

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

```!cybereason-is-probe-connected machine=machine-name```

#### Context Example

```json
{
    "Cybereason": {
        "Machine": {
            "Name": "<machine-name>",
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

```!cybereason-query-connections ip=<host>```

#### Context Example

```json
{
    "Connection": [
        {
            "CreationTime": "2021-04-20T00:00:00.00000",
            "Direction": "OUTGOING",
            "EndTime": "2021-04-20T00:00:00.000000",
            "Name": "<connection_ip_addresses>",
            "OwnerMachine": "simplify-cyber",
            "OwnerProcess": "nbtscan.exe",
            "PortType": "SERVICE_WINDOWS",
            "ReceivedBytes": "0",
            "RemoteCountry": null,
            "ServerAddress": "<server_address>",
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
>| 2021-04-20T00:00:00.000000 | OUTGOING | 2021-04-20T00:00:00.000000 | connection_ip_addresses | simplify-cyber | test.exe | SERVICE_WINDOWS | 0 |  | 192.168.1.103 | 137 | 50 |

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

```!cybereason-isolate-machine machine=machine-name```

#### Context Example

```json
{
    "Cybereason": {
        "IsIsolated": true,
        "Machine": "<machine-name>"
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

```!cybereason-unisolate-machine machine=machine-name```

#### Context Example

```json
{
    "Cybereason": {
        "IsIsolated": false,
        "Machine": "<machine-name>"
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
| malopGuid | Malop GUIDs to filter by (Comma separated values supported, e.g. 11.123456789,11.9874563210). | Optional | 


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
                "CreationTime": "2021-07-12T00:00:00.000000",
                "DecisionFailure": "blackListedFileHash",
                "GUID": "<malop_id>",
                "InvolvedHash": [
                    1
                ],
                "LastUpdateTime": "2021-08-28T00:00:00.000000",
                "Link": "<malop_link>",
                "Status": "OPEN",
                "Suspects": "Process: test.exe"
            }
        ]
    }
}
```

#### Human Readable Output

>### Cybereason Malops

>|GUID|Link|CreationTime|Status|LastUpdateTime|DecisionFailure|Suspects|AffectedMachine|InvolvedHash|
>|---|---|---|---|---|---|---|---|---|
>| <malop_id> | https:<span>//</span>test.server.net:0000/#/malop/11.1234567890 | 2021-07-12T00:00:00.000000 | OPEN | 2021-08-28T00:00:00.000000 | blackListedFileHash | Process: test.exe | affected_machine_name | 1 |

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
            "CommandLine": "\"C:\\Users\\user\\winrar-x64-602.pdf.exe\"",
            "CompanyName": "Hello World",
            "CreationTime": "2022-03-14T00:00:00.000000",
            "EndTime": "2022-03-14T00:00:00.000000",
            "ImageFile": "<image_file_name>",
            "MD5": "<md5>",
            "Malicious": "indifferent",
            "Name": "<file_name>",
            "OwnerMachine": "<machine-name>",
            "Parent": "explorer.exe",
            "ProductName": "WinRAR",
            "ProductType": null,
            "SHA1": "<sha1>",
            "SignedandVerified": null,
            "User": "machine-name\\user"
        }
    ]
}
```

#### Human Readable Output

>### Cybereason Malop Processes

>|Name|Malicious|Creation Time|End Time|Command Line|Parent|Owner Machine|User|Image File|SHA1|MD5|Company Name|Product Name|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| winrar-x64-602.exe | indifferent | 2022-03-14T00:00:00.000000 | 2022-03-14T00:00:00.000000 | "C:\Users\user\winrar-x64-602.exe" | explorer.exe | machine-name | machine-name\user | winrar-x64-602.exe | 1234sajklfshljjvhlsdfhilh23 | md5_hash | Hello World | WinRAR |

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
            "GUID": "<malop_id>",
            "Status": "To Review"
        }
    }
}
```

#### Human Readable Output

>Successfully updated malop <malop_id> to status To Review

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

```!cybereason-prevent-file md5=MD5```

#### Context Example

```json
{
    "Process": {
        "MD5": "<md5>",
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

```!cybereason-unprevent-file md5=MD5```

#### Context Example

```json
{
    "Process": {
        "MD5": "MD5",
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
            "Company": "Hello World",
            "CreationTime": "2022-02-28T00:00:00.000Z",
            "Evidence": [],
            "IsConnected": false,
            "MD5": "<md5>",
            "Machine": "<machine-name>",
            "Malicious": false,
            "ModifiedTime": "2022-05-09T00:00:00.000Z",
            "Name": "<file_name>",
            "OSVersion": null,
            "Path": "c:\\users\\user\\winrar-x64-602.exe",
            "SHA1": "<sha1>",
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
>| Hello World | 2022-02-28T00:00:00.000Z | false | MD5 | machine-name | false | 2022-05-09T00:00:00.000Z | winrar-x64-602.pdf.exe | c:\users\test\winrar-x64-602.pdf.exe | 1245sedecthebdfkjkgjljldl2348 | true |

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

```!cybereason-query-user username="user-name"```

#### Context Example

```json
{
    "Cybereason": {
        "User": {
            "Domain": "<machine-name>",
            "LastMachineLoggedInTo": "<machine-name>",
            "LocalSystem": false,
            "Organization": "INTEGRATION",
            "Username": "user-name"
        }
    }
}
```

#### Human Readable Output

>### Cybereason user query results for the username: machine-name\prase

>|Username|Domain|LastMachineLoggedInTo|Organization|LocalSystem|
>|---|---|---|---|---|
>| machine-name\prase | machine-name | machine-name | INTEGRATION | false |

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

```!cybereason-archive-sensor sensorID=SENSOR_ID archiveReason="Archive this Sensor"```

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

```!cybereason-unarchive-sensor sensorID=SENSOR_ID unarchiveReason="Unarchive this Sensor"```

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

```!cybereason-delete-sensor sensorID=SENSOR_ID```

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
            "MalopID": "<malop_id>",
            "batchID": [
                -1234
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

>Filename: ['winrar-x64-602.exe'] Status: [True] Batch ID: [-1234]

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

```!cybereason-download-file batchID=-1234```

#### Context Example

```json
{
    "File": {
        "EntryID": "<entry_id>",
        "Extension": "zip",
        "Info": "application/zip",
        "MD5": "<md5>",
        "Name": "download.zip",
        "SHA1": "<sha1>",
        "SHA256": "<SHA256>",
        "SHA512": "<SHA512>",
        "SSDeep": "<SSDeep_value>",
        "Size": 3168792,
        "Type": "Zip archive data, at least v2.0 to extract"
    }
}
```

#### Human Readable Output

>Integration log: Downloading the file with this Batch ID: -1234

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

```!cybereason-close-file-batch-id batchID=-1234```

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
>            "machineId": "machine_id",
>            "machineName": "<machine-name>",
>            "machinesCount": 1,
>            "malopId": "<malop_id>",
>            "malopType": "MalopProcess",
>            "remediationType": "BLOCK_FILE",
>            "targetId": "<target_id>",
>            "targetName": "<target_name>",
>            "uniqueId": "<unique_id>"
>        },
>        {
>            "machineConnected": false,
>            "machineId": "<machine_id>",
>            "machineName": "<machine-name>",
>            "machinesCount": 1,
>            "malopId": "<malop_id>",
>            "malopType": "MalopProcess",
>            "remediationType": "UNQUARANTINE_FILE",
>            "targetId": "<target_id>",
>            "targetName": "<target_name>",
>            "uniqueId": "<unique_id>"
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

```!cybereason-kill-process machine=machine-name malopGuid=<malop_id> targetId=<target_id> userName=<user_name> comment="Kill the Process"```

#### Human Readable Output

>Kill process remediation action status is: SUCCESS
>Remediation ID: REMEDIATION_ID

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

```!cybereason-quarantine-file machine=machine-name malopGuid=<malop_id> targetId=<target_id> userName=<user_name> comment="Quarantine the File"```

#### Human Readable Output

>Quarantine file remediation action status is: SUCCESS
>Remediation ID: REMEDIATION_ID

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

```!cybereason-unquarantine-file machine=machine-name malopGuid=<malop_id> targetId=<target_id> userName=<user_name> comment="Unquarantine the File"```

#### Human Readable Output

>Unquarantine file remediation action status is: SUCCESS
>Remediation ID: REMEDIATION_ID

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

```!cybereason-block-file machine=machine-name malopGuid=<malop_id> targetId=<target_id> userName=<user_name> comment="Block a File"```

#### Human Readable Output

>Block file remediation action status is: SUCCESS
>Remediation ID: REMEDIATION_ID

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

```!cybereason-delete-registry-key machine=machine-name malopGuid=<malop_id> targetId=<target_id> userName=<user_name> comment="Remove the registry key"```

#### Human Readable Output

>Delete registry key remediation action status is: SUCCESS
>Remediation ID: REMEDIATION_ID

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

```!cybereason-kill-prevent-unsuspend machine=machine-name malopGuid=<malop_id> targetId=<target_id> userName=<user_name> comment="Kill Prevent"```

#### Human Readable Output

>Kill prevent unsuspend remediation action status is: SUCCESS
>Remediation ID: REMEDIATION_ID

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

```!cybereason-unsuspend-process machine=machine-name malopGuid=<malop_id> targetId=<target_id> userName=<user_name> comment="Unsuspend Process"```

#### Human Readable Output

>Unsuspend process remediation action status is: SUCCESS
>Remediation ID: REMEDIATION_ID

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

```!cybereason-start-host-scan sensorID=SENSOR_ID scanType=FULL```

#### Human Readable Output

>Batch ID: -11156

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

```!cybereason-fetch-scan-status batchID=-11156```

#### Human Readable Output

>```
>{
>    "abortHttpStatusCode": null,
>    "abortTime": 0,
>    "abortTimeout": false,
>    "aborterUser": null,
>    "actionArguments": [
>        "ScheduleScanAction",
>        "FULL"
>    ],
>    "actionType": "SchedulerScan",
>    "batchId": -11156,
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

```!cybereason-get-sensor-id machineName=machine-name```

#### Human Readable Output

>Sensor ID for the machine 'machine-id' is: SENSOR_ID

### cybereason-get-machine-details

***
Get the results related to machines.


#### Base Command

`cybereason-get-machine-details`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| machineName | The hostname of the machine. | Required | 
| page | The page number of machine records to retrieve (used for pagination) starting from 1. The page size is defined by the "pageSize" argument. | Optional | 
| pageSize | The number of machine records per page to retrieve (used for pagination). The page number is defined by the "page" argument. | Optional | 
| limit | The maximum number of records to retrieve. If "pageSize" is defined, this argument is ignored. Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cybereason.Sensor.MachineID | string | Sensor ID of machine | 
| Cybereason.Sensor.MachineName | string | Host name of machine | 
| Cybereason.Sensor.MachineFQDN | string | FQDN of machine | 
| Cybereason.Sensor.GroupID | string | Group ID of machine | 
| Cybereason.Sensor.GroupName | string | Group Name of machine | 

#### Command example

```!cybereason-get-machine-details machineName=xyz-1```

#### Context Example

```json
{
    "MachineID": "example-machine-id",
    "MachineName": "example-machine-name",
    "MachineFQDN": "example-machine-fqdn",
    "GroupID": "example-group-id",
    "GroupName": "example-group-name"
}
```

#### Base Command

`cybereason-query-malop-management`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| malopGuid | malopGuid of the Cybereason Malop. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cybereason.Malops.GUID | string | The unique globally unique identifier \(guid\) for the Malop. | 
| Cybereason.Malops.CreationTime | string | The time reported as when the malicious behavior began on the system. This is not the time that the Malop was first detected by Cybereason. |
| Cybereason.Malops.Link | string | Link to the Malop on Cybereason. | 
| Cybereason.Malops.LastUpdatedTime | string | Last updated time of malop | 
| Cybereason.Malops.InvolvedHash | string | List of file hashes involved in this Malop | 
| Cybereason.Malops.Status | string | Malop managemant status | 

#### Command example

```!cybereason-query-malop-management malopGuid=<malop-guid>```

#### Context Example

```json
{
    "GUID": "malop-guid",
    "Link": "malop-url",
    "CreationTime": 1686720403740,
    "LastUpdateTime": 1686720403743,
    "Status": "Pending",
    "InvolvedHash": "involed-hash"
}
```

#### Base Command

`cybereason_process_attack_tree_command`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| malopGuid | malopGuid of the Cybereason Malop | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
|Cybereason.Process.ProcessID | string | Cybereason Process ID |
|Cybereason.Process.URL | string | Attack tree url for a given Process |

#### Command example

```!cybereason-process-attack-tree processGuid=<process-guid>```

#### Context Example

```json
{
    "Process": [
        {
        "ProcessID": "<process-id>",
        "URL": "<url>"
        },
        {
        "ProcessID": "<process-id>",
        "URL": "<url>"
        } 
    ]
}
```
