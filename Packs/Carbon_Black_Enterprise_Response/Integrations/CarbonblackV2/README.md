Deprecated. Use VMware Carbon Black EDR v2 instead. 
Query and response with Carbon Black endpoint detection and response.

This integration was integrated and tested with version 6.2.0 of Carbon Black Response
## Configure carbonblack-v2 in Cortex


| **Parameter** | **Required** |
| --- | --- |
| Server URL | True |
| API Token | True |
| Trust any certificate (not secure) | False |
| Use system proxy settings | False |
| Fetch incidents | False |
| Incident type | False |
| Fetch Alert Severity Threshold Higher Than | False |
| Maximum Number Of Incidents To Fetch | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### cb-alert
***
Retrieve alerts from Carbon Black Response.


#### Base Command

`cb-alert`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| status | Alert status to filter by. Possible values are: Unresolved, In Progress, Resolved, False Positive. | Optional | 
| username | Alert username to filter by. | Optional | 
| feedname | Alert feedname to filter by. | Optional | 
| hostname | Alert hostname to filter by. | Optional | 
| report | Alert report name (watchlist_id) to filter by. | Optional | 
| query | Query string. Accepts the same data as the search box on the Binary Search page. See https://github.com/carbonblack/cbapi/blob/master/client_apis/docs/query_overview.pdf. | Optional | 
| rows | Return this many rows, 10 by default. | Optional | 
| start | Start at this row, 0 by default. | Optional | 
| sort | Sort rows by this field and order. server_added_timestamp desc by default. | Optional | 
| facet | Return facet results. 'false' by default, set to 'true' for facets. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CbResponse.Alerts.CbAlertID | unknown | Alert unique id | 
| CbResponse.Alerts.ProcessPath | string | Alert Process Path | 
| CbResponse.Alerts.Hostname | string | Alert Hostname | 
| CbResponse.Alerts.InterfaceIP | string | Alert interface IP | 
| CbResponse.Alerts.CommsIP | string | Communications IP | 
| CbResponse.Alerts.MD5 | string | Alert process MD5 | 
| CbResponse.Alerts.Description | unknown | Alert description | 
| CbResponse.Alerts.FeedName | unknown | Alert feed name | 
| CbResponse.Alerts.Severity | unknown | Alert severity | 
| CbResponse.Alerts.Time | unknown | Alert created time | 
| CbResponse.Alerts.Status | unknown | Alert status. One of: Unresolved, Resolved, False Positive | 


#### Command Example
``` ```

#### Human Readable Output



### cb-binary
***
Query for binaries based on given parameters


#### Base Command

`cb-binary`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| digital-signature | Whether digital signature is signed or not. Possible values are: Signed, Unsigned. | Optional | 
| publisher | Filter binary by publisher. | Optional | 
| company-name | Filter binary by company name. | Optional | 
| product-name | Filter binary by product name. | Optional | 
| filepath | Filter binary by file path. | Optional | 
| group | Filter binary by group. | Optional | 
| hostname | Filter binary by hostname. | Optional | 
| query | Query string. Accepts the same data as the search box on the Binary Search page. See https://github.com/carbonblack/cbapi/blob/master/client_apis/docs/query_overview.pdf. | Optional | 
| rows | Return this many rows, 10 by default. | Optional | 
| start | Start at this row, 0 by default. | Optional | 
| sort | Sort rows by this field and order. server_added_timestamp desc by default. | Optional | 
| facet | Return facet results. 'false' by default, set to 'true' for facets. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.DigSig.Publisher | unknown | The publisher of the Digital Signature | 
| File.InternalName | unknown | The Internal Name | 
| File.ServerAddedTimestamp | unknown | The server added timestamp | 
| File.Name | unknown | Binary Name | 
| File.Extension | unknown | Binary Extension | 
| File.Timestamp | unknown | Binary Timestamp | 
| File.Hostname | unknown | Binary Hostname | 
| File.Description | unknown | The description | 
| File.DigSig.Result | unknown | Cb's decision after checking this binary's Digital Signature | 
| File.LastSeen | unknown | Last time binary was seen | 
| File.Path | unknown | Binary Path | 
| File.ProductName | unknown | The Product Name | 
| File.OS | unknown | The OS | 
| File.MD5 | unknown | Binary MD5 | 
| File.Company | string | Name of the company that released a binary | 
| File.DigitalSignature.Publisher | string | Publisher of the digital signature for the file. | 
| File.Name | string | Full Filename e.g. data.xls. | 
| File.Signature.OriginalName | string | File's original name. | 
| File.Signature.InternalName | string | File's internal name. | 
| File.Signature.FileVersion | string | File version. | 
| File.Signature.Description | string | Description of the signature. | 


#### Command Example
``` ```

#### Human Readable Output



### cb-block-hash
***
Blocking hash


#### Base Command

`cb-block-hash`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| md5hash | the blacklisted hash. | Required | 
| text | text description of block list. | Required | 
| lastBanTime | the last time the hash was blocked or prevented from being executed. | Optional | 
| banCount | total number of blocks on this block list. | Optional | 
| lastBanHost | last hostname to block this hash. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.LastAction | unknown | Last action taken on this file | 


#### Command Example
``` ```

#### Human Readable Output



### cb-get-hash-blacklist
***
Returns a list of hashes on block list, with each list entry describing one hash on block list.


#### Base Command

`cb-get-hash-blacklist`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter | OPTIONAL filters blacklist by fields. Example: filter="md5hash == put_your_hash_here". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CbResponse.BlockedHashes.MD5 | unknown | Blocked MD5 | 
| CbResponse.BlockedHashes.Enabled | unknown | Is Enabled | 
| CbResponse.BlockedHashes.Description | unknown | Blocked Description | 
| CbResponse.BlockedHashes.Timestamp | unknown | Blocked Timestamp | 
| CbResponse.BlockedHashes.BlockCount | unknown | Blocked Count | 
| CbResponse.BlockedHashes.Username | unknown | Blocked hash username | 
| CbResponse.BlockedHashes.LastBlock.Time | unknown | Last block time | 
| CbResponse.BlockedHashes.LastBlock.Hostname | unknown | Last block hostname | 
| CbResponse.BlockedHashes.LastBlock.CbSensorID | unknown | Last block sensor ID | 


#### Command Example
``` ```

#### Human Readable Output



### cb-get-process
***
Gets basic process information for segment (segment_id) of process (process_id)


#### Base Command

`cb-get-process`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| pid | the internal CB process id; this is the id field in search results. | Required | 
| segid | the process segment id, the segment_id field in search results. | Required | 
| get_related | If set to true, will get process siblings, parent and children. Possible values are: false, true. Default is false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Process.Siblings.MD5 | unknown | The sibling Process MD5 | 
| Process.CbSegmentID | unknown | Cb 'segment' where this process instance is stored. Required to fetch further info on a process. | 
| Process.Parent.MD5 | unknown | The parent Process MD5 | 
| Process.Children.CommandLine | unknown | The children Process CommandLine | 
| Process.Hostname | unknown | Process Hostname | 
| Process.Parent.CbSegmentID | unknown | The parent Cb 'segment' where this process instance is stored. Required to fetch further info on a process. | 
| Process.CbID | unknown | Cb unique ID for this process instance - required \(together with CbSegmentID\) to fetch further info on a process. | 
| Process.Siblings.CbSegmentID | unknown | The sibling Cb 'segment' where this process instance is stored. Required to fetch further info on a process. | 
| Process.Children.Name | unknown | The children Process Name | 
| Process.Parent.Name | unknown | The parent Process Name | 
| Process.Siblings.Hostname | unknown | The sibling Process Hostname | 
| Process.Parent.Path | unknown | The parent Process Path | 
| Process.Children.Hostname | unknown | The children Process Hostname | 
| Process.PID | unknown | Process PID | 
| Process.Children.CbSegmentID | unknown | The children Cb 'segment' where this process instance is stored. Required to fetch further info on a process. | 
| Process.Children.CbID | unknown | The children Cb unique ID for this process instance - required \(together with CbSegmentID\) to fetch further info on a process. | 
| Process.Path | unknown | Process Path | 
| Process.Parent.PID | unknown | The parent Process PID | 
| Process.Children.Path | unknown | The children Process Path | 
| Process.Name | unknown | Process Name | 
| Process.Children.PID | unknown | The children Process PID | 
| Process.Parent.CbID | unknown | The parent Cb unique ID for this process instance - required \(together with CbSegmentID\) to fetch further info on a process. | 
| Process.CommandLine | unknown | Process CommandLine | 
| Process.Siblings.CommandLine | unknown | The sibling Process CommandLine | 
| Process.Siblings.Name | unknown | The sibling Process Name | 
| Process.Parent.CommandLine | unknown | The parent Process CommandLine | 
| Process.Parent.Hostname | unknown | The parent Process Hostname | 
| Process.MD5 | unknown | Process MD5 | 
| Process.Children.MD5 | unknown | The children Process MD5 | 
| Process.Siblings.CbID | unknown | The sibling Cb unique ID for this process instance - required \(together with CbSegmentID\) to fetch further info on a process. | 
| Process.Siblings.Path | unknown | The sibling Process Path | 
| Process.Siblings.PID | unknown | The sibling Process PID | 
| Process.StartTime | date | Start time of the process. | 


#### Command Example
``` ```

#### Human Readable Output



### cb-get-processes
***
Query processes based on given parameters


#### Base Command

`cb-get-processes`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Filter processes by name. | Optional | 
| group | Filter processes by group. | Optional | 
| hostname | Filter processes by hostname. | Optional | 
| parent-process-name | Filter processes by parent process name. | Optional | 
| process-path | Filter processes by process path (Example: "c:\windows\resources\spoolsv.exe"). | Optional | 
| md5 | Filter processes by md5 hash. | Optional | 
| query | Query string. Accepts the same data as the search box on the Binary Search page. See https://github.com/carbonblack/cbapi/blob/master/client_apis/docs/query_overview.pdf. | Optional | 
| rows | Return this many rows, 10 by default. | Optional | 
| start | Start at this row, 0 by default. | Optional | 
| sort | Sort rows by this field and order. server_added_timestamp desc by default. | Optional | 
| facet | Return facet results. 'false' by default, set to 'true' for facets. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.Name | unknown | File Name | 
| File.MD5 | unknown | File MD5 | 
| File.Path | unknown | File Path | 
| Endpoint.Hostname | unknown | Endpoint Hostname | 
| Process.CommandLine | unknown | Process  Commandline | 
| Process.PID | unknown | Process PID | 
| Process.CbID | unknown | Cb unique ID for this process instance - required \(together with CbSegmentID\) to fetch further info on a process. | 
| Process.CbSegmentId | unknown | Cb "segment" where this process instance is stored. Required to fetch further info on a process. | 
| Process.Parent.PID | unknown | Process Parent PID | 
| Process.Parent.Name | unknown | Process Parent Name | 
| Process.StartTime | date | Start time of the process. | 


#### Command Example
``` ```

#### Human Readable Output



### cb-list-sensors
***
List the CarbonBlack sensors


#### Base Command

`cb-list-sensors`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum amount of sensors to be returned. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CbResponse.Sensors.Status | unknown | Sensor Status | 
| CbResponse.Sensors.LastUpdate | unknown | Sensor Last Updated | 
| CbResponse.Sensors.Uptime | unknown | The Sensor uptime | 
| CbResponse.Sensors.SupportsCbLive | unknown | Sensor Support CB Live | 
| CbResponse.Sensors.Notes | unknown | Sensor Notes | 
| CbResponse.Sensors.Hostname | unknown | Hostname | 
| CbResponse.Sensors.CbSensorID | unknown | Sensor ID | 
| CbResponse.Sensors.Isolated | unknown | Sensor Isolated | 
| CbResponse.Sensors.IPAddresses | unknown | Sensor IP Addresses | 
| CbResponse.Sensors.OS | unknown | Sensor OS | 
| Endpoint.Hostname | unknown | Sensor Hostname | 
| Endpoint.OS | unknown | Sensor OS | 
| Endpoint.IPAddresses | unknown | Sensor IP Addresses | 


#### Command Example
``` ```

#### Human Readable Output



### cb-process-events
***
Retrieve all process events for a given process segmented by segment ID


#### Base Command

`cb-process-events`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| pid | the internal CB process id; this is the id field in search results. | Required | 
| segid | the process segment id; this is the segment_id field in search results. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Process.CrossProc.OtherProcessMD5 | unknown | Other process MD5 | 
| Process.MD5 | unknown | Process MD5 | 
| Process.Modules.MD5 | unknown | Module MD5 | 
| Process.CommandLine | unknown | Process CommandLine | 
| Process.Registry.RegistryPath | unknown | Registry path | 
| Process.Path | unknown | Process Path | 
| Process.CbID | unknown | Cb unique ID for this process instance - required \(together with CbSegmentID\) to fetch further info on a process. | 
| Process.Parent.Name | unknown | The parent Process Name | 
| Process.Hostname | unknown | Process Hostname | 
| Process.Binaries.DigSig.Publisher | unknown | The publisher of the Digital Signature | 
| Process.CrossProc.Action | unknown | Cross process action | 
| Process.CrossProc.OtherProcessCbID | unknown | Other process CbID | 
| Process.CbSegmentID | unknown | Cb 'segment' where this process instance is stored. Required to fetch further info on a process. | 
| Process.Name | unknown | Process Name | 
| Process.CrossProc.Time | unknown | Time of action | 
| Process.PID | unknown | Process PID | 
| Process.Modules.Filepath | unknown | Module path | 
| Process.Binaries.DigSig.Result | unknown | Cb's decision after checking this binary's Digital Signature | 
| Process.Parent.PID | unknown | The parent Process PID | 
| Process.Binaries.MD5 | unknown | Binary MD5 | 
| Process.CrossProc.OtherProcessBinary | unknown | Other process binary | 
| Process.Registry.Time | unknown | Registry time | 
| Process.Modules.Time | unknown | Module time | 


#### Command Example
``` ```

#### Human Readable Output



### cb-quarantine-device
***
Isolate the endpoint from the network


#### Base Command

`cb-quarantine-device`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sensor | the sensor ID to quarantine. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Endpoint.LastAction | unknown | Endpoint Actions | 


#### Command Example
``` ```

#### Human Readable Output



### cb-sensor-info
***
Display information about the given sensor


#### Base Command

`cb-sensor-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sensor | the sensor id. | Optional | 
| ip | returns the sensor registration(s) with specified IP address. | Optional | 
| hostname | returns the sensor registration(s) with matching hostname. | Optional | 
| groupid | returns the sensor registration(s) in the specified sensor group id. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CbResponse.Sensors.Status | unknown | Sensor Status | 
| CbResponse.Sensors.LastUpdate | unknown | Sensor Last Updated | 
| CbResponse.Sensors.Uptime | unknown | The Sensor uptime | 
| CbResponse.Sensors.SupportsCbLive | unknown | Sensor Support CB Live | 
| CbResponse.Sensors.Notes | unknown | Sensor Notes | 
| CbResponse.Sensors.Hostname | unknown | Sensor Hostname | 
| CbResponse.Sensors.CbSensorID | unknown | Sensor ID | 
| CbResponse.Sensors.Isolated | unknown | Sensor Isolated | 
| CbResponse.Sensors.IPAddresses | unknown | Sensor IP Addresses | 
| CbResponse.Sensors.OS | unknown | Sensor OS | 


#### Command Example
``` ```

#### Human Readable Output



### cb-unblock-hash
***
Unblocking hash


#### Base Command

`cb-unblock-hash`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| md5hash | the hash on the block list. | Required | 
| text | text description of block list. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.LastAction | unknown | Last action taken on this file | 


#### Command Example
``` ```

#### Human Readable Output



### cb-unquarantine-device
***
Unquarantine the endpoint


#### Base Command

`cb-unquarantine-device`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sensor | the sensor ID to quarantine. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Endpoint.LastAction | unknown | Endpoint Actions | 


#### Command Example
``` ```

#### Human Readable Output



### cb-version
***
Display the CarbonBlack version


#### Base Command

`cb-version`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### cb-watchlist-del
***
Delete a watchlist in Carbon black Response.


#### Base Command

`cb-watchlist-del`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| watchlist-id | Watchlist ID. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### cb-watchlist-get
***
Retrieve info for a watchlist in Carbon black Response.


#### Base Command

`cb-watchlist-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| watchlist-id | Watchlist ID. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CbResponse.Watchlists.LastHit | unknown | Watchlist last hit | 
| CbResponse.Watchlists.TotalHits | unknown | Watchlist Total hits | 
| CbResponse.Watchlists.SearchQuery | unknown | Cb search query used for the watchlist. | 
| CbResponse.Watchlists.Name | unknown | Watchlist Name | 
| CbResponse.Watchlists.Enabled | unknown | Watchlist is enabled | 
| CbResponse.Watchlists.LastHitCount | unknown | Watchlist last hit count | 
| CbResponse.Watchlists.DateAdded | unknown | Watchlist Date added | 
| CbResponse.Watchlists.SearchTimestamp | unknown | Watchlist last hit count | 
| CbResponse.Watchlists.CbWatchlistID | unknown | Watchlist ID | 


#### Command Example
``` ```

#### Human Readable Output



### cb-watchlist-new
***
Create a new watchlist in Carbon black Response.


#### Base Command

`cb-watchlist-new`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| search-query | the raw Carbon Black query that this watchlist matches. | Required | 
| name | name of this watchlist. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CbResponse.Watchlists.LastHit | unknown | Watchlist last hit | 
| CbResponse.Watchlists.TotalHits | unknown | Watchlist Total hits | 
| CbResponse.Watchlists.SearchQuery | unknown | Cb search query used for the watchlist. | 
| CbResponse.Watchlists.Name | unknown | Watchlist Name | 
| CbResponse.Watchlists.Enabled | unknown | Watchlist is enabled | 
| CbResponse.Watchlists.LastHitCount | unknown | Watchlist last hit count | 
| CbResponse.Watchlists.DateAdded | unknown | Watchlist Date added | 
| CbResponse.Watchlists.SearchTimestamp | unknown | Watchlist last hit count | 
| CbResponse.Watchlists.CbWatchlistID | unknown | Watchlist ID | 


#### Command Example
``` ```

#### Human Readable Output



### cb-watchlist-set
***
Modify a watchlist in Carbon black Response.


#### Base Command

`cb-watchlist-set`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| watchlist-id | Watchlist ID. | Required | 
| search-query | the raw Carbon Black query that this watchlist matches. | Optional | 
| name | name of this watchlist. | Optional | 
| indexType | the type of watchlist. Valid values are 'modules' and 'events' for binary and process watchlists, respectively. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### cb-alert-update
***
Alert update and resolution


#### Base Command

`cb-alert-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uniqueId | Alert unique identifier. | Required | 
| status | Updated alert's status: Resolved,Unresolved,In Progress or False Positive. Possible values are: Resolved, Unresolved, In Progress, False Positive. | Required | 
| setIgnored | Whether to stop showing this type of alert. Possible values are: true, false. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### cb-watchlist
***
Retrieve watchlist in Carbon black Response.


#### Base Command

`cb-watchlist`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CbResponse.Watchlists.LastHit | unknown | Watchlist last hit | 
| CbResponse.Watchlists.TotalHits | unknown | Watchlist Total hits | 
| CbResponse.Watchlists.SearchQuery | unknown | Cb search query used for the watchlist. | 
| CbResponse.Watchlists.Name | unknown | Watchlist Name | 
| CbResponse.Watchlists.Enabled | unknown | Watchlist is enabled | 
| CbResponse.Watchlists.LastHitCount | unknown | Watchlist last hit count | 
| CbResponse.Watchlists.DateAdded | unknown | Watchlist Date added | 
| CbResponse.Watchlists.SearchTimestamp | unknown | Watchlist last hit count | 
| CbResponse.Watchlists.CbWatchlistID | unknown | Watchlist ID | 


#### Command Example
``` ```

#### Human Readable Output



### cb-binary-download
***
Retrieve a binary from CarbonBlack based on hash. Returns a .zip file containing the requested file and it's metadata.


#### Base Command

`cb-binary-download`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| md5 | MD5 hash of the file. | Required | 
| summary | Whether to include the summary. Possible values are: yes, no. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.DigSig.Publisher | unknown | The publisher of the digital signature. | 
| File.InternalName | unknown | The internal name. | 
| File.ServerAddedTimestamp | unknown | The timestamp when the server was added. | 
| File.Name | unknown | The binary name. | 
| File.Extension | unknown | The binary extension. | 
| File.Timestamp | unknown | The binary timestamp. | 
| File.Hostname | unknown | The binary hostname. | 
| File.Description | unknown | The binary description. | 
| File.DigSig.Result | unknown | The Carbon Black decision after checking this binary's digital signature. | 
| File.LastSeen | unknown | LThe lst time the binary was seen. | 
| File.Path | unknown | The binary path. | 
| File.ProductName | unknown | The product name. | 
| File.OS | unknown | The OS. | 
| File.MD5 | unknown | The MD5 hash of the binary. | 
| File.Company | unknown | Name of the company that released a binary. | 
| File.DigitalSignature.Publisher | unknown | Publisher of the digital signature for the file. | 
| File.Name | unknown | Full filename, for example data.xls. | 
| File.Signature.OriginalName | unknown | The file's original name. | 
| File.Signature.InternalName | unknown | The file's internal name. | 
| File.Signature.FileVersion | unknown | The file version. | 
| File.Signature.Description | unknown | The description of the signature. | 


#### Command Example
``` ```

#### Human Readable Output

