Real-time threat intelligence from a crowd-sourced network of security experts and antivirus companies.
## Configure PolySwarmV2 in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| PolySwarm API Key |  | True |
| The base URL to connect to |  | True |
| PolySwarm v2 Community | the segment of PolySwarm's marketplace to query on. | True |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### polyswarm-get-report
***
Returns a report using the UUID.


#### Base Command

`polyswarm-get-report`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scan_uuid | UUID string. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PolySwarm.Total | Number | The total number of scans. | 
| PolySwarm.Permalink | String | PolySwarm permalink results. | 
| PolySwarm.Positives | Number | The total number of positives found. | 
| PolySwarm.Scan_UUID | String | The PolySwarm scan UUID. | 
| PolySwarm.Artifact | String | The artifact queried. | 

##### Command Example

`!polyswarm-get-report scan_uuid="25e755c8957163376b3437ce808843c1c2598e0fb3c5f31dc958576cd5cde63e"`  
`!polyswarm-get-report scan_uuid="25e755c8957163376b3437ce808843c1c2598e0fb3c5f31dc958576cd5cde63e, 2410907a92b16dbd23a88d6bbd5037eae20eea809279f370293b587e1996eafe"`

#### Human Readable Output



### file
***
Queries PolySwarm for file reputation information.


#### Base Command

`file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hash | The value of the file hash for which to retrieve the reputation information. The hash type can be: "SHA256", "SHA1", or "MD5". | Optional | 
| file | The type of the file hash for which to retrieve the reputation information. The hash type can be: "SHA256", "SHA1", or "MD5". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PolySwarm.Total | Number | The total number of scans. | 
| PolySwarm.Permalink | String | PolySwarm permalink results. | 
| PolySwarm.Positives | Number | The total number of positives found. | 
| PolySwarm.Scan_UUID | String | The PolySwarm scan UUID. | 
| PolySwarm.Artifact | String | The artifact queried. | 
| DBotScore.Indicator | The indicator that was tested. | String |
| DBotScore.Score | The actual score. | Number |
| DBotScore.Type | The type of indicator. | String |
| DBotScore.Vendor | The vendor used to calculate the score. | String |
| DBotScore.Reliability | Reliability of the source providing the intelligence data. | String |
| File.MD5 | The MD5 hash of the file. | String |
| File.SHA256 | The SHA256 hash of the file. | String |
| File.SHA1 | The SHA1 hash of the file. | String |

#### Command Example
`!file hash="2410907a92b16dbd23a88d6bbd5037eae20eea809279f370293b587e1996eafe"`  
`!file hash="2410907a92b16dbd23a88d6bbd5037eae20eea809279f370293b587e1996eafe, 1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a"`

#### Human Readable Output



### ip
***
Queries PolySwarm for IP reputation information.


#### Base Command

`ip`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | The IP address for which to retrieve the reputation information. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PolySwarm.Total | Number | The total number of scans. | 
| PolySwarm.Permalink | String | PolySwarm permalink results. | 
| PolySwarm.Positives | Number | The total number of positives found. | 
| PolySwarm.Scan_UUID | String | The PolySwarm scan UUID. | 
| PolySwarm.Artifact | String | The artifact queried. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| IP.Address | String | The IP address. | 
| IP.Malicious.Vendor | String | For malicious files, the vendor that made the decision. | 
| IP.MalwareFamily | String | The malware family associated with the IP. | 
| IP.Tags | String | Tags that are associated with the IP. | 


#### Command Example
```!ip ip="8.8.8.8"```



### url
***
Queries PolySwarm for URL reputation information.

Notice: Submitting indicators using this command might make the indicator data publicly available. See the vendor’s documentation for more details.

#### Base Command

`url`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | The URL for which to retrieve the reputation information. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PolySwarm.Total | Number | The total number of scans. | 
| PolySwarm.Permalink | String | PolySwarm permalink results. | 
| PolySwarm.Positives | Number | The total number of positives found. | 
| PolySwarm.Scan_UUID | String | The PolySwarm scan UUID. | 
| PolySwarm.Artifact | String | The artifact queried. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| URL.Data | String | The URL address. | 
| URL.Malicious.Vendor | String | For malicious files, the vendor that made the decision. | 
| URL.MalwareFamily | String | The malware family associated with the url. | 
| URL.Tags | String | Tags that are associated with the url. | 


#### Command Example
```!url url="https://polyswarm.io"```

#### Context Example



#### Human Readable Output


### domain
***
Queries PolySwarm to retrieve domain reputation information.

Notice: Submitting indicators using this command might make the indicator data publicly available. See the vendor’s documentation for more details.


#### Base Command

`domain`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | Domain for which to retrieve the reputation information. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PolySwarm.Total | Number | The total number of scans. | 
| PolySwarm.Permalink | String | PolySwarm permalink results. | 
| PolySwarm.Positives | Number | The total number of positives found. | 
| PolySwarm.Scan_UUID | String | The PolySwarm scan UUID. | 
| PolySwarm.Artifact | String | The artifact queried. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| Domain.Name | String | The domain name, for example: "google.com". | 
| Domain.Malicious.Vendor | String | For malicious files, the vendor that made the decision. | 
| Domain.MalwareFamily | String | The malware family associated with the domain. | 
| Domain.Tags | String | Tags that are associated with the domain. | 


#### Command Example
```!domain domain="polyswarm.io"```

#### Context Example


#### Human Readable Output



### url-scan
***
Uploads a URL to PolySwarm and retrieves the analysis results.

Notice: Submitting indicators using this command might make the indicator data publicly available. See the vendor’s documentation for more details.


#### Base Command

`url-scan`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | The URL to scan. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PolySwarm.Total | Number | The total number of scans. | 
| PolySwarm.Permalink | String | PolySwarm permalink results. | 
| PolySwarm.Positives | Number | The total number of positives found. | 
| PolySwarm.Scan_UUID | String | The PolySwarm scan UUID. | 
| PolySwarm.Artifact | String | The artifact queried. | 

#### Command Example

`!url-scan url="https://polyswarm.io"`  
`!url-scan url="https://polyswarm.io, https://polyswarm.network"`

#### Human Readable Output



### file-rescan
***
Rescans the uploaded artifact by hash.


#### Base Command

`file-rescan`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hash | The type of the file hash to rescan. The hash type can be: "SHA256", "SHA1", or "MD5". | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PolySwarm.Total | Number | The total number of scans. | 
| PolySwarm.Permalink | String | PolySwarm permalink results. | 
| PolySwarm.Positives | Number | The total number of positives found. | 
| PolySwarm.Scan_UUID | String | The PolySwarm scan UUID. | 
| PolySwarm.Artifact | String | The artifact queried. | 


#### Command Example

`!file-rescan hash="2410907a92b16dbd23a88d6bbd5037eae20eea809279f370293b587e1996eafe"`  
`!file-rescan hash="2410907a92b16dbd23a88d6bbd5037eae20eea809279f370293b587e1996eafe, 25e755c8957163376b3437ce808843c1c2598e0fb3c5f31dc958576cd5cde63e"`

#### Human Readable Output



### get-file
***
Downloads a file hash from PolySwarm.


#### Base Command

`get-file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hash | The file hash type to download. The hash type can be: "SHA256", "SHA1", or "MD5". | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.Size | Number | The file size. | 
| File.SHA1 | String | The SHA1 hash of the file. | 
| File.SHA256 | String | The SHA256 hash of the file. | 
| File.Name | String | The sample name. | 
| File.SSDeep | String | The SSDeep hash of the file. | 
| File.EntryID | String | The War Room entry ID of the file. | 
| File.Info | String | Basic information of the file. | 
| File.Type | String | File type. For example, "PE". | 
| File MD5 | String | The MD5 hash of the file. | 
| File.Extension | String | The file extension. | 
| PolySwarm.FileID | String | The file ID. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| File.Tags.TagGroups.TagGroupName | String | The tag's group name. | 
| File.Tags.Aliases | String | Aliases of the tags. | 
| File.Tags.PublicTagName | String | The public name of the tag. This is usually used as the ID of the tag. | 
| File.Tags.TagName | String | The simple name of the tag. | 


#### Command Example

`!get-file hash="2410907a92b16dbd23a88d6bbd5037eae20eea809279f370293b587e1996eafe`

#### Human Readable Output



### file-scan
***
Uploads a file to PolySwarm and retrieves the analysis results.


#### Base Command

`file-scan`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entryID | The War Room entry ID of the file. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PolySwarm.Total | Number | The total number of scans. | 
| PolySwarm.Permalink | String | PolySwarm permalink results. | 
| PolySwarm.Positives | Number | The total number of positives found. | 
| PolySwarm.Scan_UUID | String | The PolySwarm scan UUID. | 
| PolySwarm.Artifact | String | The artifact queried. | 


#### Command Example
`!file-scan entryID="995@0c42ee2d-57ff-4ccf-88ef-8d51c7936595"`

#### Human Readable Output

