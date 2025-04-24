Use the MalQuery Integration to query the contents of clean and malicious binary files, which forms part of Falcon's search engine.
This integration was integrated and tested with version 1.0 of CrowdStrikeMalquery
## Configure CrowdStrikeMalquery in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| base_url | Server URL \(e.g. https://example.net\) | True |
| client_id | Client ID | True |
| client_secret | Client Secret | True |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### cs-malquery-exact-search
***
Searches Falcon MalQuery for a combination of hex patterns and strings to identify malware samples based upon file content, which returns a request ID. Use the request ID in the cs-malquery-get-request command to   retrieve results. You can filter results based on criteria such as file type, file size and first seen date.


#### Base Command

`cs-malquery-exact-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hex | The hex pattern to search. For example, deadbeef0102 (for bytes de, ad, be, ef, 01, 02). | Optional | 
| ascii | The ASCII pattern to search. For example, CrowdStrike. | Optional | 
| wide | The wide string pattern to search. For example, CrowdStrike. | Optional | 
| limit | The maximum number of results to be returned. Default is 100. | Optional | 
| max_size | The maximum file size. The value can be specified either in bytes or in multiples of KB/MB/GB. For example, 128000, 1.3 KB, 8mb. | Optional | 
| min_size | The minimum file size. The value can be specified either in bytes or in multiples of KB/MB/GB. For example, 128000, 1.3 KB, 8mb. | Optional | 
| max_date | Limits results to files first seen before this date. The format is YYYY/MM/DD. For example, 2018/01/31. | Optional | 
| min_date | Limits results to files first seen after this date. The format is YYYY/MM/DD. For example, 2018/01/31. | Optional | 
| filter_filetypes | Limits results to certain file types such as EMAIL, PCAP, PDF, PE32. Comma separated values. For a full list of file types, see the MalQuery API documentation. | Optional | 
| filter_meta | Specifies a subset of metadata fields to return in the results. Possible values - sha256, md5, type, size, first_seen, label, family. Comma separated values. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Malquery.Request_ID | String | The request ID. | 


#### Command Example
```!cs-malquery-exact-search hex=8948208b480833ca33f989502489482889782c8bd7 filter_meta=sha256,type,size limit=5```

#### Context Example
```
{
    "Malquery": {
        "Request_ID": "08942ddd-373e-493d-54f9-f6e495174913"
    }
}
```

#### Human Readable Output

>### Search Result
>|Request_ID|
>|---|
>| 08942ddd-373e-493d-54f9-f6e495174913 |


### cs-malquery-hunt
***
Schedules a YARA rule-based search for execution, which returns a request ID. Use the request ID in the cs-malquery-get-request command to retrieve results. You can filter based on criteria such as file type, file size and first seen date.


#### Base Command

`cs-malquery-hunt`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| yara_rule | The YARA rule to search. | Optional | 
| yar_file_entry_id | A YAR file entry ID that contains the YARA rule to search. Only one Yara rule per request. | Optional | 
| limit | The maximum number of results to be returned. | Optional | 
| max_size | The maximum file size. The value can be specified either in bytes or in multiples of KB/MB/GB. For example, 128000, 1.3 KB, 8mb. | Optional | 
| min_size | The minimum file size. For example, 128000, 1.3 KB, 8mb. | Optional | 
| max_date | Limits results to files first seen before this date. The format is YYYY/MM/DD. For example, 2018/01/31. | Optional | 
| min_date | Limits results to files first seen after this date. The format is YYYY/MM/DD. For example, 2018/01/31. | Optional | 
| filter_filetypes | Limits results to files of certain types such as EMAIL, PCAP, PDF, PE32. Comma separated values. For a full list of types, see the MalQuery API documentation. | Optional | 
| filter_meta | Specifies a subset of metadata fields to return in the results. Possible values - sha256, md5, type, size, first_seen, label, family. Comma separated values. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Malquery.Request_ID | String | The request ID. | 


#### Command Example
```!cs-malquery-hunt file_type=PE32 filter_meta=sha256,type,size limit=5 yara_rule="rule CrowdStrike_16142_01 : wiper { strings: $ = { 41 61 43 63 64 44 65 46 66 47 68 69 4B 4C 6C 4D 6D 6E 4E 6F 4F 70 50 72 52 73 53 54 74 55 75 56 76 77 57 78 79 5A 7A 33 32 2E 5C 45 62 67 6A 48 49 20 5F 59 51 42 3A 22 2F 40 } condition: all of them and filesize < 800KB }"```

#### Context Example
```
{
    "Malquery": {
        "Request_ID": "503efffd-2d44-4566-7794-8de45568cbbf"
    }
}
```

#### Human Readable Output

>### Search Result
>|Request_ID|
>|---|
>| 503efffd-2d44-4566-7794-8de45568cbbf |


### cs-malquery-fuzzy-search
***
Searches Falcon MalQuery quickly. Uses partial matching, but with more potential for false positives. Search for a combination of hex patterns and strings to identify samples based upon file content.


#### Base Command

`cs-malquery-fuzzy-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hex | The hex pattern to search. For example, deadbeef0102 (for bytes de, ad, be, ef, 01, 02). | Optional | 
| ascii | The ASCII pattern to search. For example, CrowdStrike. | Optional | 
| wide | The wide string pattern to search. For example, CrowdStrike. | Optional | 
| limit | The maximum number of results to be returned. Default is 100. | Optional | 
| filter_meta | Specifies a subset of metadata fields to return in the results. Possible values - sha256, md5, type, size, first_seen, label, family. Comma separated values. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Malquery.File.family | String | The malware family of the file. For example, StoneDrill. | 
| Malquery.File.filesize | String | The size of the file. | 
| Malquery.File.filetype | String | The type of the file. | 
| Malquery.File.first_seen | String | The date when the file was first seen. | 
| Malquery.File.label | String | The label of the file. For example, Malware. | 
| Malquery.File.md5 | String | The MD5 of the file. | 
| Malquery.File.sha1 | String | The SHA1 of the file. | 
| Malquery.File.sha256 | String | The SHA256 of the file. | 


#### Command Example
```!cs-malquery-fuzzy-search hex=8948208b480833ca33f989502489482889782c8bd7 filter_meta=sha256,type,size limit=5```

#### Context Example
```
{
    "Malquery": {
        "File": [
            {
                "filesize": 310552,
                "filetype": "PE32",
                "sha256": "e51f0a8884eb08fc43da0501ebd3776831e2fd4b0a8dd12e69866a8febe41495"
            },
            {
                "filesize": 1672180,
                "filetype": "PE32",
                "sha256": "bc74f8fc37b902536b52c1157b74724edc96a586b0e3e38717dd845981443a5b"
            },
            {
                "filesize": 1672188,
                "filetype": "PE32",
                "sha256": "72b021085f62e5dc1335f878a2751bce68d95918c84215ec8dfebf491009ea09"
            },
            {
                "filesize": 279624,
                "filetype": "PE32",
                "sha256": "5e2e1735e10684b36d30b3a3362e66cd30fb493afac8e711d92bde8372b9b6d0"
            },
            {
                "filesize": 19055104,
                "filetype": "PE32",
                "sha256": "d5023cd464d7578506770338e0fc43bd64887dbf234785b4d8f8547e57efa33d"
            }
        ]
    }
}
```

#### Human Readable Output

>### Fuzzy Search Result
>|filesize|filetype|sha256|
>|---|---|---|
>| 310552 | PE32 | e51f0a8884eb08fc43da0501ebd3776831e2fd4b0a8dd12e69866a8febe41495 |
>| 1672180 | PE32 | bc74f8fc37b902536b52c1157b74724edc96a586b0e3e38717dd845981443a5b |
>| 1672188 | PE32 | 72b021085f62e5dc1335f878a2751bce68d95918c84215ec8dfebf491009ea09 |
>| 279624 | PE32 | 5e2e1735e10684b36d30b3a3362e66cd30fb493afac8e711d92bde8372b9b6d0 |
>| 19055104 | PE32 | d5023cd464d7578506770338e0fc43bd64887dbf234785b4d8f8547e57efa33d |


### cs-malquery-get-request
***
Checks the status and results of an asynchronous request, such as hunt or exact-search.  Supports a single request ID.


#### Base Command

`cs-malquery-get-request`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| request_id | The identifier of a MalQuery request. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Malquery.Request_ID | String | The request ID. | 
| Malquery.Status | String | The status of the request. | 
| Malquery.File.family | String | The malware family of the file. For example, StoneDrill. | 
| Malquery.File.filesize | String | The size of the file. | 
| Malquery.File.filetype | String | The type of the file. For example, PE32. | 
| Malquery.File.first_seen | String | The date when the file was first seen. | 
| Malquery.File.label | String | The label of the file. For example, malware. | 
| Malquery.File.md5 | String | The file MD5. | 
| Malquery.File.sha1 | String | The file SHA1. | 
| Malquery.File.sha256 | String | The file SHA256. | 


#### Command Example
```!cs-malquery-get-request request_id=096f6aa5-f245-4b09-790f-133bc89d4d26```

#### Context Example
```
{
    "Malquery": {
        "File": [
            {
                "filesize": 151552,
                "filetype": "PE32",
                "first_seen": "2020/06/09",
                "label": "unknown",
                "md5": "0b189ab69d40e782fe827c63e1cc6f06",
                "samples": [],
                "sha1": "85be23059c9abb3370586dc49dbd8f1ced05df8e",
                "sha256": "d207ccf1eabcc9453288896d963f1a1c558c427abfe9305d7328e3a6fb06f6ee"
            },
            {
                "family": "Stonedrill",
                "filesize": 245760,
                "filetype": "PE32",
                "first_seen": "2019/03/12",
                "label": "malware",
                "md5": "688bdedf1f9dd44d6db51a7f8499939c",
                "samples": [],
                "sha1": "2ca2622317bc840bf890d1e337d2c547be2cfebf",
                "sha256": "41a1d7b98d0ce3259270c9a8f26fe8899cca402cba69ef8e5c70449faea8b714"
            },
            {
                "family": "Stonedrill",
                "filesize": 317440,
                "filetype": "PE32",
                "first_seen": "2018/01/24",
                "label": "malware",
                "md5": "345ade2a73ee83e4f75447a26c4e78c9",
                "samples": [],
                "sha1": "6ae00484a878201e6150108ca1b234dd1f68930d",
                "sha256": "0f191518ab7f24643218bd3384ae4bd1f52ec80419730d87196605a2a69938d7"
            },
            {
                "family": "Cadlotcorg",
                "filesize": 128512,
                "filetype": "PE32",
                "first_seen": "2017/07/20",
                "label": "malware",
                "md5": "2b82ce15a632e3ce1485bfc87e586ee5",
                "samples": [],
                "sha1": "df07d50296914de0ca3116d4ca6d3845d55c7540",
                "sha256": "3fb85b787fa005e591cd2cd7e1e83c79d103b1c26f5da31fdf788764ae0b8bb0"
            },
            {
                "family": "Cadlotcorg",
                "filesize": 130560,
                "filetype": "PE32",
                "first_seen": "2016/12/09",
                "label": "malware",
                "md5": "697c515a46484be4f9597cb4f39b2959",
                "samples": [],
                "sha1": "b9fc1ac4a7ccee467402f190391974a181391da3",
                "sha256": "bf79622491dc5d572b4cfb7feced055120138df94ffd2b48ca629bb0a77514cc"
            }
        ],
        "Request_ID": "096f6aa5-f245-4b09-790f-133bc89d4d26",
        "Status": "done"
    }
}
```

#### Human Readable Output

>### Search Result for request: 096f6aa5-f245-4b09-790f-133bc89d4d26
>|filesize|filetype|first_seen|label|md5|sha1|sha256|
>|---|---|---|---|---|---|---|
>| 151552 | PE32 | 2020/06/09 | unknown | 0b189ab69d40e782fe827c63e1cc6f06 | 85be23059c9abb3370586dc49dbd8f1ced05df8e | d207ccf1eabcc9453288896d963f1a1c558c427abfe9305d7328e3a6fb06f6ee |
>| 245760 | PE32 | 2019/03/12 | malware | 688bdedf1f9dd44d6db51a7f8499939c | 2ca2622317bc840bf890d1e337d2c547be2cfebf | 41a1d7b98d0ce3259270c9a8f26fe8899cca402cba69ef8e5c70449faea8b714 |
>| 317440 | PE32 | 2018/01/24 | malware | 345ade2a73ee83e4f75447a26c4e78c9 | 6ae00484a878201e6150108ca1b234dd1f68930d | 0f191518ab7f24643218bd3384ae4bd1f52ec80419730d87196605a2a69938d7 |
>| 128512 | PE32 | 2017/07/20 | malware | 2b82ce15a632e3ce1485bfc87e586ee5 | df07d50296914de0ca3116d4ca6d3845d55c7540 | 3fb85b787fa005e591cd2cd7e1e83c79d103b1c26f5da31fdf788764ae0b8bb0 |
>| 130560 | PE32 | 2016/12/09 | malware | 697c515a46484be4f9597cb4f39b2959 | b9fc1ac4a7ccee467402f190391974a181391da3 | bf79622491dc5d572b4cfb7feced055120138df94ffd2b48ca629bb0a77514cc |


### cs-malquery-get-ratelimit
***
Returns information about search and download quotas in your environment.


#### Base Command

`cs-malquery-get-ratelimit`

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Malquery.Quota.hunt_count | number | How many hunts were executed in the last month. | 
| Malquery.Quota.download_count | number | How many downloads were executed in the last month. | 
| Malquery.Quota.monitor_count | number | How many monitors were created in the last month. | 
| Malquery.Quota.hunt_limit | number | Total hunt limit per month. | 
| Malquery.Quota.download_limit | number | The total download limit per month. | 
| Malquery.Quota.monitor_limit | number | The total monitor limit per month. | 
| Malquery.Quota.refresh_time | string | The time when the limits are refreshed. ISO 8601 format. | 
| Malquery.Quota.days_left | number | The days left until the limits are refreshed. | 
| Malquery.Quota.hunt_counts.userid | String | The download counts per user. | 
| Malquery.Quota.hunt_counts.counter | number | The download counts per user. | 


#### Command Example
```!cs-malquery-get-ratelimit```

#### Context Example
```
{
    "Malquery": {
        "Quota": {
            "days_left": 3,
            "download_count": 28,
            "download_counts": [
                {
                    "counter": 28,
                    "userid": ""
                }
            ],
            "download_limit": 50,
            "hunt_count": 83,
            "hunt_counts": [
                {
                    "counter": 83,
                    "userid": ""
                }
            ],
            "hunt_limit": 100,
            "monitor_count": 0,
            "monitor_limit": 10,
            "refresh_time": "2020-08-01T00:00:00Z"
        }
    }
}
```

#### Human Readable Output

>### Quota Data
>|hunt_count|download_count|monitor_count|hunt_limit|download_limit|monitor_limit|refresh_time|days_left|
>|---|---|---|---|---|---|---|---|
>| 83 | 28 | 0 | 100 | 50 | 10 | 2020-08-01T00:00:00Z | 3 |


### cs-malquery-samples-multidownload
***
Schedule samples for download, which returns a request ID. Use the request ID in the cs-malquery-get-request, to check the status of the operation. When the request status is “done”, use the cs-malquery-sample-fetch to download the results as a password-protected archive. The password to extract results from the archive: infected' 


#### Base Command

`cs-malquery-samples-multidownload`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| samples | Sample sha256 IDs. Comma separated values. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Malquery.Request_ID | String | The request ID. | 
| Malquery.Status | String | The request status. | 


#### Command Example
```!cs-malquery-samples-multidownload samples=742db9f3ae1b7322dfe8ab81476cd3146f9c0ce086fc4cd38a1072fb6cae8662,accc6794951290467e01b7676e8b4ba177076d54f836589ea7d3298cdf6fc995```

#### Context Example
```
{
    "Malquery": {
        "Request_ID": "e2e1aecb-6e34-44f7-5d42-932880276c5e"
    }
}
```

#### Human Readable Output

>### Samples Multidownload Request
>|Request_ID|
>|---|
>| e2e1aecb-6e34-44f7-5d42-932880276c5e |



### cs-malquery-file-download
***
Download a file indexed by MalQuery. Specify the file using its SHA256. Only one file is supported.


#### Base Command

`cs-malquery-file-download`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file_id | The SHA256 file. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.SHA256 | String | The SHA256 hash of the file. | 
| File.SHA1 | String | The SHA1 hash of the file. | 
| File.SHA512 | String | The SHA512 hash of the file. | 
| File.Name | String | The name of the file. | 
| File.EntryID | String | The Entry ID. | 
| File.Info | String | Information about the file. | 
| File.Type | String | The type of the file. | 
| File.MD5 | String | MD5 hash of the file. | 


#### Command Example
```!cs-malquery-file-download file_id=d77cf874521ee7d4bb7f54bd8cef3d60ec24d267cf2d502f819880f0819f5766```

#### Context Example
```
{
    "File": {
        "EntryID": "3993@904ba2df-a395-4270-8a6b-e9b8d614911e",
        "Info": "application/x-dosexec",
        "MD5": "c6a6a731f341ced1d93b61bc7628721d",
        "Name": "d77cf874521ee7d4bb7f54bd8cef3d60ec24d267cf2d502f819880f0819f5766",
        "SHA1": "8953cdddbe825e8378c590084dca1e3d76ced233",
        "SHA256": "d77cf874521ee7d4bb7f54bd8cef3d60ec24d267cf2d502f819880f0819f5766",
        "SHA512": "09c164142da9b4d8decb3cbbfa2916326aeab50d79bffa6090816f2cdb89838ac79fc7451c5997c06a9186c1bc0661283fc86cd5838d40e4b07b8a5d6bd8bb13",
        "SSDeep": "24576:qripAq8fCAmHY/Ph9Kv18re7NHHReC3Mm:quptkhOveSBImMm",
        "Size": 1076152,
        "Type": "PE32 executable (DLL) (GUI) Intel 80386, for MS Windows"
    }
}
```



### cs-malquery-sample-fetch
***
Fetches a zip archive file using the password, "infected" containing the samples. Use this after the cs-malquery-samples-multidownload request has finished processing.


#### Base Command

`cs-malquery-sample-fetch`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| request_id | Identifier of a MalQuery request. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.SHA256 | String | THe SHA256 hash of the file. | 
| File.SHA1 | String | The SHA1 hash of the file. | 
| File.SHA512 | String | The SHA512 hash of the file. | 
| File.Name | String | The name of the file. | 
| File.EntryID | String | The entry ID. | 
| File.Info | String | Information about the file. | 
| File.Type | String | The type of the file. | 
| File.MD5 | String | The MD5 hash of the file. | 


#### Command Example
```!cs-malquery-sample-fetch request_id=93b55373-3b69-43cb-6ea1-2870a44e1c1e```

#### Context Example
```
{
    "File": {
        "EntryID": "3517@904ba2df-a395-4270-8a6b-e9b8d614911e",
        "Info": "application/zip",
        "MD5": "a19a427b08c84f27a5a2b9f59fd8f752",
        "Name": "93b55373-3b69-43cb-6ea1-2870a44e1c1e",
        "SHA1": "01583032c5b9df88266da1d0cc46d41678203f2d",
        "SHA256": "a959753414fcf8367054e195424d86feb75f3819272754178efc6ec0963f6bb0",
        "SHA512": "3cce7bbca53570da2925da32942c7f20f1f619b016395a663c0abdb1e54eed06ad0b7b60687286f04278196693b4e44255c2cf25ed953a1c512d58625775704b",
        "SSDeep": "49152:Pm7wDIVHR7jadrFtkGU5fW/Lv4yZ4mXoGODTmtvL7ERwjU3IDcJA2I:O7wDAHgfkpfiv4PmXoGO3mhLIRwL7",
        "Size": 3059253,
        "Type": "Zip archive data, at least v1.0 to extract"
    }
}
```

#### Human Readable Output



### file
***
Retrieves indexed files metadata by their hash.


#### Base Command

`file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file | The SHA256 of the files. Comma separated values. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| File.Vendor | String | The vendor used to calculate the score. | 
| Malquery.File.family | String | The malware family of the file. For example, StoneDrill. | 
| Malquery.File.filesize | String | The size of the file. | 
| Malquery.File.filetype | String | The type of the file. | 
| Malquery.File.first_seen | String | The date when the file was first seen. | 
| Malquery.File.label | String | The label of the file. | 
| Malquery.File.md5 | String | The MD5 hash of the file. | 
| Malquery.File.sha1 | String | The SHA1 hash of the file. | 
| Malquery.File.sha256 | String | The SHA256 hash of the file. | 


#### Command Example
```!file file=d77cf874521ee7d4bb7f54bd8cef3d60ec24d267cf2d502f819880f0819f5766```

#### Context Example
```
{
    "DBotScore": {
        "Indicator": "d77cf874521ee7d4bb7f54bd8cef3d60ec24d267cf2d502f819880f0819f5766",
        "Score": 0,
        "Type": "file",
        "Vendor": "CrowdStrike Malquery"
    },
    "File": {
        "SHA256": "d77cf874521ee7d4bb7f54bd8cef3d60ec24d267cf2d502f819880f0819f5766"
    },
    "Malquery": {
        "File": {
            "filesize": 1076152,
            "filetype": "PE32",
            "first_seen": "2014/01/27",
            "label": "unknown",
            "md5": "c6a6a731f341ced1d93b61bc7628721d",
            "sha1": "8953cdddbe825e8378c590084dca1e3d76ced233",
            "sha256": "d77cf874521ee7d4bb7f54bd8cef3d60ec24d267cf2d502f819880f0819f5766"
        }
    }
}
```

#### Human Readable Output

>### CrowdStrike Malquery File reputation
>|filesize|filetype|first_seen|label|md5|sha1|sha256|
>|---|---|---|---|---|---|---|
>| 1076152 | PE32 | 2014/01/27 | unknown | c6a6a731f341ced1d93b61bc7628721d | 8953cdddbe825e8378c590084dca1e3d76ced233 | d77cf874521ee7d4bb7f54bd8cef3d60ec24d267cf2d502f819880f0819f5766 |
