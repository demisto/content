This automation translate endpoint (hostname/IP) to sensor id, Than it downloads given file paths by opening session and closing it.  
## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | carbon-black, endpoint |
| Cortex XSOAR Version | 4.1.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| endpoint | hostname of a Carbon Black sensor \(Could be IP\). |
| path | Comma seprated files path to download from the endpoint.. |
| timeout | Session timeout \(ms\). |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| CbLiveResponse.Commands.CbCommandID | Unique command identifier. | Number |
| CbLiveResponse.Commands.CommandName | The command name. | String |
| CbLiveResponse.Commands.Status | The command Status \('pending', 'in progress', 'complete', 'error', 'canceled'\). | String |
| CbLiveResponse.Commands.CommandCompletionTime | The command completion time \(0 if not complete\). | String |
| CbLiveResponse.Commands.OperandObject | The source path of the file. | String |
| CbLiveResponse.Commands.FileID | Unique file ID. | Number |
| CbLiveResponse.File.Size | File size. | String |
| CbLiveResponse.File.SHA1 | File SHA1. | String |
| CbLiveResponse.File.SHA256 | File SHA256. | String |
| CbLiveResponse.File.Name | File name. | String |
| CbLiveResponse.File.SSDeep | File SSDeep. | String |
| CbLiveResponse.File.EntryID | File EntryID. | Number |
| CbLiveResponse.File.Info | File info. | String |
| CbLiveResponse.File.Type | File type. | String |
| CbLiveResponse.File.MD5 | File MD5. | String |
| CbLiveResponse.File.Extension | File extension. | String |


#### Command Example
```!CBLiveGetFile_v2 endpoint=EC2AMAZ-L4C2OKC path="c:\\Users\\All Users\\Desktop\\mooncake.jpg" timeout=2000```

#### Context Example
```
{
    "CbLiveResponse": {
        "Commands": {
            "CbCommandID": 2,
            "CbSensorID": 17,
            "CbSessionID": 356,
            "CommandCompletionTime": 1540229207.655335,
            "CommandName": "get file",
            "CreateTime": 1540229207.608662,
            "FileID": 1,
            "OperandObject": "c:\\Users\\All Users\\Desktop\\mooncake.jpg",
            "Result": {
                "Code": 0,
                "Desc": "",
                "Type": "WinHresult"
            },
            "Status": "complete"
        }
    },
    "File": {
        "EntryID": "168@583490",
        "Extension": "jpg",
        "Info": "image/jpeg",
        "MD5": "1fe52b291d16c7f9a6eaf43074024011",
        "Name": "mooncake.jpg",
        "SHA1": "30bd2461d6cee80227bcf557a6fd47922b96263c",
        "SHA256": "a87b0fa1006b301b7ef2259cfa9aed2ff12c15217796b5dd08b36e006a137cd2",
        "SSDeep": "192:pAzQbZ/ujghzcZHcsWw6o6E7ODeADcBwjZ4P:pAzG/ujgh6xCo60ODe3wj8",
        "Size": 11293,
        "Type": "data\n"
    }
}
```

#### Human Readable Output
>### Files downloaded from endpoint EC2AMAZ-L4C2OKC
>|File ID|File Path|
>|---|---|
>| 1 | "c:\\Users\\All Users\\Desktop\\mooncake.jpg" |

