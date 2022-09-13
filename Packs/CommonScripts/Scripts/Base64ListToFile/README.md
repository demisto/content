Converts Base64 file in a list to a binary file and upload to warroom

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | list, Utility |
| Cortex XSOAR Version | 5.0.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| listname | List Name of Base64 item \(need to be a single file in list\) |
| filename | Optional Warroom Output Filename \(default filename is list name\) |
| isZipFile | Is data compressed \(zip format\)? |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| File.Name | Filename \(only in case of report type=json\) | Unknown |
| File.Type | File type e.g. "PE" \(only in case of report type=json\) | Unknown |
| File.Size | File size \(only in case of report type=json\) | Unknown |
| File.MD5 | MD5 hash of the file \(only in case of report type=json\) | Unknown |
| File.SHA1 | SHA1 hash of the file \(only in case of report type=json\) | Unknown |
| File.SHA256 | SHA256 hash of the file \(only in case of report type=json\) | Unknown |
| File.EntryID | EntryID of the file \(only in case of report type=json\) | Unknown |


## Script Examples
### Example command
```!Base64ListToFile listname="test_list_name" filename="test_file_name.txt" isZipFile="no"```
### Context Example
```json
{
    "File": {
        "EntryID": "192@2ae905f4-bec0-43aa-8af3-99fb982d719f",
        "Extension": "txt",
        "Info": "text/plain; charset=utf-8",
        "MD5": "4d8d433345a1a5d3b0ba3157e7d6b411",
        "Name": "test_file_name.txt",
        "SHA1": "e4e62ac169793ebecc9e45eb14906a6a8c04a399",
        "SHA256": "0d732beba373d960e4dc305b6862309ae996748e21b1417e0bb9f0dfe9aab08e",
        "SHA512": "47d276725420776ac107319135a8b61aeff605397e9486ff4642d2b0b804376e781505ad3a41a8f084ac220495201502dbae2d736a7d9cd3a59301c3d650c1c6",
        "SSDeep": "3:YKE4Lr/CLXxMt:Yf4veKt",
        "Size": 40,
        "Type": "ASCII text"
    }
}
```
