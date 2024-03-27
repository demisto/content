Creates a file (using the given data input or entry ID) and uploads it to the current investigation War Room.


## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | Utility |
| Cortex XSOAR Version | 6.0.0 |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| filename | The name of the file to be created. |
| data | Input data to write to the file. |
| entryId | Entry ID contents to write in the file. |
| data_encoding | Encoding type of the input data or contents. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| File.Size | The size of the file. | Number |
| File.SHA1 | The SHA1 hash of the file. | String |
| File.SHA256 | The SHA256 hash of the file. | String |
| File.SHA512 | The SHA512 hash of the file. | String |
| File.Name | The name of the file. | String |
| File.SSDeep | The SSDeep hash of the file. | String |
| File.EntryID | The entry ID of the file. | String |
| File.Info | File information. | String |
| File.Type | The file type. | String |
| File.MD5 | The MD5 hash of the file. | String |
| File.Extension | The file extension. | String |

## Script Examples

### Example command

```!FileCreateAndUploadV2 filename=test.txt data=test_data```

### Context Example

```json
{
    "File": {
        "EntryID": "123@456",
        "Extension": "txt",
        "Info": "application/x-perl",
        "MD5": "aaabbb",
        "Name": "test.txt",
        "SHA1": "aaabbb",
        "SHA256": "aaabbb",
        "SHA512": "aaabbb",
        "SSDeep": "a:a:a",
        "Size": 4,
        "Type": "ASCII text, with no line terminators"
    }
}
```

### Limitation

To copy data from another file in a different incident, you can use the `entryID` argument. This feature is only available from XSOAR version 6.12.0 onwards.