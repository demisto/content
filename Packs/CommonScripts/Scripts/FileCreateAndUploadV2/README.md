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

```!FileCreateAndUploadV2 filename=test.txt data=test```

### Context Example

```json
{
    "File": {
        "EntryID": "919@35961d68-3216-49b9-870a-2f09e5dac489",
        "Extension": "txt",
        "Info": "text/plain; charset=utf-8",
        "MD5": "098f6bcd4621d373cade4e832627b4f6",
        "Name": "test.txt",
        "SHA1": "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3",
        "SHA256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        "SHA512": "ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff",
        "SSDeep": "3:Hn:Hn",
        "Size": 4,
        "Type": "ASCII text, with no line terminators"
    }
}
```

### Limitation

Using the `entryID` argument to copy the contents of an existing file **from different incidents** is only available from XSOAR version 6.12.0 onwards.