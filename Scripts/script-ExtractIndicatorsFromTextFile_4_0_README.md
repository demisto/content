Extracts indicators from a text-based file.

Indicators that can be extracted:
* IP
* Domain
* URL
* File Hash
* Email Address

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python |
| Tags | - |
| Demisto Version | 3.6.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| entryID | The War Room entryID of the file to read. |
| maxFileSize | The maximum file size to load, in bytes. The default is 1000000 (1MB). |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Domain.Name | The extracted domains. | string |
| Account.Email.Address | The extracted emails. | string |
| File.MD5 | The extracted MD5 hash of a file. | string |
| File.SHA1 | The extracted SHA1 hash of a file. | string |
| File.SHA256 | The extracted SHA256 hash of a file. | string |
| IP.Address | The extracted IP addresses. | string |
| URL.Data | The extracted URLs. | string |
