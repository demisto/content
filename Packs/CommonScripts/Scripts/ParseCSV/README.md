This script will parse a CSV file and place the unique IPs, Domains and Hashes into the context.
## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python2 |
| Tags | file, csv, Utility |

## Used In
---
This script is used in the following playbooks and scripts.
* Block IOCs from CSV - External Dynamic List

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| entryID | The war room entryID of the file. |
| file | The name of the file. The file must be uploaded to the War Room. |
| ips | The column number that contains IP Addresses. \(First column is column 0\) |
| domains | The column number that contains domains. \(First column is column 0\) |
| hashes | The column number that contains file hashes. \(First column is column 0\) |
| parseAll | Parses and converts all of the rows in the CSV into JSON and puts them into the context. |
| codec | The codec type used to parse the file. \(some character sets are not UTF\-8 supported\) |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| IP.Address | IP address found in the parsed file. | Unknown |
| Domain.Name | Domain found in the parsed file. | Unknown |
| File.MD5 | MD5 found in the parsed file. | Unknown |
| File.SHA1 | SHA1 found in the parsed file. | Unknown |
| File.SHA256 | SHA256 found in the parsed file. | Unknown |
| ParseCSV.ParsedCSV | Parsed csv in the form of JSON array. | Unknown |
