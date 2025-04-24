CIRCL hash lookup is a public API to lookup hash values against known database of files. NSRL RDS database is included and many others are also included. The API is accessible via HTTP ReST API and the API is also described as an OpenAPI. The service is free and served as a best-effort basis.
This integration was integrated and tested with online version of CIRCLEHashlookup

## Configure CIRCLEHashlookup in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL (e.g. https://hashlookup.circl.lu) |  | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Source Reliability | Reliability of the source providing the intelligence data. | True |
| Create relationships | Create relationships between indicators as part of Enrichment. | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### circl-info
***
Get information about the hash lookup database


#### Base Command

`circl-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Circl.Info | string | Info about the hashlookup database | 


#### Command Example
``` ```

#### Human Readable Output



### circl-bulk-md5
***
Bulk search of MD5 hashes


#### Base Command

`circl-bulk-md5`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| md5_list | List of MD5s to query. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Circl.MD5 | string | Results of bulk MD5 query | 


#### Command Example
``` ```

#### Human Readable Output



### circl-bulk-sha1
***
Bulk search of SHA1 hashes


#### Base Command

`circl-bulk-sha1`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sha1_list | List of SHA1 to search. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Circl.SHA1 | string | Results of bulk SHA1 query | 


#### Command Example
``` ```

#### Human Readable Output



### file
***
Checks the file reputation of the specified hash.


#### Base Command

`file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file | Hash to query. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.Name | string | Name of the file | 
| File.Size | number | Size of the file | 
| File.MD5 | string | MD5 hash of the file | 
| File.SHA1 | string | SHA1 hash of the file | 
| File.SHA256 | string | SHA256 hash of the file | 
| File.SHA512 | string | SHA512 hash of the file | 
| File.SSDeep | string | SSDeep of the file | 
| DbotScore.Indicator | string | The indicator value. | 
| DbotScore.Reliability | string | The reliability of the source providing the intelligence data | 
| DbotScore.Score | number | An integer regarding the status of the indicator | 
| DbotScore.Type | string | The indicator type | 
| DbotScore.Vendor | string | The vendor used to calculate the score | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | Type of indicator. | 
| DBotScore.Vendor | String | Vendor used to calculate the score. | 


#### Command Example
``` ```

#### Human Readable Output



### circl-top
***
Return the top 100 of most queried values.


#### Base Command

`circl-top`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Circl.Top | string | The top 100 of most queried values | 


#### Command Example
``` ```

#### Human Readable Output

