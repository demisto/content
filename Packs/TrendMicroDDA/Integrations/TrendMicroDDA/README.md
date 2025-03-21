
### trendmicro-dda-get-sample

***
Retrieves a sample

#### Base Command

`trendmicro-dda-get-sample`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sha1 | The SHA1 of the sample to get. | Required | 
| type | The export data type. Possible values are: tgz, zip. Default is zip. | Optional | 
| encrypted | 0 (not encrypted) or 1 (Encrypted with password "virus"). Possible values are: 0, 1. Default is 0. | Optional | 
| archive_name | A name for the retrieved archive. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.EntryID | string | Demisto entry ID of archive | 
| File.Size | number | File size | 
| File.SHA1 | string | File SHA1 | 
| File SHA256 | string | File SHA256 | 
| File.Name | string | File name | 
| File.SSDeep | string | File SSDeep | 
| File.Info | string | File info | 
| File.Type | string | File type | 
| File.MD5 | string | File MD5 | 
| File.Extension | string | File extension | 
### trendmicro-dda-get-report

***
Retrieves XML report of a given submission

#### Base Command

`trendmicro-dda-get-report`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sha1 | The SHA1 of the submission. | Required | 
| threshold | DDA severity score (greater or equal to) for which the submission will be considered malicious. Possible values are: 0, 1, 2, 3. Default is 1. | Optional | 
| verbose | Return detailed report. Possible values are: false, true. Default is false. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TrendMicroDDA.Submission.Status | string | The status of the submission | 
| TrendMicroDDA.Submission.SHA1 | string | SHA1 of the submission | 
| TrendMicroDDA.Submission.RiskLevel | number | The Risk Level of the submission | 
| DBotScore.Score | number | The actual score | 
| DBotScore.Indicator | string | The indicator we tested | 
| DBotScore.Type | string | The type of the indicator | 
| DBotScore.Vendor | string | Vendor used to calculate the score | 
| InfoFile.MD5 | string | MD5 hash of the report file | 
| InfoFile.SHA1 | string | SHA1 hash of the report file | 
| InfoFile.SHA256 | string | SHA256 hash of the report  file | 
| InfoFile.Name | string | Report file name | 
| InfoFile.Type | string | Report file type e.g. "PE" | 
| InfoFile.Size | number | Report file size | 
| File.Malicious.Vendor | string | For malicious files, the vendor that made the decision | 
| File.Malicious.Description | string | For malicious files, the reason for the vendor to make the decision | 
| IP.Address | string | IPs relevant to the submission | 
| Domain.Name | string | Domains relevant to the submission | 
| URL.Data | string | URL data | 
| File.MD5 | string | MD5 hash of the file | 
| File.SHA1 | string | SHA1 hash of the file | 
| File.SHA256 | string | SHA256 hash of the file | 
| File.Size | number | File size | 
| File.Name | string | File name | 
| TrendMicroDDA.Submission.SHA256 | string | SHA256 of the submission | 
| TrendMicroDDA.Submission.MD5 | string | MD5 of the submission | 
| TrendMicroDDA.Submission.VirusDetected | boolean | True if virus detected, else Flase | 
| TrendMicroDDA.Submission.DownloadURL | string | Download URL address of files | 
### trendmicro-dda-get-sample-list

***
Retrieves a list of SHA1 of samples submitted within the given time interval

#### Base Command

`trendmicro-dda-get-sample-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| interval_start | Interval start time, given in format ~~YYYY-MM-DD HH:MM:SS, e.g. 2008-11-22 19:53:42. | Required | 
| interval_end | Interval end time, given in format YYYY-MM-DD HH:MM:SS, e.g. 2008-11-22 19:53:42. | Required | 
| interval_type | 0: Submission time, 1: Completion time. Possible values are: 0, 1. Default is 0. | Optional | 

#### Context Output

There is no context output for this command.
### trendmicro-dda-check-status

***
Checks the analysis status of the submissions

#### Base Command

`trendmicro-dda-check-status`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sha1 | The SHA1 of the submissions. Example: "2492A18532745251FBC5DAF7160DAA49B90DBBE1,  52483514F07EB14570142F6927B77DEB7B4DA99F". | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TrendMicroDDA.Submission.Status | string | The status of the submission | 
| TrendMicroDDA.Submission.SHA1 | string | The SHA1 of the submission | 
### trendmicro-dda-upload-url

***
Upload a URL to Trend Micro DDA 

#### Base Command

`trendmicro-dda-upload-url`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | The URL to upload. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TrendMicroDDA.Submission.SHA1 | string | The SHA1 of the submission | 
| TrendMicroDDA.Submission.URL | string | The submitted URL | 
### trendmicro-dda-upload-file

***
Upload a file to Trend Micro DDA 

#### Base Command

`trendmicro-dda-upload-file`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entryID | EntryID of the file to upload. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TrendMicroDDA.Submission.SHA1 | string | The SHA1 of the submission | 
### trendmicro-dda-get-brief-report

***
Retrieves a brief XML report of a given submission

#### Base Command

`trendmicro-dda-get-brief-report`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sha1 | SHA1 of the submission. | Required | 
| threshold | DDA severity score (greater or equal to) for which the submission will be considered malicious. Possible values are: 0, 1, 2, 3. Default is 1. | Optional | 

#### Context Output

There is no context output for this command.