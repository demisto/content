Use the Intezer v2 integration to detect and analyze malware, based on code reuse.

## Configure Intezer v2 in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| API Key |  | True |
| Intezer Analyze Base URL | The API address to intezer Analyze - i.e. <https://analyze.intezer.com/api/> | False |
| Use system proxy settings |  | False |
| Trust any certificate (not secure) |  | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### intezer-analyze-by-hash

***
Checks file reputation of the given hash, supports SHA256, SHA1 and MD5

#### Base Command

`intezer-analyze-by-hash`

#### Input

| **Argument Name** | **Description**                                           | **Required** |
|-------------------|-----------------------------------------------------------|--------------|
| file_hash         | Hash of the file to query. Supports SHA256, MD5 and SHA1. | Required     | 
| wait_for_result   | Waits for analysis result, support polling                | Optional     | 
| interval          | Number of seconds between poll requests                   | Optional     | 
| timeout           | Number of seconds until polling timeout                   | Optional     | 

#### Context Output

| **Path**                | **Type** | **Description**        |
|-------------------------|----------|------------------------|
| Intezer.Analysis.ID     | string   | Intezer analysis id    | 
| Intezer.Analysis.Status | string   | status of the analysis | 
| Intezer.Analysis.Type   | string   | type of the analysis   | 

#### Command Example

``` 
!intezer-analyze-by-hash file_hash="<file hash>"
```

#### Context Example

```
{
    "Intezer.Analysis": {
        "Status": "Created", 
        "type": "File", 
        "ID": "59e2f081-45f3-4822-bf45-407670dcb4d7"
    }
}
```

#### Human Readable Output

```
Analysis created successfully: 59e2f081-45f3-4822-bf45-407670dcb4d7
```

#### intezer-analyze-url

***
Checks file reputation of the given URL

Notice: Submitting indicators using this command might make the indicator data publicly available. See the vendor’s documentation for more details.

#### Base Command

`intezer-analyze-url`

#### Input

| **Argument Name** | **Description** | **Required** |
|-------------------|-----------------|--------------|
| Url               | Url to query.   | Required     | 

#### Context Output

| **Path**                | **Type** | **Description**                                      |
|-------------------------|----------|------------------------------------------------------|
| Intezer.Analysis.ID     | string   | Intezer analysis id                                  | 
| Intezer.Analysis.Status | string   | status of the analysis                               | 
| Intezer.Analysis.Type   | string   | type of the analysis                                 | 
| URL.Data                | string   | The submitted Url                                    | 
| URL.Malicious.Vendor    | string   | For malicious Url, the vendor that made the decision | 
| URL.Metadata            | Unknown  | Metadata returned from Intezer analysis              |
| URL.ExistsInIntezer     | Boolean  | Does the url exists on intezer                       |

#### Command Example

``` 
!intezer-analyze-url url="<url>"
```

#### Context Example

```
{
    "Intezer.Analysis": {
        "Status": "Created", 
        "type": "Url", 
        "ID": "59e2f081-45f3-4822-bf45-407670dcb4d7"
    }
}
```

#### Human Readable Output

```
Analysis created successfully: 59e2f081-45f3-4822-bf45-407670dcb4d7
```

### intezer-get-latest-report

***
Checks file reputation of the given hash, supports SHA256, SHA1 and MD5 by looking at the latest available report

#### Base Command

`intezer-get-latest-report`

#### Input

| **Argument Name** | **Description**                                           | **Required** |
|-------------------|-----------------------------------------------------------|--------------|
| file_hash         | Hash of the file to query. Supports SHA256, MD5 and SHA1. | Required     | 

#### Context Output

| **Path**              | **Type** | **Description**                                                                                                                                                               |
|-----------------------|----------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| File.SHA256           | string   | Hash SHA256                                                                                                                                                                   | 
| File.Malicious.Vendor | string   | For malicious files, the vendor that made the decision                                                                                                                        | 
| DBotScore.Indicator   | string   | The indicator we tested                                                                                                                                                       | 
| DBotScore.Type        | string   | The type of the indicator                                                                                                                                                     | 
| DBotScore.Vendor      | string   | Vendor used to calculate the score                                                                                                                                            | 
| DBotScore.Score       | number   | The actual score                                                                                                                                                              | 
| File.Metadata         | Unknown  | Metadata returned from Intezer analysis \(analysis id, analysis url, family, family type, sha256, verdict, sub_verdict\). Metadata will be returned only for supported files. | 
| File.ExistsInIntezer  | Boolean  | Does the file exists on intezer genome database                                                                                                                               | 

#### Command Example

```
intezer-get-latest-report file_hash="8cbf90aeab2c93b2819fcfd6262b2cdb"
```

#### Context Example

```
{
    "DBotScore": {
        "Vendor": "Intezer", 
        "Indicator": "<some sha>>", 
        "Score": 0, 
        "Type": "hash"
    }, 
    "File": {
        "ExistsInIntezer": true, 
        "SHA256": "<some sha256>", 
        "Metadata": {
            "analysis_id": "006c54ba-3159-43a0-98a0-1c5032145f47", 
            "sub_verdict": "known_malicious", 
            "analysis_url": "https://analyze.intezer.com/analyses/006c54ba-3159-43a0-98a0-1c5032145f47", 
            "verdict": "malicious", 
            "family_id": "0b13c0d4-7779-4c06-98fa-4d33ca98f8a9",
            "family_name": "WannaCry",
            "sha256": "<some sha256>",
            "is_private": true, 
            "analysis_time": "Wed, 19 Jun 2019 07:48:12 GMT"
        }
    }
}
```

#### Human Readable Output

```
Intezer File analysis result
----
SHA256: some-sha256
Verdict: malicious (known_malicious)
Family: WannaCry


Analysis Report
---
analysis_id	006c54ba-3159-43a0-98a0-1c5032145f47
analysis_time	Tue, 29 Jun 2021 13:40:01 GMT
analysis_url	https://analyze.intezer.com/analyses/006c54ba-3159-43a0-98a0-1c5032145f47
family_id	0b13c0d4-7779-4c06-98fa-4d33ca98f8a9
family_name	WannaCry
is_private	false
sha256          some-sha256
sub_verdict	known_malicious
verdict	        malicious
```

### intezer-analyze-by-file

***
Checks file reputation for uploaded file (up to 150MB)

#### Base Command

`intezer-analyze-by-file`

#### Input

| **Argument Name** | **Description**                                            | **Required** |
|-------------------|------------------------------------------------------------|--------------|
| file_entry_id     | The file entry id to upload.                               | Required     | 
| related_alert_ids | An array of alert ids to associate with the file analysis. | Required     | 

#### Context Output

| **Path**                | **Type** | **Description**                                                                                                                                                               |
|-------------------------|----------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Intezer.Analysis.ID     | string   | Intezer analysis id                                                                                                                                                           | 
| Intezer.Analysis.Status | string   | status of the analysis                                                                                                                                                        | 
| Intezer.Analysis.Type   | string   | type of the analysis                                                                                                                                                          | 
| File.SHA256             | string   | Hash SHA256                                                                                                                                                                   | 
| File.Malicious.Vendor   | string   | For malicious files, the vendor that made the decision                                                                                                                        | 
| File.Metadata           | Unknown  | Metadata returned from Intezer analysis \(analysis id, analysis url, family, family type, sha256, verdict, sub_verdict\). Metadata will be returned only for supported files. | 
| File.ExistsInIntezer    | Boolean  | Does the file exists on intezer genome database                                                                                                                               |

#### Command Example

``` 
intezer-analyze-by-file file_entry_id=1188@6
```

#### Context Example

```
{
    "Intezer.Analysis": {
        "Status": "Created", 
        "type": "File", 
        "ID": "675515a1-62e9-4d55-880c-fd46a7963a56"
    }
}
```

#### Human Readable Output

```
Analysis created successfully: 675515a1-62e9-4d55-880c-fd46a7963a56
```

### intezer-get-endpoint-analysis-result

***
Check the endpoint analysis status and get analysis result, supports polling.

#### Base Command

`intezer-get-endpoint-analysis-result`

#### Input

| **Argument Name** | **Description**                             | **Required** |
|-------------------|---------------------------------------------|--------------|
| analysis_id       | The analysis ID we want to get results for. | Required     | 
| wait_for_result   | Waits for analysis result, support polling  | Optional     | 
| interval          | Number of seconds between poll requests     | Optional     | 
| timeout           | Number of seconds until polling timeout     | Optional     | 

#### Context Output

| **Path**            | **Type** | **Description**                                                                                                       |
|---------------------|----------|-----------------------------------------------------------------------------------------------------------------------|
| DBotScore.Indicator | string   | The indicator we tested                                                                                               | 
| DBotScore.Type      | string   | The type of the indicator                                                                                             | 
| DBotScore.Vendor    | string   | Vendor used to calculate the score                                                                                    | 
| DBotScore.Score     | number   | The actual score                                                                                                      |
| Endpoint.Metadata   | Unknown  | Metadata returned from Intezer analysis \(endpoint analysis id, endpoint analysis url, families, verdict, host_name\) | 

#### Command Example

``` 
intezer-get-endpoint-analysis-result analysis_id="9e3acdc3-b7ea-412b-88ae-7103eebc9398" wait_for_result="true"
```

### intezer-get-url-analysis-result

***
Check the url analysis status and get analysis result, supports polling.

#### Base Command

`intezer-get-url-analysis-result`

#### Input

| **Argument Name** | **Description**                             | **Required** |
|-------------------|---------------------------------------------|--------------|
| analysis_id       | The analysis ID we want to get results for. | Required     | 
| wait_for_result   | Waits for analysis result, support polling  | Optional     | 
| interval          | Number of seconds between poll requests     | Optional     | 
| timeout           | Number of seconds until polling timeout     | Optional     | 

#### Context Output

| **Path**             | **Type** | **Description**                                      |
|----------------------|----------|------------------------------------------------------|
| DBotScore.Indicator  | string   | The indicator we tested                              | 
| DBotScore.Type       | string   | The type of the indicator                            | 
| DBotScore.Vendor     | string   | Vendor used to calculate the score                   | 
| DBotScore.Score      | number   | The actual score                                     |
| URL.Data             | string   | The submitted Url                                    | 
| URL.Malicious.Vendor | string   | For malicious Url, the vendor that made the decision | 
| URL.Metadata         | Unknown  | Metadata returned from Intezer analysis              | 
| URL.ExistsInIntezer  | Boolean  | Does the url exists on intezer                       |

#### Command Example

``` 
intezer-get-url-analysis-result analysis_id="9e3acdc3-b7ea-412b-88ae-7103eebc9398" wait_for_result="true"
```

### intezer-get-file-analysis-result

***
Check the file analysis status and get analysis result, supports polling.

#### Base Command

`intezer-get-file-analysis-result`

#### Input

| **Argument Name** | **Description**                             | **Required** |
|-------------------|---------------------------------------------|--------------|
| analysis_id       | The analysis ID we want to get results for. | Required     | 
| wait_for_result   | Waits for analysis result, support polling  | Optional     | 
| interval          | Number of seconds between poll requests     | Optional     | 
| timeout           | Number of seconds until polling timeout     | Optional     | 

#### Context Output

| **Path**              | **Type** | **Description**                                                                                                                                                               |
|-----------------------|----------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| DBotScore.Indicator   | string   | The indicator we tested                                                                                                                                                       | 
| DBotScore.Type        | string   | The type of the indicator                                                                                                                                                     | 
| DBotScore.Vendor      | string   | Vendor used to calculate the score                                                                                                                                            | 
| DBotScore.Score       | number   | The actual score                                                                                                                                                              |
| File.SHA256           | string   | Hash SHA256                                                                                                                                                                   | 
| File.SHA1             | string   | Hash SHA1                                                                                                                                                                     | 
| File.MD5              | string   | Hash MD5                                                                                                                                                                      | 
| File.Malicious.Vendor | string   | For malicious files, the vendor that made the decision                                                                                                                        | 
| File.Metadata         | Unknown  | Metadata returned from Intezer analysis \(analysis id, analysis url, family, family type, sha256, verdict, sub_verdict\). Metadata will be returned only for supported files. | 
| File.ExistsInIntezer  | Boolean  | Does the file exists on intezer genome database                                                                                                                               |                                             | 

#### Command Example

``` 
intezer-get-file-analysis-result analysis_id="9e3acdc3-b7ea-412b-88ae-7103eebc9398" wait_for_result="true"
```

### intezer-get-analysis-result

***
Check the analysis status and get analysis result, support file and endpoint analysis

#### Base Command

`intezer-get-analysis-result`

#### Input

| **Argument Name** | **Description**                                                                      | **Required** |
|-------------------|--------------------------------------------------------------------------------------|--------------|
| analysis_id       | The analysis ID we want to get results for.                                          | Optional     | 
| analysis_type     | The type of the analysis. Possible values are: File, Endpoint, Url. Default is File. | Optional     | 
| indicator_name    | indicator to classify.                                                               | Optional     | 

#### Context Output

| **Path**              | **Type** | **Description**                                                                                                                                                               |
|-----------------------|----------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| DBotScore.Indicator   | string   | The indicator we tested                                                                                                                                                       | 
| DBotScore.Type        | string   | The type of the indicator                                                                                                                                                     | 
| DBotScore.Vendor      | string   | Vendor used to calculate the score                                                                                                                                            | 
| DBotScore.Score       | number   | The actual score                                                                                                                                                              |
| File.SHA256           | string   | Hash SHA256                                                                                                                                                                   | 
| File.SHA1             | string   | Hash SHA1                                                                                                                                                                     | 
| File.MD5              | string   | Hash MD5                                                                                                                                                                      | 
| File.Malicious.Vendor | string   | For malicious files, the vendor that made the decision                                                                                                                        | 
| File.Metadata         | Unknown  | Metadata returned from Intezer analysis \(analysis id, analysis url, family, family type, sha256, verdict, sub_verdict\). Metadata will be returned only for supported files. | 
| File.ExistsInIntezer  | Boolean  | Does the file exists on intezer genome database                                                                                                                               |
| URL.Data              | string   | The submitted Url                                                                                                                                                             | 
| Url.URL               | string   | The submitted Url (deprecated)                                                                                                                                                | 
| URL.Malicious.Vendor  | string   | For malicious Url, the vendor that made the decision                                                                                                                          | 
| Url.Malicious.Vendor  | string   | For malicious Url, the vendor that made the decision (deprecated)                                                                                                             | 
| URL.Metadata          | Unknown  | Metadata returned from Intezer analysis                                                                                                                                       | 
| Url.Metadata          | Unknown  | Metadata returned from Intezer analysis (deprecated)                                                                                                                          | 
| URL.ExistsInIntezer   | Boolean  | Does the url exists on intezer                                                                                                                                                |
| Url.ExistsInIntezer   | Boolean  | Does the url exists on intezer (deprecated)                                                                                                                                   |
| Endpoint.Metadata     | Unknown  | Metadata returned from Intezer analysis \(endpoint analysis id, endpoint analysis url, families, verdict, host_name\)                                                         | 

#### Command Example

``` 
intezer-get-analysis-result analysis_id="9e3acdc3-b7ea-412b-88ae-7103eebc9398"
```

#### Context Example

```
{
    "DBotScore": {
        "Vendor": "Intezer", 
        "Indicator": "<some sha>>", 
        "Score": 0, 
        "Type": "hash"
    }, 
    "File": {
        "ExistsInIntezer": true, 
        "SHA256": "<some sha256>", 
        "Metadata": {
            "analysis_id": "006c54ba-3159-43a0-98a0-1c5032145f47", 
            "sub_verdict": "known_malicious", 
            "analysis_url": "https://analyze.intezer.com/analyses/006c54ba-3159-43a0-98a0-1c5032145f47", 
            "verdict": "malicious", 
            "family_id": "0b13c0d4-7779-4c06-98fa-4d33ca98f8a9",
            "family_name": "WannaCry",
            "sha256": "<some sha256>",
            "is_private": true, 
            "analysis_time": "Wed, 19 Jun 2019 07:48:12 GMT"
        }
    },
    "Url: {
        "ExistsInIntezer": true,
        "URL": "foo.com",
        "Metadata": {
        "analysis_id": "70d09f68-c7a3-43a3-a8de-07ec31fbf4ed",
        "domain_info": {
            "creation_date": "1997-08-13 04:00:00.000000",
            "domain_name": "foo.com",
            "registrar": "TUCOWS, INC."
        },
        "indicators": [
        {
            "classification": "informative",
            "text": "URL is accessible"
        },
        {
            "classification": "informative",
            "text": "Assigned IPv4 domain"
        },
        {
            "classification": "informative",
            "text": "Vaild IPv4 domain"
        }
        ],
        "ip": "34.206.39.153",
        "redirect_chain": [
        {
            "response_status": 301,
            "url": "https://foo.com/"
        },
        {
            "response_status": 200,
            "url": "http://www.foo.com/"
        }
        ],
        "scanned_url": "http://www.foo.com/",
        "submitted_url": "foo.com",
        "downloaded_file": {
            "analysis_id": "8db9a401-a142-41be-9a31-8e5f3642db62",
            "analysis_summary": {
               "verdict_description": "This file contains code from malicious software, therefore it's very likely that it's malicious.",
               "verdict_name": "malicious",
               "verdict_title": "Malicious",
               "verdict_type": "malicious"
            },
            "sha256": "4293c1d8574dc87c58360d6bac3daa182f64f7785c9d41da5e0741d2b1817fc7"
         },
        "summary": {
            "description": "No suspicious activity was detected for this URL",
            "title": "No Threats",
            "verdict_name": "no_threats",
            "verdict_type": "no_threats"
        }
    }
}
```

#### Human Readable Output

```
Intezer File analysis result
----
SHA256: some-sha256
Verdict: malicious (known_malicious)
Family: WannaCry


Analysis Report
---
analysis_id	006c54ba-3159-43a0-98a0-1c5032145f47
analysis_time	Tue, 29 Jun 2021 13:40:01 GMT
analysis_url	https://analyze.intezer.com/analyses/006c54ba-3159-43a0-98a0-1c5032145f47
family_id	0b13c0d4-7779-4c06-98fa-4d33ca98f8a9
family_name	WannaCry
is_private	false
sha256          some-sha256
sub_verdict	known_malicious
verdict	        malicious
```

### intezer-get-sub-analyses

***
Get a list of the analysis sub analyses

#### Base Command

`intezer-get-sub-analyses`

#### Input

| **Argument Name** | **Description**                                      | **Required** |
|-------------------|------------------------------------------------------|--------------|
| analysis_id       | The analysis ID we want to get the sub analyses for. | Required     | 

#### Context Output

| **Path**                        | **Type** | **Description**                               |
|---------------------------------|----------|-----------------------------------------------|
| Intezer.Analysis.ID             | string   | Intezer analysis id                           | 
| Intezer.Analysis.SubAnalysesIDs | Unknown  | List of all sub analyses of the give analysis | 

#### Command Example

```
intezer-get-sub-analyses analysis_id=006c54ba-3159-43a0-98a0-1c5032145f47
```

#### Context Example

```
{
    "Intezer.Analysis": {
        "Status": "Done", 
        "type": "File", 
        "ID": "675515a1-62e9-4d55-880c-fd46a7963a56",
        "SubAnalysesIDs": [
            "2bf5baa9-6964-4171-b060-5e3d8de8741f"
        ]
    }
}
```

#### Human Readable Output

```
Sub Analyses -
[
...
List of analyses ids
...
]
```

### intezer-get-family-info

***
Get family information from Intezer Analyze

#### Base Command

`intezer-get-family-info`

#### Input

| **Argument Name** | **Description** | **Required** |
|-------------------|-----------------|--------------|
| family_id         | The Family ID.  | Required     | 

#### Context Output

| **Path**            | **Type** | **Description**                      |
|---------------------|----------|--------------------------------------|
| Intezer.Family.ID   | string   | Family id in intezer genome database | 
| Intezer.Family.Name | string   | Family name                          | 
| Intezer.Family.Type | string   | Family Type                          | 

#### Command Example

``` 
intezer-get-family-info family_id=006c54ba-3159-43a0-98a0-1c5032145f47
```

#### Context Example

```
{
    "Intezer.Family": {
        "ID": "e710e4b3-3dd1-40ff-be74-9d8a95466ae4", 
        "Type": "malware", 
        "Name": "CobaltStrike"
    }
}
```

#### Human Readable Output

```
Family Info
---

FamilyId    006c54ba-3159-43a0-98a0-1c5032145f47
FamilyName  Some Family Name
FamilyType  Malware
```

### intezer-get-analysis-code-reuse

***
Get All code reuse report for an analysis or sub analysis
To get the code reuse results of a sub analysis you also must specify the "parent analysis",

For example - If you ran the command `intezer-get-sub-analyses analysis_id=123`
and got the sub analysis `456`, you need to specify both in the command

#### Base Command

`intezer-get-analysis-code-reuse`

#### Input

| **Argument Name** | **Description**                                                                                               | **Required** |
|-------------------|---------------------------------------------------------------------------------------------------------------|--------------|
| analysis_id       | The analysis ID (parent analysis in case we're trying to get sub abalysis) we want to get the code reuse for. | Required     | 
| sub_analysis_id   | The Sub Analysis we want to get the code reuse for.                                                           | Optional     | 

#### Context Output

| **Path**                                       | **Type** | **Description**                                  |
|------------------------------------------------|----------|--------------------------------------------------|
| Intezer.Analysis.ID                            | string   | The composed analysis ID                         |
| Intezer.Analysis.CodeReuse                     | Unknown  | General Code Reuse of the analysis               | 
| Intezer.Analysis.CodeReuseFamilies             | Unknown  | List of the families appearing in the code reuse | 
| Intezer.Analysis.SubAnalyses.CodeReuse         | Unknown  | General Code Reuse of the analysis               | 
| Intezer.Analysis.SubAnalyses.CodeReuseFamilies | Unknown  | List of the families appearing in the code reuse | 
| Intezer.Analysis.SubAnalyses.RootAnalysis      | string   | The Composed analysis id                         | 

#### Command Example

``` 
# Get the code reuse of an analysis
intezer-get-analysis-code-reuse analysis_id=<Root analysis>

# Get the root analysis sub analyses
intezer-get-sub-analyses analysis_id=<Root analysis>

# Use one of the results to get the sub analysis code reuse
intezer-get-analysis-code-reuse analysis_id=<Root analysis> sub_analysis_id=<Sub Analysis Id>
```

#### Context Example

```
{
    "Intezer.Analysis": {
        "Status": "Done", 
        "type": "File", 
        "ID": "675515a1-62e9-4d55-880c-fd46a7963a56",
        "SubAnalyses": [
            {
                "ID": "Some sub analysis id",
                "RootAnalysis": "675515a1-62e9-4d55-880c-fd46a7963a56",
                "CodeReuse": {
                    "common_gene_count": 10,
                    "gene_count": 100,
                    "gene_type": "native_windows",
                    "unique_gene_count": 50
                },
                "CodeReuseFamilies": [
                    {
                        "family_id": "5be245ca-793c-4991-9329-c42d6365a530",
                        "family_name": "Microsoft Corporation",
                        "family_type": "application",
                        "reused_gene_count": 8
                    }
                ]
            }
        ]
    }
}
```

#### Human Readable Output

This will show information about the analysis code reuse and families

```
Code Reuse
---
common_gene_count   544
gene_count          543
gene_type           native_windows
unique_gene_count   0

Families:
---

WannaCry
family_id	        0b13c0d4-7779-4c06-98fa-4d33ca98f8a9
family_name	        WannaCry
family_type	        malware
reused_gene_count	362

Lazarus
family_id	        7ae9c0f1-5e81-4ed1-928d-d966a1b1525c
family_name	        Lazarus
family_type	        malware
reused_gene_count	33

... More Families if available
```

### intezer-get-analysis-metadata

***
Get metadata for an analysis or sub analysis
To get the metadata of a sub analysis you also must specify the "parent analysis",

For example - If you ran the command `intezer-get-sub-analyses analysis_id=123`
and got the sub analysis `456`, you need to specify both in the command

#### Base Command

`intezer-get-analysis-metadata`

#### Input

| **Argument Name** | **Description**                                   | **Required** |
|-------------------|---------------------------------------------------|--------------|
| analysis_id       | The analysis ID we want to get the metadata for.  | Required     | 
| sub_analysis_id   | The Sub Analysis we want to get the metadata for. | Optional     | 

#### Context Output

| **Path**                              | **Type** | **Description**           |
|---------------------------------------|----------|---------------------------|
| Intezer.Analysis.ID                   | string   | The composed analysis ID  | 
| Intezer.Analysis.Metadata             | Unknown  | The Analysis metadata     | 
| Intezer.Analysis.SubAnalyses.Metadata | Unknown  | The Sub Analysis metadata | 

#### Command Example

``` 
# Get the metadata of an analysis
intezer-get-analysis-metadata analysis_id=<Root analysis>

# Get the root analysis sub analyses
intezer-get-sub-analyses analysis_id=<Root analysis>

# Use one of the results to get the sub analysis code reuse
intezer-get-analysis-metadata analysis_id=<Root analysis> sub_analysis_id=<Sub Analysis Id>
```

#### Context Example

```
{
    "Intezer.Analysis": {
        "Status": "Done", 
        "type": "File", 
        "ID": "675515a1-62e9-4d55-880c-fd46a7963a56",
        "SubAnalyses": [
            {
                "ID": "some sub analyses id",
                "RootAnalysis": "675515a1-62e9-4d55-880c-fd46a7963a56",
                "Metadata": {
                    "sha1": "<sha1>",
                    "sha256": "<sha256>",
                    "md5": "<md5>",
                    "product": "product name",
                    "product_version": "5.4",
                    "ssdeep": "<ssdeep>",
                    "size_in_bytes": 15540,
                    "architecture": "i386",
                    "original_filename": "myfile.exe",
                    "compilation_timestamp": "2019:07:26 18:23:19+00:00",
                    "file_type": "pe",
                    "company": "Microsoft"
                }
            }
        ]
    }
}
```

#### Human Readable Output

```
Analysis Metadata
---

architecture	        i386
company	                Microsoft Corporation
compilation_timestamp	2009:07:13 23:19:35+00:00
file_type	        pe
md5	                md5
original_filename	LODCTR.EXE
product	                Microsoft® Windows® Operating System
product_version	        6.1.7600.16385 ^^^
sha1	                sha1
sha256	                sha256
size_in_bytes	        245760
ssdeep	                ssdeep
```

### intezer-get-analysis-iocs

***
Gets the list of network and files IOCs of a specific analysis id.

#### Base Command

`intezer-get-analysis-iocs`

#### Input

| **Argument Name** | **Description**                              | **Required** |
|-------------------|----------------------------------------------|--------------|
| analysis_id       | The analysis ID we want to get the IOCs for. | Required     | 

#### Context Output

| **Path**              | **Type** | **Description**          |
|-----------------------|----------|--------------------------|
| Intezer.Analysis.ID   | string   | The composed analysis ID | 
| Intezer.Analysis.IOCs | Dict     | The Analysis IOCs        | 

#### Context Example

```json
{
    "Intezer.Analysis": {
        "Status": "Done",
        "type": "File",
        "ID": "675515a1-62e9-4d55-880c-fd46a7963a56",
        "IOCs": {
            "files": [
                {
                    "path": "test_file_1.csv",
                    "sha256": "eeb1199f7db006e4d20086171cc312cf5bdf53682cc37997223ad0c15a27dc88",
                    "verdict": "malicious",
                    "family": "Turla",
                    "type": "Main file"
                }
            ],
            "network": [
                {
                    "ioc": "1.1.1.1",
                    "source": [
                        "Network communication"
                    ],
                    "type": "ip"
                },
                {
                    "ioc": "raw.exampledomain.com",
                    "source": [
                        "Network communication"
                    ],
                    "type": "domain"
                }
            ]
        }
    }
}
```

#### Human Readable Output

```markdown
### Network IOCs

| ioc                   | source                | type   |
|-----------------------|-----------------------|--------|
| 1.1.1.1.1             | Network communication | ip     |
| raw.exampledomain.com | Network communication | domain |

### Files IOCs

| family  | path             | sha256                                                           | type           | verdict   |
|---------|------------------|------------------------------------------------------------------|----------------|-----------|
| Turla   | test_file_1.csv  | eeb1199f7db006e4d20086171cc312cf5bdf53682cc37997223ad0c15a27dc88 | Main file      | malicious |
```

### intezer-submit-alert

***
Submit a new alert, including the raw alert information, to Intezer for processing.

#### Base Command

`intezer-submit-alert`

#### Input

| **Argument Name** | **Description**                            | **Required** |
|-------------------|--------------------------------------------|--------------|
| raw_alert         | The raw alert as it stored in the context. | Required     | 
| mapping           | The mapping for the raw alert data.        | Required     | 
| source            | The source of the alert.                   | Required     | 

#### Context Output

| **Path**             | **Type** | **Description**         |
|----------------------|----------|-------------------------|
| Intezer.Alert.ID     | string   | The Alert ID            | 
| Intezer.Alert.Status | string   | The status of the Alert | 

#### Context Example

```json
{
    "Intezer.Alert": {
        "Status": "Done",
        "ID": "675515a1-62e9-4d55-880c-fd46a7963a56"
    }
}
```

### intezer-submit-suspected-phishing-email

***
Submit a suspicious phishing email in a raw format (.MSG or .EML) to Intezer for processing.

#### Base Command

`intezer-submit-suspected-phishing-email`

#### Input

| **Argument Name**   | **Description**                    | **Required** |
|---------------------|------------------------------------|--------------|
| email_file_entry_id | The email file entry id to upload. | Required     |

#### Context Output

| **Path**             | **Type** | **Description**         |
|----------------------|----------|-------------------------|
| Intezer.Alert.ID     | string   | The Alert ID            | 
| Intezer.Alert.Status | string   | The status of the Alert | 

#### Context Example

```json
{
    "Intezer.Alert": {
        "Status": "Done",
        "ID": "675515a1-62e9-4d55-880c-fd46a7963a56"
    }
}
```

### intezer-get-alert-result

***
Get an ingested alert triage and response information using alert ID.

#### Base Command

`intezer-get-alert-result`

#### Input

| **Argument Name** | **Description**                          | **Required** |
|-------------------|------------------------------------------|--------------|
| alert_id          | The alert id to query.                   | Required     | 
| wait_for_result   | Waits for alert result, support polling. | Optional     | 

#### Context Output

| **Path**                                                       | **Type** | **Description**                                |
|----------------------------------------------------------------|----------|------------------------------------------------|
| Intezer.Alert.ID                                               | string   | The Alert ID                                   | 
| Intezer.Alert.Status                                           | string   | The Alert status                               | 
| Intezer.Alert.Result                                           | Object   | The full report of the alert                   | 
| Intezer.Alert.Result.intezer_alert_url                         | Object   | The url for the alert result on Intezer Analyze | 
| DBotScore.Indicator                                            | string   | The indicator we tested                        | 
| DBotScore.Type                                                 | string   | The type of the indicator                      | 
| DBotScore.Vendor                                               | string   | Vendor used to calculate the score             | 
| DBotScore.Score                                                | string   | The actual score                               |
| File.SHA256                                                    | string   | Hash SHA256                                    |
| File.SHA1                                                      | string   | Hash SHA1                                      | 
| File.MD5                                                       | string   | Hash MD5                                       |
| URL.Data                                                       | string   | The tested URL                                 | 
| URL.Malicious.Vendor                                           | string   | For malicious URL, the vendor that made the decision | 
| URL.Relationships                                              | object   | The relationships between two urls             |
| Intezer.Alert.Result.raw_alert                                 | object   | The raw alert as submitted to Intezer          |
| Intezer.Alert.Result.triage_result.alert_verdict_display       | string   | The verdict of the alert                       |
| Intezer.Alert.Result.source_display                            | string   | The calculated verdict of the Alert            |
| Intezer.Alert.Result.triage_result.risk_category_display       | string   | The risk category of the Alert                 |
| Intezer.Alert.Result.response.user_recommended_actions_display  | string   | The actions recommended by Intezer to be taken |

#### Command Example

``` 
# Get an alert result
intezer-get-alert-result alert_id=<Alert ID> wait_for_result=true
```

#### Context Example

```
{
    "Intezer.Analysis": {
        "Status": "Done", 
        "ID": "675515a1-62e9-4d55-880c-fd46a7963a56",
        "DBotScore": {
            "Vendor": "Intezer", 
            "Indicator": "<some sha>>", 
            "Score": 0, 
            "Type": "file/url/domain/ip/endpoint"
            },
        "Result": {
            "alert": {'alert_id': '111223', 'alert_title': '111223', 'alert_url': None, 'creation_time': '2023-07-24T12:26:06',
               'creation_time_display': '24 Jul 23 | 12:26 UTC', 'device': {}, 'severity': 'high',
               'severity_display': 'High'},
            'alert_id': '111223',
            'alert_sub_types': ['custom'],
            'intezer_alert_url': 'https://analyze.intezer.com/alerts/111223',
            'raw_alert': {},
            'response': {'automated_response_actions': [],
                          'iocs': {'files': [
                              {'family': None,
                               'path': 'some_path.sample',
                               'sha256': '<hash>',
                               'type': 'main_file',
                               'verdict': 'malicious'}
                          ],
                              'network': [
                                  {'ioc': '101.111.222.333', 'source': ['Network communication'],
                                   'type': 'ip'},
                              ]},
                          'status': 'escalated', 'status_display': 'Escalated',
                          'user_recommended_actions': [],
                          'user_recommended_actions_display': ''},
            'scans': [{'collection_status': 'collected', 'file_analysis': {
                'analysis_id': '<some_analysis_id>', 'analysis_time': '2023-07-24T11:00:28',
                'analysis_url': 'https://analyze.intezer.com/analyses/<some_analysis_id>',
                'file_name': 'file_name.sample',
                'iocs': {'files': [
                    {'family': None, 'path': 'some_path.sample',
                     'sha256': '<hash_of_file>', 'type': 'main_file',
                     'verdict': 'malicious'}],
                    'network': [
                        {'ioc': 'https://3-4.oss-c.malicious.domain.com/md.exe', 'source': ['Network communication'],
                         'type': 'url'}]}, 'sha256': '<hash>',
                'sub_verdict': 'known_malicious', 'ttps': [
                    {'tactic': 'Command And Control', 'tactic_id': 'TA0011', 'technique': 'Encrypted Channel',
                     'technique_id': 'T1573'}], 'sender': 'cs', 'source': 'cs',
                'source_display': 'CrowdStrike',
                'triage_result': {'alert_verdict': 'confirmed_threat', 'alert_verdict_display': 'Confirmed Threat',
                                  'risk_category': 'generic_threat', 'risk_category_display': 'Generic Threat',
                                  'risk_level': 'high',
                                  'risk_score': 20, 'ttps': [
                        {'source': 'analysis', 'tactic': 'Command And Control', 'tactic_id': 'TA0011',
                         'technique': 'Encrypted Channel', 'technique_id': 'T1573'},
                        {'source': 'analysis', 'tactic': 'Execution', 'tactic_id': 'TA0002', 'technique': 'Shared Modules',
                         'technique_id': 'T1129'}]
                                  }}}]
            }
        ]
    }
}
```

#### Human Readable Output

```markdown
### Intezer Alert Result

Verdict: Confirmed Threat
Risk category: Generic Threat
Alert Link: https://analyze.intezer.com/alerts/111223
```