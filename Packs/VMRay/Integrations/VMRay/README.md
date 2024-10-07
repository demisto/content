# VMRay XSOAR Integration

This integration enables users to design playbooks that involve analyzing a file in VMRay and retrieving the analysis results and associated threat intelligence.


The Playbooks accelerate incident response and make security operations more scalable and efficient.

## Configure VMRay in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Source Reliability | Reliability of the source providing the intelligence data. | False |
| Server URL (e.g., <https://cloud.vmray.com>) |  | True |
| API Key (Recommended) |  | False |
| Use system proxy settings |  | False |
| Trust any certificate (not secure) |  | False |
| Retry requests when API is rate limited |  | False |
| API Key (Deprecated) | Use the "API Key \(Recommended\)" parameter instead. | False |


## Known Limitations

- Non-ASCII characters in file names will be ignored when uploading.


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

- [vmray-upload-sample](#vmray-upload-sample): Submit a sample for analysis
- [vmray-upload-url](#vmray-upload-url): Submit a URL for analysis
- [vmray-get-analysis-by-sample](#vmray-get-analysis-by-sample): Get analysis details for a sample
- [vmray-get-job-by-sample](#vmray-get-job-by-sample): Get job details for a sample
- [vmray-get-submission](#vmray-get-submission): Get submission results
- [vmray-get-sample](#vmray-get-sample): Get information for a sample
- [vmray-get-sample-by-hash](#vmray-get-sample-by-hash): Get information for a sample by hash
- [vmray-get-threat-indicators](#vmray-get-threat-indicators): Get threat indicators
- [vmray-add-tag](#vmray-add-tag): Add a tag to an analysis or submission
- [vmray-delete-tag](#vmray-delete-tag): Delete a tag from an analysis or submission
- [vmray-get-iocs](#vmray-get-iocs): Get IOCs for a sample
- [vmray-get-job-by-id](#vmray-get-job-by-id): Get information for a job
- [vmray-get-summary](#vmray-get-summary): Download Summary JSON v2 for an analysis
- [vmray-get-license-usage-verdicts](#vmray-get-license-usage-verdicts): Get the used quota of verdicts
- [vmray-get-license-usage-reports](#vmray-get-license-usage-reports): Get the used quota of reports


### vmray-upload-sample

***
Submits a sample to VMRay for analysis.

#### Base Command

`vmray-upload-sample`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entry_id | Entry ID of the file to submit. | Required | 
| document_password | Password of the document. | Optional | 
| archive_password | Password of an archive. | Optional | 
| sample_type | Force type of the file. | Optional | 
| shareable | Whether the file is shareable. Possible values are: true, false. | Optional | 
| max_jobs | Maximum number of jobs to create (number). Default is 1. | Optional | 
| tags | A CSV list of tags to add to the sample. | Optional | 
| reanalyze | Deprecated. Analyze even if analyses already exist. To control analysis caching, use the API Key settings instead, which are available via the Analysis Settings page, in the VMRay Web Interface. Possible values are: true, false. | Optional | 
| net_scheme_name | The network scheme to use. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMRay.Job.JobID | Number | ID of a new job | 
| VMRay.Job.Created | Date | Timestamp of job creation. | 
| VMRay.Job.SampleID | Number | ID of the sample. | 
| VMRay.Job.VMName | String | Name of the virtual machine. | 
| VMRay.Job.VMID | Number | ID of the virtual machine. | 
| VMRay.Sample.SampleID | Number | ID of the sample. | 
| VMRay.Sample.SampleURL | String | URL to sample page. | 
| VMRay.Sample.Created | Date | Timestamp of sample creation. | 
| VMRay.Submission.SubmissionID | Number | Submission ID. | 
| VMRay.Submission.SubmissionURL | String | URL to submission page. | 


#### Command Example

```
vmray-upload-sample entry_id=79@4 max_jobs=1
```

#### Context Example

```json
{
    "VMRay.Sample": [
        {
            "SHA1": "69df095557346b3c136db4378afd5ee7a4839dcc",
            "Created": "2019-05-27T07:48:11",
            "SampleID": 3902285,
            "SampleURL": "https://cloud.vmray.com/user/sample/view?id=3902285",
            "FileName": "KeePass-2.41-Setup.exe",
            "FileSize": 3301376,
            "SSDeep": "98304:rk/6KPcsSO9iShSf0UTsj+te5NrYWM+40n3vGJyc:rkCK0UhSfHsKw5z4OvGJL"
        }
    ],
    "VMRay.Submission": [
        {
            "SampleID": 3902285,
            "SubmissionID": 4569315,
            "SubmissionURL": "https://cloud.vmray.com/user/sample/view?id=3902285"
        }
    ],
    "VMRay.Job": [
        {
            "Created": "2019-05-27T07:48:11",
            "JobRuleSampleType": "Windows PE (x86)",
            "VMID": 20,
            "SampleID": 3902285,
            "JobID": 3908304,
            "VMName": "win10_64_th2"
        }
    ]
}
```

#### Human Readable Output

**File submitted to VMRay**

| **Jobs ID** | **Samples ID** | **Submissions ID** | **Sample URL** |
| --- | --- | --- | --- |
| 3908304 | 3902285 | 4569315 | <https://cloud.vmray.com/user/sample/view?id=3902285> |

### vmray-upload-url

***
Submits a URL for analysis.

#### Base Command

`vmray-upload-url`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url |  The URL to analyze. For example: <https://demisto.com>. . | Required | 
| shareable | Whether the analysis is shareable. Possible values are: true, false. | Optional | 
| max_jobs | Maximum number of jobs to create (number). Default is 1. | Optional | 
| tags | A CSV list of tags to add to the sample. | Optional |
| net_scheme_name | The network scheme to use. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMRay.Job.JobID | Number | ID of a new job | 
| VMRay.Job.Created | Date | Timestamp of job creation. | 
| VMRay.Job.SampleID | Number | ID of the sample. | 
| VMRay.Job.VMName | String | Name of the virtual machine. | 
| VMRay.Job.VMID | Number | ID of the virtual machine. | 
| VMRay.Sample.SampleID | Number | ID of the sample. | 
| VMRay.Sample.SampleURL | String | URL to sample page. | 
| VMRay.Sample.Created | Date | Timestamp of sample creation. | 
| VMRay.Submission.SubmissionID | Number | Submission ID. | 
| VMRay.Submission.SubmissionURL | String | URL to submission page. | 


#### Command Example

```json
{
    "VMRay.Sample": [
        {
            "SHA1": "884a2738124be5dae95e685fb8c919b1460734c5",
            "Created": "2019-05-27T07:48:11",
            "SampleID": 3902285,
            "SampleURL": "https://cloud.vmray.com/user/sample/view?id=3902285",
            "FileName": "https://demisto.com",
            "FileSize": 20,
            "SSDeep": "3:N8W2K:2W2K"
        }
    ],
    "VMRay.Submission": [
        {
            "SampleID": 3902285,
            "SubmissionID": 4569315,
            "SubmissionURL": "https://cloud.vmray.com/user/sample/view?id=3902285"
        }
    ],
    "VMRay.Job": [
        {
            "Created": "2019-05-27T07:48:11",
            "JobRuleSampleType": "Windows PE (x86)",
            "VMID": 20,
            "SampleID": 3902285,
            "JobID": 3908304,
            "VMName": "win10_64_th2"
        }
    ]
}
```

#### Human Readable Output

**URL submitted to VMRay**

| **Jobs ID** | **Samples ID** | **Submissions ID** |
| --- | --- | --- |
| 3908304 | 3902285 | 4569315 |

### vmray-get-analysis-by-sample

***
Retrieves all analysis details for a specified sample.

#### Base Command

`vmray-get-analysis-by-sample`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sample_id | Sample ID. | Required | 
| limit | Maximum number of results to return (number). | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMRay.Analysis.AnalysisID | Number | Analysis ID. | 
| VMRay.Analysis.AnalysisURL | String | URL to analysis page. | 
| VMRay.Analysis.SampleID | Number | Sample ID in the analysis. | 
| VMRay.Analysis.Verdict | String | Verdict for the sample \(Malicious, Suspicious, Clean, Not Available\). | 
| VMRay.Analysis.VerdictReason | String | Description of the Verdict Reason. | 
| VMRay.Analysis.Severity | String | Severity of the sample in the submission \(Malicious, Suspicious, Good, Blacklisted, Whitelisted, Unknown\). Deprecated. | 
| VMRay.Analysis.JobCreated | Date | Date when the analysis job started. | 
| VMRay.Analysis.MD5 | String | MD5 hash of the sample. | 
| VMRay.Analysis.SHA1 | String | SHA1 hash of the sample. | 
| VMRay.Analysis.SHA256 | String | SHA256 hash of the sample. | 
| VMRay.Analysis.SSDeep | String | ssdeep hash of the sample. | 

#### Command Example

```
!vmray-get-analysis-by-sample sample_id=3902238
```

#### Context Example

```json
{
    "VMRay.Analysis": [
        {
            "SampleID": 3902238,
            "SampleURL": "https://cloud.vmray.com/user/sample/view?id=3902238",
            "SHA1": "868a53c394f29f8d3aac7b0a20a371999045b6ed",
            "SHA256": "b8a4b647e56cb71773d0086b51906b902a7ccafe699f4068da4cb5cd234d9d66",
            "JobCreated": "2021-06-14T12:17:07",
            "AnalysisID": 2779353,
            "Verdict": "Suspicious",
            "VerdictReason": null,
            "Severity": "Suspicious",
            "MD5": "2e0499dc90c2d715a53e05b1890e0442"
        }
    ]
}
```

#### Human Readable Output

**Analysis results from VMRay for ID 3902238:**

| **AnalysisID** | **SampleID** | **Verdict** | **AnalysisURL** |
| --- | --- | --- | --- |
| 2779353 | 3902238 | Suspicious | <https://cloud.vmray.com/user/sample/view?id=3902238>

### vmray-get-job-by-sample

***
Retrieves details for all jobs  for a specified sample.

#### Base Command

`vmray-get-job-by-sample`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sample_id | Sample ID. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMRay.Job.JobID | Number | ID of the job. | 
| VMRay.Job.SampleID | Number | Sample ID of the job. | 
| VMRay.Job.SubmissionID | Number | ID of the submission. | 
| VMRay.Job.MD5 | String | MD5 hash of the sample in the job. | 
| VMRay.Job.SHA1 | String | SHA1 hash of the sample in the job. | 
| VMRay.Job.SHA256 | String | SHA256 hash of the sample in the job. | 
| VMRay.Job.SSDeep | String | ssdeep hash of the sample in the job. | 
| VMRay.Job.VMName | String | Name of the virtual machine. | 
| VMRay.Job.VMID | Number | ID of the virtual machine. | 
| VMRay.Job.Status | String | Status of the job.  | 

#### Command Example

```
!vmray-get-job-by-sample sample_id=3902238
```

#### Context Example

```json
{
    "VMRay.Job": [
        {
            "VMName": "win7_32_sp1",
            "SampleID": 3902238,
            "SHA1": "868a53c394f29f8d3aac7b0a20a371999045b6ed",
            "SubmissionID": 18950,
            "SHA256": "b8a4b647e56cb71773d0086b51906b902a7ccafe699f4068da4cb5cd234d9d66",
            "SSDeep": "1536:Hg8ktOZtz+PZvpJyrOM1GhFNkYL2BxNRjWW:H/kY0Z3yrOMGTkrNRjH",
            "Status": "inwork",
            "VMID": 3,
            "JobID": 29208,
            "MD5": "2e0499dc90c2d715a53e05b1890e0442"
        }
    ]
}
```

#### Human Readable Output

**Job results for sample id: 3902238**

| **JobID** | **SampleID** | **VMName** | **VMID** |
| --- | --- | --- | --- |
| 29208 | 3902238 | win7_32_sp1 | 3 |

### vmray-get-submission

***
Retrieves the results of a submission.

#### Base Command

`vmray-get-submission`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| submission_id | ID of the submission. Can be obtained by running the 'vmray-upload-sample' or 'vmray-upload-url' command. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMRay.Submission.IsFinished | Boolean | Whether the submission is finished \(true or false\). | 
| VMRay.Submission.HasErrors | Boolean | Whether there are any errors in the submission \(true or false\). | 
| VMRay.Submission.SubmissionID | Number | ID of the sample in the submission. | 
| VMRay.Submission.SubmissionURL | String | URL of submission page. | 
| VMRay.Submission.MD5 | String | MD5 hash of the sample in the submission. | 
| VMRay.Submission.SHA1 | String | SHA1 hash of the sample in the submission. | 
| VMRay.Submission.SHA256 | String | SHA256 hash of the sample in the submission. | 
| VMRay.Submission.SSDeep | String | ssdeep hash of the sample in the submission. | 
| VMRay.Submission.Verdict | String | Verdict for the sample \(Malicious, Suspicious, Clean, Not Available\). | 
| VMRay.Submission.VerdictReason | String | Description of the Verdict Reason. | 
| VMRay.Submission.Severity | String | Severity of the sample in the submission \(Malicious, Suspicious, Good, Blacklisted, Whitelisted, Unknown\). Deprecated. | 
| VMRay.Submission.SampleID | Number | ID of the sample in the submission. | 

#### Command Example

```
vmray-get-submission submission_id=4569262
```

#### Context Example

```json
{
    "DBotScore": [
        {
            "Indicator": "2e0499dc90c2d715a53e05b1890e0442",
            "Score": 3,
            "Type": "hash",
            "Vendor": "VMRay"
        },
        {
            "Indicator": "b8a4b647e56cb71773d0086b51906b902a7ccafe699f4068da4cb5cd234d9d66",
            "Score": 3,
            "Type": "hash",
            "Vendor": "VMRay"
        },
        {
            "Indicator": "868a53c394f29f8d3aac7b0a20a371999045b6ed",
            "Score": 3,
            "Type": "hash",
            "Vendor": "VMRay"
        },
        {
            "Indicator": "1536:Hg8ktOZtz+PZvpJyrOM1GhFNkYL2BxNRjWW:H/kY0Z3yrOMGTkrNRjH",
            "Score": 3,
            "Type": "hash",
            "Vendor": "VMRay"
        }
    ],
    "VMRay.Submission": {
        "SampleID": 3902238,
        "SHA1": "868a53c394f29f8d3aac7b0a20a371999045b6ed",
        "HasErrors": true,
        "SubmissionID": 4569262,
        "SubmissionURL": "https://cloud.vmray.com/user/sample/view?id=3902238",
        "SHA256": "b8a4b647e56cb71773d0086b51906b902a7ccafe699f4068da4cb5cd234d9d66",
        "SSDeep": "1536:Hg8ktOZtz+PZvpJyrOM1GhFNkYL2BxNRjWW:H/kY0Z3yrOMGTkrNRjH",
        "Verdict": "Malicious",
        "IsFinished": true,
        "VerdictReason": null,
        "Severity": "Malicious",
        "MD5": "2e0499dc90c2d715a53e05b1890e0442"
    }
}
```

#### Human Readable Output

**Submission results from VMRay for ID 3902238 with verdict of Malicious**

| Attribute | Value |
| --- | --- |
| **IsFinished** | true |
| **Verdict** | Malicious |
| **HasErrors** | true |
| **MD5** | 2e0499dc90c2d715a53e05b1890e0442 |
| **SHA1** | 868a53c394f29f8d3aac7b0a20a371999045b6ed |
| **SHA256** | b8a4b647e56cb71773d0086b51906b902a7ccafe699f4068da4cb5cd234d9d66 |
| **SSDeep** | 1536:Hg8ktOZtz+PZvpJyrOM1GhFNkYL2BxNRjWW:H/kY0Z3yrOMGTkrNRjH |
| **SubmissionURL** | <https://cloud.vmray.com/user/sample/view?id=3902238> |

### vmray-get-sample

***
Retrieves a sample using the sample ID.

#### Base Command

`vmray-get-sample`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sample_id | ID of the sample. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMRay.Sample.SampleID | Number | ID of the sample. | 
| VMRay.Sample.SampleURL | String | URL to sample page. | 
| VMRay.Sample.FileName | String | File name of the sample. | 
| VMRay.Sample.MD5 | String | MD5 hash of the sample. | 
| VMRay.Sample.SHA1 | String | SHA1 hash of the sample. | 
| VMRay.Sample.SHA256 | String | SHA256 hash of the sample. | 
| VMRay.Sample.SSDeep | String | ssdeep hash of the sample. | 
| VMRay.Sample.Verdict | String | Verdict for the sample \(Malicious, Suspicious, Clean, Not Available\). | 
| VMRay.Sample.VerdictReason | String | Description of the Verdict Reason. | 
| VMRay.Sample.Severity | String | Severity of the sample in the submission \(Malicious, Suspicious, Good, Blacklisted, Whitelisted, Unknown\). Deprecated. | 
| VMRay.Sample.Type | String | File type. | 
| VMRay.Sample.Created | Date | Timestamp of sample creation. | 
| VMRay.Sample.Classifications | String | Classifications of the sample. | 
| VMRay.Sample.ChildSampleIDs | Number | List of child sample IDs. | 
| VMRay.Sample.ParentSampleIDs | Number | List of parent sample IDs. | 

#### Command Example

```
!vmray-get-sample sample_id=3902238
```

#### Context Example

```json
{
    "DBotScore": [
        {
            "Indicator": "2e0499dc90c2d715a53e05b1890e0442",
            "Score": 3,
            "Type": "hash",
            "Vendor": "VMRay"
        },
        {
            "Indicator": "b8a4b647e56cb71773d0086b51906b902a7ccafe699f4068da4cb5cd234d9d66",
            "Score": 3,
            "Type": "hash",
            "Vendor": "VMRay"
        },
        {
            "Indicator": "868a53c394f29f8d3aac7b0a20a371999045b6ed",
            "Score": 3,
            "Type": "hash",
            "Vendor": "VMRay"
        },
        {
            "Indicator": "1536:Hg8ktOZtz+PZvpJyrOM1GhFNkYL2BxNRjWW:H/kY0Z3yrOMGTkrNRjH",
            "Score": 3,
            "Type": "hash",
            "Vendor": "VMRay"
        }
    ],
    "VMRay.Sample": {
        "SampleID": 3902238,
        "SampleURL": "https://cloud.vmray.com/user/sample/view?id=3902238",
        "SHA1": "868a53c394f29f8d3aac7b0a20a371999045b6ed",
        "Classification": [],
        "SHA256": "b8a4b647e56cb71773d0086b51906b902a7ccafe699f4068da4cb5cd234d9d66",
        "FileName": "pafish.exe",
        "Created": "2018-03-20T15:06:49",
        "SSDeep": "1536:Hg8ktOZtz+PZvpJyrOM1GhFNkYL2BxNRjWW:H/kY0Z3yrOMGTkrNRjH",
        "Verdict": "Malicious",
        "Type": "Windows Exe (x86-32)",
        "VerdictReason": null,
        "Severity": "Malicious",
        "MD5": "2e0499dc90c2d715a53e05b1890e0442",
        "ChildSampleIDs": [20, 21, 22],
        "ParentSampleIDs": [18]
    }
}
```

#### Human Readable Output

**Results for sample id: 3902238 with verdict Malicious**

| Attribute | Value |
| --- | --- |
| **FileName** | pafish.exe |
| **Type** | Windows Exe (x86-32) |
| **MD5** | 2e0499dc90c2d715a53e05b1890e0442 |
| **SHA1** | 868a53c394f29f8d3aac7b0a20a371999045b6ed |
| **SHA256** | b8a4b647e56cb71773d0086b51906b902a7ccafe699f4068da4cb5cd234d9d66 |
| **SSDeep** | 1536:Hg8ktOZtz+PZvpJyrOM1GhFNkYL2BxNRjWW:H/kY0Z3yrOMGTkrNRjH |
| **SampleURL** | <https://cloud.vmray.com/user/sample/view?id=3902238> |

### vmray-get-sample-by-hash

***
Retrieves sample information by hash.

#### Base Command

`vmray-get-sample-by-hash`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hash | MD5, SHA1 or SHA256 hash of the sample. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.Name | String | The full file name \(including file extension\). | 
| File.MD5 | String | The MD5 hash of the file. | 
| File.SHA1 | String | The SHA1 hash of the file. | 
| File.SHA256 | String | The SHA256 hash of the file. | 
| File.SSDeep | String | The SSDeep hash of the file. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. | 
| VMRay.Sample.SampleID | Number | ID of the sample. | 
| VMRay.Sample.SampleURL | String | URL to sample page. | 
| VMRay.Sample.FileName | String | File name of the sample. | 
| VMRay.Sample.MD5 | String | MD5 hash of the sample. | 
| VMRay.Sample.SHA1 | String | SHA1 hash of the sample. | 
| VMRay.Sample.SHA256 | String | SHA256 hash of the sample. | 
| VMRay.Sample.SSDeep | String | ssdeep hash of the sample. | 
| VMRay.Sample.Verdict | String | Verdict for the sample \(Malicious, Suspicious, Clean, Not Available\). | 
| VMRay.Sample.VerdictReason | String | Description of the Verdict Reason. | 
| VMRay.Sample.Severity | String | Severity of the sample in the submission \(Malicious, Suspicious, Good, Blacklisted, Whitelisted, Unknown\). Deprecated. | 
| VMRay.Sample.Type | String | File type. | 
| VMRay.Sample.Created | Date | Timestamp of sample creation. | 
| VMRay.Sample.Classifications | String | Classifications of the sample. | 
| VMRay.Sample.ChildSampleIDs | Number | List of child sample IDs. | 
| VMRay.Sample.ParentSampleIDs | Number | List of parent sample IDs. | 

#### Command Example

```
!vmray-get-sample-by-hash hash=124f46228d1e220d88ae5e9a24d6e713039a64f9
```

#### Context Example

```json
{
    "DBotScore": [
        {
        "Indicator": "9159edb64c4a21d8888d088bf2db23f3",
        "Score": 3,
        "Type": "hash",
        "Vendor": "VMRay"
        },
        {
            "Indicator": "2180f4a13add5e346e8cf6994876a9d2f5eac3fcb695db8569537010d24cd6d5",
            "Score": 3,
            "Type": "hash",
            "Vendor": "VMRay"
        },
        {
            "Indicator": "124f46228d1e220d88ae5e9a24d6e713039a64f9",
            "Score": 3,
            "Type": "hash",
            "Vendor": "VMRay"
        },
        {
            "Indicator": "1536:tI05L48IVDAQVzZpJyrOM1GhFNkYL2BxNRj:tI05LBIDAuztyrOMGTkrNRj",
            "Score": 3,
            "Type": "hash",
            "Vendor": "VMRay"
        }
    ],
    "VMRay.Sample": [
        {
            "ParentSampleIDs": [],
            "SampleID": 6822,
            "SHA1": "124f46228d1e220d88ae5e9a24d6e713039a64f9",
            "SampleURL": "https://cloud.vmray.com/user/sample/view?id=6822",
            "Classification": [],
            "SHA256": "2180f4a13add5e346e8cf6994876a9d2f5eac3fcb695db8569537010d24cd6d5",
            "FileName": "pafish.exe",
            "Created": "2021-06-24T15:06:04",
            "SSDeep": "1536:tI05L48IVDAQVzZpJyrOM1GhFNkYL2BxNRj:tI05LBIDAuztyrOMGTkrNRj",
            "ChildSampleIDs": [],
            "Verdict": "Malicious",
            "Type": "Windows Exe (x86-32)",
            "VerdictReason": null,
            "Severity": "Malicious",
            "MD5": "9159edb64c4a21d8888d088bf2db23f3"
        }
    ]
}
```

#### Human Readable Output

**Results for sha1 hash 124f46228d1e220d88ae5e9a24d6e713039a64f9:**

| Attribute | Value |
| --- | --- |
| **SampleID** | 5948 |
| **FileName** | pafish.exe |
| **Type** | Windows Exe (x86-32) |
| **Verdict** | Malicious |
| **SampleURL** | <https://cloud.vmray.com/user/sample/view?id=5948> |

### vmray-get-threat-indicators

***
Retrieves threat indicators (VTI).

#### Base Command

`vmray-get-threat-indicators`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sample_id | ID of the sample. Can be obtained from the 'VMRay.Sample.ID' output. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMRay.ThreatIndicator.AnalysisID | Number | List of connected analysis IDs. | 
| VMRay.ThreatIndicator.Category | String | Category of threat indicators. | 
| VMRay.ThreatIndicator.Classification | String | Classifications of threat indicators. | 
| VMRay.ThreatIndicator.ID | Number | ID of a threat indicator. | 
| VMRay.ThreatIndicator.Operation | String | Operation the indicators caused. | 

#### Command Example

```
!vmray-get-threat-indicators sample_id=3902238
```

#### Context Output

*Omitted for brevity.*

#### Human Readable Output

*Omitted for brevity.*

### vmray-add-tag

***
Adds a tag to an analysis and/or a submission.

#### Base Command

`vmray-add-tag`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| submission_id | ID of the submission to which to add tags. | Optional | 
| analysis_id | ID of the analysis from which to add tags. | Optional | 
| tag | Tag to add. | Optional | 

#### Context Output

There is no context output for this command.

#### Command Example

```
!vmray-add-tag submission_id=4569262 tag=faulty
```

#### Human Readable Output

    Tags: faulty has been added to submission: 4569262

### vmray-delete-tag

***
Deletes tags from an analysis and/or a submission.

#### Base Command

`vmray-delete-tag`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| analysis_id | ID of the analysis from which to delete a tag. | Optional | 
| submission_id | ID of the submission from which to delete a tag. | Optional | 
| tag | Tag to delete. | Optional | 

#### Context Output

There is no context output for this command.

#### Command Example

```
!vmray-delete-tag submission_id=4569262 tag=faulty
```

#### Human Readable Output

    Tags: faulty has been removed from submission: 4569262

### vmray-get-iocs

***
Retrieves Indicators of Compromise for a specified sample.

#### Base Command

`vmray-get-iocs`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sample_id | ID of the sample. | Required | 
| all_artifacts | Whether all artifacts should be returned or only Indicators of Compromise. Possible values are: true, false. Default is false. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. | 
| Domain.Name | String | The domain name | 
| IP.Address | String | IP address | 
| URL.Data | String | The URL | 
| Email.Address | String | The Email address | 
| File.Path | String | The full file path. | 
| File.MD5 | String | The MD5 hash of the file. | 
| File.SHA1 | String | The SHA1 hash of the file. | 
| File.SHA256 | String | The SHA256 hash of the file. | 
| File.SSDeep | String | The SSDeep hash of the file. | 
| VMRay.Sample.IOC.Domain.AnalysisID | Number | IDs of other analyses that contain the domain. | 
| VMRay.Sample.IOC.Domain.Countries | String | Countries associated with the domain. | 
| VMRay.Sample.IOC.Domain.CountryCodes | String | ISO 3166-1 two-letter country codes associated with the domain. | 
| VMRay.Sample.IOC.Domain.Domain | String | Domain. | 
| VMRay.Sample.IOC.Domain.ID | Number | ID of the domain. \(deprecated; is always 0\) | 
| VMRay.Sample.IOC.Domain.IsIOC | Boolean | Whether this artifact is an Indicator of Compromise \(IOC\). | 
| VMRay.Sample.IOC.Domain.IOCType | String | Type of IOC. | 
| VMRay.Sample.IOC.Domain.IpAddresses | String | IP addresses associated with the domain. | 
| VMRay.Sample.IOC.Domain.OriginalDomains | String | Original domains associated with the domain. | 
| VMRay.Sample.IOC.Domain.ParentProcesses | String | Full commandline of processes where the domain was used. | 
| VMRay.Sample.IOC.Domain.ParentProcessesNames | String | Names of processes where the domain was used. | 
| VMRay.Sample.IOC.Domain.Protocols | String | The protocols used for the domain in a request. | 
| VMRay.Sample.IOC.Domain.Sources | String | The sources where the domain was obtained from. | 
| VMRay.Sample.IOC.Domain.Type | String | Type of domain. | 
| VMRay.Sample.IOC.Domain.Verdict | String | Verdict for the artifact \(Malicious, Suspicious, Clean, Not Available\). | 
| VMRay.Sample.IOC.Domain.VerdictReason | String | Description of the Verdict Reason. | 
| VMRay.Sample.IOC.EmailAddress.AnalysisID | Number | IDs of other analyses that contain the email address. | 
| VMRay.Sample.IOC.EmailAddress.Classifications | String | The classifications of the email address. | 
| VMRay.Sample.IOC.EmailAddress.EmailAddress | String | The email address. | 
| VMRay.Sample.IOC.EmailAddress.IsIOC | Boolean | Whether this artifact is an Indicator of Compromise \(IOC\). | 
| VMRay.Sample.IOC.EmailAddress.IsRecipient | Boolean | Indicates whether this email address was used as a recipient email. | 
| VMRay.Sample.IOC.EmailAddress.IsSender | Boolean | Indicates whether this email address was used as a sender email. | 
| VMRay.Sample.IOC.EmailAddress.IOCType | String | Type of IOC. | 
| VMRay.Sample.IOC.EmailAddress.Subjects | String | Email subjects this email address was used in. | 
| VMRay.Sample.IOC.EmailAddress.ThreatNames | String | The threat names of the email address. | 
| VMRay.Sample.IOC.EmailAddress.Type | String | Type of email address. | 
| VMRay.Sample.IOC.EmailAddress.Verdict | String | Verdict for the artifact \(Malicious, Suspicious, Clean, Not Available\). | 
| VMRay.Sample.IOC.EmailAddress.VerdictReason | String | Description of the Verdict Reason. | 
| VMRay.Sample.IOC.Email.AnalysisID | Number | IDs of other analyses that contain the email. | 
| VMRay.Sample.IOC.Email.AttachmentTypes | String | MIME types of attachments found in this email. | 
| VMRay.Sample.IOC.Email.Classifications | String | The classifications of the email. | 
| VMRay.Sample.IOC.Email.Hashes.MD5 | String | MD5 of given email. | 
| VMRay.Sample.IOC.Email.Hashes.SSDeep | String | SSDeep of given email. | 
| VMRay.Sample.IOC.Email.Hashes.SHA256 | String | SHA256 of given email. | 
| VMRay.Sample.IOC.Email.Hashes.SHA1 | String | SHA1 of given email. | 
| VMRay.Sample.IOC.Email.IsIOC | Boolean | Whether this artifact is an Indicator of Compromise \(IOC\). | 
| VMRay.Sample.IOC.Email.IOCType | String | Type of IOC. | 
| VMRay.Sample.IOC.Email.NrAttachments | Number | Number of attachments found in the email. | 
| VMRay.Sample.IOC.Email.NrLinks | Number | Number of links found in the email. | 
| VMRay.Sample.IOC.Email.Recipients | String | The email recipients. | 
| VMRay.Sample.IOC.Email.Sender | String | Sender of the email. | 
| VMRay.Sample.IOC.Email.Subject | String | Subject of the email. | 
| VMRay.Sample.IOC.Email.ThreatNames | String | The threat names of the email. | 
| VMRay.Sample.IOC.Email.Type | String | Type of email. | 
| VMRay.Sample.IOC.Email.Verdict | String | Verdict for the artifact \(Malicious, Suspicious, Clean, Not Available\). | 
| VMRay.Sample.IOC.Email.VerdictReason | String | Description of the Verdict Reason. | 
| VMRay.Sample.IOC.Filename.AnalysisID | Number | IDs of other analyses that contain the filename. | 
| VMRay.Sample.IOC.Filename.Categories | String | The filename categories. | 
| VMRay.Sample.IOC.Filename.Classifications | String | The classifications of the filename. | 
| VMRay.Sample.IOC.Filename.Filename | String | The filename. | 
| VMRay.Sample.IOC.Filename.IsIOC | Boolean | Whether this artifact is an Indicator of Compromise \(IOC\). | 
| VMRay.Sample.IOC.Filename.IOCType | String | Type of IOC. | 
| VMRay.Sample.IOC.Filename.Operations | String | The filename operations that were performed, e.g., access, create, read, write, and delete. | 
| VMRay.Sample.IOC.Filename.ThreatNames | String | The threat names of the filename. | 
| VMRay.Sample.IOC.Filename.Type | String | Type of filename. | 
| VMRay.Sample.IOC.Filename.Verdict | String | Verdict for the artifact \(Malicious, Suspicious, Clean, Not Available\). | 
| VMRay.Sample.IOC.Filename.VerdictReason | String | Description of the Verdict Reason. | 
| VMRay.Sample.IOC.File.AnalysisID | Number | IDs of other analyses that contain the file. | 
| VMRay.Sample.IOC.File.Categories | String | The file categories. | 
| VMRay.Sample.IOC.File.Classifications | String | The classifications of the file. | 
| VMRay.Sample.IOC.File.FileSize | Number | The original size of the file in bytes. | 
| VMRay.Sample.IOC.File.Filename | String | Name of the file. | 
| VMRay.Sample.IOC.File.Filenames | String | All known names of the file. | 
| VMRay.Sample.IOC.File.Hashes.MD5 | String | MD5 hash of the file. | 
| VMRay.Sample.IOC.File.Hashes.SSDeep | String | SSDeep hash of the file. | 
| VMRay.Sample.IOC.File.Hashes.SHA256 | String | SHA256 hash of the file. | 
| VMRay.Sample.IOC.File.Hashes.SHA1 | String | SHA1 hash of the file. | 
| VMRay.Sample.IOC.File.ID | Number | ID of the file. \(deprecated; is always 0\) | 
| VMRay.Sample.IOC.File.IsIOC | Boolean | Whether this artifact is an Indicator of Compromise \(IOC\). | 
| VMRay.Sample.IOC.File.IOCType | String | Type of IOC. | 
| VMRay.Sample.IOC.File.MIMEType | String | The MIME type of the file. | 
| VMRay.Sample.IOC.File.Name | String | Same as Filename. | 
| VMRay.Sample.IOC.File.NormFilename | String | Normalized name of the file. | 
| VMRay.Sample.IOC.File.Operation | String | Same as Operations, left in for backwards compatibility. | 
| VMRay.Sample.IOC.File.Operations | String | The file operations which were performed, e.g., access, create, read, write, and delete. | 
| VMRay.Sample.IOC.File.ParentFiles | String | Files where this file was contained in. | 
| VMRay.Sample.IOC.File.ParentProcesses | String | Full commandline of processes where the file was referenced. | 
| VMRay.Sample.IOC.File.ParentProcessesNames | String | Names of processes where the file was referenced. | 
| VMRay.Sample.IOC.File.ResourceURL | String | URL of where the file was downloaded. | 
| VMRay.Sample.IOC.File.ThreatNames | String | The threat names of the file. | 
| VMRay.Sample.IOC.File.Type | String | Type of file. | 
| VMRay.Sample.IOC.File.Verdict | String | Verdict for the artifact \(Malicious, Suspicious, Clean, Not Available\). | 
| VMRay.Sample.IOC.File.VerdictReason | String | Description of the Verdict Reason. | 
| VMRay.Sample.IOC.IP.AnalysisID | Number | IDs of other analyses that contain the IP address. | 
| VMRay.Sample.IOC.IP.Countries | String | Countries associated with the IP address. | 
| VMRay.Sample.IOC.IP.CountryCodes | String | ISO 3166-1 two-letter country codes associated with the IP address. | 
| VMRay.Sample.IOC.IP.Domains | String | Domains associated with the IP address. | 
| VMRay.Sample.IOC.IP.IP | String | The IP address. | 
| VMRay.Sample.IOC.IP.ID | Number | ID of the IP address. \(deprecated; is always 0\) | 
| VMRay.Sample.IOC.IP.IsIOC | Boolean | Whether this artifact is an Indicator of Compromise \(IOC\). | 
| VMRay.Sample.IOC.IP.IOCType | String | Type of IOC. | 
| VMRay.Sample.IOC.IP.Operation | String | Deprecated, always empty. | 
| VMRay.Sample.IOC.IP.ParentProcesses | String | Full commandline of processes where the IP address was referenced. | 
| VMRay.Sample.IOC.IP.ParentProcessesNames | String | Names of processes where the IP address was referenced. | 
| VMRay.Sample.IOC.IP.Protocols | String | Protocols used in communication with this IP. | 
| VMRay.Sample.IOC.IP.Sources | String | The sources where the IP address was obtained from. | 
| VMRay.Sample.IOC.IP.Type | String | Type of IP address. | 
| VMRay.Sample.IOC.IP.Verdict | String | Verdict for the artifact \(Malicious, Suspicious, Clean, Not Available\). | 
| VMRay.Sample.IOC.IP.VerdictReason | String | Description of the Verdict Reason. | 
| VMRay.Sample.IOC.Mutex.AnalysisID | Number | IDs of other analyses that contain the mutex. | 
| VMRay.Sample.IOC.Mutex.Classifications | String | The mutex classifications. | 
| VMRay.Sample.IOC.Mutex.ID | Number | ID of the mutex. \(deprecated; is always 0\) | 
| VMRay.Sample.IOC.Mutex.IsIOC | Boolean | Whether this artifact is an Indicator of Compromise \(IOC\). | 
| VMRay.Sample.IOC.Mutex.IOCType | String | Type of IOC. | 
| VMRay.Sample.IOC.Mutex.Name | String | Name of the mutex. | 
| VMRay.Sample.IOC.Mutex.Operation | String | Same as Operations, left in for backwards compatibility. | 
| VMRay.Sample.IOC.Mutex.Operation | String | The mutex operations that were performed, e.g., access, create, read, write, and delete. | 
| VMRay.Sample.IOC.Mutex.ParentProcesses | String | Full commandline of processes where the mutex was used. | 
| VMRay.Sample.IOC.Mutex.ParentProcessesNames | Unknown | Names of processes where the mutex was used. | 
| VMRay.Sample.IOC.Mutex.ThreatNames | String | The threat names of the mutex. | 
| VMRay.Sample.IOC.Mutex.Type | String | Type of mutex. | 
| VMRay.Sample.IOC.Mutex.Verdict | String | Verdict for the artifact \(Malicious, Suspicious, Clean, Not Available\). | 
| VMRay.Sample.IOC.Mutex.VerdictReason | String | Description of the Verdict Reason. | 
| VMRay.Sample.IOC.Process.AnalysisID | Number | IDs of other analyses that contain the process. | 
| VMRay.Sample.IOC.Process.Classifications | String | The process classifications. | 
| VMRay.Sample.IOC.Process.CmdLine | String | Command line of the process. | 
| VMRay.Sample.IOC.Process.ImageNames | String | Names of the process executable. | 
| VMRay.Sample.IOC.Process.IsIOC | Boolean | Whether this artifact is an Indicator of Compromise \(IOC\). | 
| VMRay.Sample.IOC.Process.IOCType | String | Type of IOC. | 
| VMRay.Sample.IOC.Process.ParentProcesses | String | Full commandline of parent processes. | 
| VMRay.Sample.IOC.Process.ParentProcessesNames | String | Names of parent processes. | 
| VMRay.Sample.IOC.Process.ProcessNames | String | Names of the processes. | 
| VMRay.Sample.IOC.Process.ThreatNames | String | The threat names of the process. | 
| VMRay.Sample.IOC.Process.Type | String | Type of process. | 
| VMRay.Sample.IOC.Process.Verdict | String | Verdict for the artifact \(Malicious, Suspicious, Clean, Not Available\). | 
| VMRay.Sample.IOC.Process.VerdictReason | String | Description of the Verdict Reason. | 
| VMRay.Sample.IOC.Registry.AnalysisID | Number | IDs of other analyses that contain the registry key. | 
| VMRay.Sample.IOC.Registry.Classifications | String | The registry key classifications. | 
| VMRay.Sample.IOC.Registry.ID | Number | ID of the registry key. \(deprecated; is always 0\) | 
| VMRay.Sample.IOC.Registry.IsIOC | Boolean | Whether this artifact is an Indicator of Compromise \(IOC\). | 
| VMRay.Sample.IOC.Registry.IOCType | String | Type of IOC. | 
| VMRay.Sample.IOC.Registry.Name | String | The normalized registry key name. | 
| VMRay.Sample.IOC.Registry.Operation | String | Same as Operations, left in for backwards compatibility. | 
| VMRay.Sample.IOC.Registry.Operation | String | The registry operations that were performed, e.g., access, create, read, write, and delete. | 
| VMRay.Sample.IOC.Registry.ParentProcesses | String | Full commandline of processes where the registry key was referenced. | 
| VMRay.Sample.IOC.Registry.ParentProcessesNames | String | Names of processes where the registry key was referenced. | 
| VMRay.Sample.IOC.Registry.ThreatNames | String | The threat names of the registry key. | 
| VMRay.Sample.IOC.Registry.Type | String | Type of registry key. | 
| VMRay.Sample.IOC.Registry.ValueTypes | String | The registry key value type. | 
| VMRay.Sample.IOC.Registry.Verdict | String | Verdict for the artifact \(Malicious, Suspicious, Clean, Not Available\). | 
| VMRay.Sample.IOC.Registry.VerdictReason | String | Description of the Verdict Reason. | 
| VMRay.Sample.IOC.URL.AnalysisID | Number | IDs of other analyses that contain the given URL. | 
| VMRay.Sample.IOC.URL.Categories | String | The URL categories. | 
| VMRay.Sample.IOC.URL.ContentTypes | String | Content types associated with the URL. | 
| VMRay.Sample.IOC.URL.Countries | String | Countries associated with the URL. | 
| VMRay.Sample.IOC.URL.CountryCodes | String | ISO 3166-1 two-letter country codes associated with the URL. | 
| VMRay.Sample.IOC.URL.ID | Number | ID of the URL. \(deprecated; is always 0\) | 
| VMRay.Sample.IOC.URL.IPAddresses | String | IP addresses associated with the URL. | 
| VMRay.Sample.IOC.URL.Methods | String | Methods of HTTP requests directed at this URL. | 
| VMRay.Sample.IOC.URL.Operation | String | Deprecated, always empty. | 
| VMRay.Sample.IOC.URL.OriginalURLs | String | The origin URLs the malware used in the artifact operation. | 
| VMRay.Sample.IOC.URL.ParentFiles | String | Names of files where the URL was referenced. | 
| VMRay.Sample.IOC.URL.ParentProcesses | String | Full commandline of processes where the URL was referenced. | 
| VMRay.Sample.IOC.URL.ParentProcessesNames | String | Names of processes where the URL was referenced. | 
| VMRay.Sample.IOC.URL.Referrers | String | Other URLs that referred to this URL. | 
| VMRay.Sample.IOC.URL.Source | String | The sources where the URL was obtained from. | 
| VMRay.Sample.IOC.URL.Type | String | Type of the URL. | 
| VMRay.Sample.IOC.URL.URL | String | The URL. | 
| VMRay.Sample.IOC.URL.UserAgents | String | User agents used to connect to this URL. | 
| VMRay.Sample.IOC.URL.Verdict | String | Verdict for the artifact \(Malicious, Suspicious, Clean, Not Available\). | 
| VMRay.Sample.IOC.URL.VerdictReason | String | Description of the Verdict Reason. | 

#### Command Example

```
!vmray-get-iocs sample_id=3902238
```

#### Context Example

*Omitted for brevity.*

#### Human Readable Output

*Omitted for brevity.*

### vmray-get-job-by-id

***
Retrieves a job by job ID.

#### Base Command

`vmray-get-job-by-id`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | ID of a job. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMRay.Job.JobID | Number | ID of the job. | 
| VMRay.Job.SampleID | Number | Sample ID of the job. | 
| VMRay.Job.SubmissionID | Number | ID of the submission. | 
| VMRay.Job.MD5 | String | MD5 hash of the sample in the job. | 
| VMRay.Job.SHA1 | String | SHA1 hash of the sample in the job. | 
| VMRay.Job.SHA256 | String | SHA256 hash of the sample in the job. | 
| VMRay.Job.SSDeep | String | ssdeep hash of the sample in the job. | 
| VMRay.Job.VMName | String | Name of the virtual machine. | 
| VMRay.Job.VMID | Number | ID of the virtual machine. | 
| VMRay.Job.Status | String | Status of the job. | 

#### Command Example

```
!vmray-get-job-by-id job_id=365547
```

#### Context Example

```json
{
    "VMRay.Job": {
        "VMName": "win7_32_sp1",
        "SampleID": 3902238,
        "SHA1": "868a53c394f29f8d3aac7b0a20a371999045b6ed",
        "SubmissionID": 4569262,
        "SHA256": "b8a4b647e56cb71773d0086b51906b902a7ccafe699f4068da4cb5cd234d9d66",
        "SSDeep": "1536:Hg8ktOZtz+PZvpJyrOM1GhFNkYL2BxNRjWW:H/kY0Z3yrOMGTkrNRjH",
        "Status": "inwork",
        "VMID": 3,
        "JobID": 365547,
        "MD5": "2e0499dc90c2d715a53e05b1890e0442"
    }
}
```

#### Human Readable Output

**Job results for job id: 365547**

| Attribute | Value |
| ---  |---|
| JobID | 365547 |
| SampleID | 3902238 |
| VMName | win7_32_sp1 |
| VMID | 3 |

### vmray-get-summary

***
Retrieves the Summary JSON v2 for a specific analysis.

#### Base Command

`vmray-get-summary`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| analysis_id | ID of the analysis from which to retrieve the Summary JSON v2 from (analysis ID is returned e.g. from vmray-get-analysis-by-sample). | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| InfoFile.Name | string | Filename | 
| InfoFile.EntryID | string | The EntryID of the Summary JSON v2 | 
| InfoFile.Size | number | The file size of the Summary JSON v2 | 
| InfoFile.Info | string | MIME type of the Summary JSON v2 | 

#### Command Example

```
!vmray-get-summary analysis_id=2779353
```

#### Context Example

```json
{
    "InfoFile": {
        "EntryID": "407@21232f297a57a5a743894a0e4a801fc3$&$9c7fe1a0-4045-4b69-8257-08ef3306318a",
        "Extension": "json",
        "Info": "application/json",
        "Name": "summary_v2.json",
        "Size": 37630,
        "Type": "ASCII text, with very long lines"
    }
}
```

#### Human Readable Output

    Returned file: summary_v2.json Download

### vmray-get-screenshots

***
Retrieves screenshots taken during a specific dynamic analysis. The screenshots are stored with file names like 'analysis\_5\_screenshot\_2.png'. In this example, '5' represents the analysis ID from which the screenshot came, and '2' indicates that it's the third screenshot taken during the analysis, in chronological order.

#### Base Command

`vmray-get-screenshots`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| analysis_id | ID of the analysis from which to retrieve the screenshots from (analysis ID is returned e.g. from vmray-get-analysis-by-sample). | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| InfoFile.Name | string | Filename | 
| InfoFile.EntryID | string | The EntryID of the file | 
| InfoFile.Size | number | The file size of the file | 
| InfoFile.Info | string | MIME type of the file | 

#### Command example

```!vmray-get-screenshots analysis_id="50615"```

#### Context Example

```json
{
    "InfoFile": [
        {
            "EntryID": "488@b7d0844f-d230-402a-81de-154dc1c57cc9",
            "Extension": "png",
            "Info": "image/png",
            "Name": "analysis_50615_screenshot_0.png",
            "Size": 753660,
            "Type": "PNG image data, 800 x 600, 8-bit/color RGB, non-interlaced"
        },
        {
            "EntryID": "489@b7d0844f-d230-402a-81de-154dc1c57cc9",
            "Extension": "png",
            "Info": "image/png",
            "Name": "analysis_50615_screenshot_1.png",
            "Size": 412598,
            "Type": "PNG image data, 800 x 600, 8-bit/color RGB, non-interlaced"
        }
    ]
}
```


### vmray-get-license-usage-verdicts
***
Gets the usage of verdicts from VMRay.


#### Base Command

`vmray-get-license-usage-verdicts`
#### Input

There is no input for this command.


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMRay.VerdictQuota.PeriodEndDate | string | License end date. | 
| VMRay.VerdictQuota.VerdictQuota | number | Total number of available verdicts (per month). |
| VMRay.VerdictQuota.VerdictRemaining | number | Remaining number of verdicts (per month). |
| VMRay.VerdictQuota.VerdictUsage | number | Percentages used. | 


#### Command Example

```vmray-get-license-usage-verdicts```

#### Context Example

```json
{
    "VMRay.VerdictQuota": {
        "PeriodEndDate": "2024-02-03 14:12 (UTC+1)",
        "VerdictQuota": 100,
        "VerdictRemaining": 90,
        "VerdictUsage": 10
    }
}
```

#### Human Readable Output

| VerdictQuota | 100 |
| VerdictRemaining | 90 |
| VerdictUsage | 10.0 |
| PeriodEndDate | 	2024-02-03 14:12 (UTC+1) |


### vmray-get-license-usage-reports
***
Gets the usage of reports from VMRay.


#### Base Command

`vmray-get-license-usage-reports`
#### Input

There is no input for this command.


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMRay.ReportQuota.PeriodEndDate | string | License end date. | 
| VMRay.ReportQuota.VerdictQuota | number | Total number of available reports (per month). |
| VMRay.ReportQuota.VerdictRemaining | number | Remaining number of reports (per month). |
| VMRay.ReportQuota.VerdictUsage | number | Percentages used. | 

#### Context Example

```json
{
    "VMRay.ReportsQuota": {
        "PeriodEndDate": "2024-02-03 14:12 (UTC+1)",
        "ReportQuota": 100,
        "ReportRemaining": 90,
        "ReportUsage": 10
    }
}
```

#### Command Example
```
vmray-get-license-usage-reports
```

#### Human Readable Output

| ReportQuota | 100 |
| ReportRemaining | 90 |
| ReportUsage | 10.0 |
| PeriodEndDate | 	2024-02-03 14:12 (UTC+1) |