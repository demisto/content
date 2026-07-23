ThreatZone malware analysis sandboxing through the official ThreatZone Python SDK 1.1.1.
This integration supports ThreatZone platform v3.2.0 and later.

## Configure ThreatZone in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL (e.g. <https://app.threat.zone>) | Required ThreatZone instance root or `/public-api` URL. The integration appends the suffix exactly once. | True |
| ThreatZone API Key | API key generated for the ThreatZone workspace. | True |
| Source Reliability | Reliability of the source. | False |
| Trust any certificate (not secure) | Disables TLS certificate validation when enabled. | False |
| Use system proxy settings | Routes SDK requests through the system proxy when enabled. | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### tz-sandbox-upload-sample

***
Submits a sample to ThreatZone for sandbox analysis.

#### Base Command

`tz-sandbox-upload-sample`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entry_id | Entry ID of the file to submit. | Required |
| environment | Choose what environment you want to run your submission. Possible values are: w7_x64, w10_x64, w11_x64, linux-ubuntu_2204, macos-ventura, android9. Default is w7_x64. | Optional |
| private | Privacy of the submission. If omitted, the current ThreatZone API-provided default is used. Possible values are: true, false. | Optional |
| extension_check | Enforce MIME-based extension correction before sandbox execution. If omitted, the current ThreatZone API-provided default is used. Possible values are: true, false. | Optional |
| auto | When true, automatically selects a sandbox environment based on the uploaded file type and ignores the environment argument. Possible values are: true, false. Default is false. | Optional |
| modules | Legacy compatibility argument. ThreatZone v3.2 does not support per-submission module selection, so this value is validated but not forwarded. | Optional |
| analyze_config | Provide raw analyzeConfig JSON to override/add sandbox metafields. | Optional |
| timeout | Duration of the submission analysis. If omitted, the current ThreatZone API-provided default is used. Possible values are: 60, 120, 180, 300. | Optional |
| work_path | The working path of the submission. If omitted, the current ThreatZone API-provided default is used. Possible values are: desktop, root, appdata, windows, temp. | Optional |
| mouse_simulation | Enable mouse simulation. If omitted, the current ThreatZone API-provided default is used. Possible values are: true, false. | Optional |
| https_inspection | Enable HTTPS inspection for encrypted traffic. If omitted, the current ThreatZone API-provided default is used. Possible values are: true, false. | Optional |
| internet_connection | Enable internet connection. If omitted, the current ThreatZone API-provided default is used. Possible values are: true, false. | Optional |
| raw_logs | Legacy compatibility argument. ThreatZone v3.2 does not accept this metafield, so it is not forwarded. Possible values are: true, false. | Optional |
| snapshot | Enable Fast Bootup. If omitted, the current ThreatZone API-provided default is used. Possible values are: true, false. | Optional |
| entrypoint | For archives, specify the filename inside the archive to execute. | Optional |
| password | Password for password-protected archives. | Optional |
| configurations | Advanced execution configuration as a JSON object (for example preScript, startArguments, or networkConfig). | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatZone.Submission.Sandbox.UUID | String | UUID of sample. |
| ThreatZone.Limits.E_Mail | String | The owner e-mail of current plan. |
| ThreatZone.Limits.API_Limit | String | The remaining/total API request limits of the current plan. |
| ThreatZone.Limits.Concurrent_Limit | String | The remaining/total concurrent analysis limits of the current plan. |
| ThreatZone.Limits.Daily_Submission_Limit | String | The remaining/total daily submission limits of the current plan. |

### tz-static-upload-sample

***
Submits a sample to ThreatZone for static analysis.

#### Base Command

`tz-static-upload-sample`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entry_id | Entry ID of the file to submit. | Required |
| private | When false, the submission is visible to everyone. When true, it is visible only to members of your workspace. Possible values are: true, false. Default is true. | Optional |
| extension_check | Enforce MIME-based extension correction before static scan. Possible values are: true, false. Default is false. | Optional |
| entrypoint | For archives, specify the filename inside the archive to analyze. | Optional |
| password | Password for password-protected archives. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatZone.Submission.Static.UUID | String | UUID of sample. |
| ThreatZone.Limits.E_Mail | String | The owner e-mail of current plan. |
| ThreatZone.Limits.API_Limit | String | The remaining/total API request limits of the current plan. |
| ThreatZone.Limits.Concurrent_Limit | String | The remaining/total concurrent analysis limits of the current plan. |
| ThreatZone.Limits.Daily_Submission_Limit | String | The remaining/total daily submission limits of the current plan. |

### tz-cdr-upload-sample

***
Submits a sample to ThreatZone for CDR.

#### Base Command

`tz-cdr-upload-sample`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entry_id | Entry ID of the file to submit. | Required |
| private | When false, the submission is visible to everyone. When true, it is visible only to members of your workspace. Possible values are: true, false. Default is true. | Optional |
| extension_check | Enforce MIME-based extension correction before sanitization. Possible values are: true, false. Default is true. | Optional |
| entrypoint | For archives, specify the filename inside the archive to sanitize. | Optional |
| password | Password for password-protected archives. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatZone.Submission.CDR.UUID | String | UUID of sample. |
| ThreatZone.Limits.E_Mail | String | The owner e-mail of current plan. |
| ThreatZone.Limits.API_Limit | String | The remaining/total API request limits of the current plan. |
| ThreatZone.Limits.Concurrent_Limit | String | The remaining/total concurrent analysis limits of the current plan. |
| ThreatZone.Limits.Daily_Submission_Limit | String | The remaining/total daily submission limits of the current plan. |

### tz-url-analysis

***
Submits a URL to ThreatZone for analysis.

#### Base Command

`tz-url-analysis`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | URL to analyze. | Required |
| private | Mark the submission as workspace-private. Possible values are: true, false. Default is true. | Optional |
| safe_browsing | Start an isolated safe-browsing session alongside URL analysis. Possible values are: true, false. Default is false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatZone.Submission.URL.UUID | String | UUID of the URL submission. |
| ThreatZone.Submission.URL.URL | String | The URL submitted for analysis. |
| ThreatZone.Limits.E_Mail | String | The owner e-mail of current plan. |
| ThreatZone.Limits.API_Limit | String | The remaining/total API request limits of the current plan. |
| ThreatZone.Limits.Concurrent_Limit | String | The remaining/total concurrent analysis limits of the current plan. |
| ThreatZone.Limits.Daily_Submission_Limit | String | The remaining/total daily submission limits of the current plan. |

### tz-get-result

***
Retrieve the analysis result from ThreatZone.

#### Base Command

`tz-get-result`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | UUID of the submission. | Required |
| details | When true, include inline Indicators, IOCs, YARA matches, artifacts, and configuration data in the readable output. Possible values are: true, false. Default is false. | Optional |
| download_sanitized | When true and the submission is a CDR analysis, download the sanitized file after the analysis completes. Possible values are: true, false. Default is false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatZone.Submission | Unknown | Raw submission data returned by ThreatZone. |
| ThreatZone.Analysis.STATUS | Number | The status of the submission scanning process. |
| ThreatZone.Analysis.LEVEL | Number | Threat Level of the scanned file. \(malicious, suspicious or informative\). |
| ThreatZone.Analysis.INFO | String | Contains submission metadata such as file name/URL and privacy status. |
| ThreatZone.Analysis.REPORT | String | The analysis report of the submission. |
| ThreatZone.Analysis.URL | String | The result page url of the submission. |
| ThreatZone.Analysis.MD5 | String | The md5 hash of the submission. |
| ThreatZone.Analysis.SHA1 | String | The sha1 hash of the submission. |
| ThreatZone.Analysis.SHA256 | String | The sha256 hash of the submission. |
| ThreatZone.Analysis.UUID | String | The UUID of the submission. |
| ThreatZone.Analysis.SANITIZED | String | The url of the sanitized file. |
| ThreatZone.IOC.URL | List | The URL data extracted from IOC. |
| ThreatZone.IOC.IP | List | The IP data extracted from IOC. |
| ThreatZone.IOC.DOMAIN | List | The DOMAIN data extracted from IOC. |
| ThreatZone.IOC.EMAIL | List | The EMAIL data extracted from IOC. |
| DBotScore.Indicator | String | The indicator that was tested. |
| DBotScore.Reliability | String | The reliability of the source providing the intelligence data. |
| DBotScore.Score | Number | The actual score. |
| DBotScore.Type | String | The indicator type. |
| DBotScore.Vendor | unknown | The vendor used to calculate the score. |

### tz-get-indicator-result

***
Retrieves dynamic behaviour indicators for a submission from ThreatZone.

#### Base Command

`tz-get-indicator-result`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | UUID of the submission. | Required |
| level | Filter by indicator severity. Possible values are: benign, suspicious, malicious. | Optional |
| category | Filter by indicator category. | Optional |
| pid | Filter by process ID. | Optional |
| attack_code | Filter by MITRE ATT&amp;CK technique code. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatZone.Submission.Indicators.UUID | String | The UUID of the submission. |
| ThreatZone.Submission.Indicators.Data | Unknown | Dynamic behaviour indicators returned by ThreatZone. |

### tz-get-ioc-result

***
Retrieves Indicators of Compromise for a submission from ThreatZone.

#### Base Command

`tz-get-ioc-result`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | UUID of the submission. | Required |
| type | Filter by IOC type. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatZone.Submission.IOCs.UUID | String | The UUID of the submission. |
| ThreatZone.Submission.IOCs.Data | Unknown | Indicators of Compromise returned by ThreatZone. |

### tz-get-yara-result

***
Retrieves YARA rules matched during analysis. Use tz-download-yara-rule for the generated rule file.

#### Base Command

`tz-get-yara-result`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | UUID of the submission. | Required |
| category | Filter by matched YARA rule category. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatZone.Submission.YaraMatches.UUID | String | The UUID of the submission. |
| ThreatZone.Submission.YaraMatches.Data | Unknown | Matched YARA rules returned by ThreatZone. |

### tz-get-artifact-result

***
Retrieves analysis artifacts for a submission from ThreatZone.

#### Base Command

`tz-get-artifact-result`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | UUID of the submission. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatZone.Submission.Artifacts.UUID | String | The UUID of the submission. |
| ThreatZone.Submission.Artifacts.Data | Unknown | Analysis artifacts returned by ThreatZone. |

### tz-get-config-result

***
Retrieves configuration extractor results for a submission from ThreatZone.

#### Base Command

`tz-get-config-result`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | UUID of the submission. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatZone.Submission.Config.UUID | String | The UUID of the submission. |
| ThreatZone.Submission.Config.Data | Unknown | Configuration extractor results returned by ThreatZone. |

### tz-get-sanitized

***
Downloads a sanitized file from the ThreatZone API and uploads it to the War Room.

#### Base Command

`tz-get-sanitized`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | UUID of the submission. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| InfoFile.Extension | String | Extension of the file sanitized by CDR. |
| InfoFile.Name | String | The name of the file sanitized by CDR. |
| InfoFile.Size | Number | Size of the file sanitized by CDR. |
| InfoFile.EntryID | String | EntryID of the file sanitized by CDR. |
| InfoFile.Info | String | Info of the file sanitized by CDR. |
| InfoFile.MD5 | String | MD5 hash of the file sanitized by CDR. |
| InfoFile.SHA1 | String | SHA1 hash of the file sanitized by CDR. |
| InfoFile.SHA256 | String | SHA256 hash of the file sanitized by CDR. |
| InfoFile.SHA512 | String | SHA512 hash of the file sanitized by CDR. |
| InfoFile.SSDeep | String | SSDeep hash of the file sanitized by CDR. |

### tz-download-html-report

***
Downloads the HTML report for a submission and uploads it to the War Room.

#### Base Command

`tz-download-html-report`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | UUID of the submission. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| InfoFile.Extension | String | Extension of the HTML report. |
| InfoFile.Name | String | The name of the downloaded HTML report. |
| InfoFile.Size | Number | Size of the downloaded HTML report. |
| InfoFile.EntryID | String | EntryID of the downloaded HTML report. |
| InfoFile.Info | String | Info for the downloaded HTML report. |
| InfoFile.MD5 | String | MD5 hash of the downloaded HTML report. |
| InfoFile.SHA1 | String | SHA1 hash of the downloaded HTML report. |
| InfoFile.SHA256 | String | SHA256 hash of the downloaded HTML report. |
| InfoFile.SHA512 | String | SHA512 hash of the downloaded HTML report. |
| InfoFile.SSDeep | String | SSDeep hash of the downloaded HTML report. |

### tz-get-metafields

***
Retrieves available ThreatZone metafields, optionally filtered by scan type.

#### Base Command

`tz-get-metafields`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scan_type | Optional scan type to filter metafields. Possible values are: sandbox, static, cdr, url, open_in_browser. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatZone.Configuration.Metafields.ScanType | String | Scan type used to filter the metafields. |
| ThreatZone.Configuration.Metafields.Data | Unknown | Metafield definitions returned by ThreatZone. |

### tz-get-environments

***
Retrieves available ThreatZone sandbox environments.

#### Base Command

`tz-get-environments`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatZone.Configuration.Environments.Data | Unknown | Sandbox environment definitions returned by ThreatZone. |

### tz-list-network-configs

***
Lists network configurations available to the current ThreatZone workspace.

#### Base Command

`tz-list-network-configs`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatZone.Configuration.NetworkConfigurations.Data | Unknown | Network configuration summaries returned by ThreatZone. |

### tz-open-in-browser

***
Creates a ThreatZone open-in-browser submission.

#### Base Command

`tz-open-in-browser`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | URL to open in an isolated browser environment. | Required |
| environment | Sandbox environment key for browser execution. | Optional |
| auto | Let ThreatZone select the browser environment. Possible values are: true, false. Default is false. | Optional |
| metafields | Open-in-browser metafields as a JSON object. | Optional |
| private | Mark the submission as workspace-private. Possible values are: true, false. Default is true. | Optional |
| configurations | Advanced execution configuration as a JSON object. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatZone.Submission.OpenInBrowser.UUID | String | UUID of the open-in-browser submission. |
| ThreatZone.Submission.OpenInBrowser.URL | String | URL submitted to ThreatZone. |

### tz-list-submissions

***
Lists ThreatZone submissions with optional filters.

#### Base Command

`tz-list-submissions`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | Page number, starting at 1. Default is 1. | Optional |
| limit | Number of submissions per page (1-100). Default is 20. | Optional |
| level | Comma-separated threat levels. | Optional |
| type | Submission type. Possible values are: file, url. | Optional |
| sha256 | SHA256 hash filter. | Optional |
| filename | Partial filename filter. | Optional |
| start_date | Include submissions created on or after this ISO 8601 date. | Optional |
| end_date | Include submissions created on or before this ISO 8601 date. | Optional |
| private | Filter by privacy status. Possible values are: true, false. | Optional |
| tags | Comma-separated tag filters. | Optional |
| sort | Field used to sort results, such as createdAt. | Optional |
| order | Sort order. Possible values are: asc, desc. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatZone.SubmissionList | Unknown | Paginated ThreatZone submission results. |

### tz-search-submissions-by-sha256

***
Searches ThreatZone submissions by SHA256 hash.

#### Base Command

`tz-search-submissions-by-sha256`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sha256 | SHA256 hash to search for. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatZone.SubmissionSearch.Data | Unknown | Matching submissions. |

### tz-get-overview-summary

***
Retrieves aggregate analysis counts for a submission.

#### Base Command

`tz-get-overview-summary`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | UUID of the submission. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatZone.Submission.OverviewSummary.UUID | String | UUID of the submission. |
| ThreatZone.Submission.OverviewSummary.Data | Unknown | Aggregate analysis summary. |

### tz-get-eml-analysis

***
Retrieves parsed EML analysis results.

#### Base Command

`tz-get-eml-analysis`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | UUID of the submission. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatZone.Submission.EMLAnalysis.UUID | String | UUID of the submission. |
| ThreatZone.Submission.EMLAnalysis.Data | Unknown | Parsed EML analysis data. |

### tz-get-mitre-techniques

***
Retrieves MITRE ATT&CK techniques matched during analysis.

#### Base Command

`tz-get-mitre-techniques`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | UUID of the submission. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatZone.Submission.MITRE.UUID | String | UUID of the submission. |
| ThreatZone.Submission.MITRE.Data | Unknown | Matched MITRE ATT&amp;CK techniques. |

### tz-get-static-scan-result

***
Retrieves the static scan result for a submission.

#### Base Command

`tz-get-static-scan-result`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | UUID of the submission. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatZone.Submission.StaticScan.UUID | String | UUID of the submission. |
| ThreatZone.Submission.StaticScan.Data | Unknown | Static scan result. |

### tz-get-cdr-result

***
Retrieves the CDR transformation result for a submission.

#### Base Command

`tz-get-cdr-result`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | UUID of the submission. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatZone.Submission.CDRResult.UUID | String | UUID of the submission. |
| ThreatZone.Submission.CDRResult.Data | Unknown | CDR transformation result. |

### tz-get-signature-check-result

***
Retrieves authenticode and signature-check results.

#### Base Command

`tz-get-signature-check-result`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | UUID of the submission. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatZone.Submission.SignatureCheck.UUID | String | UUID of the submission. |
| ThreatZone.Submission.SignatureCheck.Data | Unknown | Signature-check result. |

### tz-get-processes

***
Retrieves processes captured during dynamic analysis.

#### Base Command

`tz-get-processes`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | UUID of the submission. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatZone.Submission.Processes.UUID | String | UUID of the submission. |
| ThreatZone.Submission.Processes.Data | Unknown | Captured processes. |

### tz-get-process-tree

***
Retrieves the process tree captured during dynamic analysis.

#### Base Command

`tz-get-process-tree`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | UUID of the submission. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatZone.Submission.ProcessTree.UUID | String | UUID of the submission. |
| ThreatZone.Submission.ProcessTree.Data | Unknown | Captured process tree. |

### tz-get-url-analysis-result

***
Retrieves the full URL analysis report.

#### Base Command

`tz-get-url-analysis-result`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | UUID of the URL or open-in-browser submission. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatZone.Submission.URLAnalysis.UUID | String | UUID of the submission. |
| ThreatZone.Submission.URLAnalysis.Data | Unknown | URL analysis report. |

### tz-get-behaviours

***
Retrieves one bounded page of behaviour telemetry.

#### Base Command

`tz-get-behaviours`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | UUID of the submission. | Required |
| type | Behaviour event type filter. | Optional |
| pid | Process ID filter. | Optional |
| operation | Operation-name filter. | Optional |
| process_name | Exact process-name filter. | Optional |
| page | Page number, starting at 1. Default is 1. | Optional |
| limit | Number of events to return (1-500). Default is 100. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatZone.Submission.Behaviours.UUID | String | UUID of the submission. |
| ThreatZone.Submission.Behaviours.Data | Unknown | Behaviour events and pagination metadata. |

### tz-get-syscalls

***
Retrieves one bounded page of syscall telemetry.

#### Base Command

`tz-get-syscalls`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | UUID of the submission. | Required |
| page | Page number, starting at 1. Default is 1. | Optional |
| limit | Number of syscall lines to return (1-2000). Default is 500. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatZone.Submission.Syscalls.UUID | String | UUID of the submission. |
| ThreatZone.Submission.Syscalls.Data | Unknown | Syscall lines and pagination metadata. |

### tz-get-network-summary

***
Retrieves aggregate network activity counts.

#### Base Command

`tz-get-network-summary`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | UUID of the submission. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatZone.Submission.NetworkSummary.UUID | String | UUID of the submission. |
| ThreatZone.Submission.NetworkSummary.Data | Unknown | Network activity summary. |

### tz-get-dns-queries

***
Retrieves a bounded window of DNS queries.

#### Base Command

`tz-get-dns-queries`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | UUID of the submission. | Required |
| limit | Maximum items to return (0-1000). | Optional |
| skip | Number of items to skip (0-1000). | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatZone.Submission.DNSQueries.UUID | String | UUID of the submission. |
| ThreatZone.Submission.DNSQueries.Data | Unknown | Captured DNS queries. |

### tz-get-http-requests

***
Retrieves a bounded window of HTTP request hosts.

#### Base Command

`tz-get-http-requests`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | UUID of the submission. | Required |
| limit | Maximum items to return (0-1000). | Optional |
| skip | Number of items to skip (0-1000). | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatZone.Submission.HTTPRequests.UUID | String | UUID of the submission. |
| ThreatZone.Submission.HTTPRequests.Data | Unknown | Captured HTTP request hosts. |

### tz-get-tcp-connections

***
Retrieves a bounded window of TCP connections.

#### Base Command

`tz-get-tcp-connections`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | UUID of the submission. | Required |
| limit | Maximum items to return (0-1000). | Optional |
| skip | Number of items to skip (0-1000). | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatZone.Submission.TCPConnections.UUID | String | UUID of the submission. |
| ThreatZone.Submission.TCPConnections.Data | Unknown | Captured TCP connections. |

### tz-get-udp-connections

***
Retrieves a bounded window of UDP connections.

#### Base Command

`tz-get-udp-connections`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | UUID of the submission. | Required |
| limit | Maximum items to return (0-1000). | Optional |
| skip | Number of items to skip (0-1000). | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatZone.Submission.UDPConnections.UUID | String | UUID of the submission. |
| ThreatZone.Submission.UDPConnections.Data | Unknown | Captured UDP connections. |

### tz-get-network-threats

***
Retrieves a bounded window of Suricata network threats.

#### Base Command

`tz-get-network-threats`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | UUID of the submission. | Required |
| limit | Maximum items to return (0-1000). | Optional |
| skip | Number of items to skip (0-1000). | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatZone.Submission.NetworkThreats.UUID | String | UUID of the submission. |
| ThreatZone.Submission.NetworkThreats.Data | Unknown | Detected network threats. |

### tz-download-static-scan-strings

***
Downloads the static scan strings JSON to the War Room.

#### Base Command

`tz-download-static-scan-strings`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | UUID of the submission. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| InfoFile.EntryID | String | Entry ID of the downloaded file. |
| InfoFile.Name | String | Name of the downloaded file. |

### tz-download-sample

***
Downloads the original submitted sample to the War Room.

#### Base Command

`tz-download-sample`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | UUID of the submission. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| InfoFile.EntryID | String | Entry ID of the downloaded file. |
| InfoFile.Name | String | Name of the downloaded file. |

### tz-download-artifact

***
Downloads an extracted artifact to the War Room.

#### Base Command

`tz-download-artifact`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | UUID of the submission. | Required |
| artifact_id | Artifact ID returned by tz-get-artifact-result. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| InfoFile.EntryID | String | Entry ID of the downloaded file. |
| InfoFile.Name | String | Name of the downloaded file. |

### tz-download-pcap

***
Downloads the network capture to the War Room.

#### Base Command

`tz-download-pcap`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | UUID of the submission. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| InfoFile.EntryID | String | Entry ID of the downloaded file. |
| InfoFile.Name | String | Name of the downloaded file. |

### tz-download-yara-rule

***
Polls for and downloads the generated YARA rule file to the War Room.

#### Base Command

`tz-download-yara-rule`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | UUID of the submission. | Required |
| timeout | Maximum seconds to poll for generated YARA rule readiness (1-3600). Default is 120. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| InfoFile.EntryID | String | Entry ID of the downloaded file. |
| InfoFile.Name | String | Name of the downloaded file. |

### tz-download-url-screenshot

***
Downloads the URL analysis screenshot to the War Room.

#### Base Command

`tz-download-url-screenshot`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | UUID of the URL analysis submission. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| InfoFile.EntryID | String | Entry ID of the downloaded file. |
| InfoFile.Name | String | Name of the downloaded file. |

### tz-list-media-files

***
Lists screenshots and videos available for a submission.

#### Base Command

`tz-list-media-files`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | UUID of the submission. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatZone.Submission.MediaFiles.UUID | String | UUID of the submission. |
| ThreatZone.Submission.MediaFiles.Data | Unknown | Available media file metadata. |

### tz-download-media-file

***
Downloads a submission media file to the War Room.

#### Base Command

`tz-download-media-file`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | UUID of the submission. | Required |
| file_id | Media file ID returned by tz-list-media-files. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| InfoFile.EntryID | String | Entry ID of the downloaded file. |
| InfoFile.Name | String | Name of the downloaded file. |

### tz-check-limits

***
Check the plan limits from ThreatZone API.

#### Base Command

`tz-check-limits`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| detailed | When true, include plan file limits, enabled modules, and account metadata. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatZone.Limits.E_Mail | String | The owner e-mail of current plan. |
| ThreatZone.Limits.API_Limit | String | The remaining/total API request limits of the current plan. |
| ThreatZone.Limits.Concurrent_Limit | String | The remaining/total concurrent analysis limits of the current plan. |
| ThreatZone.Limits.Daily_Submission_Limit | String | The remaining/total daily submission limits of the current plan. |
| ThreatZone.Plan.File_Size_Limit_MiB | Number | Maximum upload size for the workspace plan \(MiB\). |
| ThreatZone.Plan.Allowed_Extensions | List | The list of permitted file extensions for uploads. |
| ThreatZone.Plan.Modules | List | Enabled ThreatZone modules for the workspace. |
| ThreatZone.Metadata.Full_Name | String | Full name of the authenticated user. |
| ThreatZone.Metadata.Workspace | String | Workspace identifier or name associated with the account. |
| ThreatZone.Metadata.Plan_Name | String | Name of the active ThreatZone plan. |
| ThreatZone.Metadata.Plan_Status | String | Status of the active ThreatZone plan. |
