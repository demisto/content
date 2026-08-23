ThreatZone malware analysis sandboxing.
This integration was integrated and tested with ThreatZone.

## Configure ThreatZone in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL (e.g. https://app.threat.zone) | The ThreatZone instance root or /public-api URL. The integration appends the suffix exactly once. | True |
| ThreatZone API Key | The API key generated for the ThreatZone workspace. | True |
| Source Reliability | The reliability of the source providing the intelligence data. | False |
| Trust any certificate (not secure) | Whether to trust any certificate \(not secure\) by disabling TLS certificate validation. | False |
| Use system proxy settings | Whether to use the system proxy settings for SDK requests. | False |

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
| entry_id | The entry ID of the file to submit. | Required |
| environment | The environment to run the submission in. Possible values are: w7_x64, w10_x64, w11_x64, linux-ubuntu_2204, macos-ventura, android9. Default is w7_x64. | Optional |
| private | Whether the submission is private. If omitted, the current ThreatZone API-provided default is used. Possible values are: true, false. | Optional |
| extension_check | Whether to enforce MIME-based extension correction before sandbox execution. If omitted, the current ThreatZone API-provided default is used. Possible values are: true, false. | Optional |
| auto | Whether to automatically select a sandbox environment based on the uploaded file type, ignoring the environment argument. Possible values are: true, false. Default is false. | Optional |
| modules | The legacy compatibility argument. ThreatZone v3.2 does not support per-submission module selection, so this value is validated but not forwarded. | Optional |
| analyze_config | The raw analyzeConfig JSON used to override or add sandbox metafields. | Optional |
| timeout | The duration of the submission analysis. If omitted, the current ThreatZone API-provided default is used. Possible values are: 60, 120, 180, 300. | Optional |
| work_path | The working path of the submission. If omitted, the current ThreatZone API-provided default is used. Possible values are: desktop, root, appdata, windows, temp. | Optional |
| mouse_simulation | Whether to enable mouse simulation. If omitted, the current ThreatZone API-provided default is used. Possible values are: true, false. | Optional |
| https_inspection | Whether to enable HTTPS inspection for encrypted traffic. If omitted, the current ThreatZone API-provided default is used. Possible values are: true, false. | Optional |
| internet_connection | Whether to enable internet connection. If omitted, the current ThreatZone API-provided default is used. Possible values are: true, false. | Optional |
| raw_logs | Whether to request raw logs. This legacy compatibility argument is not forwarded because ThreatZone v3.2 does not accept the metafield. Possible values are: true, false. | Optional |
| snapshot | Whether to enable Fast Bootup. If omitted, the current ThreatZone API-provided default is used. Possible values are: true, false. | Optional |
| entrypoint | The filename inside the archive to execute (for archives). | Optional |
| password | The password for password-protected archives. | Optional |
| configurations | The advanced execution configuration as a JSON object (for example preScript, startArguments, or networkConfig). | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatZone.Submission.Sandbox.UUID | String | The UUID of the sample. |
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
| entry_id | The entry ID of the file to submit. | Required |
| private | Whether the submission is visible only to members of your workspace. When false, the submission is visible to everyone. Possible values are: true, false. Default is true. | Optional |
| extension_check | Whether to enforce MIME-based extension correction before static scan. Possible values are: true, false. Default is false. | Optional |
| entrypoint | The filename inside the archive to analyze (for archives). | Optional |
| password | The password for password-protected archives. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatZone.Submission.Static.UUID | String | The UUID of the sample. |
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
| entry_id | The entry ID of the file to submit. | Required |
| private | Whether the submission is visible only to members of your workspace. When false, the submission is visible to everyone. Possible values are: true, false. Default is true. | Optional |
| extension_check | Whether to enforce MIME-based extension correction before sanitization. Possible values are: true, false. Default is true. | Optional |
| entrypoint | The filename inside the archive to sanitize (for archives). | Optional |
| password | The password for password-protected archives. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatZone.Submission.CDR.UUID | String | The UUID of the sample. |
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
| url | The URL to analyze. | Required |
| private | Whether to mark the submission as workspace-private. Possible values are: true, false. Default is true. | Optional |
| safe_browsing | Whether to start an isolated safe-browsing session alongside URL analysis. Possible values are: true, false. Default is false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatZone.Submission.URL.UUID | String | The UUID of the URL submission. |
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
| uuid | The UUID of the submission. | Required |
| details | Whether to include inline Indicators, IOCs, YARA matches, artifacts, and configuration data in the readable output. Possible values are: true, false. Default is false. | Optional |
| download_sanitized | Whether to download the sanitized file after a CDR analysis completes. Possible values are: true, false. Default is false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatZone.Submission | Unknown | The raw submission data returned by ThreatZone. |
| ThreatZone.Analysis.STATUS | Number | The status of the submission scanning process as an integer code \(0=declined, 1=file received, 2=accepted, 3=running, 4=VM ready, 5=finished\). |
| ThreatZone.Analysis.LEVEL | Number | The threat level of the scanned file as an integer code \(0=not measured, 1=informative, 2=suspicious, 3=malicious\). |
| ThreatZone.Analysis.INFO | String | The submission metadata such as file name/URL and privacy status. |
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
| uuid | The UUID of the submission. | Required |
| level | The indicator severity to filter by. Possible values are: benign, suspicious, malicious. | Optional |
| category | The indicator category to filter by. | Optional |
| pid | The process ID to filter by. | Optional |
| attack_code | The MITRE ATT&amp;CK technique code to filter by. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatZone.Submission.Indicators.UUID | String | The UUID of the submission. |
| ThreatZone.Submission.Indicators.Data | Unknown | The dynamic behaviour indicators returned by ThreatZone. |

### tz-get-ioc-result

***
Retrieves Indicators of Compromise for a submission from ThreatZone.

#### Base Command

`tz-get-ioc-result`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | The UUID of the submission. | Required |
| type | The IOC type to filter by. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatZone.Submission.IOCs.UUID | String | The UUID of the submission. |
| ThreatZone.Submission.IOCs.Data | Unknown | The Indicators of Compromise returned by ThreatZone. |

### tz-get-yara-result

***
Retrieves YARA rules matched during analysis. Use tz-download-yara-rule for the generated rule file.

#### Base Command

`tz-get-yara-result`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | The UUID of the submission. | Required |
| category | The matched YARA rule category to filter by. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatZone.Submission.YaraMatches.UUID | String | The UUID of the submission. |
| ThreatZone.Submission.YaraMatches.Data | Unknown | The matched YARA rules returned by ThreatZone. |

### tz-get-artifact-result

***
Retrieves analysis artifacts for a submission from ThreatZone.

#### Base Command

`tz-get-artifact-result`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | The UUID of the submission. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatZone.Submission.Artifacts.UUID | String | The UUID of the submission. |
| ThreatZone.Submission.Artifacts.Data | Unknown | The analysis artifacts returned by ThreatZone. |

### tz-get-config-result

***
Retrieves configuration extractor results for a submission from ThreatZone.

#### Base Command

`tz-get-config-result`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | The UUID of the submission. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatZone.Submission.Config.UUID | String | The UUID of the submission. |
| ThreatZone.Submission.Config.Data | Unknown | The configuration extractor results returned by ThreatZone. |

### tz-get-sanitized

***
Downloads a sanitized file from the ThreatZone API and uploads it to the War Room.

#### Base Command

`tz-get-sanitized`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | The UUID of the submission. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| InfoFile.Extension | String | The extension of the file sanitized by CDR. |
| InfoFile.Name | String | The name of the file sanitized by CDR. |
| InfoFile.Size | Number | The size of the file sanitized by CDR. |
| InfoFile.EntryID | String | The entry ID of the file sanitized by CDR. |
| InfoFile.Info | String | The info of the file sanitized by CDR. |
| InfoFile.MD5 | String | The MD5 hash of the file sanitized by CDR. |
| InfoFile.SHA1 | String | The SHA1 hash of the file sanitized by CDR. |
| InfoFile.SHA256 | String | The SHA256 hash of the file sanitized by CDR. |
| InfoFile.SHA512 | String | The SHA512 hash of the file sanitized by CDR. |
| InfoFile.SSDeep | String | The SSDeep hash of the file sanitized by CDR. |

### tz-download-html-report

***
Downloads the HTML report for a submission and uploads it to the War Room.

#### Base Command

`tz-download-html-report`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | The UUID of the submission. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| InfoFile.Extension | String | The extension of the HTML report. |
| InfoFile.Name | String | The name of the downloaded HTML report. |
| InfoFile.Size | Number | The size of the downloaded HTML report. |
| InfoFile.EntryID | String | The entry ID of the downloaded HTML report. |
| InfoFile.Info | String | The info for the downloaded HTML report. |
| InfoFile.MD5 | String | The MD5 hash of the downloaded HTML report. |
| InfoFile.SHA1 | String | The SHA1 hash of the downloaded HTML report. |
| InfoFile.SHA256 | String | The SHA256 hash of the downloaded HTML report. |
| InfoFile.SHA512 | String | The SHA512 hash of the downloaded HTML report. |
| InfoFile.SSDeep | String | The SSDeep hash of the downloaded HTML report. |

### tz-get-metafields

***
Retrieves available ThreatZone metafields, optionally filtered by scan type.

#### Base Command

`tz-get-metafields`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scan_type | The scan type to filter metafields. Possible values are: sandbox, static, cdr, url, open_in_browser. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatZone.Configuration.Metafields.ScanType | String | The scan type used to filter the metafields. |
| ThreatZone.Configuration.Metafields.Data | Unknown | The metafield definitions returned by ThreatZone. |

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
| ThreatZone.Configuration.Environments.Data | Unknown | The sandbox environment definitions returned by ThreatZone. |

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
| ThreatZone.Configuration.NetworkConfigurations.Data | Unknown | The network configuration summaries returned by ThreatZone. |

### tz-open-in-browser

***
Creates a ThreatZone open-in-browser submission.

#### Base Command

`tz-open-in-browser`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | The URL to open in an isolated browser environment. | Required |
| environment | The sandbox environment key for browser execution. | Optional |
| auto | Whether to let ThreatZone select the browser environment. Possible values are: true, false. Default is false. | Optional |
| metafields | The open-in-browser metafields as a JSON object. | Optional |
| private | Whether to mark the submission as workspace-private. Possible values are: true, false. Default is true. | Optional |
| configurations | The advanced execution configuration as a JSON object. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatZone.Submission.OpenInBrowser.UUID | String | The UUID of the open-in-browser submission. |
| ThreatZone.Submission.OpenInBrowser.URL | String | The URL submitted to ThreatZone. |

### tz-list-submissions

***
Lists ThreatZone submissions with optional filters.

#### Base Command

`tz-list-submissions`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | The page number, starting at 1. Default is 1. | Optional |
| limit | The number of submissions per page (1-100). Default is 20. | Optional |
| level | The comma-separated threat levels. | Optional |
| type | The submission type. Possible values are: file, url. | Optional |
| sha256 | The SHA256 hash filter. | Optional |
| filename | The partial filename filter. | Optional |
| start_date | The ISO 8601 date to include submissions created on or after (for example, 2020-01-01T00:11:22Z). | Optional |
| end_date | The ISO 8601 date to include submissions created on or before (for example, 2020-01-01T00:11:22Z). | Optional |
| private | Whether to filter by privacy status. Possible values are: true, false. | Optional |
| tags | The comma-separated tag filters. | Optional |
| sort | The field used to sort results, such as createdAt. | Optional |
| order | The sort order. Possible values are: asc, desc. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatZone.Submission.List | Unknown | The paginated ThreatZone submission results. |

### tz-search-submissions-by-sha256

***
Searches ThreatZone submissions by SHA256 hash.

#### Base Command

`tz-search-submissions-by-sha256`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sha256 | The SHA256 hash to search for. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatZone.SubmissionSearch.Data | Unknown | The matching submissions. |

### tz-get-overview-summary

***
Retrieves aggregate analysis counts for a submission.

#### Base Command

`tz-get-overview-summary`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | The UUID of the submission. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatZone.Submission.OverviewSummary.UUID | String | The UUID of the submission. |
| ThreatZone.Submission.OverviewSummary.Data | Unknown | The aggregate analysis summary. |

### tz-get-eml-analysis

***
Retrieves parsed EML analysis results.

#### Base Command

`tz-get-eml-analysis`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | The UUID of the submission. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatZone.Submission.EMLAnalysis.UUID | String | The UUID of the submission. |
| ThreatZone.Submission.EMLAnalysis.Data | Unknown | The parsed EML analysis data. |

### tz-get-mitre-techniques

***
Retrieves MITRE ATT&CK techniques matched during analysis.

#### Base Command

`tz-get-mitre-techniques`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | The UUID of the submission. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatZone.Submission.MITRE.UUID | String | The UUID of the submission. |
| ThreatZone.Submission.MITRE.Data | Unknown | The matched MITRE ATT&amp;CK techniques. |

### tz-get-static-scan-result

***
Retrieves the static scan result for a submission.

#### Base Command

`tz-get-static-scan-result`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | The UUID of the submission. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatZone.Submission.StaticScan.UUID | String | The UUID of the submission. |
| ThreatZone.Submission.StaticScan.Data | Unknown | The static scan result. |

### tz-get-cdr-result

***
Retrieves the CDR transformation result for a submission.

#### Base Command

`tz-get-cdr-result`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | The UUID of the submission. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatZone.Submission.CDRResult.UUID | String | The UUID of the submission. |
| ThreatZone.Submission.CDRResult.Data | Unknown | The CDR transformation result. |

### tz-get-signature-check-result

***
Retrieves authenticode and signature-check results.

#### Base Command

`tz-get-signature-check-result`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | The UUID of the submission. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatZone.Submission.SignatureCheck.UUID | String | The UUID of the submission. |
| ThreatZone.Submission.SignatureCheck.Data | Unknown | The signature-check result. |

### tz-get-processes

***
Retrieves processes captured during dynamic analysis.

#### Base Command

`tz-get-processes`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | The UUID of the submission. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatZone.Submission.Processes.UUID | String | The UUID of the submission. |
| ThreatZone.Submission.Processes.Data | Unknown | The captured processes. |

### tz-get-process-tree

***
Retrieves the process tree captured during dynamic analysis.

#### Base Command

`tz-get-process-tree`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | The UUID of the submission. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatZone.Submission.ProcessTree.UUID | String | The UUID of the submission. |
| ThreatZone.Submission.ProcessTree.Data | Unknown | The captured process tree. |

### tz-get-url-analysis-result

***
Retrieves the full URL analysis report.

#### Base Command

`tz-get-url-analysis-result`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | The UUID of the URL or open-in-browser submission. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatZone.Submission.URLAnalysis.UUID | String | The UUID of the submission. |
| ThreatZone.Submission.URLAnalysis.Data | Unknown | The URL analysis report. |

### tz-get-behaviours

***
Retrieves one bounded page of behaviour telemetry.

#### Base Command

`tz-get-behaviours`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | The UUID of the submission. | Required |
| type | The behaviour event type filter. | Optional |
| pid | The process ID filter. | Optional |
| operation | The operation-name filter. | Optional |
| process_name | The exact process-name filter. | Optional |
| page | The page number, starting at 1. Default is 1. | Optional |
| limit | The number of events to return (1-500). Default is 100. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatZone.Submission.Behaviours.UUID | String | The UUID of the submission. |
| ThreatZone.Submission.Behaviours.Data | Unknown | The behaviour events and pagination metadata. |

### tz-get-syscalls

***
Retrieves one bounded page of syscall telemetry.

#### Base Command

`tz-get-syscalls`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | The UUID of the submission. | Required |
| page | The page number, starting at 1. Default is 1. | Optional |
| limit | The number of syscall lines to return (1-2000). Default is 500. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatZone.Submission.Syscalls.UUID | String | The UUID of the submission. |
| ThreatZone.Submission.Syscalls.Data | Unknown | The syscall lines and pagination metadata. |

### tz-get-network-summary

***
Retrieves aggregate network activity counts.

#### Base Command

`tz-get-network-summary`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | The UUID of the submission. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatZone.Submission.NetworkSummary.UUID | String | The UUID of the submission. |
| ThreatZone.Submission.NetworkSummary.Data | Unknown | The network activity summary. |

### tz-get-dns-queries

***
Retrieves a bounded window of DNS queries.

#### Base Command

`tz-get-dns-queries`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | The UUID of the submission. | Required |
| limit | The maximum items to return (0-1000). | Optional |
| skip | The number of items to skip (0-1000). | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatZone.Submission.DNSQueries.UUID | String | The UUID of the submission. |
| ThreatZone.Submission.DNSQueries.Data | Unknown | The captured DNS queries. |

### tz-get-http-requests

***
Retrieves a bounded window of HTTP request hosts.

#### Base Command

`tz-get-http-requests`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | The UUID of the submission. | Required |
| limit | The maximum items to return (0-1000). | Optional |
| skip | The number of items to skip (0-1000). | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatZone.Submission.HTTPRequests.UUID | String | The UUID of the submission. |
| ThreatZone.Submission.HTTPRequests.Data | Unknown | The captured HTTP request hosts. |

### tz-get-tcp-connections

***
Retrieves a bounded window of TCP connections.

#### Base Command

`tz-get-tcp-connections`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | The UUID of the submission. | Required |
| limit | The maximum items to return (0-1000). | Optional |
| skip | The number of items to skip (0-1000). | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatZone.Submission.TCPConnections.UUID | String | The UUID of the submission. |
| ThreatZone.Submission.TCPConnections.Data | Unknown | The captured TCP connections. |

### tz-get-udp-connections

***
Retrieves a bounded window of UDP connections.

#### Base Command

`tz-get-udp-connections`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | The UUID of the submission. | Required |
| limit | The maximum items to return (0-1000). | Optional |
| skip | The number of items to skip (0-1000). | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatZone.Submission.UDPConnections.UUID | String | The UUID of the submission. |
| ThreatZone.Submission.UDPConnections.Data | Unknown | The captured UDP connections. |

### tz-get-network-threats

***
Retrieves a bounded window of Suricata network threats.

#### Base Command

`tz-get-network-threats`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | The UUID of the submission. | Required |
| limit | The maximum items to return (0-1000). | Optional |
| skip | The number of items to skip (0-1000). | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatZone.Submission.NetworkThreats.UUID | String | The UUID of the submission. |
| ThreatZone.Submission.NetworkThreats.Data | Unknown | The detected network threats. |

### tz-download-static-scan-strings

***
Downloads the static scan strings JSON to the War Room.

#### Base Command

`tz-download-static-scan-strings`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | The UUID of the submission. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| InfoFile.EntryID | String | The entry ID of the downloaded file. |
| InfoFile.Name | String | The name of the downloaded file. |

### tz-download-sample

***
Downloads the original submitted sample to the War Room.

#### Base Command

`tz-download-sample`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | The UUID of the submission. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| InfoFile.EntryID | String | The entry ID of the downloaded file. |
| InfoFile.Name | String | The name of the downloaded file. |

### tz-download-artifact

***
Downloads an extracted artifact to the War Room.

#### Base Command

`tz-download-artifact`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | The UUID of the submission. | Required |
| artifact_id | The artifact ID returned by tz-get-artifact-result. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| InfoFile.EntryID | String | The entry ID of the downloaded file. |
| InfoFile.Name | String | The name of the downloaded file. |

### tz-download-pcap

***
Downloads the network capture to the War Room.

#### Base Command

`tz-download-pcap`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | The UUID of the submission. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| InfoFile.EntryID | String | The entry ID of the downloaded file. |
| InfoFile.Name | String | The name of the downloaded file. |

### tz-download-yara-rule

***
Polls for and downloads the generated YARA rule file to the War Room.

#### Base Command

`tz-download-yara-rule`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | The UUID of the submission. | Required |
| timeout | The maximum seconds to poll for generated YARA rule readiness (1-3600). Default is 120. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| InfoFile.EntryID | String | The entry ID of the downloaded file. |
| InfoFile.Name | String | The name of the downloaded file. |

### tz-download-url-screenshot

***
Downloads the URL analysis screenshot to the War Room.

#### Base Command

`tz-download-url-screenshot`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | The UUID of the URL analysis submission. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| InfoFile.EntryID | String | The entry ID of the downloaded file. |
| InfoFile.Name | String | The name of the downloaded file. |

### tz-list-media-files

***
Lists screenshots and videos available for a submission.

#### Base Command

`tz-list-media-files`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | The UUID of the submission. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatZone.Submission.MediaFiles.UUID | String | The UUID of the submission. |
| ThreatZone.Submission.MediaFiles.Data | Unknown | The available media file metadata. |

### tz-download-media-file

***
Downloads a submission media file to the War Room.

#### Base Command

`tz-download-media-file`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | The UUID of the submission. | Required |
| file_id | The media file ID returned by tz-list-media-files. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| InfoFile.EntryID | String | The entry ID of the downloaded file. |
| InfoFile.Name | String | The name of the downloaded file. |

### tz-check-limits

***
Check the plan limits from ThreatZone API.

#### Base Command

`tz-check-limits`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| detailed | Whether to include plan file limits, enabled modules, and account metadata. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatZone.Limits.E_Mail | String | The owner e-mail of current plan. |
| ThreatZone.Limits.API_Limit | String | The remaining/total API request limits of the current plan. |
| ThreatZone.Limits.Concurrent_Limit | String | The remaining/total concurrent analysis limits of the current plan. |
| ThreatZone.Limits.Daily_Submission_Limit | String | The remaining/total daily submission limits of the current plan. |
| ThreatZone.Plan.File_Size_Limit_MiB | Number | The maximum upload size for the workspace plan \(MiB\). |
| ThreatZone.Plan.Allowed_Extensions | List | The list of permitted file extensions for uploads. |
| ThreatZone.Plan.Modules | List | The enabled ThreatZone modules for the workspace. |
| ThreatZone.Metadata.Full_Name | String | The full name of the authenticated user. |
| ThreatZone.Metadata.Workspace | String | The workspace identifier or name associated with the account. |
| ThreatZone.Metadata.Plan_Name | String | The name of the active ThreatZone plan. |
| ThreatZone.Metadata.Plan_Status | String | The status of the active ThreatZone plan. |
