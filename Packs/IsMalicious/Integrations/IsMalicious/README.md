Enrich IP, domain, URL and file-hash indicators with IsMalicious reputation, evidence and data-trust context.
This integration uses the public IsMalicious REST API contract. Local validation uses synthetic provider responses and the real CommonServerPython framework; no production Cortex XSOAR deployment is claimed.

API checks consume the applicable account quota. Unknown hashes, delisted indicators and absent supported verdicts remain DBotScore 0; risk and confidence are separate fields. See the pack README for evidence interpretation and limits.

## Configure IsMalicious in Cortex

Create an API key and API secret at https://ismalicious.com/app/account. Configure the password field with Base64 of the exact apiKey:apiSecret pair. Keep this complete credential secret. TLS verification is mandatory, redirects and retries are disabled. Test connection performs an example.com lookup to validate authentication, not safety.

URL strings are preserved, including commas. Pass URL batches as arrays. URLs containing user information or passwords are rejected before any request.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| X-API-KEY credential (Base64 of apiKey:apiSecret) | Use the complete encoded credential, not the raw API key. Keep it secret. | True |
| Use system proxy settings | Route requests through the proxy configured in the Cortex system settings. | False |
| Source Reliability | Choose the reliability assessed by your team; this is not the provider's risk or confidence score. | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

The examples below illustrate command syntax only; they are not recorded production executions or verdicts.

### ip

***
Enrich ip indicators with IsMalicious evidence. At most 50 values per command.

#### Base Command

`ip`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | Indicators to check; comma-separated list or array. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IsMalicious.Check.Indicator | String | The indicator queried, unchanged. |
| IsMalicious.Check.Type | String | Indicator type. |
| IsMalicious.Check.Verdict | String | Server-evidence-derived verdict; unknown remains unknown. |
| IsMalicious.Check.RiskScore | Number | Risk score from 0 to 100, higher is riskier. Missing remains unknown. |
| IsMalicious.Check.Confidence | Number | Confidence from 0 to 100, separate from risk. Missing remains unknown. |
| IsMalicious.Check.BlocklistHits | Number | Number of explicit blocklist matches as provided by API. |
| IsMalicious.Check.Evidence | Unknown | Server evidence, reasons, contradictions, source summary and recommended action. |
| IsMalicious.Check.DataTrust | Unknown | Provider data quality and freshness profile. |
| IsMalicious.Check.Sources | Unknown | Raw source context. Do not interpret all rows as malicious detections. |
| IsMalicious.Check.LookupStatus | String | Known or unknown hash lookup state. |
| IsMalicious.Check.KnownGood | Boolean | Known-good hash flag when provided. |
| IsMalicious.Check.Delisted | Boolean | Reviewed delisting flag when provided. |
| IsMalicious.Check.ReportURL | String | IsMalicious report URL. |
| DBotScore.Indicator | String | The indicator that was tested. |
| DBotScore.Type | String | The indicator type. |
| DBotScore.Vendor | String | The vendor used to calculate the score. |
| DBotScore.Score | Number | The actual score. |
| IP.Address | String | IP address. |

#### Command Example

```text
!ip ip=198.51.100.1
```

### domain

***
Enrich domain indicators with IsMalicious evidence. At most 50 values per command.

#### Base Command

`domain`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | Indicators to check; comma-separated list or array. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IsMalicious.Check.Indicator | String | The indicator queried, unchanged. |
| IsMalicious.Check.Type | String | Indicator type. |
| IsMalicious.Check.Verdict | String | Server-evidence-derived verdict; unknown remains unknown. |
| IsMalicious.Check.RiskScore | Number | Risk score from 0 to 100, higher is riskier. Missing remains unknown. |
| IsMalicious.Check.Confidence | Number | Confidence from 0 to 100, separate from risk. Missing remains unknown. |
| IsMalicious.Check.BlocklistHits | Number | Number of explicit blocklist matches as provided by API. |
| IsMalicious.Check.Evidence | Unknown | Server evidence, reasons, contradictions, source summary and recommended action. |
| IsMalicious.Check.DataTrust | Unknown | Provider data quality and freshness profile. |
| IsMalicious.Check.Sources | Unknown | Raw source context. Do not interpret all rows as malicious detections. |
| IsMalicious.Check.LookupStatus | String | Known or unknown hash lookup state. |
| IsMalicious.Check.KnownGood | Boolean | Known-good hash flag when provided. |
| IsMalicious.Check.Delisted | Boolean | Reviewed delisting flag when provided. |
| IsMalicious.Check.ReportURL | String | IsMalicious report URL. |
| DBotScore.Indicator | String | The indicator that was tested. |
| DBotScore.Type | String | The indicator type. |
| DBotScore.Vendor | String | The vendor used to calculate the score. |
| DBotScore.Score | Number | The actual score. |
| Domain.Name | String | Domain name. |

#### Command Example

```text
!domain domain=example.com
```

### url

***
Enrich url indicators with IsMalicious evidence. At most 50 values per command.

#### Base Command

`url`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | One complete HTTP(S) URL or an array of complete URLs. Commas inside a URL are preserved. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IsMalicious.Check.Indicator | String | The indicator queried, unchanged. |
| IsMalicious.Check.Type | String | Indicator type. |
| IsMalicious.Check.Verdict | String | Server-evidence-derived verdict; unknown remains unknown. |
| IsMalicious.Check.RiskScore | Number | Risk score from 0 to 100, higher is riskier. Missing remains unknown. |
| IsMalicious.Check.Confidence | Number | Confidence from 0 to 100, separate from risk. Missing remains unknown. |
| IsMalicious.Check.BlocklistHits | Number | Number of explicit blocklist matches as provided by API. |
| IsMalicious.Check.Evidence | Unknown | Server evidence, reasons, contradictions, source summary and recommended action. |
| IsMalicious.Check.DataTrust | Unknown | Provider data quality and freshness profile. |
| IsMalicious.Check.Sources | Unknown | Raw source context. Do not interpret all rows as malicious detections. |
| IsMalicious.Check.LookupStatus | String | Known or unknown hash lookup state. |
| IsMalicious.Check.KnownGood | Boolean | Known-good hash flag when provided. |
| IsMalicious.Check.Delisted | Boolean | Reviewed delisting flag when provided. |
| IsMalicious.Check.ReportURL | String | IsMalicious report URL. |
| DBotScore.Indicator | String | The indicator that was tested. |
| DBotScore.Type | String | The indicator type. |
| DBotScore.Vendor | String | The vendor used to calculate the score. |
| DBotScore.Score | Number | The actual score. |
| URL.Data | String | Full URL. |

#### Command Example

```text
!url url="https://example.com/path?a=1&b=2"
```

### file

***
Enrich MD5, SHA1 or SHA256 hashes with IsMalicious evidence. At most 50 values per command.

#### Base Command

`file`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file | MD5, SHA1 or SHA256 hashes; comma-separated list or array. No file upload. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IsMalicious.Check.Indicator | String | The indicator queried, unchanged. |
| IsMalicious.Check.Type | String | Indicator type. |
| IsMalicious.Check.Verdict | String | Server-evidence-derived verdict; unknown remains unknown. |
| IsMalicious.Check.RiskScore | Number | Risk score from 0 to 100, higher is riskier. Missing remains unknown. |
| IsMalicious.Check.Confidence | Number | Confidence from 0 to 100, separate from risk. Missing remains unknown. |
| IsMalicious.Check.BlocklistHits | Number | Number of explicit blocklist matches as provided by API. |
| IsMalicious.Check.Evidence | Unknown | Server evidence, reasons, contradictions, source summary and recommended action. |
| IsMalicious.Check.DataTrust | Unknown | Provider data quality and freshness profile. |
| IsMalicious.Check.Sources | Unknown | Raw source context. Do not interpret all rows as malicious detections. |
| IsMalicious.Check.LookupStatus | String | Known or unknown hash lookup state. |
| IsMalicious.Check.KnownGood | Boolean | Known-good hash flag when provided. |
| IsMalicious.Check.Delisted | Boolean | Reviewed delisting flag when provided. |
| IsMalicious.Check.ReportURL | String | IsMalicious report URL. |
| DBotScore.Indicator | String | The indicator that was tested. |
| DBotScore.Type | String | The indicator type. |
| DBotScore.Vendor | String | The vendor used to calculate the score. |
| DBotScore.Score | Number | The actual score. |
| File.MD5 | String | MD5 hash. |
| File.SHA1 | String | SHA1 hash. |
| File.SHA256 | String | SHA256 hash. |

#### Command Example

```text
!file file=d41d8cd98f00b204e9800998ecf8427e
```
