A polling wrapper script; creates a new indicator in Microsoft Defender for Endpoint.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | Utilities |
| Cortex XSOAR Version | 6.1.0 |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| indicator_value | The value of the indicator to update. |
| indicator_type | Indicator Type. |
| action | The action taken if the indicator is discovered in the organization. |
| severity | The severity of the malicious behavior identified by the data within the indicator, where High is the most severe and Informational is not severe at all. |
| expiration_time | DateTime string indicating when the indicator expires. Format: \(&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days\). |
| indicator_description | Brief description \(100 characters or less\) of the threat represented by the indicator. |
| indicator_title | The indicator alert title. |
| indicator_application | The application associated with the indicator. |
| recommended_actions | The indicator alert recommended actions. |
| rbac_group_names | A comma-separated list of RBAC group names the indicator is applied to. |
| ran_once_flag | Flag for the rate limit retry. |
| generate_alert | Whether to generate an alert for the indicator. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| MicrosoftATP.Indicators.id | Created by the system when the indicator is ingested. Generated GUID/unique identifier. | String |
| MicrosoftATP.Indicators.action | The action to apply if the indicator is matched from within the targetProduct security tool. Possible values: unknown, allow, block, alert. | String |
| MicrosoftATP.Indicators.description | Brief description \(100 characters or less\) of the threat represented by the indicator. | String |
| MicrosoftATP.Indicators.expirationTime | DateTime string indicating when the indicator expires. To avoid stale indicators persisting in the system, all indicators must have an expiration date. The timestamp type represents date and time information in ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 looks like: '2014-01-01T00:00:00Z'. | Date |
| MicrosoftATP.Indicators.severity | The severity of the malicious behavior identified by the data within the indicator. Possible values: Informational, Low, Medium, and High, where High is the most severe and Informational is not severe at all. | String |
| MicrosoftATP.Indicators.indicatorValue | The value of the indicator. | String |
| MicrosoftATP.Indicators.recommendedActions | Recommended actions for the indicator. | String |
| MicrosoftATP.Indicators.generateAlert | Whether an alert was generated. | Boolean |
| MicrosoftATP.Indicators.rbacGroupNames | A list of RBAC device group names where the indicator is exposed and active. Empty list if it is exposed to all devices. | Unknown |
| MicrosoftATP.Indicators.mitreTechniques | A list of MITRE techniques. | Unknown |
| MicrosoftATP.Indicators.indicatorType | The indicator Type. Possible values: FileSha1, FileSha256, IpAddress, DomainName and Url. | String |
| MicrosoftATP.Indicators.lastUpdateTime | The last time the indicator was updated. | Date |
| MicrosoftATP.Indicators.createdByDisplayName | The display name of the created app. | String |
| MicrosoftATP.Indicators.application | The application associated with the indicator. | String |
| MicrosoftATP.Indicators.title | The indicator title. | String |
| MicrosoftATP.Indicators.createdBySource | Source of indicator creation. For example, PublicApi. | String |
| MicrosoftATP.Indicators.historicalDetection | Whether a historical detection exists. | Boolean |
| MicrosoftATP.Indicators.lastUpdatedBy | The identity of the user/application that last updated the indicator. | String |
| MicrosoftATP.Indicators.creationTimeDateTimeUtc | The date and time the indicator was created. | Date |
| MicrosoftATP.Indicators.category | An number representing the indicator category. | Number |
| MicrosoftATP.Indicators.createdBy | Unique identity of the user/application that submitted the indicator. | String |
| File.MD5 | The MD5 hash of the file. | String |
| File.SHA1 | The SHA1 hash of the file. | String |
| File.SHA256 | The SHA256 hash of the file. | String |
| Domain.Name | The domain name. For example: "google.com". | String |
| IP.Address | IP address. | String |
| URL.Data | The URL. | String |
| DBotScore.Indicator | The indicator that was tested. | String |
| DBotScore.Type | The indicator type. | String |
| DBotScore.Vendor | The vendor used to calculate the score. | String |
| DBotScore.Score | The actual score. | Number |
