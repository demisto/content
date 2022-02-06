Transform a XSOAR indicator into a Microsoft Defender for Endpoint IOC. The output (at TransformIndicatorToMSDefenderIOC.JsonOutput) is a json represents the indicators in MSDE format. This json can be the input for the *microsoft-atp-indicator-batch-update* command.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags |  |
| Cortex XSOAR Version | 6.0.0 |

## Inputs
---

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | The indicators query. | Required |
| action | The action that will be taken if the indicator will be discovered in the organization. | Required |
| limit | The maximum number of indicators to fetch. | Optional | 
| offset | The results offset page. Only change when the number of the results exceed the limit. | Optional | 

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| TransformIndicatorToMSDefenderIOC.JsonOutput | Json output of the indicators. Should be the input for the \*microsoft-atp-indicator-batch-update\*. | String |
| TransformIndicatorToMSDefenderIOC.Indicators.indicatorValue | The value of the Indicator. | String |
| TransformIndicatorToMSDefenderIOC.Indicators.indicatorType | Type of the indicator. Possible values are: FileSha1, FileSha256, FileMd5, CertificateThumbprint, IpAddress, DomainName, Url | String |
| TransformIndicatorToMSDefenderIOC.Indicators.lastUpdateTime | The last time the indicator was updated. | String |
| TransformIndicatorToMSDefenderIOC.Indicators.lastUpdatedBy | Identity of the user/application that last updated the indicator. | String |
| TransformIndicatorToMSDefenderIOC.Indicators.action | The action that will be taken if the indicator will be discovered in the organization. Possible values are: "Warn", "Block", "Audit", "Alert", "AlertAndBlock", "BlockAndRemediate" and "Allowed". | String |
| TransformIndicatorToMSDefenderIOC.Indicators.title | Indicator title. | String |
| TransformIndicatorToMSDefenderIOC.Indicators.expirationTime | The expiration time of the indicator. | String |
| TransformIndicatorToMSDefenderIOC.Indicators.description | Description of the indicator. | String |
| TransformIndicatorToMSDefenderIOC.Indicators.creationTimeDateTimeUtc | The date and time when the indicator was created. | String |
| TransformIndicatorToMSDefenderIOC.Indicators.Severity | The severity of the indicator. possible values are: Informational, Low, Medium and High. | String |
| TransformIndicatorToMSDefenderIOC.Indicators.application | The application associated with the indicator. | String |
| TransformIndicatorToMSDefenderIOC.Indicators.externalID | Id the customer can submit in the request for custom correlation. | String |
| TransformIndicatorToMSDefenderIOC.Indicators.sourceType | User in case the Indicator created by a user. "AadApp" in case it submitted using automated application via the API. | String |
| TransformIndicatorToMSDefenderIOC.Indicators.createdBySource | The name of the user or application that submitted the indicator. | String |
| TransformIndicatorToMSDefenderIOC.Indicators.createdBy | Unique identity of the user or application that submitted the indicator. | String |
| TransformIndicatorToMSDefenderIOC.Indicators.recommendedActions | Recommended actions for the indicator. | String |
| TransformIndicatorToMSDefenderIOC.Indicators.rbacGroupNames | RBAC device group names where the indicator is exposed and active. Empty list in case it exposed to all devices. | Unknown |
| TransformIndicatorToMSDefenderIOC.Indicators.rbacGroupIds | RBAC device group ID's where the indicator is exposed and active. Empty list in case it exposed to all devices. | Unknown |
| TransformIndicatorToMSDefenderIOC.Indicators.generateAlert | True if alert generation is required, False if this indicator should not generate an alert. | String |


## More info
---
1. Please read about MSDE Indicator resource type [here](https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/ti-indicator?view=o365-worldwide).
2. Please read about limitations for creating and updating batch of indicators [here](https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/import-ti-indicators?view=o365-worldwide#limitations).
3. Please read about the required permissions for creating and updating batch of indicators [here](https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/import-ti-indicators?view=o365-worldwide#permissions). 
