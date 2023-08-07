This playbook performs an investigation on a specific user in Azure environments, using queries and logs from Azure Log Analytics.


## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

* Azure Log Analytics

### Scripts

* SetMultipleValues
* SetAndHandleEmpty

### Commands

* azure-log-analytics-execute-query

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Username | The username to investigate. | avishai@demistodev.onmicrosoft.com | Optional |
| AzureSearchTime | The Search Time for the Azure Log Analytics search query. Default value: ago\(1d\) | ago(7d) | Optional |
| failedLogonThreshold | The threshold number of failed login by the user. required to determine how many failed logon event count as suspicious events. | 20 | Optional |
| MfaAttemptThreshold | The threshold number of MFA failed login by the user. required to determine how many MFA failed logon event count as suspicious events. | 10 | Optional |

## Playbook Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| AzureScriptBasedUserAgentEvents | Script-based user agent events used by the user in the Azure environment. | unknown |
| CountAzureEvents.AzureScriptBasedUserAgentCount | Count of script-based user agent usages by the user in the Azure environment. | unknown |
| AzureAdminActivitiesEvents | Administrative activities performed by the user in the Azure environment. | unknown |
| CountAzureEvents.AzureAdminActivitiesCount | Count of administrative activities performed by the user in the Azure environment. | unknown |
| AzureSecurityRulesChangeEvents | Security rules that were changed by the user in the Azure environment. | unknown |
| CountAzureEvents.AzureSecurityRulesChangeCount | Count of the security rules that were changed by the user in the Azure environment. | unknown |
| AzureUnsuccessSecurityRulesChangeEvents | An unsuccessful attempts to change security rules by the user in the Azure environment. | unknown |
| CountAzureEvents.AzureUnsuccessSecurityRulesChangeCount | count of unsuccessful attempts to change security rules by the user in the Azure environment. | unknown |
| AzureFailLoginCount | Count of failed logins by the user in the Azure environment. | unknown |
| AzureFailLoginMFACount | Count of failed logins by the user using MFA in the Azure environment. | unknown |
| AzureAnomaliesEvents | Anomalies Events on the user in the Azure environment. | unknown |
| CountAzureEvents.AzureAnomaliesCount | Count of anomalies Events on the user in the Azure environment. | unknown |
| AzureRiskyUserCount | Count the events where the user was defined as a risky user  in the Azure environment. | unknown |
| AzureUncommonCountryLogonEvents | Uncommon country logon events by the user in the Azure environment. | unknown |
| CountAzureEvents.AzureUncommonCountryLogonCount | Count of uncommon country logon events by the user in the Azure environment. | unknown |
| AzureUncommonVolumeEvents | Uncommon volume events by the user in the Azure environment. | unknown |
| CountAzureEvents.AzureUncommonVolumeCount | Count of uncommon volume events by the user in the Azure environment. | unknown |
| AzureUncommonActivitiesEvents | Uncommon activities events by the user in the Azure environment. | unknown |
| CountAzureEvents.AzureUncommonActivitiesCount | Count of uncommon activities events by the user in the Azure environment. | unknown |

## Playbook Image

---

![Azure - User Investigation](../doc_files/Azure_-_User_Investigation.png)
