This playbook performs an investigation on a specific user in cloud environments, using queries and logs from Azure Log Analytics, AWS CloudTrail, G Suite Auditor, and GCP Logging.


## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

* Azure - User Investigation
* GCP - User Investigation
* AWS - User Investigation

### Integrations

This playbook does not use any integrations.

### Scripts

This playbook does not use any scripts.

### Commands

This playbook does not use any commands.

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Username | The username to investigate. |  | Optional |
| AzureSearchTime | The Search Time for the Azure Log Analytics search query. Default value: ago\(1d\) | ago(1d) | Optional |
| failedLogonThreshold | The threshold number of failed login by the user. required to determine how many failed logon event count as suspicious events. | 20 | Optional |
| MfaAttemptThreshold | The threshold number of MFA failed login by the user. required to determine how many MFA failed logon event count as suspicious events. | 10 | Optional |
| AwsTimeSearchFrom | The Search Time for the \`GetTime\` task used by the Aws Cloud Trail search query. <br/>This value represents the number of days to include in the search.<br/>Default value: 1.  \(1 Day\) | 1 | Optional |
| GcpProjectName | The GCP project name. This is a mandatory field for GCP queries. |  | Optional |
| GcpTimeSearchFrom | The Search Time for the \`GetTime\` task used by the GCP Logging search query. <br/>This value represents the number of days to include in the search.<br/>Default value: 1.  \(1 Day\) | 1 | Optional |
| cloudProvider | The cloud service provider involved. |  | Optional |

## Playbook Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| AwsMFAConfigCount | Count of MFA config performed by the user in the AWS environment. | unknown |
| AwsUserRoleChnagesCount | Count of the user roles that were changed by the user in the AWS environment. | unknown |
| AwsSuspiciousActivitiesCount | Count of the suspicious activities performed by the user in the AWS environment. | unknown |
| AwsScriptBasedUserAgentCount | Count of Script-based user agent usages by the user in the AWS environment. | unknown |
| AwsAccessKeyActivitiesCount | Count of access key activities performed by the user in the AWS environment. | unknown |
| AwsSecurityChangesCount | Count of the security rules that were changed by the user in the AWS environment. | unknown |
| AwsAdminActivitiesCount | Count of administrative activities performed by the user in the AWS environment. | unknown |
| AwsApiAccessDeniedCount | Count of Api access denied by the user in the AWS environment. | unknown |
| AwsFailedLogonCount | Count of failed logins by the user in the AWS environment. | unknown |
| GcpAnomalousNetworkTraffic | Determines whether there are events of anomalous network traffic performed by the user in the GCP environment. | unknown |
| GcpSuspiciousApiUsage | Determines whether there are event of suspicious Api usage by the user in the GCP environment. | unknown |
| GcpFailLogonCount | Count of failed logins by the user in the GCP environment. | unknown |
| GsuiteFailLogonCount | Count of failed logins by the user in the G Suite environment. | unknown |
| GsuiteUnusualLoginAllowedCount | Count of unusual logins performed by the user and allowed in the G Suite environment. | unknown |
| GsuiteUnusualLoginBlockedCount | Count of unusual logins performed by the user and blocked in the G Suite environment. | unknown |
| GsuiteSuspiciousLoginCount | Count of the suspicious logon performed by the user in the G Suite environment. | unknown |
| GsuiteUserPasswordLeaked | Determines whether user's password was leaked in the G Suite environment. | unknown |
| AzureScriptBasedUserAgentEvents | Script-based user agent events used by the user in the Azure environment. | unknown |
| AzureAdminActivitiesEvents | Administrative activities performed by the user in the Azure environment. | unknown |
| AzureSecurityRulesChangeEvents | Security rules that were changed by the user in the Azure environment. | unknown |
| AzureUnsuccessSecurityRulesChangeEvents | An unsuccessful attempts to change security rules by the user in the Azure environment. | unknown |
| AzureFailLoginCount | Count of failed logins by the user in the Azure environment. | unknown |
| AzureFailLoginMFACount | Count of failed logins by the user using MFA in the Azure environment. | unknown |
| AzureAnomaliesEvents | Anomalies Events on the user in the Azure environment. | unknown |
| AzureRiskyUserCount | Count the events where the user was defined as a risky user  in the Azure environment. | unknown |
| AzureUncommonCountryLogonEvents | Uncommon country logon events by the user in the Azure environment. | unknown |
| AzureUncommonVolumeEvents | Uncommon volume events by the user in the Azure environment. | unknown |
| AzureUncommonActivitiesEvents | Uncommon activities events by the user in the Azure environment. | unknown |
| CountAzureEvents.AzureScriptBasedUserAgentCount | Count of Script-based user agent usages by the user in the Azure environment. | unknown |
| CountAzureEvents.AzureAdminActivitiesCount | Count of administrative activities performed by the user in the Azure environment. | unknown |
| CountAzureEvents.AzureSecurityRulesChangeCount | Count of the security rules that were changed by the user in the Azure environment. | unknown |
| CountAzureEvents.AzureUnsuccessSecurityRulesChangeCount | count of unsuccessful attempts to change security rules by the user in the Azure environment. | unknown |
| CountAzureEvents.AzureAnomaliesCount | Count of anomalies Events on the user in the Azure environment. | unknown |
| CountAzureEvents.AzureUncommonCountryLogonCount | Count of uncommon country logon events by the user in the Azure environment. | unknown |
| CountAzureEvents.AzureUncommonVolumeCount | Count of uncommon volume events by the user in the Azure environment. | unknown |
| CountAzureEvents.AzureUncommonActivitiesCount | Count of uncommon activities events by the user in the Azure environment. | unknown |

## Playbook Image

---

![Cloud User Investigation - Generic](../doc_files/Cloud_User_Investigation_-_Generic.png)
