This playbook handles ASM alerts by enriching asset information and providing a means of remediating the issue directly or through contacting service owners.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

* Cortex ASM - Jira Notification
* Cortex ASM - Detect Service
* Cortex ASM - Remediation Path Rules
* Cortex ASM - Email Notification
* Cortex ASM - ServiceNow Notification
* Cortex ASM - Remediation
* Cortex ASM - Enrichment

### Integrations

This playbook does not use any integrations.

### Scripts

* GenerateASMReport
* GridFieldSetup

### Commands

* closeInvestigation
* setAlert
* send-mail

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| OwnerNotificationSubject | Subject of the notification \(email or ticket\) sent to potential service owner. | A new security risk was identified on an external service owned by your team | Required |
| OwnerNotificationBody | Body of the notification \(email or ticket\) sent to potential service owner. | Infosec identified a security risk on an external service potentially owned by your team: ${alert.name}&lt;br&gt;&lt;br&gt;<br/><br/>Description: ${alert.details}<br/>&lt;br&gt;&lt;br&gt;<br/><br/> | Required |
| RemediationNotificationSubject | Subject of the notification \(email or ticket\) sent to the service owner after remediation. | A new security risk was addressed on an external service owned by your team | Required |
| RemediationNotificationHTMLBody | Body of the notification \(email or ticket\) sent to the service owner after remediation. | &lt;!DOCTYPE html&gt;<br/>&lt;html lang="en"&gt;<br/>&lt;body&gt;<br/>    &lt;p&gt;<br/>        Infosec identified a security risk on an external service potentially owned by your<br/>        team:&lt;br&gt;&lt;b&gt;${alert.name}&lt;/b&gt;<br/>    &lt;/p&gt;<br/>    &lt;p&gt;<br/>        &lt;b&gt;Alert Details:&lt;/b&gt; ${alert.details}&lt;br&gt;<br/>        &lt;b&gt;Action Taken:&lt;/b&gt; ${alert.asmremediation.[0].action}&lt;br&gt;<br/>        &lt;b&gt;Action Outcome:&lt;/b&gt; ${alert.asmremediation.[0].outcome}&lt;br&gt;<br/>    &lt;/p&gt;<br/>&lt;/body&gt;<br/>&lt;/html&gt; | Required |
| BypassDevCheck | Determine whether to bypass the Dev Check in automated remediation criteria: https://docs-cortex.paloaltonetworks.com/r/Cortex-XPANSE/Cortex-Xpanse-Expander-User-Guide/Automated-Remediation-Capabilities-Matrix<br/><br/>Set to "True" if you want to bypass.  Default is "False". | False | Optional |
| AcceptedRiskDs | Comma-separated list of instance/VM IDs that are considered an accepted risk and that should be closed. |  | Optional |
| AcceptedRiskProjects | Comma-separated list of projects numbers that are considered an accepted risk and that should be closed.  For example, a list of GCP projects and AWS accounts. |  | Optional |
| AcceptedRiskOther | Comma-separated list of other items that are considered an accepted risk and that should be closed. For example, a list of folders numbers in GCP and subscription IDs in Azure. |  | Optional |
| JiraProjectKey | The Jira project key to associate with the issue. | XPANSE | Required |

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![Cortex ASM - ASM Alert](../doc_files/Cortex_ASM_-_ASM_Alert.png)
