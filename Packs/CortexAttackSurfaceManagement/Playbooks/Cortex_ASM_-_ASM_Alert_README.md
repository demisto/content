This playbook handles ASM alerts by enriching asset information and providing a means of remediating the issue directly or through contacting service owners.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

* Cortex ASM - Detect Service
* Cortex ASM - Email Notification
* Cortex ASM - Enrichment
* Cortex ASM - Instant Message
* Cortex ASM - Jira Notification
* Cortex ASM - Remediation
* Cortex ASM - Remediation Guidance
* Cortex ASM - Remediation Path Rules
* Cortex ASM - ServiceNow Notification

### Integrations

This playbook does not use any integrations.

### Scripts

* DeleteContext
* GenerateASMReport
* GridFieldSetup

### Commands

* closeInvestigation
* send-mail
* setAlert

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| OwnerNotificationSubject | Subject of the notification \(email or ticket\) sent to potential service owner. | A new security risk was identified on an external service owned by your team | Required |
| OwnerNotificationBody | Body of the notification \(email or ticket\) sent to potential service owner. | Infosec identified a security risk on an external service potentially owned by your team: ${alert.name}&lt;br&gt;&lt;br&gt;<br/><br/>Description: ${alert.details}<br/>&lt;br&gt;&lt;br&gt;<br/><br/> | Required |
| NotificationTicketType | The ticket type used by ticketing systems. The default is "incident" because ticketing systems such as ServiceNow and Cherwell use it as default. | incident | Required |
| RemediationNotificationSubject | Subject of the notification \(email or ticket\) sent to the service owner after remediation. | A new security risk was addressed on an external service owned by your team | Required |
| RemediationNotificationHTMLBody | Body of the notification \(email or ticket\) sent to the service owner after remediation. | &lt;!DOCTYPE html&gt;<br/>&lt;html lang="en"&gt;<br/>&lt;body&gt;<br/>    &lt;p&gt;<br/>        Infosec identified a security risk on an external service potentially owned by your<br/>        team:&lt;br&gt;&lt;b&gt;${alert.name}&lt;/b&gt;<br/>    &lt;/p&gt;<br/>    &lt;p&gt;<br/>        &lt;b&gt;Alert Details:&lt;/b&gt; ${alert.details}&lt;br&gt;<br/>        &lt;b&gt;Action Taken:&lt;/b&gt; ${alert.asmremediation.[0].action}&lt;br&gt;<br/>        &lt;b&gt;Action Outcome:&lt;/b&gt; ${alert.asmremediation.[0].outcome}&lt;br&gt;<br/>    &lt;/p&gt;<br/>&lt;/body&gt;<br/>&lt;/html&gt; | Required |
| BypassDevCheck | Determine whether to bypass the Dev Check in automated remediation criteria: https://docs-cortex.paloaltonetworks.com/r/Cortex-XPANSE/Cortex-Xpanse-Expander-User-Guide/Automated-Remediation-Capabilities-Matrix<br/><br/>Set to "True" if you want to bypass.  Default is "False". | False | Optional |
| AcceptedRiskIDs | Comma-separated list of instance/VM IDs that are considered an accepted risk and that should be closed. |  | Optional |
| AcceptedRiskProjects | Comma-separated list of projects numbers that are considered an accepted risk and that should be closed.  For example, a list of GCP projects, names of Azure Resource Groups, and AWS accounts. |  | Optional |
| AcceptedRiskOther | Comma-separated list of other items that are considered an accepted risk and that should be closed. For example, a list of folders numbers in GCP and subscription IDs in Azure. |  | Optional |
| JiraProjectKey | The Jira project key to associate with the issue. |  | Required |
| AWSAssumeRoleName | If assuming roles for AWS, this is the name of the role to assume \(should be the same for all organizations\). |  | Optional |
| InstantMessageChannel | Channel to send instant messages for notification purposes.  For Slack, this will be the channel ID. |  | Optional |

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![Cortex ASM - ASM Alert](../doc_files/Cortex_ASM_-_ASM_Alert.png)
