## Overview

This content pack helps fix common cloud misconfigurations automatically with analyst approval or performs auto-remediation without approval, optionally notifying stakeholders. It also includes two versatile, cloud-agnostic playbooks for creating tickets and sending notifications via ServiceNow, Jira, Email, Slack, or Microsoft Teams.

## Key Use Cases

- Automatically remediate AWS misconfigurations with optional analyst approval.
- Automatically remediate AWS, Azure, and GCP public access misconfigurations with minimal or no manual intervention.
- Create or update issue tickets in Jira or ServiceNow.
- Notify teams through Slack, Microsoft Teams, or email.

## Included Playbooks

### AWS Remediation Playbooks

1. **AWS EC2 Instance Misconfiguration Remediation**
   - Ensures EC2 instances are configured with Instance Metadata Service v2 (IMDSv2).
   - Offers analyst-in-the-loop or fully automated remediation.
   - Integrates with AWS and Cortex Core IR.

2. **AWS IAM Password Policy Remediation**
   - Remediates 9 different insecure IAM password policy configurations, such as:
     - Password reuse
     - Minimum password length
     - Lack of complexity requirements (uppercase, symbols, etc.)
     - No expiration policy
   - Supports both automated and analyst approval flows.

3. **AWS S3 Bucket Public Access Remediation**
   - Detects and remediates publicly accessible S3 buckets (read or write access).
   - Ensures S3 compliance with cloud security policies.

4. **AWS Public Access Misconfiguration - Auto-remediate**
    - Automatically disables public access settings for RDS Database instances, EBS Snapshots and S3 buckets.
    - Option to notify stakeholders about the remediation via Email, Slack or MS Teams.
        - Set enableNotifications to 'yes' and configure inputs for the Notify Stakeholders playbook to send issue, asset and remediation details.

### Azure Remediation Playbooks

1. **Azure Public Access Misconfiguration - Auto-remediate**
    - Automatically remediates the misconfiguration issues for publicly accessible Azure blob containers, overly permissive Azure VM Disks or default Allow network access to Azure Storage Accounts.
    - Option to notify stakeholders about the remediation via Email, Slack or MS Teams.
        - Set enableNotifications to 'yes' and configure inputs for the Notify Stakeholders playbook to send issue, asset and remediation details.

### GCP Remediation Playbooks

1. **GCP Public Access Misconfiguration - Auto-remediate**
    - Automatically secure the publicly exposed GCP bucket by updating policies to block public access immediately.
    - Option to notify stakeholders about the remediation via Email, Slack or MS Teams.
        - Set enableNotifications to 'yes' and configure inputs for the Notify Stakeholders playbook to send issue, asset and remediation details.

All remediation playbooks leverage:

- AWS integrations
- Sub-playbooks for ticket creation and/or notification
- Context-aware command execution

### Generic Utility Playbook

1. **Create Ticket and Notify**
   - Creates or updates incident tickets using Jira V3 or ServiceNow v2.
   - Notifies stakeholders via Slack, Microsoft Teams, or email.
   - Customizable behavior: ticket-only, notification-only, or both.
   - Detects available integrations and adapts accordingly.

2. **Notify Stakeholders**
    - This is a sub-playbook that is used in the Public Access Misconfiguration remediation playbooks for AWS, Azure, and GCP.
    - It is used to send issue and asset details along with the remediation action taken, in a well formatted notification message via Email, Slack or MS Teams, depending on the configured and enabled integrations.
    - Configure recipients for email, slack or MS Teams notification in the Playbook Triggered header of this playbook
    - If no inputs are pre-configured and enableNotifications is set to 'yes' in the remediation playbook, execution will pause to request at least one recipient.

## Dependencies

This pack uses the following integrations:

- AWS
- Azure
- GCP
- Cortex Core - IR
- Jira V3
- ServiceNow v2
- Microsoft Teams
- SlackV3
- mail-sender

## Future Roadmap

- Additional coverage for High/Critical severity AWS, Azure, and GCP misconfiguration issues

## Requirements

- Active integrations for AWS, Azure, GCP, Jira, ServiceNow, Slack, Microsoft Teams (depending on use)
- Access to cloud account APIs with sufficient permissions for remediation

### Pack Contributors

---

- Shashi Kiran N
- Aneesha More

Contributions are welcome and appreciated. For more info, visit our [Contribution Guide](https://xsoar.pan.dev/docs/contributing/contributing).
