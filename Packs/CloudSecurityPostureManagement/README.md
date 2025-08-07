## Overview

This content pack helps fix common cloud misconfigurations automatically with analyst approval. It currently supports AWS, with planned support for Azure and GCP. The pack also includes a versatile and cloud-agnostic playbook for creating tickets and sending notifications through ServiceNow, Jira, Slack, and Microsoft Teams.

## Key Use Cases

- Automatically remediate AWS misconfigurations with optional analyst approval.
- Create or update issue tickets in Jira or ServiceNow.
- Notify teams through Slack, Microsoft Teams, or email.
- Build cloud-agnostic, modular remediation workflows.

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

All remediation playbooks leverage:

- AWS integrations
- Sub-playbooks for ticket creation and notification
- Context-aware command execution

### Generic Utility Playbook

4. **Create Ticket and Notify**
   - Creates or updates incident tickets using Jira V3 or ServiceNow v2.
   - Notifies stakeholders via Slack, Microsoft Teams, or email.
   - Customizable behavior: ticket-only, notification-only, or both.
   - Detects available integrations and adapts accordingly.

## Dependencies

This pack uses the following integrations:

- AWS
- Cortex Core - IR
- Jira V3
- ServiceNow v2
- Microsoft Teams
- SlackV3
- mail-sender

## Future Roadmap

- Add Azure remediation playbooks (e.g., Azure Storage, RBAC misconfigurations)
- Add GCP remediation playbooks (e.g., GCS bucket access, IAM conditions)

## Requirements

- Active integrations for AWS, Jira, ServiceNow, Slack, Microsoft Teams (depending on use)
- Access to cloud account APIs with sufficient permissions for remediation

### Pack Contributors

---

- Shashi Kiran N

Contributions are welcome and appreciated. For more info, visit our [Contribution Guide](https://xsoar.pan.dev/docs/contributing/contributing).
