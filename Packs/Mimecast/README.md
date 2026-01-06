# Mimecast

Use the Mimecast integration to protect against email threats and data leaks while preventing service downtime through email archiving and uptime services.

## What does this pack do?

The <~XSOAR>Mimecast V2 integration</~XSOAR> <~XSIAM>Mimecast Event Collector</~XSIAM> fetches the following log types from Mimecast:

- **Audit** events that include information about administrative actions and configuration changes within a Mimecast account. For example, the user who performed the action, the type of action, timestamp, and additional context about the action.

- **SIEM** logs that include the following security and email processing events:
  - **Antivirus (av)** - Virus detection and remediation events
  - **Delivery** - Email delivery status and routing information
  - **Internal Email Protect** - Internal email security events
  - **Impersonation Protect** - Impersonation attack detection events
  - **Journal** - Email journaling events
  - **Process** - Email processing events
  - **Receipt** - Email receipt and acceptance events
  - **Attachment Protect** - Attachment security scanning events
  - **Spam** - Spam detection and filtering events
  - **URL Protect** - URL rewriting and click protection events

**Note**: All timestamps are in the Coordinated Universal Time (UTC) timezone.
