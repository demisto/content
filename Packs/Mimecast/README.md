# Mimecast

Mimecast is a cloud-based email security and management platform that provides comprehensive protection against email-borne threats, data leaks, and ensures business continuity through email archiving and continuity services.

## What does this pack do?

The <~XSOAR>Mimecast V2 integration</~XSOAR> <~XSIAM>Mimecast Event Collector</~XSIAM> can be configured to fetch two categories of logs from Mimecast:

- **Audit** - Information about administrative actions and configuration changes within the Mimecast account. Events include details such as the user who performed the action, the type of action, timestamp, and additional context about the activity.

- **SIEM** - Security and email processing events across multiple categories:
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

All timestamps are in Coordinated Universal Time (UTC) timezone.
