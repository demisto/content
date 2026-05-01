## Core Support Ticket

Automates Cortex support ticket creation by classifying issues with AI, validating user permissions, and populating ticket fields. Includes an Agentix action for conversational ticket filing.

### What Does This Pack Do?

This pack provides an end-to-end workflow for creating Cortex support tickets directly from within the Cortex platform:

- **Permission check**: Verifies whether the current user has the required CSP permissions and tenant entitlement to manage support tickets.
- **Taxonomy retrieval**: Fetches the live support ticket taxonomy — all issue categories and their associated problem concentrations — directly from the Cortex support API.
- **AI classification**: Uses an AI-powered LLM task (`SupportTicketClassification`) to automatically map the user's issue description to the correct category and sub-category from the taxonomy.
- **Validation**: Parses and validates the AI classification result against the fetched taxonomy, providing warnings for unrecognised values.
- **Ticket population**: Fills all required support ticket fields, including description, contact number, issue impact, frequency, and timestamp.
- **Agentix integration**: Exposes the full workflow as an Agentix action (`Cortex - Fill Support Ticket`) so users can file support tickets through a conversational AI interface.

### Playbooks

- **Cortex - Fill Support Ticket**: Orchestrates the full support ticket creation flow — permission check → taxonomy fetch → AI classification → field population.

### Scripts

| Script | Description |
|---|---|
| FillSupportTicket | Maps validated inputs to the support ticket context fields. |
| GetSupportTicketTaxonomy | Fetches the live issue category and problem concentration taxonomy from the Cortex support API. |
| GetSupportTicketTaxonomyWrapper | Wrapper to ensure GetSupportTicketTaxonomy runs on the correct engine. |
| SupportTicketCategoryParser | Parses and validates the `category\|\|\|concentration` string from the AI classifier against the taxonomy. |
| VerifySupportTicketPermission | Checks user CSP permission and tenant entitlement for support ticket management. |
| VerifySupportTicketPermissionWrapper | Wrapper to ensure VerifySupportTicketPermission runs on the correct engine. |

### Use Cases

- Enable end-users to file Cortex support tickets directly through the Agentix AI agent without leaving the platform.
- Automate issue triage by classifying ticket descriptions using AI before submission.
- Enforce permission gates to prevent unauthorised support ticket creation.
