# Hoxhunt Integration for Cortex XSOAR

The Hoxhunt Integration automates the ingestion and processing of phishing threats identified in Hoxhunt, enabling streamlined threat response workflows by bringing Hoxhunt-reported incidents into Cortex XSOAR for analysis, enrichment, and remediation.

## Use Cases

- Synchronize incident status between Hoxhunt and Cortex XSOAR for consistent lifecycle management.
- Automatically ingest phishing incidents reported in Hoxhunt into Cortex XSOAR for analysis and response.
- Add analytical notes to Hoxhunt incidents directly from Cortex XSOAR workflows.
- Remove threats from Hoxhunt incidents.
- Send SOC feedback to Hoxhunt when closing an incident in Cortex XSOAR.
- Update incident sensitivity based on internal policies.

## What does this pack do

- **Fetch Hoxhunt Incidents**: Pulls phishing incidents from Hoxhunt into Cortex XSOAR for centralized management and response.

- **Synchronize Incident Data**: Ensures up-to-date incident data in both Hoxhunt and Cortex XSOAR, maintaining lifecycle alignment between platforms.

- **Incident Enrichment**: Adds detailed threat information to incidents, including screenshots, to support rapid analyst review of phishing evidence.

- **Add and Update Incident Notes**: Allows analysts to add contextual notes and updates to Hoxhunt incidents from Cortex XSOAR, aiding collaborative investigation.

- **Remove Threats from Incidents**: Enables the removal of threats linked to an incident, streamlining cleanup of false positives or low-priority threats.

- **Send SOC Feedback**: Allows SOC teams to provide structured feedback to Hoxhunt, including custom messages, as part of incident resolution.

- **Set Incident Sensitivity and Classification**: Sets incident sensitivity and classification directly from Cortex XSOAR, aligning with organizational policies.

- **Update Incident State**: Manages incident state transitions, such as between "Open" and "Resolved," ensuring real-time status updates.

## Prerequisites

Hoxhunt external API key: Ensure access to Hoxhunt with necessary permissions.
Acquirable from Hoxhunt admin panel [https://admin.hoxhunt.com/account-settings/access-tokens](https://admin.hoxhunt.com/account-settings/access-tokens)

## Main playbook: Hoxhunt - Enrich Incident

Run for incidents fetched from Hoxhunt into XSOAR

Enrich Incident's main function is to provide a visual reference for the first threat in the Hoxhunt incident, adding additional context to the incident within XSOAR. The screenshot can be used for further review or as part of an investigation report.

### Summary of playbook features

- Automated Screenshot: Takes a screenshot of the first threat URL.
- Simple Workflow: Completes automatically with minimal manual intervention, enriching the incident with visual content.
