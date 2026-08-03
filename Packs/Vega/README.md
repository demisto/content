# Vega

## Overview

The Vega Content Pack enables seamless integration between the Vega security platform and Cortex XSOAR, allowing security teams to centralise alert management, automate investigations, and orchestrate incident response from a single operational workspace.

By synchronising Vega alerts and incidents with Cortex XSOAR, analysts can investigate, triage, and remediate security events using XSOAR playbooks while maintaining bidirectional synchronisation with the Vega platform. This reduces manual effort, improves operational efficiency, and ensures both platforms remain consistently updated throughout the incident lifecycle.

---

## About Vega

Vega is an AI-powered security operations platform that correlates security telemetry across identity, endpoint, network, cloud, email, and application environments to detect sophisticated threats. By combining advanced analytics with actionable recommendations, Vega enables security teams to rapidly investigate, prioritise, and respond to security incidents.

---

## Key Capabilities

The Vega Content Pack extends Cortex XSOAR with native integration capabilities that enable organisations to automate their Vega-driven security operations.

### Alert and Incident Ingestion

Automatically retrieve Vega alerts and incidents into Cortex XSOAR, where they are converted into native XSOAR incidents for investigation and response.

### Bidirectional Incident Synchronisation

Keep Vega and Cortex XSOAR synchronised throughout the incident lifecycle. Comments, investigation updates, status changes, verdicts, and reasoning can be mirrored between both platforms, ensuring analysts always work with the latest information regardless of where updates originate.

### Investigation Enrichment

Retrieve detailed alert events directly from Vega to provide analysts with rich contextual information during investigations. This enables deeper understanding of the affected assets, attack techniques, and event timelines without leaving Cortex XSOAR.

### Automated Response

Leverage Cortex XSOAR playbooks together with Vega's recommended actions to automate common remediation tasks across identity, endpoint, network, cloud, email, and application security technologies.

### Native Vega Commands

The integration provides commands that allow playbooks and analysts to interact directly with the Vega platform, including:

- Update Vega alerts
- Update Vega incidents
- Retrieve alert events
- Synchronise investigation status
- Manage incident lifecycle from Cortex XSOAR

### Custom Incident Experience

The pack includes custom incident layouts that present Vega-specific information in a structured and intuitive format, including:

- Alert and Incident Details
- Severity and Status
- MITRE ATT&CK Techniques
- Verdict and Investigation Reasoning
- Recommended Actions
- Associated Alert Events
- Additional Vega Context

---

## Typical SOC Workflow

1. Vega detects suspicious activity and generates an alert or incident.
2. Cortex XSOAR automatically ingests the event.
3. Analysts investigate the incident using enriched Vega context.
4. Cortex XSOAR playbooks execute automated investigation and remediation workflows.
5. Investigation progress, comments, verdicts, and status changes are synchronised back to Vega.
6. Both platforms remain aligned throughout the incident lifecycle.

---

## Included Content

This Content Pack includes:

- Vega Integration
- Incident Fetching
- Alert Fetching
- Bidirectional Mirroring
- Custom Incident Layouts
- Investigation Commands
- Sample Automation Playbooks

---

## Customer Benefits

Using the Vega Content Pack helps security teams:

- Reduce manual investigation effort
- Eliminate duplicate updates across platforms
- Accelerate incident triage and response
- Improve analyst productivity
- Standardise automated response workflows
- Maintain consistent incident state across Vega and Cortex XSOAR
- Leverage Vega intelligence directly within Cortex XSOAR investigations

---

The Vega Content Pack enables organisations to combine Vega's advanced threat detection capabilities with Cortex XSOAR's powerful orchestration and automation platform, helping Security Operations Centers respond to threats faster while reducing operational overhead.

## Documentation

Comprehensive documentation is available to help you configure, deploy, and use the Vega Content Pack.

The documentation includes:

- Installation prerequisites
- Application configuration
- Authentication and API credentials
- Incident fetching configuration
- Bidirectional mirroring setup
- Available automation commands
- Playbook usage
- Troubleshooting guidance
- Best practices

For the complete configuration and user guide, please visit:

**[Cortex XSOAR App](https://docs.vega.io/connectors/external-connectors/cortex_xsoar_app)**

> **Note:** We recommend reviewing the documentation before deploying the integration to ensure the application is configured according to your organization's security and operational requirements.
