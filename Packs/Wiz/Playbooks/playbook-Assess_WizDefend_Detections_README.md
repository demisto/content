# Assess WizDefend Detections

This playbook provides a structured workflow for assessing and investigating Wiz Detections that come from the WizDefend integration. The playbook includes built-in validation to ensure proper integration setup before execution and automatically retrieves associated threat information when available.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* WizDefend

### Scripts
This playbook does not use any scripts.

### Commands
* wiz-get-detection
* wiz-get-threat

## Prerequisites
---
Before running this playbook, ensure:
* WizDefend integration is properly configured and enabled
* The incident contains a valid `wizdetectionid` field
* Proper API connectivity to Wiz services

## Playbook Inputs
---
The playbook automatically uses the following incident fields:
* `incident.wizdetectionid` - The Wiz detection ID (required)

There are no manual inputs required for this playbook.

## Playbook Outputs
---
The playbook outputs the following context data:
* `Wiz.Manager.Detection` - Detailed detection information
* `Wiz.Manager.Threat` - Associated threat information (if available)

## Playbook Image
---
![Assess Wiz Detections](../doc_files/Assess_WizDefend_Detections.png)

## Workflow
The playbook follows these steps:

### 1. Pre-execution Validation
- **Integration Check**: Verifies that the WizDefend integration is enabled and active
- **Data Validation**: Confirms that a detection ID exists in the incident

### 2. Detection Investigation (if validation passes)
- **Get Detection Information**: Retrieves detailed information about the specific detection using the detection ID
- **Issue ID Check**: Examines the detection response to determine if there's an associated threat (issue ID)

### 3. Threat Investigation (conditional)
- **Get Threat Information**: If an issue ID is found in the detection, retrieves detailed threat information using `wiz-get-threat`

### 4. Analysis and Documentation
- **Assess Impact**: Guides the analyst through impact assessment based on detection severity, threat information (if available), and affected resources

### 5. Completion
- **Done**: Structured end point indicating playbook completion

## Logic Flow
The playbook uses intelligent conditional logic:

```
Detection Retrieved → Check for Issue ID
                   ├─ Issue ID Found → Get Threat Info → Assess Impact
                   └─ No Issue ID → Skip Threat → Assess Impact
```

## Error Handling
The playbook gracefully handles the following scenarios:
- WizDefend integration not enabled or configured
- Missing detection ID in the incident
- API connectivity issues
- Detections without associated threats/issues

If prerequisites are not met, the playbook will skip the investigation steps and proceed directly to completion, preventing errors and ensuring smooth operation.

## Context Data Usage
The playbook leverages XSOAR context data effectively:
- Detection information is stored in `Wiz.Manager.Detection`
- The issue ID is accessed via `Wiz.Manager.Detection.issue.id`
- Threat information (when retrieved) is stored in `Wiz.Manager.Threat`

## Best Practices
- Ensure the WizDefend integration is properly configured before enabling incident fetching
- Verify that incident mapping includes the required field (`wizdetectionid`)
- Review and customize the impact assessment steps based on your organization's processes
- Consider the additional context provided by threat information when available for more comprehensive analysis

## Customization Options
The playbook can be extended with additional tasks such as:
- **Automated Enrichment**: Add tasks to enrich detection/threat data with external sources
- **Risk Scoring**: Implement custom risk scoring based on detection and threat characteristics
- **Assign Owner**: Add logic to automatically assign incidents based on detection type, severity, or threat presence
- **Document Investigation**: Add structured documentation steps for investigation findings
- **Escalation Logic**: Include conditional paths based on threat severity or detection type
- **Integration with SIEM**: Add tasks to query additional security tools for context
- **Automated Response**: Include containment or remediation steps for specific detection/threat types

## Technical Notes
- The playbook uses the `Wiz.Manager.Detection.issue.id` context path to check for associated threats
- Conditional logic ensures efficient execution by only retrieving threat data when relevant
- All API calls are wrapped in proper error handling through the integration validation steps