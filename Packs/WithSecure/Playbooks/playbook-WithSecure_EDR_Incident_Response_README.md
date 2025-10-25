This playbook handles automated response to critical EDR incidents (Broad Context Detections) from WithSecure.

The playbook is designed to contain and remediate threats detected by WithSecure EDR by automating the initial response actions.

## Playbook Flow

1. **Check Integration Availability**: Verifies that WithSecure Event Collector is enabled
2. **Get Incident Detections**: Retrieves all detections associated with the EDR incident
3. **Isolate Affected Endpoints**: Automatically isolates all devices involved in the incident from the network
4. **Trigger Malware Scan**: Initiates a malware scan on isolated endpoints
5. **Add Investigation Comment**: Documents the automated response actions in the incident
6. **Update Incident Status**: Marks the incident as "inProgress"
7. **Wait for Analyst Review**: Prompts the analyst to confirm threat remediation
8. **Release Endpoints** (conditional): Releases endpoints from isolation after confirmation

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

* WithSecureEventCollector

### Scripts

This playbook does not use any scripts.

### Commands

* with-secure-get-incident-detections
* with-secure-isolate-endpoint
* with-secure-scan-endpoint
* with-secure-add-incident-comment
* with-secure-update-incident-status
* with-secure-release-endpoint

## Playbook Inputs

This playbook requires that the incident contains a WithSecure incident ID in the custom field `withsecureincidentid`.

## Playbook Outputs

None.

## Use Cases

### Automated Threat Containment
When a critical EDR incident is detected, this playbook automatically:
- Isolates compromised endpoints to prevent lateral movement
- Scans for additional malware
- Documents actions taken
- Escalates to security team for investigation

### Ransomware Response
For ransomware detections, isolation prevents file encryption from spreading to other systems while security team investigates.

### Lateral Movement Prevention
When lateral movement is detected, immediate isolation stops the attacker from pivoting to additional systems.

## Important Notes

- **Endpoint Isolation**: Only works on Windows computers in active state
- **Operations are Asynchronous**: Use `with-secure-get-device-operations` to check operation status
- **Analyst Confirmation**: Playbook waits for manual confirmation before releasing endpoints
- **Incident ID Mapping**: Ensure incidents include the `withsecureincidentid` field

## Customization

You can customize this playbook to:
- Add enrichment steps before isolation
- Include additional forensic data collection
- Send notifications to specific teams
- Integrate with ticketing systems
- Automate endpoint release based on scan results

