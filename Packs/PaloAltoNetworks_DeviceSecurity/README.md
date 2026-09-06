## Palo Alto Networks Device Security Content Pack

This content pack enables Cortex XSOAR to integrate with Palo Alto Networks Device Security. It includes one integration and four automation scripts.

### Palo Alto Networks Device Security Integration

A wrapper around the Device Security Portal APIs for:

- getting device details by ID
- listing devices
- listing alerts and vulnerabilities
- resolving alerts and vulnerabilities

This integration can be used for incident response.

### RACI Model Calculation Script

Based on a mapping defined in Settings > Advanced > Lists, device attributes, and alert/vulnerability fields, this automation script can evaluate the "R" and "I" in RACI (Responsible and Informed). This is useful when incidents must be assigned to different departments in a large company.

### ServiceNow Ticket Check Script

This pack works with ServiceNow by persisting the new ticket ID in the custom field "Device Security ServiceNow Record ID". This automation script loops through all open Device Security alerts and vulnerabilities in XSOAR and queries ServiceNow for ticket status. If the status is "CLOSED", the corresponding XSOAR incident is closed.

### Alert and Vulnerability Resolution Post-Processing Script

Resolves Device Security portal incidents in the XSOAR post-processing stage.
