## Palo Alto Networks IoT Content Pack
This content pack enables XSOAR to integrate with Palo Alto Networks IoT solution. It includes one integration and four automation scripts.


### Palo Alto Networks IoT Integration
Wrap around the IoT Security Portal APIs for
 - getting a device detail by an ID
 - listing devices
 - listing alerts and vulnerabilities
 - resolving alert and vulnerability

This integration can be used for the incident response purpose.

### RACI model calculation
Based on a mapping defined in the Settings > Advanced > Lists, the device attributes and the alert/vulnerability fields, this automation script can evalute the "R" and "I" in RACI (Responsible and Informed). This is useful when you have a requirement of assigning incidents to different departments in a large company.

### ServiceNow ticket check
The way this pack works with ServiceNow is persisting the new ticket ID in a custom field "ServiceNow Record ID". This automation script is to loop all the opened IoT alerts and vulnerabilities in XSOAR, and query ServiceNow for the ticket status. If the status is "CLOSED", the corresponding XSOAR incident will be closed.

### Alert and Vulnerability resolution post-processing script
For resolving the IoT security portal incidents in the post-processing XSOAR stage.
