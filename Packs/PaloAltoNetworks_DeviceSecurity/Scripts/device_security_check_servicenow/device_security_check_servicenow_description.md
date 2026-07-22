## device-security-check-servicenow Script

This script is run by 'device-security-check-service-playbook', which is triggered by a recurring Cortex XSOAR job.

It goes through all open Cortex XSOAR incidents based on two incident types:
"Device Security Alert" and "Device Security Vulnerability". It searches for incidents where the custom fields "Device Security ServiceNow Table Name" and "Device Security ServiceNow Record ID" are populated, which indicates that a corresponding ServiceNow ticket was created.

It then loops through each one of these incidents, and queries ServiceNow for the ticket
status. If the status is "Closed" in ServiceNow, the script closes the Cortex XSOAR incident.