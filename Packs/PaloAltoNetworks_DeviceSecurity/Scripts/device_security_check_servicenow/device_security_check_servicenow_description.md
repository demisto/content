## device-security-check-servicenow Script

This script is run by 'device-security-check-service-playbook', which is triggered by a recurring XSOAR job.

It goes through all the open XSOAR incidents based on two incident types:
"Device Security Alert" and "Device Security Vulnerability". It searches for the ones with a customized instance field: ServiceNow table name, which tells us if a
corresponding ServiceNow ticket was created. 

It then loops through each one of these incidents, and queries ServiceNow for the ticket
status. If the status is "Closed" in ServiceNow, the script closes the XSOAR incident.