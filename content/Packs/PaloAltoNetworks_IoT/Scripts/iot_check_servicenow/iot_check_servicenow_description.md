## iot-security-check-servicenow Script

This script is run by 'iot-check-service-playbook', which is triggered by a recurring XSOAR job.

It goes through all the open XSOAR incidents based on two incident types:
"IoT Alert" and "IoT Vulnerability". It searches for the ones with a customized instance field: ServiceNow table name, which tells us if a
corresponding ServiceNow ticket was created. 

It then loops through each one of these incidents, and queries ServiceNow for the ticket
status. If the status is "Closed" in ServiceNow, the script closes the XSOAR incident.
