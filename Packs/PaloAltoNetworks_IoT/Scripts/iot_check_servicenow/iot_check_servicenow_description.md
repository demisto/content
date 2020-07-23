## iot-security-check-servicenow Script

This script is run by a playbook 'iot-check-service-playbook', that is run by a recurring XSOAR job.

First of all, we are looping all the open XSOAR incidents based on two incident types:
"IoT Alert" and "IoT Vulnerability"

Then we are only interested the ones with a customized instance field: ServiceNow table name, which tells us a
corresponding ServiceNow ticket was created. Looping each one of this incident, and query ServiceNow for the ticket
status. If the status is "Closed", we are closing the XSOAR incident.
