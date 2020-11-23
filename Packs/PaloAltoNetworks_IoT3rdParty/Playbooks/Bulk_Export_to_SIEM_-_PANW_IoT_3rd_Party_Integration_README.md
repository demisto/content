This playbook gets all available assets ( alerts, vulnerabilities and devices) and send then to configured PANW third-party integration SIEM server.
 
## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* Syslog Sender
* Palo Alto Networks IoT 3rd Party

### Scripts
* SendALLPANWIoTDevicesToSIEM
* SendAllPANWIoTAlertsToSIEM
* SendAllPANWIoTVulnerabilitiesToSIEM
* IsIntegrationAvailable
* isError

### Commands
* closeInvestigation

## Playbook Inputs
---
There are no inputs for this playbook.

## Playbook Outputs
---
There are no outputs for this playbook.
