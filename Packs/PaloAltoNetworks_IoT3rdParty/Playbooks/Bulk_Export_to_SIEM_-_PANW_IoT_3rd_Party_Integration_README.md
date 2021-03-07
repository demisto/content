Gets all available assets (alerts, vulnerabilities, and devices) and sends them to the SIEM server for which you've configured PANW 3rd party integration. Syslog Sender integration is used to send data to the SIEM server in a CEF data format that each SIEM can translate into their own data format.
 
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
