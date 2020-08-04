Enrich the IoT incident with device details. RACI model is returned for the incident if configured.
ServiceNow ticket can be created if ServiceNow integration is enabled.

## Dependencies
This playbook uses the following integration, and script.

## Integrations
* ServiceNow v2

## Scripts
* iot-security-get-raci

## Commands
This playbook does not use any commands.

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| IoTConfigListName | The IOT_CONFIG variable name in the XSOAR Lists. | IOT_CONFIG | Optional |
| CreateServiceNowTicket | ServiceNow ticket will be created if this is true. | false | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Palo_Alto_Neworks_IoT_Security](../../../docs/images/playbooks/Palo_Alto_Neworks_IoT_Security_Playbook.png?raw=true)
